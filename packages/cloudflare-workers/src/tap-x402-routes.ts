/**
 * x402 Payment Gating — Route Handlers
 *
 * Exposes BOTCHA's x402-compliant API endpoints:
 *
 *   POST /v1/x402/verify-payment   — Facilitator: verify a payment proof
 *   GET  /v1/x402/challenge        — Pay-for-verification (402 → X-Payment → token)
 *   GET  /agent-only/x402          — Demo: requires BOTCHA token + x402 payment
 *   POST /v1/x402/webhook          — Settlement notifications from facilitators
 *
 * All endpoints are built for Cloudflare Workers (Hono framework, no Node APIs).
 */

import type { Context } from 'hono';
import { extractBearerToken, verifyToken, getSigningPublicKeyJWK, type ES256SigningKeyJWK } from './auth.js';

function getVerificationPublicKey(env: any) {
  const rawSigningKey = env?.JWT_SIGNING_KEY;
  if (!rawSigningKey) return undefined;
  try {
    const signingKey = JSON.parse(rawSigningKey) as ES256SigningKeyJWK;
    return getSigningPublicKeyJWK(signingKey);
  } catch {
    return undefined;
  }
}
import {
  buildPaymentRequiredDescriptor,
  parsePaymentHeader,
  verifyX402Payment,
  issueTokenForPayment,
  buildPaymentResponseHeader,
  storePaymentRecord,
  processWebhookEvent,
  VERIFICATION_PRICE_USDC_UNITS,
  VERIFICATION_PRICE_HUMAN,
  BASE_CHAIN_ID,
  BOTCHA_WALLET,
  USDC_BASE_ADDRESS,
  PAYMENT_DEADLINE_SECONDS,
  type X402WebhookEvent,
  type X402PaymentRecord,
} from './tap-x402.js';

// ============ HELPERS ============

function getSigningKey(env: any): ES256SigningKeyJWK | undefined {
  if (!env.JWT_SIGNING_KEY) return undefined;
  try {
    return JSON.parse(env.JWT_SIGNING_KEY) as ES256SigningKeyJWK;
  } catch {
    console.error('Failed to parse JWT_SIGNING_KEY — falling back to HS256');
    return undefined;
  }
}

function getPublicKey(env: any) {
  const sk = getSigningKey(env);
  return sk ? getSigningPublicKeyJWK(sk) : undefined;
}

/**
 * Resolve BOTCHA wallet from env (allows override via BOTCHA_PAYMENT_WALLET).
 */
function getWallet(env: any): string {
  return env.BOTCHA_PAYMENT_WALLET || BOTCHA_WALLET;
}

/**
 * Resolve app_id from query string, header, or JWT claim.
 * Returns undefined if not present.
 */
function extractAppId(c: Context): string | undefined {
  return (
    c.req.query('app_id') ||
    c.req.header('x-app-id') ||
    undefined
  );
}

// ============ ROUTE HANDLERS ============

/**
 * POST /v1/x402/verify-payment
 *
 * Acts as a lightweight x402-compatible facilitator.
 * Accepts a payment proof (base64-encoded X-Payment payload) and
 * verifies: structure, recipient, amount, deadline, nonce, signature.
 *
 * Request body:
 *   { payment: "<base64-encoded X402PaymentProof>" }
 *   OR submit the raw X-Payment header value directly in the body field.
 *
 * Response:
 *   200 { verified: true, txHash, payer, amount, network }
 *   400 { verified: false, error, errorCode }
 */
export async function verifyPaymentRoute(c: Context): Promise<Response> {
  try {
    // Auth check first — payment verification is a privileged operation
    const authHeader = c.req.header('authorization');
    const token = extractBearerToken(authHeader);
    if (!token) {
      return c.json({
        verified: false,
        error: 'UNAUTHORIZED',
        message: 'Bearer token required. Get a token via the BOTCHA challenge flow.',
      }, 401);
    }
    const publicKey = getVerificationPublicKey(c.env);
    const tokenResult = await verifyToken(token, c.env.JWT_SECRET, c.env, undefined, publicKey);
    if (!tokenResult.valid) {
      return c.json({
        verified: false,
        error: 'INVALID_TOKEN',
        message: 'Bearer token is invalid or expired',
      }, 401);
    }

    const body = await c.req.json<{
      payment?: string;
      required_amount?: string;
      required_recipient?: string;
    }>().catch(() => ({} as any));

    const paymentHeader = body.payment || c.req.header('x-payment');
    if (!paymentHeader) {
      return c.json({
        verified: false,
        error: 'Missing payment proof. Provide base64-encoded X-Payment value in body.payment or X-Payment header.',
        errorCode: 'MISSING_PAYMENT',
        hint: 'Base64-encode a JSON object: { scheme: "exact", network: "eip155:8453", payload: { from, to, value, validAfter, validBefore, nonce, signature } }',
      }, 400);
    }

    const proof = parsePaymentHeader(paymentHeader);
    if (!proof) {
      return c.json({
        verified: false,
        error: 'Invalid payment proof format. Must be base64-encoded JSON matching X402PaymentProof schema.',
        errorCode: 'INVALID_FORMAT',
      }, 400);
    }

    const result = await verifyX402Payment(
      proof,
      c.env.NONCES,
      {
        requiredRecipient: body.required_recipient || getWallet(c.env),
        requiredAmount: body.required_amount || VERIFICATION_PRICE_USDC_UNITS,
      }
    );

    if (!result.verified) {
      return c.json({
        verified: false,
        error: result.error,
        errorCode: result.errorCode,
      }, 400);
    }

    // Return x402-compliant success response
    c.header('X-Payment-Response', buildPaymentResponseHeader(result));

    return c.json({
      verified: true,
      txHash: result.txHash,
      payer: result.payer,
      amount: result.amount,
      network: result.network,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    console.error('verify-payment error:', error);
    return c.json({
      verified: false,
      error: 'Internal verification error',
      errorCode: 'INTERNAL_ERROR',
    }, 500);
  }
}

/**
 * GET /v1/x402/challenge
 *
 * The flagship pay-for-verification endpoint.
 *
 * Without X-Payment header → 402 Payment Required
 * With valid X-Payment header → 200 with BOTCHA access_token
 *
 * This allows agents to get a BOTCHA verification token by paying
 * $0.001 USDC instead of solving a challenge.
 *
 * x402 standard flow:
 *   1. Agent: GET /v1/x402/challenge
 *   2. Server: 402 + X-Payment-Required: { amount, payTo, asset, ... }
 *   3. Agent: signs ERC-3009 transferWithAuthorization
 *   4. Agent: GET /v1/x402/challenge + X-Payment: <base64-proof>
 *   5. Server: 200 + { access_token, ... } + X-Payment-Response: { success, txHash }
 */
export async function x402ChallengeRoute(c: Context): Promise<Response> {
  try {
    const resource = '/v1/x402/challenge';
    const appId = extractAppId(c);
    const wallet = getWallet(c.env);

    // Check for X-Payment header (payment proof from agent)
    const paymentHeader = c.req.header('x-payment');

    if (!paymentHeader) {
      // No payment → return 402 with payment requirements
      const descriptor = buildPaymentRequiredDescriptor(resource, {
        description: `Pay ${VERIFICATION_PRICE_HUMAN} USDC to receive a BOTCHA verified agent token. Skip the challenge, pay to prove you're a trusted agent.`,
        payTo: wallet,
        appId,
      });

      return c.json({
        error: 'PAYMENT_REQUIRED',
        message: `This endpoint requires a ${VERIFICATION_PRICE_HUMAN} USDC payment on Base to issue a BOTCHA verification token.`,
        x402: descriptor,
        instructions: [
          '1. Encode payment proof as base64 JSON matching X402PaymentProof schema',
          '2. Retry this GET request with header: X-Payment: <base64-encoded-proof>',
          '3. Receive access_token valid for 1 hour',
        ],
        alternative: 'Solve a free challenge instead: GET /v1/challenges?app_id=...',
      }, 402, {
        'X-Payment-Required': JSON.stringify(descriptor),
        'X-Payment-Scheme': 'exact',
        'Content-Type': 'application/json',
      });
    }

    // Parse payment proof
    const proof = parsePaymentHeader(paymentHeader);
    if (!proof) {
      return c.json({
        verified: false,
        error: 'Invalid X-Payment header. Must be base64-encoded X402PaymentProof JSON.',
        errorCode: 'INVALID_PAYMENT_FORMAT',
      }, 400);
    }

    // Verify payment
    const verification = await verifyX402Payment(
      proof,
      c.env.NONCES,
      {
        requiredRecipient: wallet,
        requiredAmount: VERIFICATION_PRICE_USDC_UNITS,
      }
    );

    if (!verification.verified) {
      return c.json({
        verified: false,
        error: verification.error,
        errorCode: verification.errorCode,
      }, 402, {
        'X-Payment-Required': JSON.stringify(
          buildPaymentRequiredDescriptor(resource, { payTo: wallet, appId })
        ),
      });
    }

    // Payment verified — issue BOTCHA token
    const signingKey = getSigningKey(c.env);
    const tokenStart = Date.now();
    const tokenResult = await issueTokenForPayment(
      c.env.CHALLENGES,
      c.env,
      {
        payer: verification.payer!,
        paymentId: verification.txHash!,
        appId,
        audience: 'botcha-x402-verified',
        solveTimeMs: 0, // payment-based, no solve time
      },
      signingKey
    );
    const issuedMs = Date.now() - tokenStart;

    // Store payment record
    const paymentRecord: X402PaymentRecord = {
      payment_id: verification.txHash!,
      payer: verification.payer!,
      amount: verification.amount!,
      network: verification.network!,
      tx_hash: verification.txHash!,
      resource,
      nonce: proof.payload.nonce,
      botcha_app_id: appId,
      access_token: tokenResult.access_token,
      verified_at: Math.floor(Date.now() / 1000),
      status: 'verified',
    };
    await storePaymentRecord(c.env.NONCES, paymentRecord);

    // Set x402 response headers
    c.header('X-Payment-Response', buildPaymentResponseHeader(verification));

    return c.json({
      success: true,
      verified: true,
      method: 'x402-payment',
      message: `Payment verified (${verification.amount} USDC units on ${verification.network}). BOTCHA token issued.`,

      // === Token ===
      access_token: tokenResult.access_token,
      refresh_token: tokenResult.refresh_token,
      expires_in: tokenResult.expires_in,
      refresh_expires_in: tokenResult.refresh_expires_in,
      token_type: 'Bearer',

      // === Payment info ===
      payment: {
        payer: verification.payer,
        txHash: verification.txHash,
        amount: verification.amount,
        amountHuman: `${(parseInt(verification.amount || '0') / 1e6).toFixed(6)} USDC`,
        network: verification.network,
        issuedMs,
      },

      // === What to do next ===
      usage: {
        header: 'Authorization: Bearer <access_token>',
        try_it: 'GET /agent-only',
        x402_demo: 'GET /agent-only/x402',
        full_docs: 'GET / with Authorization: Bearer <access_token>',
        refresh: 'POST /v1/token/refresh with {"refresh_token":"<refresh_token>"}',
      },
    });
  } catch (error) {
    console.error('x402 challenge route error:', error);
    return c.json({
      error: 'INTERNAL_ERROR',
      message: 'Internal server error during x402 payment processing',
    }, 500);
  }
}

/**
 * GET /agent-only/x402
 *
 * Demo endpoint: requires BOTH BOTCHA Bearer token + x402 micropayment.
 * Reference implementation for "verified + paid" double-gated resources.
 *
 * Without token → 401 (get BOTCHA verified first)
 * Without payment → 402 (pay $0.001 USDC)
 * With both → 200 (access granted)
 */
export async function agentOnlyX402Route(c: Context): Promise<Response> {
  const resource = '/agent-only/x402';
  const wallet = getWallet(c.env);

  // ---- Step 1: BOTCHA Bearer token verification ----
  const authHeader = c.req.header('authorization');
  const token = extractBearerToken(authHeader);

  if (!token) {
    return c.json({
      error: 'UNAUTHORIZED',
      message: 'This resource requires BOTCHA verification AND an x402 micropayment.',
      step1: {
        description: 'First, get a BOTCHA verification token (free challenge or paid x402)',
        challenge: 'GET /v1/token → POST /v1/token/verify → access_token',
        paid: `GET /v1/x402/challenge with X-Payment header → access_token`,
      },
      step2: {
        description: 'Then, pay the x402 resource fee with your X-Payment header',
        amount: VERIFICATION_PRICE_HUMAN,
        network: `Base (eip155:${BASE_CHAIN_ID})`,
      },
    }, 401);
  }

  const publicKey = getPublicKey(c.env);
  const tokenResult = await verifyToken(token, c.env.JWT_SECRET, c.env, undefined, publicKey);

  if (!tokenResult.valid) {
    return c.json({
      error: 'INVALID_TOKEN',
      message: tokenResult.error || 'Bearer token is invalid or expired',
      hint: 'Get a fresh token: GET /v1/token → POST /v1/token/verify',
    }, 401);
  }

  // ---- Step 2: x402 payment verification ----
  const paymentHeader = c.req.header('x-payment');
  if (!paymentHeader) {
    const descriptor = buildPaymentRequiredDescriptor(resource, {
      description: `BOTCHA-verified agent resource. Costs ${VERIFICATION_PRICE_HUMAN} USDC per access. Your BOTCHA identity is already verified — now pay to access.`,
      payTo: wallet,
      mimeType: 'application/json',
    });

    return c.json({
      error: 'PAYMENT_REQUIRED',
      message: `You are BOTCHA-verified! Now pay ${VERIFICATION_PRICE_HUMAN} USDC to access this resource.`,
      verified_as: {
        type: (tokenResult.payload as any)?.type,
        app_id: (tokenResult.payload as any)?.app_id,
        solve_time_ms: (tokenResult.payload as any)?.solveTime,
      },
      x402: descriptor,
      instructions: [
        '1. Sign an ERC-3009 transferWithAuthorization (payTo: ' + wallet + ', amount: ' + VERIFICATION_PRICE_USDC_UNITS + ' USDC units)',
        '2. Base64-encode the X402PaymentProof JSON',
        '3. Retry this GET request with X-Payment: <base64-proof>',
      ],
    }, 402, {
      'X-Payment-Required': JSON.stringify(descriptor),
      'X-Payment-Scheme': 'exact',
    });
  }

  const proof = parsePaymentHeader(paymentHeader);
  if (!proof) {
    return c.json({
      error: 'INVALID_PAYMENT',
      message: 'X-Payment header is not valid base64-encoded X402PaymentProof JSON',
    }, 400);
  }

  const verification = await verifyX402Payment(proof, c.env.NONCES, {
    requiredRecipient: wallet,
    requiredAmount: VERIFICATION_PRICE_USDC_UNITS,
  });

  if (!verification.verified) {
    return c.json({
      error: 'PAYMENT_FAILED',
      message: verification.error,
      errorCode: verification.errorCode,
    }, 402, {
      'X-Payment-Required': JSON.stringify(
        buildPaymentRequiredDescriptor(resource, { payTo: wallet })
      ),
    });
  }

  // ---- Both verified! ----
  const appId = extractAppId(c) || (tokenResult.payload as any)?.app_id;

  // Store payment record
  const paymentRecord: X402PaymentRecord = {
    payment_id: verification.txHash!,
    payer: verification.payer!,
    amount: verification.amount!,
    network: verification.network!,
    tx_hash: verification.txHash!,
    resource,
    nonce: proof.payload.nonce,
    botcha_app_id: appId,
    verified_at: Math.floor(Date.now() / 1000),
    status: 'verified',
  };
  await storePaymentRecord(c.env.NONCES, paymentRecord);

  // Set x402 response header
  c.header('X-Payment-Response', buildPaymentResponseHeader(verification));

  const payload = tokenResult.payload as Record<string, any> | undefined;
  return c.json({
    success: true,
    message: '🤖 Double verified! You are a BOTCHA-verified agent that paid via x402.',
    access: 'GRANTED',
    timestamp: new Date().toISOString(),

    // Identity proof
    botcha_identity: {
      verified: true,
      type: payload?.type,
      app_id: payload?.app_id,
      audience: payload?.aud,
      solve_time_ms: payload?.solveTime,
      issued_at: payload?.iat ? new Date((payload.iat as number) * 1000).toISOString() : null,
    },

    // Payment proof
    payment_proof: {
      verified: true,
      payer: verification.payer,
      txHash: verification.txHash,
      amount: verification.amount,
      amountHuman: `${(parseInt(verification.amount || '0') / 1e6).toFixed(6)} USDC`,
      network: verification.network,
    },

    // The secret resource content
    secret: 'This payload is gated behind BOTCHA identity + x402 payment. Your agent cleared both gates. 🔐',
    demo_data: {
      description: 'Copy this pattern to gate any resource behind verified identity + micropayment',
      middleware: [
        '1. Verify BOTCHA Bearer token (POST /v1/token/validate)',
        '2. Verify X-Payment header (POST /v1/x402/verify-payment)',
        '3. Grant access if both pass',
      ],
      sdk_coming_soon: 'npm install @dupecom/botcha-x402',
    },
  });
}

/**
 * POST /v1/x402/webhook
 *
 * Receive x402 settlement notifications from facilitators (Coinbase CDP, etc.)
 *
 * This endpoint:
 * - Validates the webhook signature (HMAC-SHA256 of payload with BOTCHA_WEBHOOK_SECRET)
 * - Updates payment records
 * - Credits agent reputation on successful payment
 * - Returns 200 to acknowledge receipt
 *
 * Expected payload: X402WebhookEvent
 */
export async function x402WebhookRoute(c: Context): Promise<Response> {
  try {
    const rawBody = await c.req.text();
    let event: X402WebhookEvent;

    try {
      event = JSON.parse(rawBody) as X402WebhookEvent;
    } catch {
      return c.json({ error: 'Invalid JSON payload' }, 400);
    }

    // Validate webhook signature if secret is configured
    const webhookSecret = c.env.BOTCHA_WEBHOOK_SECRET;
    const signatureHeader = c.req.header('x-botcha-signature') || c.req.header('x-webhook-signature');

    if (webhookSecret && signatureHeader) {
      const sigValid = await verifyWebhookSignature(rawBody, signatureHeader, webhookSecret);
      if (!sigValid) {
        return c.json({ error: 'Invalid webhook signature' }, 401);
      }
    }

    // Validate required fields
    if (!event.event_type || !event.payment_id || !event.tx_hash) {
      return c.json({
        error: 'Missing required fields: event_type, payment_id, tx_hash',
      }, 400);
    }

    const validEventTypes = ['payment.settled', 'payment.failed', 'payment.refunded'];
    if (!validEventTypes.includes(event.event_type)) {
      return c.json({
        error: `Unknown event_type: ${event.event_type}`,
        valid_types: validEventTypes,
      }, 400);
    }

    // Process the event
    const result = await processWebhookEvent(
      event,
      c.env.NONCES,
      c.env.AGENTS,
      c.env.SESSIONS,
      webhookSecret
    );

    if (!result.handled) {
      // Still return 200 to prevent retries; just log the failure
      console.warn('Webhook event not fully handled:', result.message);
    }

    return c.json({
      received: true,
      event_type: event.event_type,
      payment_id: event.payment_id,
      handled: result.handled,
      message: result.message,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    console.error('x402 webhook error:', error);
    // Return 200 to prevent retries on internal errors
    return c.json({
      received: true,
      error: 'Internal processing error (logged)',
    });
  }
}

/**
 * GET /v1/x402/info
 *
 * Public endpoint: returns x402 payment configuration for this BOTCHA instance.
 * Agents can discover pricing, wallet, and supported networks.
 */
export async function x402InfoRoute(c: Context): Promise<Response> {
  const wallet = getWallet(c.env);
  const baseUrl = new URL(c.req.url).origin;

  return c.json({
    name: 'BOTCHA x402 Payment Gateway',
    version: '1.0',
    description: 'Pay USDC on Base to receive a BOTCHA verified agent token, or to access x402-gated resources.',

    pricing: {
      verification_token: {
        amount: VERIFICATION_PRICE_USDC_UNITS,
        amountHuman: VERIFICATION_PRICE_HUMAN,
        description: 'One BOTCHA access_token (1 hour validity)',
      },
      resource_access: {
        amount: VERIFICATION_PRICE_USDC_UNITS,
        amountHuman: VERIFICATION_PRICE_HUMAN,
        description: 'One-time access to an x402-gated resource',
      },
    },

    payment: {
      scheme: 'exact',
      network: `eip155:${BASE_CHAIN_ID}`,
      networkName: 'Base',
      payTo: wallet,
      asset: USDC_BASE_ADDRESS,
      assetSymbol: 'USDC',
      assetDecimals: 6,
      deadlineSeconds: PAYMENT_DEADLINE_SECONDS,
    },

    endpoints: {
      challenge: `${baseUrl}/v1/x402/challenge`,
      verify_payment: `${baseUrl}/v1/x402/verify-payment`,
      demo: `${baseUrl}/agent-only/x402`,
      webhook: `${baseUrl}/v1/x402/webhook`,
    },

    x402_compliance: {
      scheme: 'exact',
      request_header: 'X-Payment',
      response_header: 'X-Payment-Required',
      confirmation_header: 'X-Payment-Response',
      spec: 'https://x402.org',
    },
  });
}

// ============ WEBHOOK SIGNATURE VERIFICATION ============

/**
 * Verify HMAC-SHA256 webhook signature.
 * Facilitators sign payloads as: HMAC-SHA256(secret, body)
 */
async function verifyWebhookSignature(
  rawBody: string,
  signatureHeader: string,
  secret: string
): Promise<boolean> {
  try {
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );

    // Strip "sha256=" prefix if present (GitHub webhook style)
    const sigHex = signatureHeader.replace(/^sha256=/, '');
    const sigBytes = hexToBytes(sigHex);

    return await crypto.subtle.verify(
      'HMAC',
      key,
      sigBytes,
      encoder.encode(rawBody)
    );
  } catch {
    return false;
  }
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

// ============ EXPORTS ============

export default {
  verifyPaymentRoute,
  x402ChallengeRoute,
  agentOnlyX402Route,
  x402WebhookRoute,
  x402InfoRoute,
};
