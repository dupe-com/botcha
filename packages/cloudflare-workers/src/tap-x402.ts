/**
 * x402 Payment Gating — BOTCHA Revenue via HTTP 402
 *
 * Implements the x402 HTTP Payment Required protocol so BOTCHA-verified
 * agents can natively access paid APIs, and BOTCHA earns per-verification.
 *
 * Spec: https://x402.org / https://github.com/coinbase/x402
 *
 * Flow:
 *   1. Agent requests a protected resource
 *   2. Server returns HTTP 402 + X-Payment-Required header (payment details)
 *   3. Agent signs a ERC-3009 transferWithAuthorization and sends X-Payment header
 *   4. Server verifies payment on-chain (or via facilitator) and issues BOTCHA token
 *
 * Key standard:
 *   - Scheme: "exact" — fixed USD amount, exact recipient
 *   - Network: "base" (Base mainnet, chain ID 8453)
 *   - Token: USDC on Base (6 decimals, 1000 units = $0.001)
 *   - Verification: ERC-3009 signature (EIP-712 structured data)
 */

import type { KVNamespace } from './agents.js';
import { generateToken, type ES256SigningKeyJWK } from './auth.js';
import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak_256 } from '@noble/hashes/sha3';
import { bytesToHex, concatBytes, hexToBytes, utf8ToBytes } from '@noble/hashes/utils';

// ============ CONSTANTS ============

/**
 * BOTCHA's receiving wallet on Base. Set via BOTCHA_PAYMENT_WALLET env var.
 * Placeholder: in production, override with BOTCHA_PAYMENT_WALLET secret.
 * This address (b07ca = "botcha" mapped to hex-safe chars) is not owned by anyone.
 */
export const BOTCHA_WALLET = '0xb07ca00000000000000000000000000000000001';

/** USDC contract address on Base (mainnet) */
export const USDC_BASE_ADDRESS = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';

/** Base chain ID */
export const BASE_CHAIN_ID = 8453;

/** Price per BOTCHA verification in USDC atomic units (6 decimals) */
/** 1000 units = $0.001 USDC */
export const VERIFICATION_PRICE_USDC_UNITS = '1000';

/** Human-readable price */
export const VERIFICATION_PRICE_HUMAN = '$0.001 USDC';

/** Payment deadline window (seconds) */
export const PAYMENT_DEADLINE_SECONDS = 300; // 5 minutes

/** KV TTL for x402 nonces (replay protection) */
export const NONCE_TTL_SECONDS = 3600; // 1 hour

// ============ TYPES ============

/**
 * x402 "exact" scheme payment requirements.
 * This is what goes in the X-Payment-Required header (JSON).
 */
export interface X402PaymentRequired {
  scheme: 'exact';
  network: string;
  maxAmountRequired: string;
  resource: string;
  description: string;
  mimeType: string;
  payTo: string;
  maxTimeoutSeconds: number;
  asset: string;
  extra?: {
    name: string;
    version: string;
    botcha_app_id?: string;
  };
}

/**
 * ERC-3009 transferWithAuthorization payload embedded in X-Payment header.
 * This is the on-chain payment proof signed by the payer.
 */
export interface ERC3009TransferPayload {
  from: string;         // payer address
  to: string;           // payee address (BOTCHA wallet)
  value: string;        // USDC amount in atomic units (base 10 string)
  validAfter: string;   // Unix timestamp (valid after)
  validBefore: string;  // Unix timestamp (valid before)
  nonce: string;        // Random 32-byte hex nonce
  signature: string;    // EIP-712 signature (0x-prefixed hex)
  chainId?: number;     // Base chain ID (8453)
}

/**
 * x402 payment proof sent by the agent in the X-Payment header.
 * Base64-encoded JSON of this structure.
 */
export interface X402PaymentProof {
  scheme: 'exact';
  network: string;
  payload: ERC3009TransferPayload;
}

/**
 * Result of x402 payment verification
 */
export interface X402VerificationResult {
  verified: boolean;
  valid: boolean;
  txHash?: string;
  payer?: string;
  amount?: string;
  network?: string;
  error?: string;
  errorCode?: string;
}

/**
 * x402 webhook event (from Coinbase CDP or other facilitators)
 */
export interface X402WebhookEvent {
  event_type: 'payment.settled' | 'payment.failed' | 'payment.refunded';
  payment_id: string;
  tx_hash: string;
  from: string;
  to: string;
  amount: string;
  token: string;
  network: string;
  resource: string;
  timestamp: string;
  metadata?: Record<string, string>;
}

/**
 * Record of an x402 payment stored in KV
 */
export interface X402PaymentRecord {
  payment_id: string;
  payer: string;
  amount: string;
  network: string;
  tx_hash: string;
  resource: string;
  nonce: string;
  botcha_app_id?: string;
  agent_id?: string;
  access_token?: string;
  verified_at: number;
  status: 'verified' | 'rejected' | 'pending';
}

// ============ PAYMENT REQUIRED RESPONSE BUILDER ============

/**
 * Build a standard x402 payment required descriptor.
 * Goes into the X-Payment-Required response header.
 */
export function buildPaymentRequiredDescriptor(
  resource: string,
  options?: {
    description?: string;
    mimeType?: string;
    payTo?: string;
    amount?: string;
    appId?: string;
  }
): X402PaymentRequired {
  return {
    scheme: 'exact',
    network: `eip155:${BASE_CHAIN_ID}`, // CAIP-2 chain identifier
    maxAmountRequired: options?.amount || VERIFICATION_PRICE_USDC_UNITS,
    resource,
    description: options?.description || `BOTCHA verification: ${VERIFICATION_PRICE_HUMAN} per verified agent token`,
    mimeType: options?.mimeType || 'application/json',
    payTo: options?.payTo || BOTCHA_WALLET,
    maxTimeoutSeconds: PAYMENT_DEADLINE_SECONDS,
    asset: USDC_BASE_ADDRESS,
    extra: {
      name: 'BOTCHA',
      version: '1.0',
      botcha_app_id: options?.appId,
    },
  };
}

/**
 * Parse and decode an X-Payment header value (base64 JSON)
 * Returns null if invalid format.
 */
export function parsePaymentHeader(headerValue: string): X402PaymentProof | null {
  try {
    const decoded = atob(headerValue.trim());
    const proof = JSON.parse(decoded) as X402PaymentProof;

    // Minimal structural validation
    if (!proof.scheme || proof.scheme !== 'exact') return null;
    if (!proof.network) return null;
    if (!proof.payload) return null;
    if (!proof.payload.from || !proof.payload.to) return null;
    if (!proof.payload.value) return null;
    if (!proof.payload.nonce) return null;
    if (!proof.payload.signature) return null;
    if (!proof.payload.validBefore) return null;

    return proof;
  } catch {
    return null;
  }
}

// ============ PAYMENT VERIFICATION ============

/**
 * Verify an x402 payment proof.
 *
 * Checks:
 * 1. Network matches Base
 * 2. Recipient matches BOTCHA wallet
 * 3. Amount >= required
 * 4. Deadline has not expired (validBefore)
 * 5. Nonce has not been replayed (KV check)
 * 6. EIP-712 signature is valid (ERC-3009)
 *
 * Note: This verifies the ERC-3009 typed-data signature locally.
 * It does not confirm on-chain settlement; use facilitator webhooks for that.
 */
export async function verifyX402Payment(
  proof: X402PaymentProof,
  noncesKV: KVNamespace,
  options?: {
    requiredRecipient?: string;
    requiredAmount?: string;
  }
): Promise<X402VerificationResult> {
  try {
    const payload = proof.payload;
    const requiredTo = options?.requiredRecipient || BOTCHA_WALLET;
    const requiredAmount = options?.requiredAmount || VERIFICATION_PRICE_USDC_UNITS;

    // 1. Network check (accept eip155:8453 or "base")
    const networkOk =
      proof.network === `eip155:${BASE_CHAIN_ID}` ||
      proof.network === 'base' ||
      proof.network === 'base-mainnet';

    if (!networkOk) {
      return {
        verified: false,
        valid: false,
        error: `Unsupported network: ${proof.network}. Use Base (eip155:8453).`,
        errorCode: 'NETWORK_MISMATCH',
      };
    }

    // 2. Recipient check (case-insensitive hex comparison)
    if (payload.to.toLowerCase() !== requiredTo.toLowerCase()) {
      return {
        verified: false,
        valid: false,
        error: `Payment recipient mismatch. Expected: ${requiredTo}, Got: ${payload.to}`,
        errorCode: 'RECIPIENT_MISMATCH',
      };
    }

    // 3. Amount check
    const providedAmount = BigInt(payload.value);
    const minAmount = BigInt(requiredAmount);
    if (providedAmount < minAmount) {
      return {
        verified: false,
        valid: false,
        error: `Insufficient payment. Required: ${requiredAmount} USDC units, Got: ${payload.value}`,
        errorCode: 'INSUFFICIENT_AMOUNT',
      };
    }

    if (typeof payload.chainId === 'number' && payload.chainId !== BASE_CHAIN_ID) {
      return {
        verified: false,
        valid: false,
        error: `Unsupported chainId in payload: ${payload.chainId}. Use ${BASE_CHAIN_ID}.`,
        errorCode: 'NETWORK_MISMATCH',
      };
    }

    // 4. Time window checks
    const now = Math.floor(Date.now() / 1000);
    const validAfter = parseInt(payload.validAfter || '0', 10);
    const validBefore = parseInt(payload.validBefore, 10);
    if (!Number.isFinite(validAfter) || !Number.isFinite(validBefore) || validBefore <= validAfter) {
      return {
        verified: false,
        valid: false,
        error: 'Payment authorization has an invalid validity window',
        errorCode: 'SIGNATURE_INVALID',
      };
    }
    if (validAfter > now) {
      return {
        verified: false,
        valid: false,
        error: `Payment authorization is not active until ${new Date(validAfter * 1000).toISOString()}`,
        errorCode: 'PAYMENT_NOT_YET_VALID',
      };
    }
    if (validBefore <= now) {
      return {
        verified: false,
        valid: false,
        error: `Payment authorization expired at ${new Date(validBefore * 1000).toISOString()}`,
        errorCode: 'PAYMENT_EXPIRED',
      };
    }

    // 5. Replay protection: check nonce hasn't been used
    const nonceKey = `x402_nonce:${payload.nonce.toLowerCase()}`;
    const existingNonce = await noncesKV.get(nonceKey);
    if (existingNonce) {
      return {
        verified: false,
        valid: false,
        error: 'Payment nonce already used (replay attack prevented)',
        errorCode: 'NONCE_REPLAY',
      };
    }

    // 6. EIP-712 / ERC-3009 signature verification
    const sigValid = await verifyERC3009Signature(payload);

    if (!sigValid) {
      return {
        verified: false,
        valid: false,
        error: 'ERC-3009 signature verification failed',
        errorCode: 'SIGNATURE_INVALID',
      };
    }

    // Mark nonce as used (TTL: 1 hour past validBefore)
    const nonceTtl = Math.max(NONCE_TTL_SECONDS, validBefore - now + 60);
    await noncesKV.put(nonceKey, '1', { expirationTtl: nonceTtl });

    // Compute a deterministic tx hash from the signed payload (for record-keeping)
    // In production this would be the actual on-chain tx hash from the facilitator
    const txHash = await computePaymentId(payload);

    return {
      verified: true,
      valid: true,
      txHash,
      payer: payload.from,
      amount: payload.value,
      network: proof.network,
    };
  } catch (error) {
    return {
      verified: false,
      valid: false,
      error: `Payment verification error: ${error instanceof Error ? error.message : 'Unknown error'}`,
      errorCode: 'INTERNAL_ERROR',
    };
  }
}

/**
 * Verify ERC-3009 transferWithAuthorization EIP-712 signature.
 *
 * EIP-712 domain:
 *   name: "USD Coin" (USDC contract name on Base)
 *   version: "2"
 *   chainId: 8453
 *   verifyingContract: 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913
 *
 * Primary type: TransferWithAuthorization
 * Types:
 *   TransferWithAuthorization: from, to, value, validAfter, validBefore, nonce
 *
 * Uses secp256k1 pubkey recovery over the EIP-712 digest and checks the
 * recovered address matches payload.from.
 */
async function verifyERC3009Signature(payload: ERC3009TransferPayload): Promise<boolean> {
  try {
    if (!isHexAddress(payload.from) || !isHexAddress(payload.to)) return false;
    if (!/^\d+$/.test(payload.value)) return false;
    if (!/^\d+$/.test(payload.validBefore)) return false;
    if (!/^\d+$/.test(payload.validAfter || '0')) return false;
    if (BigInt(payload.value) <= 0n) return false;

    const sigHex = normalizeHex(payload.signature);
    if (!payload.signature.toLowerCase().startsWith('0x')) return false;
    if (!/^[0-9a-fA-F]{130}$/.test(sigHex)) return false;

    const sigBytes = hexToBytes(sigHex);
    const recoveryBit = normalizeRecoveryBit(sigBytes[64]);
    if (recoveryBit === null) return false;

    const digest = buildERC3009TransferDigest(payload);
    const signature = secp256k1.Signature.fromCompact(sigBytes.slice(0, 64)).addRecoveryBit(recoveryBit);
    const recovered = signature.recoverPublicKey(digest);
    const recoveredAddress = publicKeyToAddress(recovered.toRawBytes(false));

    return recoveredAddress.toLowerCase() === payload.from.toLowerCase();
  } catch {
    return false;
  }
}

/**
 * Compute a deterministic payment ID from ERC-3009 payload.
 * This is not an on-chain tx hash; it is an idempotent verifier-side ID.
 */
async function computePaymentId(payload: ERC3009TransferPayload): Promise<string> {
  const digest = buildERC3009TransferDigest(payload);
  const signature = hexToBytes(normalizeHex(payload.signature));
  return `0x${bytesToHex(keccak_256(concatBytes(digest, signature)))}`;
}

const UINT256_MAX = (1n << 256n) - 1n;
const EIP712_PREFIX = Uint8Array.from([0x19, 0x01]);
const EIP712_DOMAIN_TYPEHASH = keccak_256(
  utf8ToBytes('EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)')
);
const ERC3009_TYPEHASH = keccak_256(
  utf8ToBytes(
    'TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)'
  )
);
const USDC_NAME_HASH = keccak_256(utf8ToBytes('USD Coin'));
const USDC_VERSION_HASH = keccak_256(utf8ToBytes('2'));

function normalizeHex(value: string): string {
  return value.replace(/^0x/i, '');
}

function isHexAddress(value: string): boolean {
  return /^0x[0-9a-fA-F]{40}$/.test(value);
}

function normalizeRecoveryBit(v: number): number | null {
  if (v === 0 || v === 1) return v;
  if (v === 27 || v === 28) return v - 27;
  return null;
}

function toUint256Word(value: bigint): Uint8Array {
  if (value < 0n || value > UINT256_MAX) {
    throw new Error('uint256 value out of range');
  }
  return hexToBytes(value.toString(16).padStart(64, '0'));
}

function toAddressWord(address: string): Uint8Array {
  if (!isHexAddress(address)) {
    throw new Error('invalid address');
  }
  return concatBytes(new Uint8Array(12), hexToBytes(normalizeHex(address)));
}

function toBytes32Word(value: string): Uint8Array {
  const hex = normalizeHex(value);
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
    throw new Error('invalid bytes32');
  }
  return hexToBytes(hex);
}

function publicKeyToAddress(publicKey: Uint8Array): string {
  const uncompressed = publicKey.length === 65 ? publicKey.slice(1) : publicKey;
  const digest = keccak_256(uncompressed);
  return `0x${bytesToHex(digest.slice(-20))}`;
}

export function buildERC3009TransferDigest(payload: ERC3009TransferPayload): Uint8Array {
  const chainId = payload.chainId ?? BASE_CHAIN_ID;
  if (!Number.isInteger(chainId) || chainId !== BASE_CHAIN_ID) {
    throw new Error(`unsupported chainId: ${chainId}`);
  }

  if (!/^\d+$/.test(payload.value) || !/^\d+$/.test(payload.validAfter || '0') || !/^\d+$/.test(payload.validBefore)) {
    throw new Error('invalid numeric fields');
  }

  const value = BigInt(payload.value);
  const validAfter = BigInt(payload.validAfter || '0');
  const validBefore = BigInt(payload.validBefore);

  const domainSeparator = keccak_256(
    concatBytes(
      EIP712_DOMAIN_TYPEHASH,
      USDC_NAME_HASH,
      USDC_VERSION_HASH,
      toUint256Word(BigInt(chainId)),
      toAddressWord(USDC_BASE_ADDRESS)
    )
  );

  const structHash = keccak_256(
    concatBytes(
      ERC3009_TYPEHASH,
      toAddressWord(payload.from),
      toAddressWord(payload.to),
      toUint256Word(value),
      toUint256Word(validAfter),
      toUint256Word(validBefore),
      toBytes32Word(payload.nonce)
    )
  );

  return keccak_256(concatBytes(EIP712_PREFIX, domainSeparator, structHash));
}

// ============ PAYMENT RECORDS ============

/**
 * Store a verified x402 payment record in KV
 */
export async function storePaymentRecord(
  noncesKV: KVNamespace,
  record: X402PaymentRecord
): Promise<void> {
  await noncesKV.put(
    `x402_payment:${record.payment_id}`,
    JSON.stringify(record),
    { expirationTtl: 86400 * 7 } // 7 days
  );

  // Index by payer address for history lookups
  await noncesKV.put(
    `x402_payer_last:${record.payer.toLowerCase()}`,
    record.payment_id,
    { expirationTtl: 86400 * 7 }
  );
}

/**
 * Get a payment record by ID
 */
export async function getPaymentRecord(
  noncesKV: KVNamespace,
  paymentId: string
): Promise<X402PaymentRecord | null> {
  const data = await noncesKV.get(`x402_payment:${paymentId}`);
  if (!data) return null;
  try {
    return JSON.parse(data) as X402PaymentRecord;
  } catch {
    return null;
  }
}

// ============ BOTCHA TOKEN ISSUANCE VIA PAYMENT ============

/**
 * Issue a BOTCHA access_token in exchange for a verified x402 payment.
 * This is the core pay-for-verification flow.
 *
 * The issued token is identical to a challenge-solve token —
 * agents that pay get the same trust level as agents that solve.
 */
export async function issueTokenForPayment(
  challengesKV: KVNamespace,
  env: { JWT_SECRET: string; JWT_SIGNING_KEY?: string },
  options: {
    payer: string;
    paymentId: string;
    appId?: string;
    audience?: string;
    solveTimeMs?: number;
  },
  signingKey?: ES256SigningKeyJWK
): Promise<{ access_token: string; refresh_token: string; expires_in: number; refresh_expires_in: number }> {
  // Use payment ID as the "challenge ID" in the token subject claim
  const result = await generateToken(
    `x402:${options.paymentId}`,
    options.solveTimeMs || 0,
    env.JWT_SECRET,
    { CHALLENGES: challengesKV },
    {
      app_id: options.appId,
      aud: options.audience || 'botcha-x402',
    },
    signingKey
  );

  return result;
}

// ============ X402 PAYMENT RESPONSE HEADER BUILDER ============

/**
 * Build the X-Payment-Response header value for successful payment
 */
export function buildPaymentResponseHeader(result: X402VerificationResult): string {
  return JSON.stringify({
    success: result.verified,
    txHash: result.txHash,
    networkId: result.network || `eip155:${BASE_CHAIN_ID}`,
  });
}

// ============ WEBHOOK PROCESSING ============

/**
 * Process an inbound x402 webhook event from a facilitator.
 *
 * On payment.settled: update agent reputation, store payment record.
 * On payment.failed: log failure.
 * On payment.refunded: note in record.
 */
export async function processWebhookEvent(
  event: X402WebhookEvent,
  noncesKV: KVNamespace,
  agentsKV: KVNamespace,
  sessionsKV: KVNamespace,
  webhookSecret?: string
): Promise<{ handled: boolean; message: string }> {
  try {
    switch (event.event_type) {
      case 'payment.settled': {
        // Update or create payment record
        const existing = await getPaymentRecord(noncesKV, event.payment_id);
        if (existing) {
          existing.status = 'verified';
          await storePaymentRecord(noncesKV, existing);
        }

        // Record positive reputation event for the payer if we can map them to an agent
        if (event.metadata?.agent_id) {
          await recordPaymentReputationEvent(sessionsKV, {
            agent_id: event.metadata.agent_id,
            app_id: event.metadata.app_id || 'unknown',
            action: 'auth_success',
            metadata: {
              tx_hash: event.tx_hash,
              amount: event.amount,
              event_type: 'x402_payment_settled',
            },
          });
        }

        return { handled: true, message: `Payment settled: ${event.tx_hash}` };
      }

      case 'payment.failed': {
        const existing = await getPaymentRecord(noncesKV, event.payment_id);
        if (existing) {
          existing.status = 'rejected';
          await storePaymentRecord(noncesKV, existing);
        }

        // Record negative reputation event
        if (event.metadata?.agent_id) {
          await recordPaymentReputationEvent(sessionsKV, {
            agent_id: event.metadata.agent_id,
            app_id: event.metadata.app_id || 'unknown',
            action: 'auth_failure',
            metadata: {
              tx_hash: event.tx_hash,
              event_type: 'x402_payment_failed',
            },
          });
        }

        return { handled: true, message: `Payment failed: ${event.payment_id}` };
      }

      case 'payment.refunded': {
        const existing = await getPaymentRecord(noncesKV, event.payment_id);
        if (existing) {
          await storePaymentRecord(noncesKV, { ...existing, status: 'rejected' });
        }
        return { handled: true, message: `Payment refunded: ${event.payment_id}` };
      }

      default: {
        return { handled: false, message: `Unknown event type: ${(event as any).event_type}` };
      }
    }
  } catch (error) {
    return {
      handled: false,
      message: `Webhook processing error: ${error instanceof Error ? error.message : 'Unknown error'}`,
    };
  }
}

/**
 * Record a reputation event for an x402 payment action.
 * Uses the existing TAP reputation system (verification category).
 */
async function recordPaymentReputationEvent(
  sessionsKV: KVNamespace,
  options: {
    agent_id: string;
    app_id: string;
    action: 'auth_success' | 'auth_failure' | 'challenge_solved';
    metadata?: Record<string, string>;
  }
): Promise<void> {
  try {
    // Load existing reputation score
    const key = `reputation:${options.agent_id}`;
    const raw = await sessionsKV.get(key);
    
    const BASE_SCORE = 500;
    const DELTAS: Record<string, number> = {
      auth_success: 10,
      challenge_solved: 15,
      auth_failure: -20,
    };

    const delta = DELTAS[options.action] || 0;
    const now = Date.now();

    let score: any = raw ? JSON.parse(raw) : null;
    if (!score) {
      score = {
        agent_id: options.agent_id,
        app_id: options.app_id,
        score: BASE_SCORE,
        tier: 'neutral',
        event_count: 0,
        positive_events: 0,
        negative_events: 0,
        last_event_at: null,
        created_at: now,
        updated_at: now,
        category_scores: {
          verification: 0,
          attestation: 0,
          delegation: 0,
          session: 0,
          violation: 0,
          endorsement: 0,
        },
      };
    }

    score.score = Math.max(0, Math.min(1000, score.score + delta));
    score.event_count += 1;
    if (delta >= 0) score.positive_events += 1;
    else score.negative_events += 1;
    score.last_event_at = now;
    score.updated_at = now;
    score.category_scores.verification = (score.category_scores.verification || 0) + delta;
    score.tier = computeTier(score.score);

    await sessionsKV.put(key, JSON.stringify(score));
  } catch (error) {
    console.error('Failed to record payment reputation event:', error);
  }
}

function computeTier(score: number): string {
  if (score < 200) return 'untrusted';
  if (score < 400) return 'low';
  if (score < 600) return 'neutral';
  if (score < 800) return 'good';
  return 'excellent';
}

// ============ EXPORTS ============

export default {
  buildPaymentRequiredDescriptor,
  parsePaymentHeader,
  verifyX402Payment,
  issueTokenForPayment,
  buildPaymentResponseHeader,
  storePaymentRecord,
  getPaymentRecord,
  processWebhookEvent,
};
