/**
 * TAP-Enhanced Agent API Routes
 * Extends existing BOTCHA agent API with Trusted Agent Protocol features
 * 
 * Provides backward-compatible endpoints with optional TAP functionality
 */

import type { Context } from 'hono';
import { extractBearerToken, verifyToken, getSigningPublicKeyJWK, type ES256SigningKeyJWK } from './auth.js';
import { 
  registerTAPAgent, 
  getTAPAgent, 
  listTAPAgents, 
  createTAPSession,
  getTAPSession,
  updateAgentVerification,
  validateCapability,
  isValidJWK,
  TAPCapability,
  TAP_VALID_ACTIONS
} from './tap-agents.js';
import { 
  parseTAPIntent,
  verifyHTTPMessageSignature
} from './tap-verify.js';
import { 
  createInvoice, 
  getInvoice, 
  verifyPaymentContainer, 
  verifyBrowsingIOU, 
  build402Response,
  fulfillInvoice,
  parsePaymentContainer
} from './tap-payment.js';
import { 
  parseAgenticConsumer, 
  verifyAgenticConsumer 
} from './tap-consumer.js';

// ============ VALIDATION HELPERS ============

function getVerificationPublicKey(env: any) {
  const rawSigningKey = env?.JWT_SIGNING_KEY;
  if (!rawSigningKey) return undefined;

  try {
    const signingKey = JSON.parse(rawSigningKey) as ES256SigningKeyJWK;
    return getSigningPublicKeyJWK(signingKey);
  } catch {
    console.error('Failed to parse JWT_SIGNING_KEY for TAP verification');
    return undefined;
  }
}

async function validateAppAccess(c: Context, requireAuth: boolean = true): Promise<{
  valid: boolean;
  appId?: string;
  error?: string;
  status?: number;
}> {
  const queryAppId = c.req.query('app_id');
  const authHeader = c.req.header('authorization');
  const token = extractBearerToken(authHeader);

  if (!token) {
    if (!requireAuth) {
      return { valid: true, appId: queryAppId };
    }

    return {
      valid: false,
      error: 'UNAUTHORIZED',
      status: 401
    };
  }

  const publicKey = getVerificationPublicKey(c.env);
  const result = await verifyToken(token, c.env.JWT_SECRET, c.env, undefined, publicKey);
  if (!result.valid || !result.payload) {
    return {
      valid: false,
      error: 'INVALID_TOKEN',
      status: 401
    };
  }

  const jwtAppId = (result.payload as any).app_id as string | undefined;
  if (!jwtAppId) {
    return {
      valid: false,
      error: 'MISSING_APP_ID',
      status: 403
    };
  }

  if (queryAppId && queryAppId !== jwtAppId) {
    return {
      valid: false,
      error: 'APP_ID_MISMATCH',
      status: 403
    };
  }

  return { valid: true, appId: jwtAppId };
}

function validateTAPRegistration(body: any): {
  valid: boolean;
  data?: {
    name: string;
    operator?: string;
    version?: string;
    public_key?: string;
    signature_algorithm?: 'ecdsa-p256-sha256' | 'rsa-pss-sha256' | 'ed25519';
    capabilities?: TAPCapability[];
    trust_level?: 'basic' | 'verified' | 'enterprise';
    issuer?: string;
  };
  error?: string;
} {
  if (!body.name || typeof body.name !== 'string') {
    return { valid: false, error: 'Agent name is required' };
  }
  
  // Normalize public_key: accept JWK objects by serializing them to JSON strings
  let publicKey = body.public_key;
  if (publicKey && typeof publicKey === 'object') {
    publicKey = JSON.stringify(publicKey);
  }

  // Validate public key if provided
  if (publicKey) {
    if (!body.signature_algorithm) {
      return { valid: false, error: 'signature_algorithm required when public_key provided' };
    }
    
    const validAlgorithms = ['ecdsa-p256-sha256', 'rsa-pss-sha256', 'ed25519'];
    if (!validAlgorithms.includes(body.signature_algorithm)) {
      return { valid: false, error: `Unsupported algorithm. Supported: ${validAlgorithms.join(', ')}` };
    }
    
    // Accept: PEM, JWK JSON string, or raw Ed25519 base64 key
    const isPEM = typeof publicKey === 'string' && publicKey.includes('BEGIN PUBLIC KEY');
    const isJWK = isValidJWK(publicKey);
    const isRawEd25519 = body.signature_algorithm === 'ed25519' && !isPEM && !isJWK;
    if (!isPEM && !isJWK && !isRawEd25519) {
      return { valid: false, error: 'Invalid public key format. Provide a PEM key, JWK object/JSON, or raw Ed25519 base64 key.' };
    }
  }
  
  // Validate capabilities if provided
  if (body.capabilities) {
    if (!Array.isArray(body.capabilities)) {
      return { valid: false, error: 'Capabilities must be an array' };
    }
    
    for (const cap of body.capabilities) {
      if (!cap.action || !(TAP_VALID_ACTIONS as readonly string[]).includes(cap.action)) {
        return { valid: false, error: `Invalid capability action. Valid: ${TAP_VALID_ACTIONS.join(', ')}` };
      }
    }
  }
  
  return {
    valid: true,
    data: {
      name: body.name,
      operator: body.operator,
      version: body.version,
      public_key: publicKey,
      signature_algorithm: body.signature_algorithm,
      capabilities: body.capabilities,
      trust_level: body.trust_level || 'basic',
      issuer: body.issuer
    }
  };
}

// ============ TAP AGENT ROUTES ============

/**
 * POST /v1/agents/register/tap
 * Enhanced agent registration with TAP capabilities
 */
export async function registerTAPAgentRoute(c: Context) {
  try {
    // Validate app access
    const appAccess = await validateAppAccess(c, true);
    if (!appAccess.valid) {
      return c.json({
        success: false,
        error: appAccess.error,
        message: 'Authentication required'
      }, (appAccess.status || 401) as 401);
    }
    
    // Parse and validate request body
    const body = await c.req.json().catch(() => ({}));
    const validation = validateTAPRegistration(body);
    
    if (!validation.valid) {
      return c.json({
        success: false,
        error: 'INVALID_REQUEST',
        message: validation.error
      }, 400);
    }
    
    // Register TAP-enhanced agent
    const result = await registerTAPAgent(
      c.env.AGENTS,
      appAccess.appId!,
      validation.data!
    );
    
    if (!result.success) {
      return c.json({
        success: false,
        error: 'AGENT_CREATION_FAILED',
        message: result.error || 'Failed to create agent'
      }, 500);
    }
    
    const agent = result.agent!;
    
    // Return enhanced agent info
    return c.json({
      success: true,
      agent_id: agent.agent_id,
      app_id: agent.app_id,
      name: agent.name,
      operator: agent.operator,
      version: agent.version,
      created_at: new Date(agent.created_at).toISOString(),
      
      // TAP-specific fields
      tap_enabled: agent.tap_enabled,
      trust_level: agent.trust_level,
      capabilities: agent.capabilities,
      signature_algorithm: agent.signature_algorithm,
      issuer: agent.issuer,
      
      // Security info (don't expose full public key)
      has_public_key: Boolean(agent.public_key),
      key_fingerprint: agent.public_key ? 
        await generateKeyFingerprint(agent.public_key) : undefined
    }, 201);
    
  } catch (error) {
    console.error('TAP agent registration error:', error);
    return c.json({
      success: false,
      error: 'INTERNAL_ERROR',
      message: 'Internal server error'
    }, 500);
  }
}

/**
 * GET /v1/agents/:id/tap
 * Get agent with TAP capabilities
 */
export async function getTAPAgentRoute(c: Context) {
  try {
    const agentId = c.req.param('id');
    if (!agentId) {
      return c.json({
        success: false,
        error: 'MISSING_AGENT_ID',
        message: 'Agent ID is required'
      }, 400);
    }
    
    const result = await getTAPAgent(c.env.AGENTS, agentId);
    
    if (!result.success) {
      return c.json({
        success: false,
        error: 'AGENT_NOT_FOUND',
        message: result.error || 'Agent not found'
      }, 404);
    }
    
    const agent = result.agent!;
    
    return c.json({
      success: true,
      agent_id: agent.agent_id,
      app_id: agent.app_id,
      name: agent.name,
      operator: agent.operator,
      version: agent.version,
      created_at: new Date(agent.created_at).toISOString(),
      
      // TAP info
      tap_enabled: agent.tap_enabled,
      trust_level: agent.trust_level,
      capabilities: agent.capabilities,
      signature_algorithm: agent.signature_algorithm,
      issuer: agent.issuer,
      last_verified_at: agent.last_verified_at ? 
        new Date(agent.last_verified_at).toISOString() : null,
      
      // Public key info (secure)
      has_public_key: Boolean(agent.public_key),
      key_fingerprint: agent.public_key ? 
        await generateKeyFingerprint(agent.public_key) : undefined,
      public_key: agent.public_key // Include for verification
    });
    
  } catch (error) {
    console.error('TAP agent retrieval error:', error);
    return c.json({
      success: false,
      error: 'INTERNAL_ERROR',
      message: 'Internal server error'
    }, 500);
  }
}

/**
 * GET /v1/agents/tap
 * List TAP-enabled agents for an app
 */
export async function listTAPAgentsRoute(c: Context) {
  try {
    const appAccess = await validateAppAccess(c, true);
    if (!appAccess.valid) {
      return c.json({
        success: false,
        error: appAccess.error,
        message: 'Authentication required'
      }, (appAccess.status || 401) as 401);
    }
    
    const tapOnly = c.req.query('tap_only') === 'true';
    
    const result = await listTAPAgents(c.env.AGENTS, appAccess.appId!, tapOnly);
    
    if (!result.success) {
      return c.json({
        success: false,
        error: 'LIST_FAILED',
        message: result.error || 'Failed to list agents'
      }, 500);
    }
    
    const agents = result.agents!.map(agent => ({
      agent_id: agent.agent_id,
      name: agent.name,
      operator: agent.operator,
      version: agent.version,
      created_at: new Date(agent.created_at).toISOString(),
      tap_enabled: agent.tap_enabled,
      trust_level: agent.trust_level,
      capabilities: agent.capabilities,
      last_verified_at: agent.last_verified_at ? 
        new Date(agent.last_verified_at).toISOString() : null
    }));
    
    return c.json({
      success: true,
      agents,
      count: agents.length,
      tap_enabled_count: agents.filter(a => a.tap_enabled).length
    });
    
  } catch (error) {
    console.error('TAP agent listing error:', error);
    return c.json({
      success: false,
      error: 'INTERNAL_ERROR',
      message: 'Internal server error'
    }, 500);
  }
}

// ============ TAP SESSION ROUTES ============

/**
 * POST /v1/sessions/tap
 * Create TAP session after verification
 */
export async function createTAPSessionRoute(c: Context) {
  try {
    const body = await c.req.json().catch(() => ({}));
    
    if (!body.agent_id || !body.user_context || !body.intent) {
      return c.json({
        success: false,
        error: 'MISSING_REQUIRED_FIELDS',
        message: 'agent_id, user_context, and intent are required'
      }, 400);
    }
    
    // Get agent
    const agentResult = await getTAPAgent(c.env.AGENTS, body.agent_id);
    if (!agentResult.success) {
      return c.json({
        success: false,
        error: 'AGENT_NOT_FOUND',
        message: 'Agent not found'
      }, 404);
    }
    
    const agent = agentResult.agent!;

    // Gate: agent must have TAP enabled (i.e. a registered public key).
    // tap_enabled is set to true only when a public key is registered, so this
    // check is the canonical guard. Without cryptographic identity, a TAP
    // session has no trust anchor and would silently bypass the entire
    // verification model.
    if (!agent.tap_enabled) {
      return c.json({
        success: false,
        error: 'TAP_NOT_ENABLED',
        message: 'Agent does not have TAP enabled. Register a public key via POST /v1/agents/register/tap (with public_key field) or POST /v1/agents/:id/tap/rotate-key to enable TAP sessions.'
      }, 403);
    }

    // ── RFC 9421 HTTP Message Signature Enforcement ──────────────────────────
    // For TAP-enabled agents, ALL session creation requests MUST carry a valid
    // RFC 9421 signature. Without this check, any caller that knows an agent_id
    // can impersonate it — defeating the entire cryptographic identity model.

    // Collect lowercased request headers for signature verification
    const reqHeaders: Record<string, string> = {};
    c.req.raw.headers.forEach((value: string, key: string) => {
      reqHeaders[key.toLowerCase()] = value;
    });

    const signatureHeader = reqHeaders['signature'];
    const signatureInputHeader = reqHeaders['signature-input'];

    // 1. No signature headers at all → SIGNATURE_REQUIRED
    if (!signatureHeader || !signatureInputHeader) {
      return c.json({
        success: false,
        error: 'SIGNATURE_REQUIRED',
        message: 'TAP-enabled agents require RFC 9421 HTTP Message Signature headers (Signature and Signature-Input). See https://botcha.ai/docs/tap for signing instructions.'
      }, 401);
    }

    // 2. Verify the signature (timestamp, nonce replay, and crypto all checked inside)
    const requestUrl = new URL(c.req.url);
    const verifyResult = await verifyHTTPMessageSignature(
      {
        method: c.req.method,
        path: requestUrl.pathname,
        headers: reqHeaders,
      },
      agent.public_key!,
      agent.signature_algorithm!,
      // Pass NONCES KV for replay protection (8-minute TTL per TAP spec)
      c.env.NONCES ?? null
    );

    if (!verifyResult.valid) {
      const errMsg = verifyResult.error ?? '';

      // Distinguish specific failure modes for actionable client errors
      if (errMsg.includes('expired') || errMsg.includes('Expired')) {
        return c.json({
          success: false,
          error: 'SIGNATURE_EXPIRED',
          message: 'The RFC 9421 signature has expired. Regenerate a fresh signature with a current timestamp.',
          detail: errMsg
        }, 401);
      }

      if (errMsg.includes('Nonce replay') || errMsg.includes('nonce replay')) {
        return c.json({
          success: false,
          error: 'NONCE_REPLAYED',
          message: 'This nonce has already been used. Generate a fresh unique nonce for each request.',
          detail: errMsg
        }, 401);
      }

      // All other verification failures (bad key, tampered data, malformed sig, etc.)
      return c.json({
        success: false,
        error: 'SIGNATURE_INVALID',
        message: 'RFC 9421 signature verification failed. Ensure you are signing the correct signature base string with the registered private key.',
        detail: errMsg
      }, 401);
    }
    // ── End RFC 9421 enforcement ─────────────────────────────────────────────

    // Parse intent
    const intentResult = parseTAPIntent(JSON.stringify(body.intent));
    if (!intentResult.valid) {
      return c.json({
        success: false,
        error: 'INVALID_INTENT',
        message: intentResult.error
      }, 400);
    }
    
    // Validate capability
    const capabilityCheck = validateCapability(
      agent.capabilities || [],
      intentResult.intent!.action,
      intentResult.intent!.resource
    );
    
    if (!capabilityCheck.valid) {
      return c.json({
        success: false,
        error: 'INSUFFICIENT_CAPABILITY',
        message: capabilityCheck.error
      }, 403);
    }
    
    // Create session
    const sessionResult = await createTAPSession(
      c.env.SESSIONS,
      agent.agent_id,
      agent.app_id,
      body.user_context,
      agent.capabilities || [],
      intentResult.intent!
    );
    
    if (!sessionResult.success) {
      return c.json({
        success: false,
        error: 'SESSION_CREATION_FAILED',
        message: sessionResult.error
      }, 500);
    }
    
    const session = sessionResult.session!;

    // Update last_verified_at — session creation is a successful TAP verification event.
    // updateAgentVerification catches and logs internally; void signals intentional fire-and-forget.
    // Note: this does a read-modify-write on the full agent KV record. A concurrent key rotation
    // could clobber that write. Future work: store last_verified_at in a separate KV key.
    void updateAgentVerification(c.env.AGENTS, agent.agent_id, true);
    
    return c.json({
      success: true,
      session_id: session.session_id,
      agent_id: session.agent_id,
      capabilities: session.capabilities,
      intent: session.intent,
      expires_at: new Date(session.expires_at).toISOString()
    }, 201);
    
  } catch (error) {
    console.error('TAP session creation error:', error);
    return c.json({
      success: false,
      error: 'INTERNAL_ERROR',
      message: 'Internal server error'
    }, 500);
  }
}

/**
 * GET /v1/sessions/:id/tap
 * Get TAP session info
 */
export async function getTAPSessionRoute(c: Context) {
  try {
    const sessionId = c.req.param('id');
    if (!sessionId) {
      return c.json({
        success: false,
        error: 'MISSING_SESSION_ID',
        message: 'Session ID is required'
      }, 400);
    }
    
    const result = await getTAPSession(c.env.SESSIONS, sessionId);
    
    if (!result.success) {
      return c.json({
        success: false,
        error: 'SESSION_NOT_FOUND',
        message: result.error || 'Session not found or expired'
      }, 404);
    }
    
    const session = result.session!;
    
    return c.json({
      success: true,
      session_id: session.session_id,
      agent_id: session.agent_id,
      app_id: session.app_id,
      capabilities: session.capabilities,
      intent: session.intent,
      created_at: new Date(session.created_at).toISOString(),
      expires_at: new Date(session.expires_at).toISOString(),
      time_remaining: Math.max(0, session.expires_at - Date.now())
    });
    
  } catch (error) {
    console.error('TAP session retrieval error:', error);
    return c.json({
      success: false,
      error: 'INTERNAL_ERROR', 
      message: 'Internal server error'
    }, 500);
  }
}

// ============ TAP KEY ROTATION ============

/**
 * POST /v1/agents/:id/tap/rotate-key
 * Rotate an agent's public key
 */
export async function rotateKeyRoute(c: Context) {
  try {
    const agentId = c.req.param('id');
    if (!agentId) {
      return c.json({ success: false, error: 'MISSING_AGENT_ID', message: 'Agent ID is required' }, 400);
    }
    
    const appAccess = await validateAppAccess(c, true);
    if (!appAccess.valid) {
      return c.json({ success: false, error: appAccess.error, message: 'Authentication required' }, (appAccess.status || 401) as 401);
    }
    
    const body = await c.req.json().catch(() => ({}));
    if (!body.public_key || !body.signature_algorithm) {
      return c.json({ success: false, error: 'MISSING_FIELDS', message: 'public_key and signature_algorithm are required' }, 400);
    }

    // Normalize public_key: accept JWK objects by serializing to JSON
    const newPublicKey = typeof body.public_key === 'object'
      ? JSON.stringify(body.public_key)
      : body.public_key;

    // Validate algorithm
    const validAlgorithms = ['ecdsa-p256-sha256', 'rsa-pss-sha256', 'ed25519'];
    if (!validAlgorithms.includes(body.signature_algorithm)) {
      return c.json({ success: false, error: 'INVALID_ALGORITHM', message: `Unsupported algorithm. Supported: ${validAlgorithms.join(', ')}` }, 400);
    }

    // Validate key format (PEM, JWK, or raw Ed25519)
    const isPEM = typeof newPublicKey === 'string' && newPublicKey.includes('BEGIN PUBLIC KEY');
    const isJWK = isValidJWK(newPublicKey);
    const isRawEd25519 = body.signature_algorithm === 'ed25519' && !isPEM && !isJWK;
    if (!isPEM && !isJWK && !isRawEd25519) {
      return c.json({ success: false, error: 'INVALID_KEY_FORMAT', message: 'Invalid public key format. Provide a PEM key, JWK object/JSON, or raw Ed25519 base64 key.' }, 400);
    }
    
    // Get existing agent
    const agentResult = await getTAPAgent(c.env.AGENTS, agentId);
    if (!agentResult.success || !agentResult.agent) {
      return c.json({ success: false, error: 'AGENT_NOT_FOUND', message: 'Agent not found' }, 404);
    }
    
    const agent = agentResult.agent;
    
    // Verify agent belongs to this app
    if (agent.app_id !== appAccess.appId) {
      return c.json({ success: false, error: 'UNAUTHORIZED', message: 'Agent does not belong to this app' }, 403);
    }
    
    // Update agent with new key
    agent.public_key = newPublicKey;
    agent.signature_algorithm = body.signature_algorithm;
    agent.key_created_at = Date.now();
    agent.key_expires_at = body.key_expires_at ? new Date(body.key_expires_at).getTime() : undefined;
    agent.tap_enabled = true;
    
    await c.env.AGENTS.put(`agent:${agentId}`, JSON.stringify(agent));
    
    return c.json({
      success: true,
      agent_id: agent.agent_id,
      message: 'Key rotated successfully',
      has_public_key: true,
      signature_algorithm: agent.signature_algorithm,
      key_created_at: new Date(agent.key_created_at).toISOString(),
      key_expires_at: agent.key_expires_at ? new Date(agent.key_expires_at).toISOString() : null,
      key_fingerprint: agent.public_key ? await generateKeyFingerprint(agent.public_key) : undefined
    });
    
  } catch (error) {
    console.error('Key rotation error:', error);
    return c.json({ success: false, error: 'INTERNAL_ERROR', message: 'Internal server error' }, 500);
  }
}

// ============ TAP INVOICE ROUTES (402 FLOW) ============

/**
 * POST /v1/invoices
 * Create an invoice for gated content
 */
export async function createInvoiceRoute(c: Context) {
  try {
    const appAccess = await validateAppAccess(c, true);
    if (!appAccess.valid) {
      return c.json({ success: false, error: appAccess.error, message: 'Authentication required' }, (appAccess.status || 401) as 401);
    }
    
    const body = await c.req.json().catch(() => ({}));
    if (!body.resource_uri || !body.amount || !body.currency || !body.card_acceptor_id) {
      return c.json({
        success: false,
        error: 'MISSING_FIELDS',
        message: 'resource_uri, amount, currency, and card_acceptor_id are required'
      }, 400);
    }
    
    const result = await createInvoice(c.env.INVOICES, appAccess.appId!, {
      resource_uri: body.resource_uri,
      amount: body.amount,
      currency: body.currency,
      card_acceptor_id: body.card_acceptor_id,
      description: body.description,
      ttl_seconds: body.ttl_seconds,
    });
    
    if (!result.success) {
      return c.json({ success: false, error: 'INVOICE_CREATION_FAILED', message: result.error }, 500);
    }
    
    return c.json({
      success: true,
      ...result.invoice,
      created_at: new Date(result.invoice!.created_at).toISOString(),
      expires_at: new Date(result.invoice!.expires_at).toISOString(),
    }, 201);
    
  } catch (error) {
    console.error('Invoice creation error:', error);
    return c.json({ success: false, error: 'INTERNAL_ERROR', message: 'Internal server error' }, 500);
  }
}

/**
 * GET /v1/invoices/:id
 * Get invoice details
 */
export async function getInvoiceRoute(c: Context) {
  try {
    const invoiceId = c.req.param('id');
    if (!invoiceId) {
      return c.json({ success: false, error: 'MISSING_INVOICE_ID', message: 'Invoice ID is required' }, 400);
    }
    
    const result = await getInvoice(c.env.INVOICES, invoiceId);
    if (!result.success) {
      return c.json({ success: false, error: 'INVOICE_NOT_FOUND', message: result.error || 'Invoice not found' }, 404);
    }
    
    return c.json({
      success: true,
      ...result.invoice,
      created_at: new Date(result.invoice!.created_at).toISOString(),
      expires_at: new Date(result.invoice!.expires_at).toISOString(),
    });
    
  } catch (error) {
    console.error('Invoice retrieval error:', error);
    return c.json({ success: false, error: 'INTERNAL_ERROR', message: 'Internal server error' }, 500);
  }
}

/**
 * POST /v1/invoices/:id/verify-iou
 * Verify a Browsing IOU against an invoice
 */
export async function verifyIOURoute(c: Context) {
  try {
    const invoiceId = c.req.param('id');
    if (!invoiceId) {
      return c.json({ success: false, error: 'MISSING_INVOICE_ID', message: 'Invoice ID is required' }, 400);
    }
    
    const body = await c.req.json().catch(() => ({}));
    if (!body.browsingIOU) {
      return c.json({ success: false, error: 'MISSING_IOU', message: 'browsingIOU object is required' }, 400);
    }
    
    // Get the invoice
    const invoiceResult = await getInvoice(c.env.INVOICES, invoiceId);
    if (!invoiceResult.success || !invoiceResult.invoice) {
      return c.json({ success: false, error: 'INVOICE_NOT_FOUND', message: 'Invoice not found or expired' }, 404);
    }
    
    // Get the agent's public key for signature verification
    const agentKeyId = body.browsingIOU.kid;
    if (!agentKeyId) {
      return c.json({ success: false, error: 'MISSING_KEY_ID', message: 'browsingIOU must include kid' }, 400);
    }
    
    // Resolve key by kid (agent/key identifier) and enforce same-app ownership.
    const agentData = await c.env.AGENTS.get(`agent:${agentKeyId}`, 'text');
    if (!agentData) {
      return c.json({ success: false, error: 'KEY_NOT_FOUND', message: `No TAP key found for kid: ${agentKeyId}` }, 404);
    }

    const agent = JSON.parse(agentData);
    if (agent.app_id !== invoiceResult.invoice.app_id) {
      return c.json({
        success: false,
        error: 'KEY_APP_MISMATCH',
        message: 'Key does not belong to the app that issued this invoice',
      }, 403);
    }

    if (!agent.public_key) {
      return c.json({ success: false, error: 'KEY_NOT_FOUND', message: 'Could not resolve public key for verification' }, 404);
    }
    
    // Verify the IOU
    const iouResult = await verifyBrowsingIOU(
      body.browsingIOU,
      invoiceResult.invoice,
      agent.public_key,
      body.browsingIOU.alg || agent.signature_algorithm || 'ES256'
    );
    
    if (!iouResult.valid) {
      return c.json({ success: false, verified: false, error: iouResult.error }, 400);
    }
    
    // Fulfill the invoice
    const fulfillResult = await fulfillInvoice(c.env.INVOICES, invoiceId, body.browsingIOU);
    if (!fulfillResult.success || !fulfillResult.access_token) {
      return c.json({
        success: false,
        verified: true,
        error: 'INVOICE_FULFILLMENT_FAILED',
        message: fulfillResult.error || 'Invoice could not be fulfilled',
      }, 502);
    }
    
    return c.json({
      success: true,
      verified: true,
      access_token: fulfillResult.access_token,
      expires_at: fulfillResult.access_token ? new Date(Date.now() + 300000).toISOString() : undefined,
    });
    
  } catch (error) {
    console.error('IOU verification error:', error);
    return c.json({ success: false, error: 'INTERNAL_ERROR', message: 'Internal server error' }, 500);
  }
}

// ============ TAP VERIFICATION UTILITY ROUTES ============

/**
 * POST /v1/verify/consumer
 * Verify an Agentic Consumer Recognition Object (utility endpoint)
 */
export async function verifyConsumerRoute(c: Context) {
  try {
    const body = await c.req.json().catch(() => ({}));
    
    const consumer = parseAgenticConsumer(body);
    if (!consumer) {
      return c.json({ success: false, error: 'INVALID_CONSUMER_OBJECT', message: 'Invalid or missing agenticConsumer object' }, 400);
    }
    
    // Need header nonce and public key for full verification
    const headerNonce = body.headerNonce || c.req.header('x-tap-nonce');
    const publicKey = body.publicKey;
    const algorithm = body.algorithm || consumer.alg;
    
    if (!publicKey) {
      return c.json({
        success: true,
        parsed: true,
        verified: false,
        message: 'Consumer object parsed but publicKey required for signature verification',
        contextualData: consumer.contextualData,
        hasIdToken: Boolean(consumer.idToken),
        nonceLinked: headerNonce ? consumer.nonce === headerNonce : null,
      });
    }
    
    const result = await verifyAgenticConsumer(consumer, headerNonce || '', publicKey, algorithm);
    
    return c.json({
      success: true,
      ...result,
    });
    
  } catch (error) {
    console.error('Consumer verification error:', error);
    return c.json({ success: false, error: 'INTERNAL_ERROR', message: 'Internal server error' }, 500);
  }
}

/**
 * POST /v1/verify/payment
 * Verify an Agentic Payment Container (utility endpoint)
 */
export async function verifyPaymentRoute(c: Context) {
  try {
    const body = await c.req.json().catch(() => ({}));
    
    const container = parsePaymentContainer(body);
    if (!container) {
      return c.json({ success: false, error: 'INVALID_PAYMENT_CONTAINER', message: 'Invalid or missing agenticPaymentContainer object' }, 400);
    }
    
    const headerNonce = body.headerNonce || c.req.header('x-tap-nonce');
    const publicKey = body.publicKey;
    const algorithm = body.algorithm || container.alg;
    
    if (!publicKey) {
      return c.json({
        success: true,
        parsed: true,
        verified: false,
        message: 'Payment container parsed but publicKey required for signature verification',
        nonceLinked: headerNonce ? container.nonce === headerNonce : null,
        hasCardMetadata: Boolean(container.cardMetadata),
        hasCredentialHash: Boolean(container.credentialHash),
        hasPayload: Boolean(container.payload),
        hasBrowsingIOU: Boolean(container.browsingIOU),
      });
    }
    
    const result = await verifyPaymentContainer(container, headerNonce || '', publicKey, algorithm);
    
    return c.json({
      success: true,
      ...result,
    });
    
  } catch (error) {
    console.error('Payment verification error:', error);
    return c.json({ success: false, error: 'INTERNAL_ERROR', message: 'Internal server error' }, 500);
  }
}

// ============ UTILITY FUNCTIONS ============

async function generateKeyFingerprint(publicKey: string): Promise<string> {
  const normalized = publicKey.replace(/\s/g, '').replace(/-----[^-]+-----/g, '');
  const encoder = new TextEncoder();
  const data = encoder.encode(normalized);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.slice(0, 8).map(b => b.toString(16).padStart(2, '0')).join('');
}

export default {
  registerTAPAgentRoute,
  getTAPAgentRoute,
  listTAPAgentsRoute,
  createTAPSessionRoute,
  getTAPSessionRoute,
  rotateKeyRoute,
  createInvoiceRoute,
  getInvoiceRoute,
  verifyIOURoute,
  verifyConsumerRoute,
  verifyPaymentRoute,
};
