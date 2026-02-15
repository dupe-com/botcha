/**
 * TAP Capability Attestation
 * 
 * Signed JWT tokens that cryptographically bind:
 *   WHO (agent_id) can do WHAT (can/cannot rules) on WHICH resources,
 *   attested by WHOM (app authority), until WHEN (expiration).
 * 
 * Permission model: "action:resource" patterns with explicit deny.
 *   - Allow: { can: ["read:invoices", "write:orders", "browse:*"] }
 *   - Deny:  { cannot: ["write:transfers", "purchase:*"] }
 *   - Deny takes precedence over allow
 *   - Wildcards: "*:*" (all), "read:*" (read anything), "*:invoices" (any action on invoices)
 *   - Backward compatible: bare actions like "browse" expand to "browse:*"
 * 
 * Attestation tokens are signed JWTs (HS256) with type 'botcha-attestation'.
 * They can be verified offline (signature check) or online (revocation check via KV).
 */

import { SignJWT, jwtVerify } from 'jose';
import type { KVNamespace } from './agents.js';
import { getTAPAgent } from './tap-agents.js';

// ============ TYPES ============

export interface AttestationPayload {
  sub: string;           // agent_id
  iss: string;           // attester (app_id)
  type: 'botcha-attestation';
  jti: string;           // unique ID for revocation
  iat: number;           // issued at
  exp: number;           // expires at
  can: string[];         // allowed capability patterns ("action:resource")
  cannot: string[];      // denied capability patterns (overrides can)
  restrictions?: {
    max_amount?: number;
    rate_limit?: number;
    [key: string]: any;
  };
  delegation_id?: string;  // optional link to delegation chain
  metadata?: Record<string, string>;
}

export interface Attestation {
  attestation_id: string;   // same as jti
  agent_id: string;
  app_id: string;
  can: string[];
  cannot: string[];
  restrictions?: {
    max_amount?: number;
    rate_limit?: number;
    [key: string]: any;
  };
  delegation_id?: string;
  metadata?: Record<string, string>;
  token: string;            // the signed JWT
  created_at: number;
  expires_at: number;
  revoked: boolean;
  revoked_at?: number;
  revocation_reason?: string;
}

export interface IssueAttestationOptions {
  agent_id: string;
  can: string[];
  cannot?: string[];
  restrictions?: {
    max_amount?: number;
    rate_limit?: number;
    [key: string]: any;
  };
  duration_seconds?: number;  // default: 3600 (1 hour)
  delegation_id?: string;
  metadata?: Record<string, string>;
}

export interface AttestationResult {
  success: boolean;
  attestation?: Attestation;
  token?: string;
  error?: string;
}

export interface CapabilityCheckResult {
  allowed: boolean;
  reason?: string;          // why denied or allowed
  matched_rule?: string;    // which rule matched
}

// ============ CONSTANTS ============

const DEFAULT_DURATION = 3600;       // 1 hour
const MAX_DURATION = 86400 * 30;     // 30 days
const MAX_RULES = 100;               // max can + cannot entries

// ============ PERMISSION MATCHING ============

/**
 * Normalize a capability string to "action:resource" format.
 * Bare actions like "browse" expand to "browse:*".
 */
export function normalizeCapability(cap: string): string {
  if (cap.includes(':')) return cap;
  return `${cap}:*`;
}

/**
 * Check if a pattern matches a target.
 * Supports wildcards: "*:*", "read:*", "*:invoices", "read:invoices"
 */
export function matchesPattern(pattern: string, target: string): boolean {
  const normalizedPattern = normalizeCapability(pattern);
  const normalizedTarget = normalizeCapability(target);

  const [patAction, patResource] = normalizedPattern.split(':', 2);
  const [tgtAction, tgtResource] = normalizedTarget.split(':', 2);

  const actionMatch = patAction === '*' || patAction === tgtAction;
  const resourceMatch = patResource === '*' || patResource === tgtResource;

  return actionMatch && resourceMatch;
}

/**
 * Check if a specific action:resource is allowed by the can/cannot rules.
 * 
 * Rules:
 * 1. Check "cannot" list first — any match means DENIED (deny takes precedence)
 * 2. Check "can" list — any match means ALLOWED
 * 3. If no match in either list — DENIED (default deny)
 */
export function checkCapability(
  can: string[],
  cannot: string[],
  action: string,
  resource?: string
): CapabilityCheckResult {
  const target = resource ? `${action}:${resource}` : normalizeCapability(action);

  // Check deny rules first (deny takes precedence)
  for (const rule of cannot) {
    if (matchesPattern(rule, target)) {
      return {
        allowed: false,
        reason: `Explicitly denied by rule: ${rule}`,
        matched_rule: rule,
      };
    }
  }

  // Check allow rules
  for (const rule of can) {
    if (matchesPattern(rule, target)) {
      return {
        allowed: true,
        reason: `Allowed by rule: ${rule}`,
        matched_rule: rule,
      };
    }
  }

  // Default deny
  return {
    allowed: false,
    reason: `No matching allow rule for: ${target}`,
  };
}

/**
 * Validate capability pattern syntax.
 * Valid: "action:resource", "action", "*:*", "read:*", "*:invoices"
 */
export function isValidCapabilityPattern(pattern: string): boolean {
  const normalized = normalizeCapability(pattern);
  const parts = normalized.split(':');
  if (parts.length !== 2) return false;

  const [action, resource] = parts;
  // Action and resource must be non-empty, alphanumeric + underscore + hyphen + wildcard
  const validPart = /^[a-zA-Z0-9_\-*]+$/;
  return validPart.test(action) && validPart.test(resource);
}

// ============ ATTESTATION ISSUANCE ============

/**
 * Issue a capability attestation token for an agent.
 * 
 * Validates:
 * - Agent exists and belongs to the app
 * - All capability patterns are syntactically valid
 * - Total rules don't exceed limit
 * 
 * Signs a JWT with the attestation payload.
 */
export async function issueAttestation(
  agents: KVNamespace,
  sessions: KVNamespace,
  appId: string,
  secret: string,
  options: IssueAttestationOptions
): Promise<AttestationResult> {
  try {
    // Validate inputs
    if (!options.agent_id) {
      return { success: false, error: 'agent_id is required' };
    }
    if (!options.can || options.can.length === 0) {
      return { success: false, error: 'At least one "can" rule is required' };
    }

    const cannot = options.cannot || [];
    const totalRules = options.can.length + cannot.length;
    if (totalRules > MAX_RULES) {
      return { success: false, error: `Too many rules (${totalRules}). Maximum: ${MAX_RULES}` };
    }

    // Validate all patterns
    for (const rule of options.can) {
      if (!isValidCapabilityPattern(rule)) {
        return { success: false, error: `Invalid capability pattern in "can": ${rule}` };
      }
    }
    for (const rule of cannot) {
      if (!isValidCapabilityPattern(rule)) {
        return { success: false, error: `Invalid capability pattern in "cannot": ${rule}` };
      }
    }

    // Verify agent exists and belongs to this app
    const agentResult = await getTAPAgent(agents, options.agent_id);
    if (!agentResult.success || !agentResult.agent) {
      return { success: false, error: 'Agent not found' };
    }
    if (agentResult.agent.app_id !== appId) {
      return { success: false, error: 'Agent does not belong to this app' };
    }

    // Calculate expiration
    const durationSeconds = Math.min(
      options.duration_seconds ?? DEFAULT_DURATION,
      MAX_DURATION
    );
    const now = Date.now();
    const expiresAt = now + durationSeconds * 1000;

    // Generate attestation ID
    const attestationId = crypto.randomUUID();

    // Sign the attestation JWT
    const encoder = new TextEncoder();
    const secretKey = encoder.encode(secret);

    const payload: Record<string, any> = {
      type: 'botcha-attestation',
      can: options.can,
      cannot,
      jti: attestationId,
    };
    if (options.restrictions) {
      payload.restrictions = options.restrictions;
    }
    if (options.delegation_id) {
      payload.delegation_id = options.delegation_id;
    }
    if (options.metadata) {
      payload.metadata = options.metadata;
    }

    const token = await new SignJWT(payload)
      .setProtectedHeader({ alg: 'HS256' })
      .setSubject(options.agent_id)
      .setIssuer(appId)
      .setIssuedAt()
      .setExpirationTime(Math.floor(expiresAt / 1000))
      .sign(secretKey);

    // Build attestation record
    const attestation: Attestation = {
      attestation_id: attestationId,
      agent_id: options.agent_id,
      app_id: appId,
      can: options.can,
      cannot,
      restrictions: options.restrictions,
      delegation_id: options.delegation_id,
      metadata: options.metadata,
      token,
      created_at: now,
      expires_at: expiresAt,
      revoked: false,
    };

    // Store attestation in KV (for revocation and lookup)
    const ttlSeconds = Math.max(1, Math.floor(durationSeconds));
    await sessions.put(
      `attestation:${attestationId}`,
      JSON.stringify(attestation),
      { expirationTtl: ttlSeconds }
    );

    // Update agent's attestation index
    await updateAttestationIndex(sessions, options.agent_id, attestationId, 'add');

    return { success: true, attestation, token };

  } catch (error) {
    console.error('Failed to issue attestation:', error);
    return { success: false, error: 'Internal server error' };
  }
}

/**
 * Get an attestation by ID (from KV, not from JWT)
 */
export async function getAttestation(
  sessions: KVNamespace,
  attestationId: string
): Promise<AttestationResult> {
  try {
    const data = await sessions.get(`attestation:${attestationId}`, 'text');
    if (!data) {
      return { success: false, error: 'Attestation not found or expired' };
    }

    const attestation = JSON.parse(data) as Attestation;
    return { success: true, attestation };

  } catch (error) {
    console.error('Failed to get attestation:', error);
    return { success: false, error: 'Internal server error' };
  }
}

/**
 * Revoke an attestation.
 */
export async function revokeAttestation(
  sessions: KVNamespace,
  attestationId: string,
  reason?: string
): Promise<AttestationResult> {
  try {
    const result = await getAttestation(sessions, attestationId);
    if (!result.success || !result.attestation) {
      return { success: false, error: 'Attestation not found' };
    }

    const attestation = result.attestation;
    if (attestation.revoked) {
      return { success: true, attestation }; // idempotent
    }

    attestation.revoked = true;
    attestation.revoked_at = Date.now();
    attestation.revocation_reason = reason;

    // Re-store with remaining TTL
    const remainingTtl = Math.max(60, Math.floor((attestation.expires_at - Date.now()) / 1000));
    await sessions.put(
      `attestation:${attestationId}`,
      JSON.stringify(attestation),
      { expirationTtl: remainingTtl }
    );

    // Also store in revocation list (for fast JWT verification without full record lookup)
    await sessions.put(
      `attestation_revoked:${attestationId}`,
      JSON.stringify({ revokedAt: attestation.revoked_at, reason }),
      { expirationTtl: remainingTtl }
    );

    return { success: true, attestation };

  } catch (error) {
    console.error('Failed to revoke attestation:', error);
    return { success: false, error: 'Internal server error' };
  }
}

/**
 * Verify an attestation JWT token.
 * 
 * Checks:
 * 1. JWT signature and expiration (cryptographic)
 * 2. Token type is 'botcha-attestation'
 * 3. Revocation status (via KV, fail-open)
 * 
 * Returns the parsed attestation payload if valid.
 */
export async function verifyAttestationToken(
  sessions: KVNamespace,
  token: string,
  secret: string
): Promise<{
  valid: boolean;
  payload?: AttestationPayload;
  error?: string;
}> {
  try {
    const encoder = new TextEncoder();
    const secretKey = encoder.encode(secret);

    const { payload } = await jwtVerify(token, secretKey, {
      algorithms: ['HS256'],
    });

    // Check token type
    if (payload.type !== 'botcha-attestation') {
      return { valid: false, error: 'Invalid token type. Expected attestation token.' };
    }

    const jti = payload.jti as string;

    // Check revocation (fail-open)
    if (jti) {
      try {
        const revoked = await sessions.get(`attestation_revoked:${jti}`);
        if (revoked) {
          return { valid: false, error: 'Attestation has been revoked' };
        }
      } catch (error) {
        console.error('Failed to check attestation revocation:', error);
        // Fail-open
      }
    }

    // Build typed payload
    const attestationPayload: AttestationPayload = {
      sub: payload.sub || '',
      iss: payload.iss || '',
      type: 'botcha-attestation',
      jti: jti || '',
      iat: payload.iat || 0,
      exp: payload.exp || 0,
      can: (payload.can as string[]) || [],
      cannot: (payload.cannot as string[]) || [],
      restrictions: payload.restrictions as any,
      delegation_id: payload.delegation_id as string | undefined,
      metadata: payload.metadata as Record<string, string> | undefined,
    };

    return { valid: true, payload: attestationPayload };

  } catch (error) {
    return {
      valid: false,
      error: error instanceof Error ? error.message : 'Invalid attestation token',
    };
  }
}

/**
 * Full capability check: verify attestation token + check specific action:resource.
 * 
 * Combines token verification with permission checking in one call.
 */
export async function verifyAndCheckCapability(
  sessions: KVNamespace,
  token: string,
  secret: string,
  action: string,
  resource?: string
): Promise<{
  allowed: boolean;
  agent_id?: string;
  reason?: string;
  matched_rule?: string;
  error?: string;
}> {
  // First verify the token
  const verification = await verifyAttestationToken(sessions, token, secret);
  if (!verification.valid || !verification.payload) {
    return {
      allowed: false,
      error: verification.error || 'Invalid attestation token',
    };
  }

  const payload = verification.payload;

  // Check restrictions if applicable
  if (payload.restrictions?.rate_limit !== undefined) {
    // Rate limit would need a counter — for now, we just pass the restriction through
    // Future: implement per-attestation rate limit counters in KV
  }

  // Check capability
  const check = checkCapability(payload.can, payload.cannot, action, resource);

  return {
    allowed: check.allowed,
    agent_id: payload.sub,
    reason: check.reason,
    matched_rule: check.matched_rule,
  };
}

// ============ ENFORCEMENT MIDDLEWARE ============

/**
 * Create a Hono middleware that enforces capability attestation.
 * 
 * Usage:
 *   app.get('/api/invoices', requireCapability('read:invoices'), handler);
 *   app.post('/api/transfers', requireCapability('write:transfers'), handler);
 * 
 * Extracts attestation token from:
 *   1. X-Botcha-Attestation header
 *   2. Authorization: Bearer header (if token type is attestation)
 * 
 * On failure: returns 403 with capability denial details.
 * On missing token: returns 401 requesting attestation.
 */
export function requireCapability(capability: string) {
  return async (c: any, next: () => Promise<void>) => {
    // Extract attestation token
    const attestationHeader = c.req.header('x-botcha-attestation');
    const authHeader = c.req.header('authorization');
    const token = attestationHeader || extractBearer(authHeader);

    if (!token) {
      return c.json({
        success: false,
        error: 'ATTESTATION_REQUIRED',
        message: 'Capability attestation token required',
        required_capability: capability,
        hint: 'Include X-Botcha-Attestation header or Authorization: Bearer with attestation token',
      }, 401);
    }

    // Verify and check
    const [action, resource] = normalizeCapability(capability).split(':', 2);
    const result = await verifyAndCheckCapability(
      c.env.SESSIONS,
      token,
      c.env.JWT_SECRET,
      action,
      resource === '*' ? undefined : resource
    );

    if (!result.allowed) {
      return c.json({
        success: false,
        error: 'CAPABILITY_DENIED',
        message: result.reason || result.error || 'Capability check failed',
        required_capability: capability,
        agent_id: result.agent_id,
        matched_rule: result.matched_rule,
      }, 403);
    }

    // Attach attestation info to context for downstream handlers
    c.set('attestation_agent_id', result.agent_id);
    c.set('attestation_capability', capability);
    c.set('attestation_matched_rule', result.matched_rule);

    await next();
  };
}

// ============ UTILITY FUNCTIONS ============

function extractBearer(header?: string): string | null {
  if (!header) return null;
  const match = header.match(/^Bearer\s+(.+)$/i);
  return match ? match[1] : null;
}

async function updateAttestationIndex(
  sessions: KVNamespace,
  agentId: string,
  attestationId: string,
  operation: 'add' | 'remove'
): Promise<void> {
  try {
    const key = `agent_attestations:${agentId}`;
    const data = await sessions.get(key, 'text');
    let ids: string[] = data ? JSON.parse(data) : [];

    if (operation === 'add' && !ids.includes(attestationId)) {
      ids.push(attestationId);
    } else if (operation === 'remove') {
      ids = ids.filter(id => id !== attestationId);
    }

    await sessions.put(key, JSON.stringify(ids));
  } catch (error) {
    console.error('Failed to update attestation index:', error);
  }
}

export default {
  issueAttestation,
  getAttestation,
  revokeAttestation,
  verifyAttestationToken,
  verifyAndCheckCapability,
  checkCapability,
  matchesPattern,
  normalizeCapability,
  isValidCapabilityPattern,
  requireCapability,
};
