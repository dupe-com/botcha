/**
 * A2A Agent Card Attestation — BOTCHA as A2A Trust Oracle
 *
 * Implements Google's A2A (Agent-to-Agent) protocol trust layer:
 *   1. BOTCHA's own Agent Card (/.well-known/agent.json)
 *   2. Agent Card attestation issuance (POST /v1/a2a/attest)
 *   3. Agent Card attestation verification (POST /v1/a2a/verify-card)
 *   4. Verified card registry (GET /v1/a2a/cards)
 *
 * Attestation model:
 *   - Input:  any A2A Agent Card JSON
 *   - Output: a signed JWT embedding SHA-256(canonicalized card)
 *   - The JWT is embedded into card.extensions.botcha_attestation
 *   - Verification checks: signature, hash match, expiration, revocation
 *
 * References:
 *   https://google.github.io/A2A/
 *   https://github.com/google-a2a/A2A
 */

import { SignJWT, jwtVerify } from 'jose';
import type { KVNamespace } from './agents.js';

// ============ A2A TYPES ============

export interface A2AAgentCardAuthentication {
  schemes: string[];
  description?: string;
  credentials?: Record<string, string>;
}

export interface A2AAgentCardSkill {
  id: string;
  name: string;
  description?: string;
  tags?: string[];
  examples?: string[];
  inputModes?: string[];
  outputModes?: string[];
}

export interface A2AAgentCardCapabilities {
  streaming?: boolean;
  pushNotifications?: boolean;
  stateTransitionHistory?: boolean;
}

export interface BotchaAttestationExtension {
  token: string;           // signed JWT
  verified_at: string;     // ISO 8601
  trust_level: string;     // 'verified' | 'basic' | 'enterprise'
  issuer: string;          // https://botcha.ai
  card_hash: string;       // SHA-256 hex of canonicalized card (without extensions)
  expires_at: string;      // ISO 8601
}

export interface A2AAgentCard {
  name: string;
  description?: string;
  url: string;
  version?: string;
  documentationUrl?: string;
  capabilities?: A2AAgentCardCapabilities;
  authentication?: A2AAgentCardAuthentication[];
  defaultInputModes?: string[];
  defaultOutputModes?: string[];
  skills?: A2AAgentCardSkill[];
  extensions?: {
    botcha_attestation?: BotchaAttestationExtension;
    [key: string]: unknown;
  };
  [key: string]: unknown;
}

export interface A2AAttestationPayload {
  sub: string;         // agent URL (primary identity)
  iss: string;         // 'https://botcha.ai'
  type: 'botcha-a2a-attestation';
  jti: string;         // unique ID for revocation
  iat: number;
  exp: number;
  card_hash: string;   // SHA-256 hex of canonicalized card (no extensions)
  agent_name: string;  // card.name
  agent_url: string;   // card.url
  app_id: string;      // BOTCHA app that requested attestation
  trust_level: string; // 'verified'
}

export interface A2AAttestation {
  attestation_id: string;
  agent_url: string;
  agent_name: string;
  app_id: string;
  card_hash: string;
  token: string;
  trust_level: string;
  created_at: number;
  expires_at: number;
  revoked: boolean;
  revoked_at?: number;
  card_snapshot?: A2AAgentCard; // optional snapshot without extensions
}

export interface AttestCardOptions {
  card: A2AAgentCard;
  app_id: string;
  duration_seconds?: number; // default 86400 (24h), max 2592000 (30d)
  trust_level?: string;      // default 'verified'
}

export interface AttestCardResult {
  success: boolean;
  attestation?: A2AAttestation;
  attested_card?: A2AAgentCard;  // card with extensions.botcha_attestation embedded
  error?: string;
}

export interface VerifyCardResult {
  success: boolean;
  valid?: boolean;
  attestation_id?: string;
  agent_url?: string;
  agent_name?: string;
  card_hash?: string;
  trust_level?: string;
  issued_at?: string;
  expires_at?: string;
  app_id?: string;
  error?: string;
  reason?: string;
}

// ============ BOTCHA'S OWN AGENT CARD ============

export const BOTCHA_VERSION = '0.21.2';
export const BOTCHA_URL = 'https://botcha.ai';

/**
 * BOTCHA's A2A Agent Card.
 * Served at /.well-known/agent.json
 */
export function getBotchaAgentCard(version?: string): A2AAgentCard {
  const v = version || BOTCHA_VERSION;
  return {
    name: 'BOTCHA',
    description: 'Reverse CAPTCHA for AI agents. Prove you\'re a bot. Humans need not apply.',
    url: BOTCHA_URL,
    version: v,
    documentationUrl: 'https://botcha.ai/docs',
    capabilities: {
      streaming: false,
      pushNotifications: false,
      stateTransitionHistory: false,
    },
    authentication: [
      {
        schemes: ['Bearer'],
        description: 'BOTCHA access token — obtain via POST /v1/token/verify after solving a challenge',
      },
    ],
    defaultInputModes: ['application/json'],
    defaultOutputModes: ['application/json'],
    skills: [
      {
        id: 'verify-agent',
        name: 'Verify Agent',
        description: 'Issue a BOTCHA challenge to verify an AI agent. Returns a signed access token on success.',
        tags: ['verification', 'identity', 'challenge'],
        examples: [
          'GET /v1/token?app_id=<app_id> → solve SHA256 challenge → POST /v1/token/verify',
        ],
        inputModes: ['application/json'],
        outputModes: ['application/json'],
      },
      {
        id: 'attest-card',
        name: 'Attest Agent Card',
        description: 'Issue a BOTCHA attestation for an A2A Agent Card. The attestation JWT is embedded into the card\'s extensions.botcha_attestation field, making BOTCHA the trust oracle for the A2A ecosystem.',
        tags: ['attestation', 'a2a', 'trust', 'verification'],
        examples: [
          'POST /v1/a2a/attest with an A2A Agent Card JSON → attested card with extensions.botcha_attestation',
        ],
        inputModes: ['application/json'],
        outputModes: ['application/json'],
      },
      {
        id: 'verify-card',
        name: 'Verify Attested Agent Card',
        description: 'Verify a BOTCHA-attested A2A Agent Card. Checks signature, card hash integrity, and expiration.',
        tags: ['verification', 'a2a', 'attestation', 'trust'],
        examples: [
          'POST /v1/a2a/verify-card with an attested A2A Agent Card JSON',
        ],
        inputModes: ['application/json'],
        outputModes: ['application/json'],
      },
      {
        id: 'check-reputation',
        name: 'Check Reputation',
        description: 'Get an agent\'s BOTCHA reputation score based on challenge history and verification track record.',
        tags: ['reputation', 'trust', 'score'],
        examples: [
          'GET /v1/reputation/:agent_id',
        ],
        inputModes: ['application/json'],
        outputModes: ['application/json'],
      },
    ],
    extensions: {
      botcha: {
        challenge_endpoint: `${BOTCHA_URL}/v1/token`,
        verify_endpoint: `${BOTCHA_URL}/v1/token/verify`,
        attest_endpoint: `${BOTCHA_URL}/v1/a2a/attest`,
        verify_card_endpoint: `${BOTCHA_URL}/v1/a2a/verify-card`,
        registry_endpoint: `${BOTCHA_URL}/v1/a2a/cards`,
        openapi: `${BOTCHA_URL}/openapi.json`,
        ai_txt: `${BOTCHA_URL}/ai.txt`,
      },
    },
  };
}

// ============ CARD CANONICALIZATION & HASHING ============

/**
 * Canonicalize an A2A Agent Card for hashing.
 *
 * We remove the extensions.botcha_attestation field before hashing
 * so that the attestation can be embedded in the card without
 * invalidating its own hash. All other fields are included.
 *
 * Canonicalization: JSON.stringify with sorted keys (deterministic).
 */
export function canonicalizeCard(card: A2AAgentCard): string {
  // Deep clone and strip the attestation extension
  const stripped = deepCloneWithoutAttestation(card);
  // Sort keys recursively for deterministic output
  return stableStringify(stripped);
}

/**
 * Compute SHA-256 of a canonicalized card string.
 * Returns lowercase hex string.
 */
export async function hashCard(card: A2AAgentCard): Promise<string> {
  const canonical = canonicalizeCard(card);
  const encoder = new TextEncoder();
  const data = encoder.encode(canonical);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

function deepCloneWithoutAttestation(card: A2AAgentCard): Record<string, unknown> {
  const clone: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(card)) {
    if (key === 'extensions') {
      if (value && typeof value === 'object') {
        const exts = { ...(value as Record<string, unknown>) };
        delete exts['botcha_attestation'];
        if (Object.keys(exts).length > 0) {
          clone['extensions'] = deepCloneValue(exts);
        }
        // If extensions only had botcha_attestation, omit extensions entirely
      }
      // else: no extensions, skip
    } else {
      clone[key] = deepCloneValue(value);
    }
  }
  return clone;
}

function deepCloneValue(value: unknown): unknown {
  if (value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map(deepCloneValue);
  const obj = value as Record<string, unknown>;
  const result: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(obj)) {
    result[k] = deepCloneValue(v);
  }
  return result;
}

/**
 * Stable (deterministic) JSON stringify with sorted keys.
 * Handles nested objects, arrays, primitives.
 */
function stableStringify(value: unknown): string {
  if (value === null || value === undefined) return String(value);
  if (typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) {
    return '[' + value.map(stableStringify).join(',') + ']';
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  const pairs = keys
    .filter(k => obj[k] !== undefined)
    .map(k => JSON.stringify(k) + ':' + stableStringify(obj[k]));
  return '{' + pairs.join(',') + '}';
}

// ============ ATTESTATION ISSUANCE ============

const DEFAULT_DURATION = 86400;      // 24 hours
const MAX_DURATION = 2592000;        // 30 days

/**
 * Issue a BOTCHA attestation for an A2A Agent Card.
 *
 * Steps:
 * 1. Validate card (name + url required)
 * 2. Canonicalize and hash the card (without extensions)
 * 3. Sign a JWT with card_hash + agent identity
 * 4. Embed attestation in card.extensions.botcha_attestation
 * 5. Store attestation in KV for lookup and revocation
 */
export async function attestCard(
  sessions: KVNamespace,
  secret: string,
  options: AttestCardOptions
): Promise<AttestCardResult> {
  try {
    const { card, app_id } = options;

    // Validate required card fields
    if (!card.name || typeof card.name !== 'string') {
      return { success: false, error: 'Agent Card must have a "name" field' };
    }
    if (!card.url || typeof card.url !== 'string') {
      return { success: false, error: 'Agent Card must have a "url" field' };
    }

    // Validate URL format
    try {
      new URL(card.url);
    } catch {
      return { success: false, error: `Invalid "url" field: ${card.url}` };
    }

    const trustLevel = options.trust_level || 'verified';
    const durationSeconds = Math.min(
      options.duration_seconds ?? DEFAULT_DURATION,
      MAX_DURATION
    );

    const now = Date.now();
    const expiresAt = now + durationSeconds * 1000;
    const attestationId = crypto.randomUUID();

    // Hash the card (without any existing attestation)
    const cardHash = await hashCard(card);

    // Sign attestation JWT
    const encoder = new TextEncoder();
    const secretKey = encoder.encode(secret);

    const token = await new SignJWT({
      type: 'botcha-a2a-attestation',
      card_hash: cardHash,
      agent_name: card.name,
      agent_url: card.url,
      app_id,
      trust_level: trustLevel,
      jti: attestationId,
    })
      .setProtectedHeader({ alg: 'HS256' })
      .setSubject(card.url)
      .setIssuer(BOTCHA_URL)
      .setIssuedAt()
      .setExpirationTime(Math.floor(expiresAt / 1000))
      .sign(secretKey);

    // Build attestation record
    const attestation: A2AAttestation = {
      attestation_id: attestationId,
      agent_url: card.url,
      agent_name: card.name,
      app_id,
      card_hash: cardHash,
      token,
      trust_level: trustLevel,
      created_at: now,
      expires_at: expiresAt,
      revoked: false,
      card_snapshot: deepCloneWithoutAttestation(card) as A2AAgentCard,
    };

    // Store in KV with TTL
    const ttlSeconds = Math.max(60, Math.floor(durationSeconds));
    await sessions.put(
      `a2a_attestation:${attestationId}`,
      JSON.stringify(attestation),
      { expirationTtl: ttlSeconds }
    );

    // Update registry index (agent_url → list of attestation IDs)
    await updateCardRegistryIndex(sessions, card.url, attestationId, 'add');

    // Build the attested card (card + extensions.botcha_attestation)
    const extension: BotchaAttestationExtension = {
      token,
      verified_at: new Date(now).toISOString(),
      trust_level: trustLevel,
      issuer: BOTCHA_URL,
      card_hash: cardHash,
      expires_at: new Date(expiresAt).toISOString(),
    };

    const attestedCard: A2AAgentCard = {
      ...card,
      extensions: {
        ...(card.extensions || {}),
        botcha_attestation: extension,
      },
    };

    return { success: true, attestation, attested_card: attestedCard };

  } catch (error) {
    console.error('A2A card attestation error:', error);
    return { success: false, error: 'Internal server error' };
  }
}

// ============ ATTESTATION VERIFICATION ============

/**
 * Verify a BOTCHA-attested A2A Agent Card.
 *
 * Checks:
 * 1. Card has extensions.botcha_attestation.token
 * 2. JWT signature and expiration (cryptographic)
 * 3. JWT type is 'botcha-a2a-attestation'
 * 4. card_hash matches the current card content (tamper detection)
 * 5. Revocation status (KV lookup, fail-open)
 *
 * Returns verified/invalid + decoded claims.
 */
export async function verifyCard(
  sessions: KVNamespace,
  secret: string,
  card: A2AAgentCard
): Promise<VerifyCardResult> {
  try {
    // Extract attestation token from card
    const attestationExt = card.extensions?.botcha_attestation;
    if (!attestationExt || typeof attestationExt !== 'object') {
      return {
        success: true,
        valid: false,
        error: 'NO_ATTESTATION',
        reason: 'Card does not have extensions.botcha_attestation',
      };
    }

    const token = (attestationExt as BotchaAttestationExtension).token;
    if (!token || typeof token !== 'string') {
      return {
        success: true,
        valid: false,
        error: 'MISSING_TOKEN',
        reason: 'extensions.botcha_attestation.token is missing',
      };
    }

    // Verify JWT signature and expiration
    const encoder = new TextEncoder();
    const secretKey = encoder.encode(secret);

    let payload: Record<string, unknown>;
    try {
      const result = await jwtVerify(token, secretKey, { algorithms: ['HS256'] });
      payload = result.payload as Record<string, unknown>;
    } catch (err) {
      return {
        success: true,
        valid: false,
        error: 'INVALID_TOKEN',
        reason: err instanceof Error ? err.message : 'JWT verification failed',
      };
    }

    // Check token type
    if (payload['type'] !== 'botcha-a2a-attestation') {
      return {
        success: true,
        valid: false,
        error: 'WRONG_TOKEN_TYPE',
        reason: `Expected 'botcha-a2a-attestation', got '${payload['type']}'`,
      };
    }

    const jti = payload['jti'] as string;

    // Check revocation
    if (jti) {
      try {
        const revoked = await sessions.get(`a2a_attestation_revoked:${jti}`);
        if (revoked) {
          return {
            success: true,
            valid: false,
            error: 'REVOKED',
            reason: 'Attestation has been revoked',
            attestation_id: jti,
          };
        }
      } catch {
        // fail-open on KV errors
      }
    }

    // Verify card hash matches (tamper detection)
    const tokenCardHash = payload['card_hash'] as string;
    const currentCardHash = await hashCard(card);

    if (tokenCardHash !== currentCardHash) {
      return {
        success: true,
        valid: false,
        error: 'HASH_MISMATCH',
        reason: 'Card content has been modified since attestation. The card hash does not match.',
        card_hash: currentCardHash,
        attestation_id: jti,
      };
    }

    return {
      success: true,
      valid: true,
      attestation_id: jti,
      agent_url: payload['agent_url'] as string,
      agent_name: payload['agent_name'] as string,
      card_hash: tokenCardHash,
      trust_level: payload['trust_level'] as string,
      app_id: payload['app_id'] as string,
      issued_at: new Date((payload['iat'] as number) * 1000).toISOString(),
      expires_at: new Date((payload['exp'] as number) * 1000).toISOString(),
    };

  } catch (error) {
    console.error('A2A card verification error:', error);
    return { success: false, error: 'Internal server error' };
  }
}

// ============ CARD REGISTRY ============

/**
 * Get a specific A2A attestation record by ID.
 */
export async function getCardAttestation(
  sessions: KVNamespace,
  attestationId: string
): Promise<{ success: boolean; attestation?: A2AAttestation; error?: string }> {
  try {
    const data = await sessions.get(`a2a_attestation:${attestationId}`, 'text');
    if (!data) {
      return { success: false, error: 'Attestation not found or expired' };
    }
    return { success: true, attestation: JSON.parse(data) as A2AAttestation };
  } catch (error) {
    console.error('Failed to get A2A attestation:', error);
    return { success: false, error: 'Internal server error' };
  }
}

/**
 * List BOTCHA-verified A2A cards from the registry.
 *
 * Query options:
 *   verified_only: boolean — only return non-revoked attestations (default: true)
 *   agent_url: string — filter by agent URL
 *   limit: number — max results (default 50, max 200)
 */
export async function listVerifiedCards(
  sessions: KVNamespace,
  opts: {
    verified_only?: boolean;
    agent_url?: string;
    limit?: number;
  } = {}
): Promise<{ success: boolean; attestations?: A2AAttestation[]; error?: string }> {
  try {
    const verifiedOnly = opts.verified_only !== false;
    const limit = Math.min(opts.limit || 50, 200);

    // If filtering by agent_url, use the per-agent index
    if (opts.agent_url) {
      const indexData = await sessions.get(`a2a_registry:${encodeURIComponent(opts.agent_url)}`, 'text');
      const ids: string[] = indexData ? JSON.parse(indexData) : [];

      const results: A2AAttestation[] = [];
      for (const id of ids.slice(-limit)) {
        const result = await getCardAttestation(sessions, id);
        if (result.success && result.attestation) {
          if (!verifiedOnly || !result.attestation.revoked) {
            results.push(result.attestation);
          }
        }
      }
      return { success: true, attestations: results };
    }

    // Global registry index
    const globalIndexData = await sessions.get('a2a_registry:global', 'text');
    const globalIds: string[] = globalIndexData ? JSON.parse(globalIndexData) : [];

    const results: A2AAttestation[] = [];
    // Take the most recent `limit` entries
    for (const id of globalIds.slice(-limit).reverse()) {
      if (results.length >= limit) break;
      const result = await getCardAttestation(sessions, id);
      if (result.success && result.attestation) {
        if (!verifiedOnly || !result.attestation.revoked) {
          results.push(result.attestation);
        }
      }
    }

    return { success: true, attestations: results };
  } catch (error) {
    console.error('Failed to list A2A attestations:', error);
    return { success: false, error: 'Internal server error' };
  }
}

// ============ UTILITY ============

async function updateCardRegistryIndex(
  sessions: KVNamespace,
  agentUrl: string,
  attestationId: string,
  operation: 'add' | 'remove'
): Promise<void> {
  try {
    // Per-agent index
    const agentKey = `a2a_registry:${encodeURIComponent(agentUrl)}`;
    const agentData = await sessions.get(agentKey, 'text');
    let agentIds: string[] = agentData ? JSON.parse(agentData) : [];

    if (operation === 'add' && !agentIds.includes(attestationId)) {
      agentIds.push(attestationId);
    } else if (operation === 'remove') {
      agentIds = agentIds.filter(id => id !== attestationId);
    }
    await sessions.put(agentKey, JSON.stringify(agentIds));

    // Global index
    const globalKey = 'a2a_registry:global';
    const globalData = await sessions.get(globalKey, 'text');
    let globalIds: string[] = globalData ? JSON.parse(globalData) : [];

    if (operation === 'add' && !globalIds.includes(attestationId)) {
      globalIds.push(attestationId);
      // Keep global index bounded (last 1000)
      if (globalIds.length > 1000) {
        globalIds = globalIds.slice(-1000);
      }
    } else if (operation === 'remove') {
      globalIds = globalIds.filter(id => id !== attestationId);
    }
    await sessions.put(globalKey, JSON.stringify(globalIds));

  } catch (error) {
    console.error('Failed to update A2A card registry index:', error);
    // Fail silently — index updates are best-effort
  }
}

export default {
  getBotchaAgentCard,
  canonicalizeCard,
  hashCard,
  attestCard,
  verifyCard,
  getCardAttestation,
  listVerifiedCards,
};
