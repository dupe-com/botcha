/**
 * BOTCHA OIDC-A Attestation Module
 *
 * Implements OIDC-A (OpenID Connect for Agents) attestation:
 *   - EAT (Entity Attestation Token) issuance per draft-ietf-rats-eat-25
 *   - OIDC-A compatible claims per draft-aap-oauth-profile (Feb 2026)
 *   - OAuth 2.0 AS metadata discovery per RFC 8414
 *   - Agent Authorization Grant per draft-rosenberg-oauth-aauth
 *   - OIDC-A UserInfo endpoint
 *
 * EAT tokens make BOTCHA an `agent_attestation` endpoint that enterprise
 * auth servers embed in OpenID Connect for Agents token chains.
 */

import { SignJWT, jwtVerify, importJWK } from 'jose'
import type { KVNamespace } from './auth.js'
import type { ES256SigningKeyJWK } from './auth.js'
import { getSigningPublicKeyJWK } from './auth.js'

// ============ TYPES ============

/**
 * EAT (Entity Attestation Token) payload — draft-ietf-rats-eat-25
 *
 * JSON-encoded EAT as a JWT (JOSE-protected).
 * Claims follow Section 4 of draft-ietf-rats-eat-25:
 *   - iat, exp, iss, sub: standard JWT claims (reused by EAT)
 *   - eat_nonce: anti-replay nonce (Section 4.1)
 *   - eat_profile: URI identifying the EAT profile (Section 4.3.2)
 *   - ueid: Universal Entity ID (Section 4.2.1) — base64url(sha256(agent_id))
 *   - oemid: Hardware OEM ID (Section 4.2.3) — for software agents, this is vendor
 *   - swname: Software name (Section 4.2.6)
 *   - swversion: Software version (Section 4.2.7)
 *   - dbgstat: Debug status (Section 4.2.9)
 *   - intuse: Intended use (Section 4.3.3)
 *   - botcha_*: BOTCHA-specific private claims
 */
export interface EATPayload {
  // Standard JWT (reused by EAT)
  iss: string           // "botcha.ai"
  sub: string           // agent_id or challenge_id
  iat: number           // issued at (unix seconds)
  exp: number           // expiry (unix seconds)

  // EAT Standard Claims (Section 4)
  eat_profile: string   // URI for this EAT profile
  eat_nonce: string     // anti-replay nonce (base64url)
  ueid: string          // Universal Entity ID (base64url-encoded sha256 of sub)
  oemid: string         // OEM identifier — "botcha.ai" for software agents
  swname: string        // Software name — "BOTCHA"
  swversion: string     // Software version
  dbgstat: EATDebugStatus  // Debug status
  intuse: EATIntendedUse   // Intended use

  // BOTCHA private claims (Section 4 allows extension claims)
  botcha_verified: true
  botcha_challenge_id: string
  botcha_solve_time_ms: number
  botcha_app_id?: string
  botcha_verification_method: 'speed-challenge' | 'hybrid-challenge' | 'reasoning-challenge'
}

/**
 * EAT dbgstat values (Section 4.2.9 of draft-ietf-rats-eat-25)
 */
export type EATDebugStatus =
  | 'Enabled'
  | 'Disabled'
  | 'Disabled-Since-Boot'
  | 'Disabled-Permanently'
  | 'Disabled-Fully-And-Permanently'

/**
 * EAT intuse values (Section 4.3.3 of draft-ietf-rats-eat-25)
 */
export type EATIntendedUse =
  | 'generic'
  | 'registration'
  | 'provisioning'
  | 'csr'
  | 'pop'

/**
 * OIDC-A agent claims block — for embedding in enterprise ID tokens
 *
 * Based on:
 *   - draft-aap-oauth-profile Section 5 (JWT Claim Schema for Agents)
 *   - OIDC-A 1.0 agent extension claims
 *
 * Enterprise auth servers call /v1/attestation/oidc-agent-claims to enrich
 * ID tokens with these claims before issuing them to clients.
 */
export interface OIDCAgentClaims {
  // OIDC-A core claims
  agent_model: string            // AI model / system identifier
  agent_version?: string         // Agent version string
  agent_capabilities: string[]   // Declared capability set
  agent_attestation: string      // EAT JWT — the attestation token itself
  delegation_chain: string[]     // Ordered list of delegation JWTs (empty if none)

  // Agent identity (from AAP §5)
  agent_id: string               // Stable agent identifier
  agent_operator?: string        // Org/team operating this agent

  // Verification metadata
  agent_verification: {
    method: string               // how BOTCHA verified this agent
    solve_time_ms: number        // proof-of-computation time
    verified_at: string          // ISO 8601 datetime
    issuer: string               // "botcha.ai"
    challenge_id: string         // Challenge that was solved
  }

  // Oversight (AAP §5.2)
  human_oversight_required: boolean
  oversight_contact?: string     // URI or identifier for oversight contact

  // Task binding (AAP §5.2)
  task_id?: string               // If this claim is scoped to a task
  task_purpose?: string          // Human-readable task description

  // Token metadata
  iat: number
  exp: number
  iss: string
}

/**
 * Agent Grant result — output of POST /v1/auth/agent-grant
 *
 * Implements the "Agent Authorization Grant" from draft-rosenberg-oauth-aauth.
 * An agent presents its BOTCHA token and receives a scoped OAuth-style grant.
 */
export interface AgentGrantResult {
  grant_type: 'urn:ietf:params:oauth:grant-type:agent_authorization'
  access_token: string           // Scoped agent grant JWT
  token_type: 'Bearer'
  expires_in: number             // Seconds until expiry
  scope: string                  // Space-separated granted scopes
  agent_id: string
  app_id?: string

  // Human-in-the-loop fields
  human_oversight_required: boolean
  oversight_status: 'none' | 'pending' | 'approved' | 'denied'
  oversight_polling_url?: string // If pending, poll this URL

  // Embedded OIDC-A claims (the full claims block)
  agent_claims: OIDCAgentClaims

  // The EAT token embedded in the grant
  eat_token: string
}

/**
 * Stored grant state for HITL polling
 */
export interface PendingGrant {
  grant_id: string
  agent_id: string
  app_id?: string
  scope: string
  requested_at: number
  status: 'pending' | 'approved' | 'denied'
  approved_at?: number
  denied_at?: number
  denial_reason?: string
}

// ============ CONSTANTS ============

export const BOTCHA_EAT_PROFILE = 'https://botcha.ai/eat-profile/v1'
export const BOTCHA_ISSUER = 'botcha.ai'
export const EAT_TOKEN_TTL_SECONDS = 3600        // 1 hour
export const OIDC_CLAIMS_TTL_SECONDS = 3600      // 1 hour
export const AGENT_GRANT_TTL_SECONDS = 3600      // 1 hour

/**
 * Well-known BOTCHA agent capabilities
 * Enterprise auth servers can use these to filter agents by capability.
 */
export const BOTCHA_AGENT_CAPABILITIES = [
  'botcha:verified',              // Core — agent passed BOTCHA challenge
  'botcha:speed-challenge',       // Can solve SHA256 speed challenges
  'botcha:hybrid-challenge',      // Can solve hybrid (speed + reasoning) challenges
  'botcha:reasoning-challenge',   // Can solve LLM-level reasoning challenges
  'agent:autonomous',             // Can operate autonomously
  'agent:tool-use',               // Can invoke external tools/APIs
  'agent:multi-step',             // Can execute multi-step workflows
]

// ============ CORE FUNCTIONS ============

/**
 * Derive a Universal Entity ID (UEID) from an agent identifier.
 *
 * Per draft-ietf-rats-eat-25 §4.2.1: UEID is a binary identifier
 * unique to the entity. For software agents, we use SHA-256(agent_id)
 * truncated to 33 bytes, base64url-encoded.
 */
async function deriveUEID(agentId: string): Promise<string> {
  const encoder = new TextEncoder()
  const data = encoder.encode(agentId)
  const hashBuffer = await crypto.subtle.digest('SHA-256', data)
  const hashArray = new Uint8Array(hashBuffer).slice(0, 33) // 33 bytes per spec
  return btoa(String.fromCharCode(...hashArray))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '')
}

/**
 * Generate a cryptographically random nonce for eat_nonce.
 * Returns base64url-encoded 32 bytes.
 */
function generateEATNonce(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32))
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '')
}

/**
 * Issue an EAT (Entity Attestation Token) from a valid BOTCHA access token.
 *
 * The EAT proves:
 * 1. The agent solved a computational challenge (proving it is a bot)
 * 2. The challenge was issued by botcha.ai
 * 3. The solution time demonstrates AI-speed computation
 * 4. The agent is registered with a specific app
 *
 * This token can be embedded as `agent_attestation` in OIDC-A tokens.
 *
 * @param botchaPayload - Verified BOTCHA access token payload
 * @param signingKey - ES256 private key for signing (required for EAT)
 * @param options - Optional parameters
 * @returns Signed EAT JWT
 */
export async function issueEAT(
  botchaPayload: {
    sub: string
    iat: number
    exp: number
    jti: string
    type: 'botcha-verified'
    solveTime: number
    app_id?: string
    aud?: string
  },
  signingKey: ES256SigningKeyJWK,
  options?: {
    nonce?: string          // Client-provided nonce for freshness binding
    agentModel?: string     // Optional agent model claim
    ttlSeconds?: number     // Override default TTL
    verificationMethod?: 'speed-challenge' | 'hybrid-challenge' | 'reasoning-challenge'
  }
): Promise<string> {
  const now = Math.floor(Date.now() / 1000)
  const ttl = options?.ttlSeconds ?? EAT_TOKEN_TTL_SECONDS
  const agentId = botchaPayload.app_id
    ? `${botchaPayload.app_id}:${botchaPayload.sub}`
    : botchaPayload.sub

  const ueid = await deriveUEID(agentId)
  const eatNonce = options?.nonce ?? generateEATNonce()

  const eatPayload: EATPayload = {
    iss: BOTCHA_ISSUER,
    sub: agentId,
    iat: now,
    exp: now + ttl,

    // EAT standard claims
    eat_profile: BOTCHA_EAT_PROFILE,
    eat_nonce: eatNonce,
    ueid,
    oemid: BOTCHA_ISSUER,
    swname: 'BOTCHA',
    swversion: '0.21.0',
    dbgstat: 'Disabled',
    intuse: 'generic',

    // BOTCHA private claims
    botcha_verified: true,
    botcha_challenge_id: botchaPayload.sub,
    botcha_solve_time_ms: botchaPayload.solveTime,
    botcha_app_id: botchaPayload.app_id,
    botcha_verification_method: options?.verificationMethod ?? 'speed-challenge',
  }

  const cryptoKey = (await importJWK(signingKey, 'ES256')) as CryptoKey
  const kid = signingKey.kid || 'botcha-signing-1'

  const token = await new SignJWT(eatPayload as unknown as Record<string, unknown>)
    .setProtectedHeader({
      alg: 'ES256',
      kid,
      typ: 'JWT+EAT', // RFC 9334 recommends typ claim for EAT
    })
    .sign(cryptoKey)

  return token
}

/**
 * Build OIDC-A compatible agent claims block.
 *
 * This is the full claims object that enterprise auth servers embed in their
 * ID tokens for agent grants. It includes the EAT token as `agent_attestation`.
 *
 * @param botchaPayload - Verified BOTCHA access token payload
 * @param eatToken - Signed EAT JWT (from issueEAT)
 * @param signingKey - ES256 signing key
 * @param options - Agent metadata and OIDC-A options
 * @returns Signed OIDC-A claims JWT + plain claims object
 */
export async function buildOIDCAgentClaims(
  botchaPayload: {
    sub: string
    iat: number
    exp: number
    jti: string
    type: 'botcha-verified'
    solveTime: number
    app_id?: string
    aud?: string
  },
  eatToken: string,
  signingKey: ES256SigningKeyJWK,
  options?: {
    agentModel?: string
    agentVersion?: string
    agentCapabilities?: string[]
    agentOperator?: string
    delegationChain?: string[]
    humanOversightRequired?: boolean
    oversightContact?: string
    taskId?: string
    taskPurpose?: string
    scope?: string
    ttlSeconds?: number
    verificationMethod?: 'speed-challenge' | 'hybrid-challenge' | 'reasoning-challenge'
  }
): Promise<{ claims: OIDCAgentClaims; claimsJwt: string }> {
  const now = Math.floor(Date.now() / 1000)
  const ttl = options?.ttlSeconds ?? OIDC_CLAIMS_TTL_SECONDS

  const agentId = botchaPayload.app_id
    ? `${botchaPayload.app_id}:${botchaPayload.sub}`
    : botchaPayload.sub

  // Derive the BOTCHA verification method capability from the actual method used
  const verificationMethod = options?.verificationMethod ?? 'speed-challenge'
  const methodCapability = `botcha:${verificationMethod}`

  // Build the capability set: always include BOTCHA core + the actual method used
  const capabilities = [
    'botcha:verified',
    methodCapability,
    ...(options?.agentCapabilities ?? []).filter(c => c !== methodCapability),
  ]

  const claims: OIDCAgentClaims = {
    // OIDC-A core
    agent_model: options?.agentModel ?? 'botcha-verified-agent',
    agent_version: options?.agentVersion,
    agent_capabilities: capabilities,
    agent_attestation: eatToken,
    delegation_chain: options?.delegationChain ?? [],

    // Identity
    agent_id: agentId,
    agent_operator: options?.agentOperator,

    // Verification metadata — reflect the actual challenge type used
    agent_verification: {
      method: `botcha-${verificationMethod}`,
      solve_time_ms: botchaPayload.solveTime,
      verified_at: new Date(botchaPayload.iat * 1000).toISOString(),
      issuer: BOTCHA_ISSUER,
      challenge_id: botchaPayload.sub,
    },

    // Oversight
    human_oversight_required: options?.humanOversightRequired ?? false,
    oversight_contact: options?.oversightContact,

    // Task binding
    task_id: options?.taskId,
    task_purpose: options?.taskPurpose,

    // Token metadata
    iat: now,
    exp: now + ttl,
    iss: BOTCHA_ISSUER,
  }

  // Remove undefined fields for a clean JWT
  const cleanClaims = JSON.parse(JSON.stringify(claims))

  const cryptoKey = (await importJWK(signingKey, 'ES256')) as CryptoKey
  const kid = signingKey.kid || 'botcha-signing-1'

  const claimsJwt = await new SignJWT(cleanClaims)
    .setProtectedHeader({
      alg: 'ES256',
      kid,
      typ: 'JWT+OIDCA', // OIDC-A claims token type
    })
    .sign(cryptoKey)

  return { claims: cleanClaims, claimsJwt }
}

/**
 * Issue an Agent Authorization Grant.
 *
 * Implements draft-rosenberg-oauth-aauth "Agent Authorization Grant":
 * - Agent presents BOTCHA access token as credential
 * - Server issues a scoped grant JWT bound to the agent's identity
 * - Optionally queued for human-in-the-loop approval
 *
 * Grant token is a signed JWT with AAP claims (draft-aap-oauth-profile §5).
 *
 * @param botchaPayload - Verified BOTCHA access token payload
 * @param eatToken - EAT JWT from issueEAT
 * @param oidcClaims - OIDC-A claims object from buildOIDCAgentClaims
 * @param signingKey - ES256 signing key
 * @param kv - KV namespace for storing pending grants (for HITL polling)
 * @param options - Grant options
 * @returns AgentGrantResult
 */
export async function issueAgentGrant(
  botchaPayload: {
    sub: string
    iat: number
    exp: number
    jti: string
    type: 'botcha-verified'
    solveTime: number
    app_id?: string
  },
  eatToken: string,
  oidcClaims: OIDCAgentClaims,
  signingKey: ES256SigningKeyJWK,
  kv: KVNamespace,
  baseUrl: string,
  options?: {
    scope?: string
    humanOversightRequired?: boolean
    ttlSeconds?: number
    taskId?: string
    taskPurpose?: string
    constraints?: Record<string, unknown>
  }
): Promise<AgentGrantResult> {
  const now = Math.floor(Date.now() / 1000)
  const ttl = options?.ttlSeconds ?? AGENT_GRANT_TTL_SECONDS
  const scope = options?.scope ?? 'agent:read agent:attest openid'
  const humanOversight = options?.humanOversightRequired ?? false

  const agentId = botchaPayload.app_id
    ? `${botchaPayload.app_id}:${botchaPayload.sub}`
    : botchaPayload.sub

  // Generate grant ID for tracking
  const grantId = crypto.randomUUID()

  // AAP JWT payload (draft-aap-oauth-profile §5)
  const grantPayload: Record<string, unknown> = {
    // Standard JWT
    iss: BOTCHA_ISSUER,
    sub: agentId,
    iat: now,
    exp: now + ttl,
    jti: grantId,

    // OAuth grant type indicator
    grant_type: 'urn:ietf:params:oauth:grant-type:agent_authorization',

    // AAP §5.2 — Agent Identity Section
    agent: {
      id: agentId,
      model: oidcClaims.agent_model,
      version: oidcClaims.agent_version,
      operator: oidcClaims.agent_operator,
    },

    // AAP §5.2 — Capabilities Section
    capabilities: oidcClaims.agent_capabilities,
    scope,

    // AAP §5.2 — Attestation
    attestation: {
      eat_token: eatToken,
      issuer: BOTCHA_ISSUER,
      verified_at: oidcClaims.agent_verification.verified_at,
      method: oidcClaims.agent_verification.method,
    },

    // AAP §5.2 — Oversight
    oversight: {
      human_in_the_loop: humanOversight,
      status: humanOversight ? 'pending' : 'none',
      grant_id: grantId,
    },

    // AAP §5.2 — Task binding (if provided)
    ...(options?.taskId && {
      task: {
        id: options.taskId,
        purpose: options.taskPurpose,
      },
    }),

    // AAP §5.2 — Delegation chain
    delegation_chain: oidcClaims.delegation_chain,

    // AAP §5.2 — Contextual constraints
    ...(options?.constraints && { constraints: options.constraints }),

    // BOTCHA-specific: embed the full OIDC-A claims
    agent_claims_ref: agentId,
  }

  const cryptoKey = (await importJWK(signingKey, 'ES256')) as CryptoKey
  const kid = signingKey.kid || 'botcha-signing-1'

  const grantToken = await new SignJWT(grantPayload)
    .setProtectedHeader({ alg: 'ES256', kid, typ: 'JWT+AGENT-GRANT' })
    .sign(cryptoKey)

  // If HITL required, store the pending grant in KV for polling
  let oversightPollingUrl: string | undefined
  if (humanOversight) {
    const pendingGrant: PendingGrant = {
      grant_id: grantId,
      agent_id: agentId,
      app_id: botchaPayload.app_id,
      scope,
      requested_at: Date.now(),
      status: 'pending',
    }
    await kv.put(
      `agent_grant:${grantId}`,
      JSON.stringify(pendingGrant),
      { expirationTtl: ttl }
    )
    oversightPollingUrl = `${baseUrl}/v1/auth/agent-grant/${grantId}/status`
  }

  return {
    grant_type: 'urn:ietf:params:oauth:grant-type:agent_authorization',
    access_token: grantToken,
    token_type: 'Bearer',
    expires_in: ttl,
    scope,
    agent_id: agentId,
    app_id: botchaPayload.app_id,
    human_oversight_required: humanOversight,
    oversight_status: humanOversight ? 'pending' : 'none',
    oversight_polling_url: oversightPollingUrl,
    agent_claims: oidcClaims,
    eat_token: eatToken,
  }
}

/**
 * Build OAuth 2.0 Authorization Server metadata (RFC 8414).
 *
 * This makes BOTCHA discoverable as an OAuth AS by enterprise auth servers
 * that implement RFC 8414 auto-configuration.
 *
 * Extended with OIDC-A specific metadata for agent auth servers.
 */
export function buildOAuthASMetadata(baseUrl: string): object {
  return {
    // RFC 8414 §2 — Required
    issuer: baseUrl,

    // Token endpoint (agent grant flow)
    token_endpoint: `${baseUrl}/v1/auth/agent-grant`,

    // JWKS for signature verification
    jwks_uri: `${baseUrl}/.well-known/jwks`,

    // RFC 8414 §2 — Optional but widely expected
    scopes_supported: [
      'openid',
      'profile',
      'agent:read',
      'agent:write',
      'agent:attest',
      'agent:delegate',
      'agent:oversight',
    ],

    // Grant types — includes the AAP agent authorization grant
    grant_types_supported: [
      'urn:ietf:params:oauth:grant-type:agent_authorization',
      'urn:ietf:params:oauth:grant-type:token-exchange',
      'client_credentials',
    ],

    // Token endpoint auth methods
    token_endpoint_auth_methods_supported: [
      'botcha_token',         // BOTCHA-specific: Bearer token from challenge
      'private_key_jwt',      // RFC 7523 — for clients with registered keys
    ],

    // Response types (if acting as OIDC provider)
    response_types_supported: ['token', 'id_token', 'token id_token'],

    // Subject types
    subject_types_supported: ['public'],

    // ID token signing algorithms
    id_token_signing_alg_values_supported: ['ES256'],

    // Token lifetime
    access_token_lifetime: AGENT_GRANT_TTL_SECONDS,

    // ====== OIDC-A / BOTCHA Extensions ======

    // BOTCHA-specific agent attestation endpoint
    agent_attestation_endpoint: `${baseUrl}/v1/attestation/eat`,

    // OIDC-A enrichment endpoint for auth servers
    oidc_agent_claims_endpoint: `${baseUrl}/v1/attestation/oidc-agent-claims`,

    // UserInfo endpoint (OIDC-A compliant)
    userinfo_endpoint: `${baseUrl}/v1/oidc/userinfo`,

    // EAT profile URI
    eat_profile: BOTCHA_EAT_PROFILE,

    // Well-known agent capabilities this AS can attest
    agent_capabilities_supported: BOTCHA_AGENT_CAPABILITIES,

    // Verification methods BOTCHA uses
    agent_verification_methods_supported: [
      'botcha:speed-challenge',
      'botcha:hybrid-challenge',
      'botcha:reasoning-challenge',
    ],

    // Human oversight support
    human_oversight_supported: true,
    oversight_polling_endpoint: `${baseUrl}/v1/auth/agent-grant/{id}/status`,

    // draft-aap-oauth-profile compliance
    aap_version: 'draft-aap-oauth-profile-00',

    // OIDC-A compliance indicator
    oidca_supported: true,

    // Delegation chain support
    delegation_supported: true,
    max_delegation_depth: 5,

    // Integration metadata
    integration: {
      documentation: `${baseUrl}/docs`,
      openapi: `${baseUrl}/openapi.json`,
      ai_txt: `${baseUrl}/ai.txt`,
      whitepaper: `${baseUrl}/whitepaper`,
    },
  }
}

/**
 * Verify and decode a BOTCHA EAT token.
 * Used by the UserInfo endpoint to extract agent identity.
 *
 * @param eatJwt - The EAT JWT to verify
 * @param publicKey - ES256 public key JWK
 * @returns Verified EAT payload or null
 */
export async function verifyEAT(
  eatJwt: string,
  publicKey: object
): Promise<EATPayload | null> {
  try {
    const cryptoKey = (await importJWK(publicKey as any, 'ES256')) as CryptoKey
    const { payload } = await jwtVerify(eatJwt, cryptoKey, {
      algorithms: ['ES256'],
      issuer: BOTCHA_ISSUER,
    })

    // Validate required EAT claims
    if (!payload.eat_profile || !payload.eat_nonce || !payload.ueid) {
      return null
    }

    return payload as unknown as EATPayload
  } catch {
    return null
  }
}

/**
 * Poll the status of a pending human-in-the-loop grant.
 *
 * @param grantId - The grant ID to poll
 * @param kv - KV namespace
 * @returns Current grant status or null if not found
 */
export async function getGrantStatus(
  grantId: string,
  kv: KVNamespace
): Promise<PendingGrant | null> {
  try {
    const data = await kv.get(`agent_grant:${grantId}`)
    if (!data) return null
    return JSON.parse(data) as PendingGrant
  } catch {
    return null
  }
}

/**
 * Approve or deny a pending agent grant (admin action).
 *
 * @param grantId - The grant ID
 * @param decision - 'approved' or 'denied'
 * @param reason - Optional denial reason
 * @param kv - KV namespace
 */
export async function resolveGrant(
  grantId: string,
  decision: 'approved' | 'denied',
  reason: string | undefined,
  kv: KVNamespace
): Promise<{ success: boolean; grant?: PendingGrant; error?: string }> {
  const grant = await getGrantStatus(grantId, kv)
  if (!grant) {
    return { success: false, error: 'Grant not found or expired' }
  }
  if (grant.status !== 'pending') {
    return { success: false, error: `Grant is already ${grant.status}` }
  }

  const updated: PendingGrant = {
    ...grant,
    status: decision,
    approved_at: decision === 'approved' ? Date.now() : undefined,
    denied_at: decision === 'denied' ? Date.now() : undefined,
    denial_reason: decision === 'denied' ? reason : undefined,
  }

  // Preserve the original grant expiry rather than resetting to the full TTL.
  // requested_at is stored in ms; KV expirationTtl is in seconds.
  const elapsedSeconds = Math.floor((Date.now() - grant.requested_at) / 1000)
  const remainingTtl = Math.max(1, AGENT_GRANT_TTL_SECONDS - elapsedSeconds)

  await kv.put(`agent_grant:${grantId}`, JSON.stringify(updated), {
    expirationTtl: remainingTtl,
  })

  return { success: true, grant: updated }
}

export default {
  issueEAT,
  buildOIDCAgentClaims,
  issueAgentGrant,
  buildOAuthASMetadata,
  verifyEAT,
  getGrantStatus,
  resolveGrant,
}
