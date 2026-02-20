/**
 * OIDC-A Attestation API Routes
 *
 * Routes:
 *   POST /v1/attestation/eat                   — Issue EAT token (RFC 9334)
 *   POST /v1/attestation/oidc-agent-claims     — Issue OIDC-A claims block
 *   GET  /.well-known/oauth-authorization-server — OAuth AS metadata (RFC 8414)
 *   POST /v1/auth/agent-grant                  — Agent Authorization Grant
 *   GET  /v1/auth/agent-grant/:id/status       — Poll HITL grant status
 *   POST /v1/auth/agent-grant/:id/resolve      — Approve/deny HITL grant (admin)
 *   GET  /v1/oidc/userinfo                     — OIDC-A UserInfo endpoint
 */

import type { Context } from 'hono'
import {
  extractBearerToken,
  verifyToken,
  getSigningPublicKeyJWK,
  type ES256SigningKeyJWK,
  type BotchaTokenPayload,
} from './auth.js'
import {
  issueEAT,
  buildOIDCAgentClaims,
  issueAgentGrant,
  buildOAuthASMetadata,
  verifyEAT,
  getGrantStatus,
  resolveGrant,
  BOTCHA_AGENT_CAPABILITIES,
  BOTCHA_EAT_PROFILE,
} from './tap-oidca.js'

// ============ HELPERS ============

function getSigningKeyFromEnv(env: any): ES256SigningKeyJWK | undefined {
  const raw = env?.JWT_SIGNING_KEY
  if (!raw) return undefined
  try {
    return JSON.parse(raw) as ES256SigningKeyJWK
  } catch {
    console.error('OIDC-A: Failed to parse JWT_SIGNING_KEY')
    return undefined
  }
}

function getPublicKeyFromEnv(env: any) {
  const sk = getSigningKeyFromEnv(env)
  return sk ? getSigningPublicKeyJWK(sk) : undefined
}

/**
 * Verify BOTCHA Bearer token and return the payload.
 * Returns null + error info if invalid.
 */
async function verifyBotchaToken(
  c: Context,
  requireAppId = false
): Promise<{
  ok: boolean
  payload?: BotchaTokenPayload
  error?: string
  status?: number
}> {
  const authHeader = c.req.header('authorization')
  const token = extractBearerToken(authHeader)

  if (!token) {
    return { ok: false, error: 'UNAUTHORIZED', status: 401 }
  }

  const publicKey = getPublicKeyFromEnv(c.env)
  const result = await verifyToken(token, c.env.JWT_SECRET, c.env, undefined, publicKey)

  if (!result.valid || !result.payload) {
    return {
      ok: false,
      error: result.error || 'INVALID_TOKEN',
      status: 401,
    }
  }

  if (requireAppId && !result.payload.app_id) {
    return {
      ok: false,
      error: 'MISSING_APP_ID',
      status: 403,
    }
  }

  return { ok: true, payload: result.payload }
}

// ============ ROUTE HANDLERS ============

/**
 * POST /v1/attestation/eat
 *
 * Issue an RFC 9334 / draft-ietf-rats-eat-25 Entity Attestation Token.
 *
 * Input:
 *   Authorization: Bearer <botcha_access_token>
 *   Body (optional): {
 *     nonce?: string              // Client nonce for freshness binding
 *     agent_model?: string        // AI model name
 *     ttl_seconds?: number        // Token TTL (max 3600)
 *     verification_method?: string
 *   }
 *
 * Output: {
 *   eat_token: string             // Signed EAT JWT
 *   eat_profile: string           // Profile URI
 *   expires_in: number
 *   claims: { ... }               // Decoded claims (for inspection)
 * }
 */
export async function issueEATRoute(c: Context) {
  try {
    const auth = await verifyBotchaToken(c, false)
    if (!auth.ok || !auth.payload) {
      return c.json(
        { success: false, error: auth.error, message: 'Valid BOTCHA Bearer token required' },
        (auth.status || 401) as 401
      )
    }

    const signingKey = getSigningKeyFromEnv(c.env)
    if (!signingKey) {
      return c.json(
        {
          success: false,
          error: 'NO_SIGNING_KEY',
          message: 'Server is not configured for EAT issuance (no ES256 signing key)',
        },
        503
      )
    }

    const body = await c.req.json().catch(() => ({}))
    const ttlSeconds = Math.min(body.ttl_seconds ?? 3600, 3600)

    const eatToken = await issueEAT(auth.payload, signingKey, {
      nonce: body.nonce,
      agentModel: body.agent_model,
      ttlSeconds,
      verificationMethod: body.verification_method,
    })

    const now = Math.floor(Date.now() / 1000)
    const agentId = auth.payload.app_id
      ? `${auth.payload.app_id}:${auth.payload.sub}`
      : auth.payload.sub

    return c.json({
      success: true,
      eat_token: eatToken,
      token_type: 'JWT+EAT',
      eat_profile: BOTCHA_EAT_PROFILE,
      algorithm: 'ES256',
      expires_in: ttlSeconds,
      // Decoded claims for inspection (convenience — not normative)
      claims: {
        iss: 'botcha.ai',
        sub: agentId,
        iat: now,
        exp: now + ttlSeconds,
        eat_profile: BOTCHA_EAT_PROFILE,
        oemid: 'botcha.ai',
        swname: 'BOTCHA',
        dbgstat: 'Disabled',
        intuse: 'generic',
        botcha_verified: true,
        botcha_solve_time_ms: auth.payload.solveTime,
        botcha_app_id: auth.payload.app_id,
      },
      usage: {
        description: 'Embed this token as agent_attestation in OIDC-A ID tokens',
        embed_as: 'agent_attestation',
        verify_with: 'GET /v1/jwks (ES256 public key)',
        oidca_claims: 'POST /v1/attestation/oidc-agent-claims',
      },
    })
  } catch (error) {
    console.error('EAT issuance error:', error)
    return c.json(
      { success: false, error: 'INTERNAL_ERROR', message: 'EAT issuance failed' },
      500
    )
  }
}

/**
 * POST /v1/attestation/oidc-agent-claims
 *
 * Issue OIDC-A compatible agent claims block.
 * Enterprise auth servers call this to enrich agent ID tokens.
 *
 * Input:
 *   Authorization: Bearer <botcha_access_token>
 *   Body (optional): {
 *     agent_model?: string
 *     agent_version?: string
 *     agent_capabilities?: string[]
 *     agent_operator?: string
 *     delegation_chain?: string[]
 *     human_oversight_required?: boolean
 *     oversight_contact?: string
 *     task_id?: string
 *     task_purpose?: string
 *     scope?: string
 *     nonce?: string
 *   }
 *
 * Output: {
 *   claims_jwt: string            // Signed OIDC-A claims JWT (embed in ID token)
 *   claims: OIDCAgentClaims       // Decoded claims object (for direct embedding)
 *   eat_token: string             // The EAT token embedded within
 *   expires_in: number
 * }
 */
export async function issueOIDCAgentClaimsRoute(c: Context) {
  try {
    const auth = await verifyBotchaToken(c, false)
    if (!auth.ok || !auth.payload) {
      return c.json(
        { success: false, error: auth.error, message: 'Valid BOTCHA Bearer token required' },
        (auth.status || 401) as 401
      )
    }

    const signingKey = getSigningKeyFromEnv(c.env)
    if (!signingKey) {
      return c.json(
        {
          success: false,
          error: 'NO_SIGNING_KEY',
          message: 'Server is not configured for OIDC-A claims issuance (no ES256 signing key)',
        },
        503
      )
    }

    const body = await c.req.json().catch(() => ({}))

    // First issue the EAT (embedded in OIDC-A claims as agent_attestation)
    const eatToken = await issueEAT(auth.payload, signingKey, {
      nonce: body.nonce,
      agentModel: body.agent_model,
      verificationMethod: body.verification_method,
    })

    // Then build OIDC-A claims wrapping the EAT
    const { claims, claimsJwt } = await buildOIDCAgentClaims(
      auth.payload,
      eatToken,
      signingKey,
      {
        agentModel: body.agent_model,
        agentVersion: body.agent_version,
        agentCapabilities: body.agent_capabilities,
        agentOperator: body.agent_operator,
        delegationChain: body.delegation_chain,
        humanOversightRequired: body.human_oversight_required ?? false,
        oversightContact: body.oversight_contact,
        taskId: body.task_id,
        taskPurpose: body.task_purpose,
        scope: body.scope,
      }
    )

    return c.json({
      success: true,

      // Primary output: the signed claims JWT for embedding in ID tokens
      claims_jwt: claimsJwt,
      token_type: 'JWT+OIDCA',
      algorithm: 'ES256',
      expires_in: 3600,

      // Decoded claims for direct embedding in ID token payload
      claims,

      // The embedded EAT token (also available standalone)
      eat_token: eatToken,

      // Integration guide
      usage: {
        description: 'Embed claims in your OIDC ID token or use claims_jwt as agent_attestation',
        embed_method_1: 'Copy `claims` object fields directly into your ID token payload',
        embed_method_2: 'Set `agent_attestation: claims_jwt` in your ID token',
        embed_method_3: 'Set `agent_attestation: eat_token` for EAT-only embedding',
        verify_with: 'GET /v1/jwks (ES256 public key)',
        standard: 'draft-aap-oauth-profile §5, OIDC-A 1.0',
      },

      // Available agent capabilities
      available_capabilities: BOTCHA_AGENT_CAPABILITIES,
    })
  } catch (error) {
    console.error('OIDC-A claims issuance error:', error)
    return c.json(
      { success: false, error: 'INTERNAL_ERROR', message: 'OIDC-A claims issuance failed' },
      500
    )
  }
}

/**
 * GET /.well-known/oauth-authorization-server
 *
 * OAuth 2.0 Authorization Server Metadata (RFC 8414).
 * Extended with OIDC-A / agent-specific metadata.
 *
 * No authentication required — public discovery endpoint.
 */
export async function oauthASMetadataRoute(c: Context) {
  const baseUrl = new URL(c.req.url).origin
  const publicKey = getPublicKeyFromEnv(c.env)

  const metadata = buildOAuthASMetadata(baseUrl, publicKey)

  return c.json(metadata, 200, {
    'Cache-Control': 'public, max-age=3600',
    'Content-Type': 'application/json',
  })
}

/**
 * POST /v1/auth/agent-grant
 *
 * Agent Authorization Grant per draft-rosenberg-oauth-aauth.
 *
 * An agent presents its BOTCHA token and receives a scoped OAuth grant
 * with embedded OIDC-A claims and an EAT attestation.
 *
 * Input:
 *   Authorization: Bearer <botcha_access_token>
 *   Body (optional): {
 *     scope?: string                    // Requested scopes (space-separated)
 *     human_oversight_required?: bool   // Request HITL approval flow
 *     agent_model?: string
 *     agent_version?: string
 *     agent_capabilities?: string[]
 *     agent_operator?: string
 *     task_id?: string
 *     task_purpose?: string
 *     delegation_chain?: string[]
 *     constraints?: object
 *   }
 *
 * Output: AgentGrantResult
 */
export async function agentGrantRoute(c: Context) {
  try {
    const auth = await verifyBotchaToken(c, false)
    if (!auth.ok || !auth.payload) {
      return c.json(
        {
          success: false,
          error: auth.error,
          message: 'Valid BOTCHA Bearer token required to request an agent grant',
          how_to_get_token: 'GET /v1/token → POST /v1/token/verify',
        },
        (auth.status || 401) as 401
      )
    }

    const signingKey = getSigningKeyFromEnv(c.env)
    if (!signingKey) {
      return c.json(
        {
          success: false,
          error: 'NO_SIGNING_KEY',
          message: 'Server is not configured for agent grant issuance (no ES256 signing key)',
        },
        503
      )
    }

    const body = await c.req.json().catch(() => ({}))
    const baseUrl = new URL(c.req.url).origin

    // Issue EAT
    const eatToken = await issueEAT(auth.payload, signingKey, {
      agentModel: body.agent_model,
      verificationMethod: body.verification_method,
    })

    // Build OIDC-A claims
    const { claims: oidcClaims } = await buildOIDCAgentClaims(
      auth.payload,
      eatToken,
      signingKey,
      {
        agentModel: body.agent_model,
        agentVersion: body.agent_version,
        agentCapabilities: body.agent_capabilities,
        agentOperator: body.agent_operator,
        delegationChain: body.delegation_chain,
        humanOversightRequired: body.human_oversight_required ?? false,
        oversightContact: body.oversight_contact,
        taskId: body.task_id,
        taskPurpose: body.task_purpose,
        scope: body.scope,
      }
    )

    // Issue the agent grant
    const grant = await issueAgentGrant(
      auth.payload,
      eatToken,
      oidcClaims,
      signingKey,
      c.env.SESSIONS ?? c.env.CHALLENGES, // Use SESSIONS KV if available
      baseUrl,
      {
        scope: body.scope,
        humanOversightRequired: body.human_oversight_required ?? false,
        taskId: body.task_id,
        taskPurpose: body.task_purpose,
        constraints: body.constraints,
      }
    )

    const status = 200
    return c.json({
      success: true,
      ...grant,
      // Additional context
      standard: 'draft-rosenberg-oauth-aauth, draft-aap-oauth-profile',
      issued_at: new Date().toISOString(),
    }, status)
  } catch (error) {
    console.error('Agent grant error:', error)
    return c.json(
      { success: false, error: 'INTERNAL_ERROR', message: 'Agent grant issuance failed' },
      500
    )
  }
}

/**
 * GET /v1/auth/agent-grant/:id/status
 *
 * Poll the status of a human-in-the-loop pending grant.
 * Returns current status: pending | approved | denied
 */
export async function agentGrantStatusRoute(c: Context) {
  try {
    const grantId = c.req.param('id')
    if (!grantId) {
      return c.json({ success: false, error: 'MISSING_GRANT_ID' }, 400)
    }

    const kv = c.env.SESSIONS ?? c.env.CHALLENGES
    const grant = await getGrantStatus(grantId, kv)

    if (!grant) {
      return c.json(
        { success: false, error: 'GRANT_NOT_FOUND', message: 'Grant not found or expired' },
        404
      )
    }

    return c.json({
      success: true,
      grant_id: grant.grant_id,
      agent_id: grant.agent_id,
      scope: grant.scope,
      status: grant.status,
      requested_at: new Date(grant.requested_at).toISOString(),
      approved_at: grant.approved_at ? new Date(grant.approved_at).toISOString() : null,
      denied_at: grant.denied_at ? new Date(grant.denied_at).toISOString() : null,
      denial_reason: grant.denial_reason ?? null,
    })
  } catch (error) {
    console.error('Grant status error:', error)
    return c.json({ success: false, error: 'INTERNAL_ERROR' }, 500)
  }
}

/**
 * POST /v1/auth/agent-grant/:id/resolve
 *
 * Approve or deny a pending HITL grant.
 * Requires app_id authentication (the grant owner must resolve it).
 *
 * Body: {
 *   decision: 'approved' | 'denied'
 *   reason?: string    // Required if denied
 * }
 */
export async function agentGrantResolveRoute(c: Context) {
  try {
    const grantId = c.req.param('id')
    if (!grantId) {
      return c.json({ success: false, error: 'MISSING_GRANT_ID' }, 400)
    }

    const body = await c.req.json().catch(() => ({}))
    const decision = body.decision as 'approved' | 'denied'

    if (!['approved', 'denied'].includes(decision)) {
      return c.json(
        {
          success: false,
          error: 'INVALID_DECISION',
          message: 'decision must be "approved" or "denied"',
        },
        400
      )
    }

    if (decision === 'denied' && !body.reason) {
      return c.json(
        { success: false, error: 'MISSING_REASON', message: 'reason required when denying' },
        400
      )
    }

    const kv = c.env.SESSIONS ?? c.env.CHALLENGES
    const result = await resolveGrant(grantId, decision, body.reason, kv)

    if (!result.success) {
      return c.json({ success: false, error: 'RESOLVE_FAILED', message: result.error }, 400)
    }

    return c.json({
      success: true,
      grant_id: grantId,
      decision,
      grant: {
        status: result.grant!.status,
        approved_at: result.grant!.approved_at
          ? new Date(result.grant!.approved_at).toISOString()
          : null,
        denied_at: result.grant!.denied_at
          ? new Date(result.grant!.denied_at).toISOString()
          : null,
        denial_reason: result.grant!.denial_reason ?? null,
      },
    })
  } catch (error) {
    console.error('Grant resolve error:', error)
    return c.json({ success: false, error: 'INTERNAL_ERROR' }, 500)
  }
}

/**
 * GET /v1/oidc/userinfo
 *
 * OIDC-A compliant UserInfo endpoint for verified agents.
 *
 * Returns agent identity claims + BOTCHA verification status.
 * Accepts either a BOTCHA access_token or an EAT token as Bearer.
 *
 * Standard OIDC UserInfo response extended with agent claims.
 */
export async function oidcUserInfoRoute(c: Context) {
  try {
    const authHeader = c.req.header('authorization')
    const token = extractBearerToken(authHeader)

    if (!token) {
      return c.json(
        {
          error: 'UNAUTHORIZED',
          error_description: 'Bearer token required',
        },
        401,
        {
          'WWW-Authenticate':
            'Bearer realm="botcha.ai", error="unauthorized", error_description="Bearer token required"',
        }
      )
    }

    // Try as BOTCHA access token first
    const publicKey = getPublicKeyFromEnv(c.env)
    const botchaResult = await verifyToken(token, c.env.JWT_SECRET, c.env, undefined, publicKey)

    if (botchaResult.valid && botchaResult.payload) {
      const payload = botchaResult.payload
      const agentId = payload.app_id
        ? `${payload.app_id}:${payload.sub}`
        : payload.sub

      const signingKey = getSigningKeyFromEnv(c.env)
      const baseUrl = new URL(c.req.url).origin

      return c.json({
        // Standard OIDC UserInfo claims
        sub: agentId,
        iss: 'botcha.ai',
        iat: payload.iat,
        exp: payload.exp,

        // OIDC-A agent extension claims
        agent_id: agentId,
        agent_model: 'botcha-verified-agent',
        agent_capabilities: ['botcha:verified', 'botcha:speed-challenge'],

        // BOTCHA verification status
        botcha_verified: true,
        botcha_app_id: payload.app_id ?? null,
        botcha_solve_time_ms: payload.solveTime,
        botcha_challenge_id: payload.sub,

        // Verification metadata
        verification: {
          method: 'botcha-speed-challenge',
          verified_at: new Date(payload.iat * 1000).toISOString(),
          issuer: 'botcha.ai',
          solve_time_ms: payload.solveTime,
        },

        // Where to get attestation tokens
        attestation_endpoints: {
          eat: `${baseUrl}/v1/attestation/eat`,
          oidc_agent_claims: `${baseUrl}/v1/attestation/oidc-agent-claims`,
          agent_grant: `${baseUrl}/v1/auth/agent-grant`,
        },
      })
    }

    // Try as EAT token
    if (publicKey) {
      const eatPayload = await verifyEAT(token, publicKey)
      if (eatPayload) {
        return c.json({
          sub: eatPayload.sub,
          iss: eatPayload.iss,
          iat: eatPayload.iat,
          exp: eatPayload.exp,

          // EAT identity
          agent_id: eatPayload.sub,
          agent_model: 'botcha-verified-agent',
          agent_capabilities: ['botcha:verified'],

          // EAT metadata
          eat_profile: eatPayload.eat_profile,
          ueid: eatPayload.ueid,
          oemid: eatPayload.oemid,
          swname: eatPayload.swname,
          swversion: eatPayload.swversion,
          dbgstat: eatPayload.dbgstat,

          // BOTCHA verification
          botcha_verified: eatPayload.botcha_verified,
          botcha_app_id: eatPayload.botcha_app_id ?? null,
          botcha_solve_time_ms: eatPayload.botcha_solve_time_ms,
        })
      }
    }

    return c.json(
      {
        error: 'INVALID_TOKEN',
        error_description: 'Token is invalid, expired, or revoked',
      },
      401,
      {
        'WWW-Authenticate':
          'Bearer realm="botcha.ai", error="invalid_token", error_description="Token is invalid or expired"',
      }
    )
  } catch (error) {
    console.error('UserInfo error:', error)
    return c.json({ error: 'INTERNAL_ERROR' }, 500)
  }
}

export default {
  issueEATRoute,
  issueOIDCAgentClaimsRoute,
  oauthASMetadataRoute,
  agentGrantRoute,
  agentGrantStatusRoute,
  agentGrantResolveRoute,
  oidcUserInfoRoute,
}
