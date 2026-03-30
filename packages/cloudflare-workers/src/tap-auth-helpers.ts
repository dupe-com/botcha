/**
 * Shared TAP Authentication Helpers
 *
 * Centralised validateTAPAppAccess replaces the copy-pasted
 * validateAppAccess functions that previously lived in each TAP route file.
 *
 * Key fix: accepts BOTH 'botcha-verified' (fresh challenge tokens) AND
 * 'botcha-agent-identity' (OAuth refresh tokens) so agents can call TAP
 * endpoints with their persistent identity token without re-solving a
 * BOTCHA challenge on every request.
 */

import type { Context } from 'hono'
import {
  extractBearerToken,
  verifyToken,
  getSigningPublicKeyJWK,
  type ES256SigningKeyJWK,
  type BotchaTokenPayload,
} from './auth.js'

/** Token types accepted by all TAP endpoints */
export const TAP_ALLOWED_TOKEN_TYPES = ['botcha-verified', 'botcha-agent-identity']

export interface TAPAppAccessResult {
  valid: boolean
  appId?: string
  agentId?: string
  tokenType?: string
  error?: string
  status?: number
}

function getVerificationPublicKey(env: any) {
  const rawSigningKey = env?.JWT_SIGNING_KEY
  if (!rawSigningKey) return undefined

  try {
    const signingKey = JSON.parse(rawSigningKey) as ES256SigningKeyJWK
    return getSigningPublicKeyJWK(signingKey)
  } catch {
    console.error('tap-auth-helpers: Failed to parse JWT_SIGNING_KEY')
    return undefined
  }
}

/**
 * Validate that the request carries a valid BOTCHA token (challenge-verified
 * OR agent-identity) and that its app_id matches any app_id supplied in the
 * query string / request body.
 *
 * @param c           Hono context
 * @param requireAuth If false, missing auth is allowed (returns valid:true with
 *                    only the querystring app_id).  Defaults to true.
 */
export async function validateTAPAppAccess(
  c: Context,
  requireAuth: boolean = true
): Promise<TAPAppAccessResult> {
  const queryAppId = c.req.query('app_id')
  const authHeader = c.req.header('authorization')
  const token = extractBearerToken(authHeader)

  if (!token) {
    if (!requireAuth) {
      return { valid: true, appId: queryAppId }
    }
    return { valid: false, error: 'UNAUTHORIZED', status: 401 }
  }

  const publicKey = getVerificationPublicKey(c.env)
  const result = await verifyToken(
    token,
    c.env.JWT_SECRET,
    c.env,
    { allowedTypes: TAP_ALLOWED_TOKEN_TYPES },
    publicKey
  )

  if (!result.valid || !result.payload) {
    return { valid: false, error: 'INVALID_TOKEN', status: 401 }
  }

  const payload = result.payload as BotchaTokenPayload
  const jwtAppId = payload.app_id

  if (!jwtAppId) {
    return { valid: false, error: 'MISSING_APP_ID', status: 403 }
  }

  if (queryAppId && queryAppId !== jwtAppId) {
    return { valid: false, error: 'APP_ID_MISMATCH', status: 403 }
  }

  return {
    valid: true,
    appId: jwtAppId,
    agentId: payload.agent_id,
    tokenType: payload.type,
  }
}
