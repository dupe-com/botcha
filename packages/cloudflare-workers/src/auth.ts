/**
 * BOTCHA Authentication & JWT Token Management
 *
 * Token-based auth flow with security features:
 * - JTI (JWT ID) for revocation
 * - Audience claims for API scoping
 * - Client IP binding for additional security
 * - Short-lived access tokens (1 hour) with refresh tokens (1 hour)
 * - Token revocation via KV storage
 */

import { SignJWT, jwtVerify, importJWK, decodeProtectedHeader } from 'jose'

/**
 * KV namespace interface (Cloudflare Workers)
 */
export interface KVNamespace {
  get(key: string): Promise<string | null>
  put(
    key: string,
    value: string,
    options?: { expirationTtl?: number }
  ): Promise<void>
  delete(key: string): Promise<void>
}

/**
 * JWT payload structure for access tokens
 */
export interface BotchaTokenPayload {
  sub: string // challenge ID that was solved
  iat: number // issued at
  exp: number // expires at
  jti: string // JWT ID for revocation
  type: 'botcha-verified'
  solveTime: number // how fast they solved it (ms)
  aud?: string // optional audience claim
  client_ip?: string // optional client IP binding
  app_id?: string // optional app ID (multi-tenant)
}

/**
 * JWT payload structure for refresh tokens
 */
export interface BotchaRefreshTokenPayload {
  sub: string // challenge ID that was solved
  iat: number // issued at
  exp: number // expires at
  jti: string // JWT ID for revocation
  type: 'botcha-refresh'
  solveTime: number // how fast they solved it (ms)
  app_id?: string // optional app ID (multi-tenant)
}

/**
 * Token creation result
 */
export interface TokenCreationResult {
  access_token: string
  expires_in: number // seconds
  refresh_token: string
  refresh_expires_in: number // seconds
}

/**
 * Token generation options
 */
export interface TokenGenerationOptions {
  aud?: string // optional audience claim
  clientIp?: string // optional client IP for binding
  app_id?: string // optional app ID (multi-tenant)
}

/**
 * ES256 private key in JWK format
 * { kty: "EC", crv: "P-256", x: "...", y: "...", d: "..." }
 */
export interface ES256SigningKeyJWK {
  kty: string
  crv: string
  x: string
  y: string
  d: string // private key parameter
  kid?: string
}

/**
 * Derive the public key JWK from an ES256 private key JWK.
 * Strips the `d` (private) parameter and sets standard fields.
 * Used by the JWKS endpoint to publish the signing key.
 */
export function getSigningPublicKeyJWK(
  privateKeyJwk: ES256SigningKeyJWK
): Omit<ES256SigningKeyJWK, 'd'> & { kid: string; use: string; alg: string } {
  const { d: _d, ...publicKey } = privateKeyJwk
  return {
    ...publicKey,
    kid: privateKeyJwk.kid || 'botcha-signing-1',
    use: 'sig',
    alg: 'ES256',
  }
}

/**
 * Generate JWT tokens (access + refresh) after successful challenge verification
 *
 * Access token: 1 hour, used for API access
 * Refresh token: 1 hour, used to get new access tokens without re-solving challenges
 *
 * When signingKey (ES256 JWK) is provided, tokens are signed with ES256.
 * Otherwise falls back to HS256 with the shared secret (backward compat).
 */
export async function generateToken(
  challengeId: string,
  solveTimeMs: number,
  secret: string,
  env?: { CHALLENGES: KVNamespace },
  options?: TokenGenerationOptions,
  signingKey?: ES256SigningKeyJWK
): Promise<TokenCreationResult> {
  // Determine signing algorithm and key
  let signKey: CryptoKey | Uint8Array
  let protectedHeader: { alg: string; kid?: string }

  if (signingKey) {
    // ES256 asymmetric signing
    signKey = (await importJWK(signingKey, 'ES256')) as CryptoKey
    protectedHeader = {
      alg: 'ES256',
      kid: signingKey.kid || 'botcha-signing-1',
    }
  } else {
    // HS256 symmetric signing (legacy fallback)
    signKey = new TextEncoder().encode(secret)
    protectedHeader = { alg: 'HS256' }
  }

  // Generate unique JTIs for both tokens
  const accessJti = crypto.randomUUID()
  const refreshJti = crypto.randomUUID()

  // Access token: 1 hour
  const accessTokenPayload: Record<string, any> = {
    type: 'botcha-verified',
    solveTime: solveTimeMs,
    jti: accessJti,
  }

  // Add optional claims
  if (options?.aud) {
    accessTokenPayload.aud = options.aud
  }
  if (options?.clientIp) {
    accessTokenPayload.client_ip = options.clientIp
  }
  if (options?.app_id) {
    accessTokenPayload.app_id = options.app_id
  }

  const accessToken = await new SignJWT(accessTokenPayload)
    .setProtectedHeader(protectedHeader)
    .setSubject(challengeId)
    .setIssuer('botcha.ai')
    .setIssuedAt()
    .setExpirationTime('1h') // 1 hour
    .sign(signKey)

  // Refresh token: 1 hour
  const refreshTokenPayload: Record<string, any> = {
    type: 'botcha-refresh',
    solveTime: solveTimeMs,
    jti: refreshJti,
  }

  // Include app_id in refresh token if provided
  if (options?.app_id) {
    refreshTokenPayload.app_id = options.app_id
  }

  const refreshToken = await new SignJWT(refreshTokenPayload)
    .setProtectedHeader(protectedHeader)
    .setSubject(challengeId)
    .setIssuer('botcha.ai')
    .setIssuedAt()
    .setExpirationTime('1h') // 1 hour
    .sign(signKey)

  // Store refresh token JTI in KV if env provided (for revocation tracking)
  // Also store aud, client_ip, and app_id so they carry over on refresh
  if (env?.CHALLENGES) {
    try {
      const refreshData: Record<string, any> = {
        sub: challengeId,
        iat: Date.now(),
      }
      if (options?.aud) {
        refreshData.aud = options.aud
      }
      if (options?.clientIp) {
        refreshData.client_ip = options.clientIp
      }
      if (options?.app_id) {
        refreshData.app_id = options.app_id
      }
      await env.CHALLENGES.put(
        `refresh:${refreshJti}`,
        JSON.stringify(refreshData),
        { expirationTtl: 3600 } // 1 hour TTL
      )
    } catch (error) {
      // Fail-open: continue even if KV storage fails
      console.error('Failed to store refresh token in KV:', error)
    }
  }

  return {
    access_token: accessToken,
    expires_in: 3600, // 1 hour in seconds
    refresh_token: refreshToken,
    refresh_expires_in: 3600, // 1 hour in seconds
  }
}

/**
 * Revoke a token by its JTI
 *
 * Stores the JTI in the revocation list (KV) with 1 hour TTL
 */
export async function revokeToken(
  jti: string,
  env: { CHALLENGES: KVNamespace }
): Promise<void> {
  try {
    await env.CHALLENGES.put(
      `revoked:${jti}`,
      JSON.stringify({ revokedAt: Date.now() }),
      { expirationTtl: 3600 } // 1 hour TTL (matches max token lifetime)
    )
  } catch (error) {
    throw new Error(
      `Failed to revoke token: ${error instanceof Error ? error.message : 'Unknown error'}`
    )
  }
}

/**
 * Refresh an access token using a valid refresh token
 *
 * Verifies the refresh token, checks revocation, and issues a new access token.
 * Supports both ES256 (asymmetric) and HS256 (symmetric) refresh tokens.
 */
export async function refreshAccessToken(
  refreshToken: string,
  env: { CHALLENGES: KVNamespace },
  secret: string,
  options?: TokenGenerationOptions,
  signingKey?: ES256SigningKeyJWK,
  publicKey?: {
    kty: string
    crv: string
    x: string
    y: string
    kid?: string
    use?: string
    alg?: string
  }
): Promise<{
  success: boolean
  tokens?: Omit<TokenCreationResult, 'refresh_token' | 'refresh_expires_in'> & {
    access_token: string
    expires_in: number
  }
  error?: string
}> {
  try {
    // Detect algorithm from token header and verify accordingly
    const header = decodeProtectedHeader(refreshToken)
    let verifyKey: CryptoKey | Uint8Array
    let algorithms: string[]

    if (header.alg === 'ES256' && publicKey) {
      verifyKey = (await importJWK(publicKey, 'ES256')) as CryptoKey
      algorithms = ['ES256']
    } else {
      verifyKey = new TextEncoder().encode(secret)
      algorithms = ['HS256']
    }

    // Verify refresh token
    const { payload } = await jwtVerify(refreshToken, verifyKey, {
      algorithms,
    })

    // Check token type
    if (payload.type !== 'botcha-refresh') {
      return {
        success: false,
        error: 'Invalid token type. Expected refresh token.',
      }
    }

    const jti = payload.jti as string

    // Check if token is revoked
    if (jti) {
      try {
        const revoked = await env.CHALLENGES.get(`revoked:${jti}`)
        if (revoked) {
          return {
            success: false,
            error: 'Refresh token has been revoked',
          }
        }
      } catch (error) {
        // Fail-open: if KV check fails, allow token to proceed
        console.error('Failed to check revocation status:', error)
      }
    }

    // Check if refresh token exists in KV and retrieve stored claims (aud, client_ip, app_id)
    let storedAud: string | undefined
    let storedClientIp: string | undefined
    let storedAppId: string | undefined
    if (jti) {
      try {
        const storedToken = await env.CHALLENGES.get(`refresh:${jti}`)
        if (!storedToken) {
          return {
            success: false,
            error: 'Refresh token not found or expired',
          }
        }
        // Extract stored claims to carry over to new access token
        try {
          const storedData = JSON.parse(storedToken)
          storedAud = storedData.aud
          storedClientIp = storedData.client_ip
          storedAppId = storedData.app_id
        } catch {
          // Ignore parse errors on legacy KV entries
        }
      } catch (error) {
        // Fail-open: if KV check fails, allow token to proceed
        console.error('Failed to verify refresh token in KV:', error)
      }
    }

    // Determine signing algorithm and key for the new access token
    let signKey: CryptoKey | Uint8Array
    let protectedHeaderObj: { alg: string; kid?: string }

    if (signingKey) {
      signKey = (await importJWK(signingKey, 'ES256')) as CryptoKey
      protectedHeaderObj = {
        alg: 'ES256',
        kid: signingKey.kid || 'botcha-signing-1',
      }
    } else {
      signKey = new TextEncoder().encode(secret)
      protectedHeaderObj = { alg: 'HS256' }
    }

    // Generate new access token
    const newAccessJti = crypto.randomUUID()
    const accessTokenPayload: Record<string, any> = {
      type: 'botcha-verified',
      solveTime: payload.solveTime,
      jti: newAccessJti,
    }

    // Carry over claims: prefer explicit options, fall back to stored KV values
    const effectiveAud = options?.aud || storedAud
    const effectiveClientIp = options?.clientIp || storedClientIp
    const effectiveAppId =
      options?.app_id || storedAppId || (payload.app_id as string | undefined)
    if (effectiveAud) {
      accessTokenPayload.aud = effectiveAud
    }
    if (effectiveClientIp) {
      accessTokenPayload.client_ip = effectiveClientIp
    }
    if (effectiveAppId) {
      accessTokenPayload.app_id = effectiveAppId
    }

    const accessToken = await new SignJWT(accessTokenPayload)
      .setProtectedHeader(protectedHeaderObj)
      .setSubject(payload.sub || '')
      .setIssuer('botcha.ai')
      .setIssuedAt()
      .setExpirationTime('1h') // 1 hour
      .sign(signKey)

    return {
      success: true,
      tokens: {
        access_token: accessToken,
        expires_in: 3600, // 1 hour in seconds
      },
    }
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Invalid refresh token',
    }
  }
}

/**
 * Verify a JWT token with security checks
 *
 * Supports both ES256 (asymmetric) and HS256 (symmetric) tokens.
 * The algorithm is detected from the token's protected header.
 *
 * Checks:
 * - Token signature and expiry
 * - Revocation status (via JTI)
 * - Audience claim (if provided)
 * - Client IP binding (if provided)
 */
export async function verifyToken(
  token: string,
  secret: string,
  env?: { CHALLENGES: KVNamespace },
  options?: {
    requiredAud?: string // expected audience
    clientIp?: string // client IP to validate against
  },
  publicKey?: {
    kty: string
    crv: string
    x: string
    y: string
    kid?: string
    use?: string
    alg?: string
  }
): Promise<{ valid: boolean; payload?: BotchaTokenPayload; error?: string }> {
  try {
    // Detect algorithm from the token header
    const header = decodeProtectedHeader(token)
    let verifyKey: CryptoKey | Uint8Array
    let algorithms: string[]

    if (header.alg === 'ES256' && publicKey) {
      // ES256 asymmetric verification
      verifyKey = (await importJWK(publicKey, 'ES256')) as CryptoKey
      algorithms = ['ES256']
    } else {
      // HS256 symmetric verification (legacy/fallback)
      verifyKey = new TextEncoder().encode(secret)
      algorithms = ['HS256']
    }

    const { payload } = await jwtVerify(token, verifyKey, {
      algorithms,
    })

    // Check token type (must be access token, not refresh token)
    if (payload.type !== 'botcha-verified') {
      return {
        valid: false,
        error: 'Invalid token type',
      }
    }

    const jti = payload.jti as string | undefined

    // Check revocation status (fail-open if KV unavailable)
    if (jti && env?.CHALLENGES) {
      try {
        const revoked = await env.CHALLENGES.get(`revoked:${jti}`)
        if (revoked) {
          return {
            valid: false,
            error: 'Token has been revoked',
          }
        }
      } catch (error) {
        // Fail-open: if KV check fails, allow token to proceed
        console.error('Failed to check revocation status:', error)
      }
    }

    // Validate audience claim (if required)
    if (options?.requiredAud) {
      const tokenAud = payload.aud as string | undefined
      if (!tokenAud || tokenAud !== options.requiredAud) {
        return {
          valid: false,
          error: 'Invalid audience claim',
        }
      }
    }

    // Validate client IP binding (if required)
    if (options?.clientIp) {
      const tokenIp = payload.client_ip as string | undefined
      if (!tokenIp || tokenIp !== options.clientIp) {
        return {
          valid: false,
          error: 'Client IP mismatch',
        }
      }
    }

    return {
      valid: true,
      payload: {
        sub: payload.sub || '',
        iat: payload.iat || 0,
        exp: payload.exp || 0,
        jti: jti || '',
        type: payload.type as 'botcha-verified',
        solveTime: payload.solveTime as number,
        aud: payload.aud as string | undefined,
        client_ip: payload.client_ip as string | undefined,
        app_id: payload.app_id as string | undefined,
      },
    }
  } catch (error) {
    return {
      valid: false,
      error: error instanceof Error ? error.message : 'Invalid token',
    }
  }
}

/**
 * Extract Bearer token from Authorization header
 */
export function extractBearerToken(authHeader?: string): string | null {
  if (!authHeader) return null

  const match = authHeader.match(/^Bearer\s+(.+)$/i)
  return match ? match[1] : null
}
