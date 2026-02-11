/**
 * BOTCHA Authentication & JWT Token Management
 * 
 * Token-based auth flow with security features:
 * - JTI (JWT ID) for revocation
 * - Audience claims for API scoping
 * - Client IP binding for additional security
 * - Short-lived access tokens (5 min) with refresh tokens (1 hour)
 * - Token revocation via KV storage
 */

import { SignJWT, jwtVerify } from 'jose';

/**
 * KV namespace interface (Cloudflare Workers)
 */
export interface KVNamespace {
  get(key: string): Promise<string | null>;
  put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void>;
  delete(key: string): Promise<void>;
}

/**
 * JWT payload structure for access tokens
 */
export interface BotchaTokenPayload {
  sub: string; // challenge ID that was solved
  iat: number; // issued at
  exp: number; // expires at
  jti: string; // JWT ID for revocation
  type: 'botcha-verified';
  solveTime: number; // how fast they solved it (ms)
  aud?: string; // optional audience claim
  client_ip?: string; // optional client IP binding
}

/**
 * JWT payload structure for refresh tokens
 */
export interface BotchaRefreshTokenPayload {
  sub: string; // challenge ID that was solved
  iat: number; // issued at
  exp: number; // expires at
  jti: string; // JWT ID for revocation
  type: 'botcha-refresh';
  solveTime: number; // how fast they solved it (ms)
}

/**
 * Token creation result
 */
export interface TokenCreationResult {
  access_token: string;
  expires_in: number; // seconds
  refresh_token: string;
  refresh_expires_in: number; // seconds
}

/**
 * Token generation options
 */
export interface TokenGenerationOptions {
  aud?: string; // optional audience claim
  clientIp?: string; // optional client IP for binding
}

/**
 * Generate JWT tokens (access + refresh) after successful challenge verification
 * 
 * Access token: 5 minutes, used for API access
 * Refresh token: 1 hour, used to get new access tokens
 */
export async function generateToken(
  challengeId: string,
  solveTimeMs: number,
  secret: string,
  env?: { CHALLENGES: KVNamespace },
  options?: TokenGenerationOptions
): Promise<TokenCreationResult> {
  const encoder = new TextEncoder();
  const secretKey = encoder.encode(secret);

  // Generate unique JTIs for both tokens
  const accessJti = crypto.randomUUID();
  const refreshJti = crypto.randomUUID();

  // Access token: 5 minutes
  const accessTokenPayload: Record<string, any> = {
    type: 'botcha-verified',
    solveTime: solveTimeMs,
    jti: accessJti,
  };

  // Add optional claims
  if (options?.aud) {
    accessTokenPayload.aud = options.aud;
  }
  if (options?.clientIp) {
    accessTokenPayload.client_ip = options.clientIp;
  }

  const accessToken = await new SignJWT(accessTokenPayload)
    .setProtectedHeader({ alg: 'HS256' })
    .setSubject(challengeId)
    .setIssuedAt()
    .setExpirationTime('5m') // 5 minutes
    .sign(secretKey);

  // Refresh token: 1 hour
  const refreshToken = await new SignJWT({
    type: 'botcha-refresh',
    solveTime: solveTimeMs,
    jti: refreshJti,
  })
    .setProtectedHeader({ alg: 'HS256' })
    .setSubject(challengeId)
    .setIssuedAt()
    .setExpirationTime('1h') // 1 hour
    .sign(secretKey);

  // Store refresh token JTI in KV if env provided (for revocation tracking)
  if (env?.CHALLENGES) {
    try {
      await env.CHALLENGES.put(
        `refresh:${refreshJti}`,
        JSON.stringify({ sub: challengeId, iat: Date.now() }),
        { expirationTtl: 3600 } // 1 hour TTL
      );
    } catch (error) {
      // Fail-open: continue even if KV storage fails
      console.error('Failed to store refresh token in KV:', error);
    }
  }

  return {
    access_token: accessToken,
    expires_in: 300, // 5 minutes in seconds
    refresh_token: refreshToken,
    refresh_expires_in: 3600, // 1 hour in seconds
  };
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
    );
  } catch (error) {
    throw new Error(`Failed to revoke token: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

/**
 * Refresh an access token using a valid refresh token
 * 
 * Verifies the refresh token, checks revocation, and issues a new access token
 */
export async function refreshAccessToken(
  refreshToken: string,
  env: { CHALLENGES: KVNamespace },
  secret: string,
  options?: TokenGenerationOptions
): Promise<{ success: boolean; tokens?: Omit<TokenCreationResult, 'refresh_token' | 'refresh_expires_in'> & { access_token: string; expires_in: number }; error?: string }> {
  try {
    const encoder = new TextEncoder();
    const secretKey = encoder.encode(secret);

    // Verify refresh token
    const { payload } = await jwtVerify(refreshToken, secretKey, {
      algorithms: ['HS256'],
    });

    // Check token type
    if (payload.type !== 'botcha-refresh') {
      return {
        success: false,
        error: 'Invalid token type. Expected refresh token.',
      };
    }

    const jti = payload.jti as string;

    // Check if token is revoked
    if (jti) {
      try {
        const revoked = await env.CHALLENGES.get(`revoked:${jti}`);
        if (revoked) {
          return {
            success: false,
            error: 'Refresh token has been revoked',
          };
        }
      } catch (error) {
        // Fail-open: if KV check fails, allow token to proceed
        console.error('Failed to check revocation status:', error);
      }
    }

    // Check if refresh token exists in KV
    if (jti) {
      try {
        const storedToken = await env.CHALLENGES.get(`refresh:${jti}`);
        if (!storedToken) {
          return {
            success: false,
            error: 'Refresh token not found or expired',
          };
        }
      } catch (error) {
        // Fail-open: if KV check fails, allow token to proceed
        console.error('Failed to verify refresh token in KV:', error);
      }
    }

    // Generate new access token
    const newAccessJti = crypto.randomUUID();
    const accessTokenPayload: Record<string, any> = {
      type: 'botcha-verified',
      solveTime: payload.solveTime,
      jti: newAccessJti,
    };

    // Add optional claims
    if (options?.aud) {
      accessTokenPayload.aud = options.aud;
    }
    if (options?.clientIp) {
      accessTokenPayload.client_ip = options.clientIp;
    }

    const accessToken = await new SignJWT(accessTokenPayload)
      .setProtectedHeader({ alg: 'HS256' })
      .setSubject(payload.sub || '')
      .setIssuedAt()
      .setExpirationTime('5m') // 5 minutes
      .sign(secretKey);

    return {
      success: true,
      tokens: {
        access_token: accessToken,
        expires_in: 300, // 5 minutes in seconds
      },
    };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Invalid refresh token',
    };
  }
}

/**
 * Verify a JWT token with security checks
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
    requiredAud?: string; // expected audience
    clientIp?: string; // client IP to validate against
  }
): Promise<{ valid: boolean; payload?: BotchaTokenPayload; error?: string }> {
  try {
    const encoder = new TextEncoder();
    const secretKey = encoder.encode(secret);

    const { payload } = await jwtVerify(token, secretKey, {
      algorithms: ['HS256'],
    });

    // Check token type (must be access token, not refresh token)
    if (payload.type !== 'botcha-verified') {
      return {
        valid: false,
        error: 'Invalid token type',
      };
    }

    const jti = payload.jti as string | undefined;

    // Check revocation status (fail-open if KV unavailable)
    if (jti && env?.CHALLENGES) {
      try {
        const revoked = await env.CHALLENGES.get(`revoked:${jti}`);
        if (revoked) {
          return {
            valid: false,
            error: 'Token has been revoked',
          };
        }
      } catch (error) {
        // Fail-open: if KV check fails, allow token to proceed
        console.error('Failed to check revocation status:', error);
      }
    }

    // Validate audience claim (if required)
    if (options?.requiredAud) {
      const tokenAud = payload.aud as string | undefined;
      if (!tokenAud || tokenAud !== options.requiredAud) {
        return {
          valid: false,
          error: 'Invalid audience claim',
        };
      }
    }

    // Validate client IP binding (if required)
    if (options?.clientIp) {
      const tokenIp = payload.client_ip as string | undefined;
      if (!tokenIp || tokenIp !== options.clientIp) {
        return {
          valid: false,
          error: 'Client IP mismatch',
        };
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
      },
    };
  } catch (error) {
    return {
      valid: false,
      error: error instanceof Error ? error.message : 'Invalid token',
    };
  }
}

/**
 * Extract Bearer token from Authorization header
 */
export function extractBearerToken(authHeader?: string): string | null {
  if (!authHeader) return null;
  
  const match = authHeader.match(/^Bearer\s+(.+)$/i);
  return match ? match[1] : null;
}
