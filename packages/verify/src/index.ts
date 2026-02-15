/**
 * BOTCHA Token Verification
 * 
 * Core verification logic for BOTCHA JWT tokens.
 * Supports both JWKS-based (ES256, recommended) and shared-secret (HS256, legacy) verification.
 * Validates signature, expiry, type, audience, issuer, and client IP claims.
 */

import { jwtVerify, createRemoteJWKSet } from 'jose';
import type { JWTVerifyResult, KeyLike, FlattenedJWSInput, JWSHeaderParameters } from 'jose';
import type { BotchaTokenPayload, BotchaVerifyOptions, VerificationResult } from './types.js';

export type { BotchaTokenPayload, BotchaVerifyOptions, VerificationResult, VerificationContext } from './types.js';

/**
 * Cache for JWKS key sets, keyed by URL.
 * createRemoteJWKSet already handles internal caching and rotation,
 * so we just avoid re-creating the function on every call.
 */
type JwksResolver = (
  protectedHeader?: JWSHeaderParameters,
  token?: FlattenedJWSInput
) => Promise<KeyLike | Uint8Array>;

type JwksCacheEntry = {
  resolver: JwksResolver;
  expiresAt: number;
};

const DEFAULT_JWKS_CACHE_TTL_SECONDS = 3600;
const jwksCache = new Map<string, JwksCacheEntry>();

/**
 * Get or create a cached JWKS key set function for the given URL.
 */
function getJWKS(jwksUrl: string, jwksCacheTtl?: number): JwksResolver {
  const ttlSeconds = Math.max(1, jwksCacheTtl ?? DEFAULT_JWKS_CACHE_TTL_SECONDS);
  const now = Date.now();
  const cached = jwksCache.get(jwksUrl);

  if (cached && cached.expiresAt > now) {
    return cached.resolver;
  }

  const resolver = createRemoteJWKSet(new URL(jwksUrl));
  jwksCache.set(jwksUrl, {
    resolver,
    expiresAt: now + ttlSeconds * 1000,
  });

  return resolver;
}

/**
 * Verify a BOTCHA JWT token
 * 
 * Checks:
 * - Token signature (ES256 via JWKS, or HS256 via shared secret)
 * - Token expiry
 * - Token type (must be 'botcha-verified')
 * - Issuer claim (validated as 'botcha.ai' when using JWKS mode)
 * - Audience claim (if options.audience provided)
 * - Client IP binding (if options.requireIp and options.clientIp provided)
 * - Revocation status (if options.checkRevocation provided)
 * 
 * If both `jwksUrl` and `secret` are provided, JWKS is tried first with
 * a fallback to shared-secret verification.
 * 
 * @param token - JWT token to verify
 * @param options - Verification options (at least one of `secret` or `jwksUrl` required)
 * @param clientIp_ - Optional client IP for validation
 * @returns Verification result with valid flag, payload, and error message
 */
export async function verifyBotchaToken(
  token: string,
  options: BotchaVerifyOptions,
  clientIp_?: string
): Promise<VerificationResult> {
  // Validate that at least one verification method is provided
  if (!options.secret && !options.jwksUrl) {
    return {
      valid: false,
      error: 'Configuration error: at least one of "secret" or "jwksUrl" must be provided',
    };
  }

  try {
    let payload: JWTVerifyResult['payload'];

    if (options.jwksUrl && options.secret) {
      // Both provided: try JWKS first, fall back to secret
      try {
        payload = (await verifyWithJWKS(token, options.jwksUrl, options.jwksCacheTtl)).payload;
      } catch {
        payload = (await verifyWithSecret(token, options.secret)).payload;
      }
    } else if (options.jwksUrl) {
      // JWKS-only mode
      const result = await verifyWithJWKS(token, options.jwksUrl, options.jwksCacheTtl);
      payload = result.payload;

      // Validate issuer when using JWKS mode
      const iss = payload.iss as string | undefined;
      if (!iss || iss !== 'botcha.ai') {
        return {
          valid: false,
          error: `Invalid issuer claim. Expected "botcha.ai", got "${iss || 'none'}"`,
        };
      }
    } else {
      // Secret-only mode (legacy)
      payload = (await verifyWithSecret(token, options.secret!)).payload;
    }

    // Check token type (must be access token, not refresh token)
    if (payload.type !== 'botcha-verified') {
      return {
        valid: false,
        error: 'Invalid token type. Expected botcha-verified token.',
      };
    }

    const jti = payload.jti as string | undefined;

    // Check revocation status (if callback provided)
    if (jti && options.checkRevocation) {
      try {
        const isRevoked = await options.checkRevocation(jti);
        if (isRevoked) {
          return {
            valid: false,
            error: 'Token has been revoked',
          };
        }
      } catch (error) {
        // Fail-open: if revocation check fails, log and allow token to proceed
        console.error('Failed to check revocation status:', error);
      }
    }

    // Validate audience claim (if required)
    if (options.audience) {
      const tokenAud = payload.aud as string | undefined;
      if (!tokenAud || tokenAud !== options.audience) {
        return {
          valid: false,
          error: `Invalid audience claim. Expected "${options.audience}", got "${tokenAud || 'none'}"`,
        };
      }
    }

    // Validate client IP binding (if required or clientIp provided)
    const effectiveClientIp = options.clientIp || clientIp_;
    if (effectiveClientIp && (options.requireIp || options.clientIp)) {
      const tokenIp = payload.client_ip as string | undefined;
      if (!tokenIp || tokenIp !== effectiveClientIp) {
        return {
          valid: false,
          error: 'Client IP mismatch',
        };
      }
    }

    // Token is valid
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
 * Verify token using JWKS (asymmetric, ES256).
 * Accepts both ES256 and HS256 tokens to support the migration period.
 */
async function verifyWithJWKS(
  token: string,
  jwksUrl: string,
  jwksCacheTtl?: number
): Promise<JWTVerifyResult> {
  const jwks = getJWKS(jwksUrl, jwksCacheTtl);
  return jwtVerify(token, jwks, {
    algorithms: ['ES256', 'HS256'],
  });
}

/**
 * Verify token using a shared secret (symmetric, HS256).
 */
async function verifyWithSecret(token: string, secret: string): Promise<JWTVerifyResult> {
  const encoder = new TextEncoder();
  const secretKey = encoder.encode(secret);
  return jwtVerify(token, secretKey, {
    algorithms: ['HS256'],
  });
}

/**
 * Extract Bearer token from Authorization header
 * 
 * @param authHeader - Authorization header value
 * @returns Extracted token or null if not found
 */
export function extractBearerToken(authHeader?: string): string | null {
  if (!authHeader) return null;
  
  const match = authHeader.match(/^Bearer\s+(.+)$/i);
  return match ? match[1] : null;
}
