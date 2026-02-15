/**
 * BOTCHA Token Verification Types
 */

/**
 * JWT payload structure for BOTCHA tokens
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
 * Options for verifying BOTCHA tokens.
 * 
 * At least one of `secret` or `jwksUrl` must be provided.
 * If both are provided, JWKS verification is tried first, falling back to shared secret.
 */
export interface BotchaVerifyOptions {
  /**
   * JWT secret used to sign tokens (HS256).
   * Legacy: prefer `jwksUrl` for asymmetric (ES256) verification.
   */
  secret?: string;

  /**
   * JWKS URL for asymmetric (ES256) verification.
   * Recommended: use 'https://botcha.ai/.well-known/jwks'
   * 
   * The JWKS endpoint is fetched automatically, and key rotation / caching
   * is handled by the `jose` library's `createRemoteJWKSet`.
   */
  jwksUrl?: string;

  /**
   * Cache JWKS keys for this many seconds.
   * Only used when `jwksUrl` is provided.
   * @default 3600
   */
  jwksCacheTtl?: number;

  /**
   * Expected audience claim. If provided, tokens without matching aud will be rejected.
   */
  audience?: string;

  /**
   * If true, validates client_ip claim matches the request IP.
   * Requires clientIp to also be provided.
   */
  requireIp?: boolean;

  /**
   * Client IP address for validation against the token's client_ip claim.
   * Used when requireIp is true, or when provided it auto-enables IP checking.
   */
  clientIp?: string;

  /**
   * Custom error handler for verification failures
   * If not provided, default 401 response is sent
   */
  onError?: (error: string, context: VerificationContext) => void | Promise<void>;

  /**
   * Optional callback to check token revocation status
   * If provided, will be called with the JTI to check if token is revoked
   */
  checkRevocation?: (jti: string) => Promise<boolean>;
}

/**
 * Context passed to error handlers
 */
export interface VerificationContext {
  token?: string;
  payload?: Partial<BotchaTokenPayload>;
  error: string;
  clientIp?: string;
}

/**
 * Result of token verification
 */
export interface VerificationResult {
  valid: boolean;
  payload?: BotchaTokenPayload;
  error?: string;
}
