/**
 * BOTCHA Authentication & JWT Token Management
 * 
 * Token-based auth flow for production API access
 */

import { SignJWT, jwtVerify } from 'jose';

/**
 * JWT payload structure
 */
export interface BotchaTokenPayload {
  sub: string; // challenge ID that was solved
  iat: number; // issued at
  exp: number; // expires at
  type: 'botcha-verified';
  solveTime: number; // how fast they solved it (ms)
}

/**
 * Generate a JWT token after successful challenge verification
 */
export async function generateToken(
  challengeId: string,
  solveTimeMs: number,
  secret: string
): Promise<string> {
  const encoder = new TextEncoder();
  const secretKey = encoder.encode(secret);

  const token = await new SignJWT({
    type: 'botcha-verified',
    solveTime: solveTimeMs,
  })
    .setProtectedHeader({ alg: 'HS256' })
    .setSubject(challengeId)
    .setIssuedAt()
    .setExpirationTime('1h') // 1 hour expiry
    .sign(secretKey);

  return token;
}

/**
 * Verify a JWT token
 */
export async function verifyToken(
  token: string,
  secret: string
): Promise<{ valid: boolean; payload?: BotchaTokenPayload; error?: string }> {
  try {
    const encoder = new TextEncoder();
    const secretKey = encoder.encode(secret);

    const { payload } = await jwtVerify(token, secretKey, {
      algorithms: ['HS256'],
    });

    return {
      valid: true,
      payload: {
        sub: payload.sub || '',
        iat: payload.iat || 0,
        exp: payload.exp || 0,
        type: payload.type as 'botcha-verified',
        solveTime: payload.solveTime as number,
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
