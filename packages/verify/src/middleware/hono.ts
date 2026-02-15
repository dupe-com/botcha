/**
 * BOTCHA Hono Middleware
 * 
 * Middleware for Hono framework to verify BOTCHA JWT tokens.
 * Extracts Bearer token from Authorization header, verifies it,
 * and attaches payload to context variables.
 */

import type { Context, MiddlewareHandler } from 'hono';
import { verifyBotchaToken, extractBearerToken } from '../index.js';
import type { BotchaVerifyOptions, BotchaTokenPayload } from '../types.js';

/**
 * Hono context variables for BOTCHA
 */
type BotchaVariables = {
  botcha: BotchaTokenPayload;
};

/**
 * Create BOTCHA verification middleware for Hono
 * 
 * @param options - Verification options including secret and optional checks
 * @returns Hono middleware handler
 * 
 * @example
 * ```typescript
 * import { Hono } from 'hono';
 * import { botchaVerify } from '@dupecom/botcha-verify/hono';
 * 
 * const app = new Hono<{ Variables: { botcha: BotchaTokenPayload } }>();
 * 
 * // RECOMMENDED: JWKS verification (no shared secret needed!)
 * app.use('/api/*', botchaVerify({
 *   jwksUrl: 'https://botcha.ai/.well-known/jwks',
 *   audience: 'https://api.example.com',
 * }));
 * 
 * // LEGACY: Shared secret verification
 * app.use('/api/*', botchaVerify({
 *   secret: env.BOTCHA_SECRET,
 *   audience: 'https://api.example.com',
 *   requireIp: true,
 * }));
 * 
 * app.get('/api/protected', (c) => {
 *   // Access verified token payload
 *   const botcha = c.get('botcha');
 *   console.log('Challenge ID:', botcha.sub);
 *   console.log('Solve time:', botcha.solveTime);
 *   return c.json({ message: 'Success' });
 * });
 * ```
 */
export function botchaVerify(options: BotchaVerifyOptions): MiddlewareHandler<{ Variables: BotchaVariables }> {
  return async (c: Context<{ Variables: BotchaVariables }>, next) => {
    try {
      // Extract Bearer token from Authorization header
      const authHeader = c.req.header('Authorization');
      const token = extractBearerToken(authHeader);

      if (!token) {
        if (options.onError) {
          await options.onError('Missing Authorization header with Bearer token', {
            error: 'Missing Authorization header with Bearer token',
            clientIp: getClientIp(c),
          });
          return;
        }
        return c.json(
          {
            error: 'Unauthorized',
            message: 'Missing Authorization header with Bearer token',
          },
          401
        );
      }

      // Get client IP for validation
      const clientIp = options.requireIp ? getClientIp(c) : undefined;

      // Verify token
      const result = await verifyBotchaToken(token, options, clientIp);

      if (!result.valid) {
        if (options.onError) {
          await options.onError(result.error || 'Token verification failed', {
            token,
            error: result.error || 'Token verification failed',
            clientIp,
          });
          return;
        }
        return c.json(
          {
            error: 'Unauthorized',
            message: result.error || 'Token verification failed',
          },
          401
        );
      }

      // Attach payload to context
      c.set('botcha', result.payload!);

      await next();
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Internal server error';
      
      if (options.onError) {
        await options.onError(errorMessage, {
          error: errorMessage,
          clientIp: getClientIp(c),
        });
        return;
      }

      return c.json(
        {
          error: 'Internal Server Error',
          message: 'Failed to verify token',
        },
        500
      );
    }
  };
}

/**
 * Extract client IP from Hono context
 * Handles X-Forwarded-For, X-Real-IP, CF-Connecting-IP headers
 */
function getClientIp(c: Context): string {
  // Check Cloudflare header
  const cfIp = c.req.header('CF-Connecting-IP');
  if (cfIp) return cfIp;

  // Check X-Forwarded-For header (proxy/load balancer)
  const forwarded = c.req.header('X-Forwarded-For');
  if (forwarded) {
    const ips = forwarded.split(',');
    return ips[0].trim();
  }

  // Check X-Real-IP header
  const realIp = c.req.header('X-Real-IP');
  if (realIp) return realIp;

  // Fall back to unknown
  return 'unknown';
}

export type { BotchaVariables };
