/**
 * BOTCHA Express Middleware
 * 
 * Middleware for Express.js to verify BOTCHA JWT tokens.
 * Extracts Bearer token from Authorization header, verifies it,
 * and attaches payload to req.botcha.
 */

import type { Request, Response, NextFunction } from 'express';
import { verifyBotchaToken, extractBearerToken } from '../index.js';
import type { BotchaVerifyOptions, BotchaTokenPayload } from '../types.js';

/**
 * Extend Express Request interface to include botcha payload
 */
declare global {
  namespace Express {
    interface Request {
      botcha?: BotchaTokenPayload;
    }
  }
}

/**
 * Create BOTCHA verification middleware for Express
 * 
 * @param options - Verification options including secret and optional checks
 * @returns Express middleware function
 * 
 * @example
 * ```typescript
 * import express from 'express';
 * import { botchaVerify } from '@dupecom/botcha-verify/express';
 * 
 * const app = express();
 * 
 * // Protect all /api routes
 * app.use('/api', botchaVerify({
 *   secret: process.env.BOTCHA_SECRET!,
 *   audience: 'https://api.example.com',
 *   requireIp: true
 * }));
 * 
 * app.get('/api/protected', (req, res) => {
 *   // Access verified token payload
 *   console.log('Challenge ID:', req.botcha?.sub);
 *   console.log('Solve time:', req.botcha?.solveTime);
 *   res.json({ message: 'Success' });
 * });
 * ```
 */
export function botchaVerify(options: BotchaVerifyOptions) {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      // Extract Bearer token from Authorization header
      const authHeader = req.headers.authorization;
      const token = extractBearerToken(authHeader);

      if (!token) {
        if (options.onError) {
          await options.onError('Missing Authorization header with Bearer token', {
            error: 'Missing Authorization header with Bearer token',
            clientIp: getClientIp(req),
          });
          return;
        }
        res.status(401).json({
          error: 'Unauthorized',
          message: 'Missing Authorization header with Bearer token',
        });
        return;
      }

      // Get client IP for validation
      const clientIp = options.requireIp ? getClientIp(req) : undefined;

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
        res.status(401).json({
          error: 'Unauthorized',
          message: result.error || 'Token verification failed',
        });
        return;
      }

      // Attach payload to request
      req.botcha = result.payload;

      next();
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Internal server error';
      
      if (options.onError) {
        await options.onError(errorMessage, {
          error: errorMessage,
          clientIp: getClientIp(req),
        });
        return;
      }

      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to verify token',
      });
    }
  };
}

/**
 * Extract client IP from Express request
 * Handles X-Forwarded-For, X-Real-IP headers and req.ip
 */
function getClientIp(req: Request): string {
  // Check X-Forwarded-For header (proxy/load balancer)
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    const ips = typeof forwarded === 'string' ? forwarded.split(',') : forwarded;
    return ips[0].trim();
  }

  // Check X-Real-IP header
  const realIp = req.headers['x-real-ip'];
  if (realIp && typeof realIp === 'string') {
    return realIp.trim();
  }

  // Fall back to req.ip
  return req.ip || 'unknown';
}
