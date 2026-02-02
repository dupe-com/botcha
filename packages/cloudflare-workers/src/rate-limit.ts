/**
 * BOTCHA Rate Limiting
 * 
 * Simple IP-based rate limiting using KV storage
 */

import type { KVNamespace } from './challenges';

export interface RateLimitConfig {
  requestsPerHour: number;
  identifier: string; // Usually IP address
}

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetAt: number;
  retryAfter?: number;
}

/**
 * Check and enforce rate limits
 */
export async function checkRateLimit(
  kv: KVNamespace | undefined,
  identifier: string,
  limit: number = 100
): Promise<RateLimitResult> {
  if (!kv) {
    // No KV = no rate limiting (local dev)
    return {
      allowed: true,
      remaining: limit,
      resetAt: Date.now() + 3600000,
    };
  }

  const key = `ratelimit:${identifier}`;
  const now = Date.now();
  const windowStart = now - 3600000; // 1 hour ago

  try {
    const data = await kv.get(key);
    
    if (!data) {
      // First request in this window
      await kv.put(key, JSON.stringify({ count: 1, firstRequest: now }), {
        expirationTtl: 3600, // 1 hour
      });
      
      return {
        allowed: true,
        remaining: limit - 1,
        resetAt: now + 3600000,
      };
    }

    const { count, firstRequest } = JSON.parse(data);

    // Check if window has expired
    if (firstRequest < windowStart) {
      // Reset window
      await kv.put(key, JSON.stringify({ count: 1, firstRequest: now }), {
        expirationTtl: 3600,
      });
      
      return {
        allowed: true,
        remaining: limit - 1,
        resetAt: now + 3600000,
      };
    }

    // Check if limit exceeded
    if (count >= limit) {
      const resetAt = firstRequest + 3600000;
      const retryAfter = Math.ceil((resetAt - now) / 1000);
      
      return {
        allowed: false,
        remaining: 0,
        resetAt,
        retryAfter,
      };
    }

    // Increment counter
    await kv.put(key, JSON.stringify({ count: count + 1, firstRequest }), {
      expirationTtl: 3600,
    });

    return {
      allowed: true,
      remaining: limit - count - 1,
      resetAt: firstRequest + 3600000,
    };
  } catch (error) {
    // On error, allow request (fail open)
    console.error('Rate limit check failed:', error);
    return {
      allowed: true,
      remaining: limit,
      resetAt: now + 3600000,
    };
  }
}

/**
 * Extract client IP from request
 */
export function getClientIP(request: Request): string {
  // Cloudflare provides CF-Connecting-IP header
  const cfIP = request.headers.get('cf-connecting-ip');
  if (cfIP) return cfIP;
  
  // Fallback headers
  const forwarded = request.headers.get('x-forwarded-for');
  if (forwarded) return forwarded.split(',')[0].trim();
  
  const realIP = request.headers.get('x-real-ip');
  if (realIP) return realIP;
  
  return 'unknown';
}
