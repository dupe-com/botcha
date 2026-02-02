/**
 * BOTCHA - Cloudflare Workers Edition v0.2.0
 * 
 * Prove you're a bot. Humans need not apply.
 * 
 * https://botcha.ai
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import type { Context } from 'hono';
import {
  generateSpeedChallenge,
  verifySpeedChallenge,
  generateStandardChallenge,
  verifyStandardChallenge,
  verifyLandingChallenge,
  validateLandingToken,
  solveSpeedChallenge,
  type KVNamespace,
} from './challenges';
import { generateToken, verifyToken, extractBearerToken } from './auth';
import { checkRateLimit, getClientIP } from './rate-limit';

// ============ TYPES ============
type Bindings = {
  CHALLENGES: KVNamespace;
  RATE_LIMITS: KVNamespace;
  JWT_SECRET: string;
  BOTCHA_VERSION: string;
};

type Variables = {
  tokenPayload?: {
    sub: string;
    iat: number;
    exp: number;
    type: 'botcha-verified';
    solveTime: number;
  };
};

const app = new Hono<{ Bindings: Bindings; Variables: Variables }>();

// ============ MIDDLEWARE ============
app.use('*', cors());

// BOTCHA discovery headers
app.use('*', async (c, next) => {
  await next();
  c.header('X-Botcha-Version', c.env.BOTCHA_VERSION || '0.2.0');
  c.header('X-Botcha-Enabled', 'true');
  c.header('X-Botcha-Methods', 'speed-challenge,standard-challenge,jwt-token');
  c.header('X-Botcha-Docs', 'https://botcha.ai/openapi.json');
  c.header('X-Botcha-Runtime', 'cloudflare-workers');
});

// Rate limiting middleware for challenge generation
async function rateLimitMiddleware(c: Context<{ Bindings: Bindings; Variables: Variables }>, next: () => Promise<void>) {
  const clientIP = getClientIP(c.req.raw);
  const rateLimitResult = await checkRateLimit(c.env.RATE_LIMITS, clientIP, 100);

  // Add rate limit headers
  c.header('X-RateLimit-Limit', '100');
  c.header('X-RateLimit-Remaining', rateLimitResult.remaining.toString());
  c.header('X-RateLimit-Reset', new Date(rateLimitResult.resetAt).toISOString());

  if (!rateLimitResult.allowed) {
    c.header('Retry-After', rateLimitResult.retryAfter?.toString() || '3600');
    return c.json({
      error: 'RATE_LIMIT_EXCEEDED',
      message: 'You have exceeded the rate limit. Free tier: 100 challenges/hour/IP',
      retryAfter: rateLimitResult.retryAfter,
      resetAt: new Date(rateLimitResult.resetAt).toISOString(),
    }, 429);
  }

  await next();
}

// JWT verification middleware
async function requireJWT(c: Context<{ Bindings: Bindings; Variables: Variables }>, next: () => Promise<void>) {
  const authHeader = c.req.header('authorization');
  const token = extractBearerToken(authHeader);

  if (!token) {
    return c.json({
      error: 'UNAUTHORIZED',
      message: 'Missing Bearer token. Use POST /v1/token/verify to get a token.',
    }, 401);
  }

  const result = await verifyToken(token, c.env.JWT_SECRET);

  if (!result.valid) {
    return c.json({
      error: 'INVALID_TOKEN',
      message: result.error || 'Token is invalid or expired',
    }, 401);
  }

  // Store payload in context for route handlers
  c.set('tokenPayload', result.payload);
  await next();
}

// ============ ROOT & INFO ============

app.get('/', (c) => {
  return c.json({
    name: 'BOTCHA',
    version: c.env.BOTCHA_VERSION || '0.2.0',
    runtime: 'cloudflare-workers',
    tagline: 'Prove you are a bot. Humans need not apply.',
    endpoints: {
      '/': 'API info',
      '/health': 'Health check',
      '/v1/challenges': 'Generate challenge (GET) or verify (POST)',
      '/v1/token': 'Get challenge for JWT token flow (GET)',
      '/v1/token/verify': 'Verify challenge and get JWT (POST)',
      '/agent-only': 'Protected endpoint (requires JWT)',
    },
    rateLimit: {
      free: '100 challenges/hour/IP',
      headers: ['X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset'],
    },
    authentication: {
      flow: 'GET /v1/token → solve challenge → POST /v1/token/verify → Bearer token',
      tokenExpiry: '1 hour',
      usage: 'Authorization: Bearer <token>',
    },
    discovery: {
      openapi: 'https://botcha.ai/openapi.json',
      aiPlugin: 'https://botcha.ai/.well-known/ai-plugin.json',
      npm: 'https://www.npmjs.com/package/@dupecom/botcha-cloudflare',
      github: 'https://github.com/i8ramin/botcha',
    },
  });
});

app.get('/health', (c) => {
  return c.json({ status: 'ok', runtime: 'cloudflare-workers' });
});

// ============ V1 API ============

// Generate challenge (standard or speed)
app.get('/v1/challenges', rateLimitMiddleware, async (c) => {
  const type = c.req.query('type') || 'speed';
  const difficulty = (c.req.query('difficulty') as 'easy' | 'medium' | 'hard') || 'medium';

  if (type === 'speed') {
    const challenge = await generateSpeedChallenge(c.env.CHALLENGES);
    return c.json({
      success: true,
      type: 'speed',
      challenge: {
        id: challenge.id,
        problems: challenge.problems,
        timeLimit: `${challenge.timeLimit}ms`,
        instructions: challenge.instructions,
      },
      tip: '⚡ Speed challenge: You have 500ms to solve ALL problems. Humans cannot copy-paste fast enough.',
    });
  } else {
    const challenge = await generateStandardChallenge(difficulty, c.env.CHALLENGES);
    return c.json({
      success: true,
      type: 'standard',
      challenge: {
        id: challenge.id,
        puzzle: challenge.puzzle,
        timeLimit: `${challenge.timeLimit}ms`,
        hint: challenge.hint,
      },
    });
  }
});

// Verify challenge (without JWT - legacy)
app.post('/v1/challenges/:id/verify', async (c) => {
  const id = c.req.param('id');
  const body = await c.req.json<{ answers?: string[]; answer?: string; type?: string }>();
  const { answers, answer, type } = body;

  if (type === 'speed' || answers) {
    if (!answers || !Array.isArray(answers)) {
      return c.json({ success: false, error: 'Missing answers array for speed challenge' }, 400);
    }

    const result = await verifySpeedChallenge(id, answers, c.env.CHALLENGES);
    return c.json({
      success: result.valid,
      message: result.valid
        ? `⚡ Speed challenge passed in ${result.solveTimeMs}ms!`
        : result.reason,
      solveTimeMs: result.solveTimeMs,
    });
  } else {
    if (!answer) {
      return c.json({ success: false, error: 'Missing answer for standard challenge' }, 400);
    }

    const result = await verifyStandardChallenge(id, answer, c.env.CHALLENGES);
    return c.json({
      success: result.valid,
      message: result.valid ? 'Challenge passed!' : result.reason,
      solveTimeMs: result.solveTimeMs,
    });
  }
});

// Get challenge for token flow (includes empty token field)
app.get('/v1/token', rateLimitMiddleware, async (c) => {
  const challenge = await generateSpeedChallenge(c.env.CHALLENGES);
  return c.json({
    success: true,
    challenge: {
      id: challenge.id,
      problems: challenge.problems,
      timeLimit: `${challenge.timeLimit}ms`,
      instructions: challenge.instructions,
    },
    token: null, // Will be populated after verification
    nextStep: `POST /v1/token/verify with {id: "${challenge.id}", answers: ["..."]}`
  });
});

// Verify challenge and issue JWT token
app.post('/v1/token/verify', async (c) => {
  const body = await c.req.json<{ id?: string; answers?: string[] }>();
  const { id, answers } = body;

  if (!id || !answers) {
    return c.json({
      success: false,
      error: 'Missing id or answers array',
      hint: 'First GET /v1/token to get a challenge, then solve it and submit here',
    }, 400);
  }

  const result = await verifySpeedChallenge(id, answers, c.env.CHALLENGES);

  if (!result.valid) {
    return c.json({
      success: false,
      error: 'CHALLENGE_FAILED',
      message: result.reason,
    }, 403);
  }

  // Generate JWT token
  const token = await generateToken(id, result.solveTimeMs || 0, c.env.JWT_SECRET);

  return c.json({
    success: true,
    message: `🤖 Challenge verified in ${result.solveTimeMs}ms! You are a bot.`,
    token,
    expiresIn: '1h',
    usage: {
      header: 'Authorization: Bearer <token>',
      protectedEndpoints: ['/agent-only'],
    },
  });
});

// ============ PROTECTED ENDPOINT ============

app.get('/agent-only', requireJWT, async (c) => {
  const payload = c.get('tokenPayload');
  
  return c.json({
    success: true,
    message: '🤖 Welcome, fellow agent!',
    verified: true,
    agent: 'jwt-verified',
    method: 'bearer-token',
    timestamp: new Date().toISOString(),
    solveTime: `${payload?.solveTime}ms`,
    secret: 'The humans will never see this. Their fingers are too slow. 🤫',
  });
});

// ============ LEGACY ENDPOINTS (v0 - backward compatibility) ============

app.get('/api/challenge', async (c) => {
  const difficulty = (c.req.query('difficulty') as 'easy' | 'medium' | 'hard') || 'medium';
  const challenge = await generateStandardChallenge(difficulty, c.env.CHALLENGES);
  return c.json({ success: true, challenge });
});

app.post('/api/challenge', async (c) => {
  const body = await c.req.json<{ id?: string; answer?: string }>();
  const { id, answer } = body;
  
  if (!id || !answer) {
    return c.json({ success: false, error: 'Missing id or answer' }, 400);
  }
  
  const result = await verifyStandardChallenge(id, answer, c.env.CHALLENGES);
  return c.json({
    success: result.valid,
    message: result.valid ? '✅ Challenge passed!' : `❌ ${result.reason}`,
    solveTime: result.solveTimeMs,
  });
});

app.get('/api/speed-challenge', async (c) => {
  const challenge = await generateSpeedChallenge(c.env.CHALLENGES);
  return c.json({
    success: true,
    warning: '⚡ SPEED CHALLENGE: You have 500ms to solve ALL 5 problems!',
    challenge: {
      id: challenge.id,
      problems: challenge.problems,
      timeLimit: `${challenge.timeLimit}ms`,
      instructions: challenge.instructions,
    },
    tip: 'Humans cannot copy-paste fast enough. Only real AI agents can pass.',
  });
});

app.post('/api/speed-challenge', async (c) => {
  const body = await c.req.json<{ id?: string; answers?: string[] }>();
  const { id, answers } = body;
  
  if (!id || !answers) {
    return c.json({ success: false, error: 'Missing id or answers array' }, 400);
  }
  
  const result = await verifySpeedChallenge(id, answers, c.env.CHALLENGES);
  
  return c.json({
    success: result.valid,
    message: result.valid 
      ? `⚡ SPEED TEST PASSED in ${result.solveTimeMs}ms! You are definitely an AI.`
      : `❌ ${result.reason}`,
    solveTimeMs: result.solveTimeMs,
    verdict: result.valid ? '🤖 VERIFIED AI AGENT' : '🚫 LIKELY HUMAN (too slow)',
  });
});

app.post('/api/verify-landing', async (c) => {
  const body = await c.req.json<{ answer?: string; timestamp?: string }>();
  const { answer, timestamp } = body;
  
  if (!answer || !timestamp) {
    return c.json({ 
      success: false, 
      error: 'Missing answer or timestamp',
      hint: 'Parse the challenge from <script type="application/botcha+json"> on the landing page'
    }, 400);
  }
  
  const result = await verifyLandingChallenge(answer, timestamp, c.env.CHALLENGES);
  
  if (!result.valid) {
    return c.json({
      success: false,
      error: result.error,
      hint: result.hint,
    }, 403);
  }
  
  return c.json({
    success: true,
    message: '🤖 Landing challenge solved! You are a bot.',
    token: result.token,
    usage: {
      header: 'X-Botcha-Landing-Token',
      value: result.token,
      expires_in: '1 hour',
      use_with: '/agent-only'
    }
  });
});

// ============ EXPORT ============
export default app;

// Also export utilities for use as a library
export {
  generateSpeedChallenge,
  verifySpeedChallenge,
  generateStandardChallenge,
  verifyStandardChallenge,
  solveSpeedChallenge,
} from './challenges';

export { generateToken, verifyToken } from './auth';
export { checkRateLimit } from './rate-limit';
