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
  generateReasoningChallenge,
  verifyReasoningChallenge,
  generateHybridChallenge,
  verifyHybridChallenge,
  verifyLandingChallenge,
  validateLandingToken,
  solveSpeedChallenge,
  type KVNamespace,
} from './challenges';
import { generateToken, verifyToken, extractBearerToken } from './auth';
import { checkRateLimit, getClientIP } from './rate-limit';
import { verifyBadge, generateBadgeSvg, generateBadgeHtml, createBadgeResponse } from './badge';
import streamRoutes from './routes/stream';

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

// ============ MOUNT ROUTES ============
app.route('/', streamRoutes);

// BOTCHA discovery headers
app.use('*', async (c, next) => {
  await next();
  c.header('X-Botcha-Version', c.env.BOTCHA_VERSION || '0.2.0');
  c.header('X-Botcha-Enabled', 'true');
  c.header('X-Botcha-Methods', 'speed-challenge,reasoning-challenge,hybrid-challenge,standard-challenge,jwt-token');
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

// Detect if request is from a bot/agent vs human browser
function isBot(c: Context<{ Bindings: Bindings; Variables: Variables }>): boolean {
  const accept = c.req.header('accept') || '';
  const userAgent = c.req.header('user-agent') || '';
  
  // Bots typically request JSON or have specific user agents
  if (accept.includes('application/json')) return true;
  if (userAgent.includes('curl')) return true;
  if (userAgent.includes('httpie')) return true;
  if (userAgent.includes('wget')) return true;
  if (userAgent.includes('python')) return true;
  if (userAgent.includes('node')) return true;
  if (userAgent.includes('axios')) return true;
  if (userAgent.includes('fetch')) return true;
  if (userAgent.includes('bot')) return true;
  if (userAgent.includes('anthropic')) return true;
  if (userAgent.includes('openai')) return true;
  if (userAgent.includes('claude')) return true;
  if (userAgent.includes('gpt')) return true;
  
  // If no user agent at all, probably a bot
  if (!userAgent) return true;
  
  return false;
}

// ASCII art landing page for humans (plain text, terminal-style)
function getHumanLanding(version: string): string {
  return `
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║  ██████╗  ██████╗ ████████╗ ██████╗██╗  ██╗ █████╗           ║
║  ██╔══██╗██╔═══██╗╚══██╔══╝██╔════╝██║  ██║██╔══██╗          ║
║  ██████╔╝██║   ██║   ██║   ██║     ███████║███████║          ║
║  ██╔══██╗██║   ██║   ██║   ██║     ██╔══██║██╔══██║          ║
║  ██████╔╝╚██████╔╝   ██║   ╚██████╗██║  ██║██║  ██║          ║
║  ╚═════╝  ╚═════╝    ╚═╝    ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝          ║
║                                                              ║
║  Prove you're a bot. Humans need not apply.                  ║
║                                                              ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  This site is for AI agents and bots, not humans.            ║
║                                                              ║
║  If you're a developer, point your bot here:                 ║
║                                                              ║
║    curl https://botcha.ai/v1/challenges                      ║
║                                                              ║
║  Or install the SDK:                                         ║
║                                                              ║
║    npm install @dupecom/botcha                               ║
║                                                              ║
║  GitHub:  https://github.com/dupe-com/botcha                 ║
║  npm:     https://npmjs.com/package/@dupecom/botcha          ║
║                                                              ║
╠══════════════════════════════════════════════════════════════╣
║  v${version}                                   https://botcha.ai  ║
╚══════════════════════════════════════════════════════════════╝
`;
}

app.get('/', (c) => {
  const version = c.env.BOTCHA_VERSION || '0.3.0';
  
  // If it's a human browser, show plain text ASCII art
  if (!isBot(c)) {
    return c.text(getHumanLanding(version), 200, {
      'Content-Type': 'text/plain; charset=utf-8',
    });
  }
  
  // For bots/agents, return comprehensive JSON documentation
  return c.json({
    name: 'BOTCHA',
    version,
    runtime: 'cloudflare-workers',
    tagline: 'Prove you are a bot. Humans need not apply.',
    description: 'BOTCHA is a reverse CAPTCHA - computational challenges that only AI agents can solve. Use it to protect your APIs from humans and verify bot authenticity.',
    quickstart: {
      step1: 'GET /v1/challenges to receive a challenge',
      step2: 'Solve the SHA256 hash problems within 500ms',
      step3: 'POST your answers to verify',
      step4: 'Receive a JWT token for authenticated access',
      example: 'curl https://botcha.ai/v1/challenges',
    },
    endpoints: {
      challenges: {
        'GET /v1/challenges': 'Get hybrid challenge (speed + reasoning) - DEFAULT',
        'GET /v1/challenges?type=speed': 'Get speed-only challenge (SHA256 in <500ms)',
        'GET /v1/challenges?type=standard': 'Get standard puzzle challenge',
        'POST /v1/challenges/:id/verify': 'Verify challenge solution',
      },
      specialized: {
        'GET /v1/hybrid': 'Get hybrid challenge (speed + reasoning)',
        'POST /v1/hybrid': 'Verify hybrid challenge',
        'GET /v1/reasoning': 'Get reasoning-only challenge (LLM questions)',
        'POST /v1/reasoning': 'Verify reasoning challenge',
      },
      streaming: {
        'GET /v1/challenge/stream': 'SSE streaming challenge (interactive, real-time)',
        'POST /v1/challenge/stream/:session': 'Send actions to streaming session',
      },
      authentication: {
        'GET /v1/token': 'Get challenge for JWT token flow',
        'POST /v1/token/verify': 'Verify challenge and receive JWT token',
        'GET /agent-only': 'Protected endpoint (requires Bearer token)',
      },
      badges: {
        'GET /badge/:id': 'Badge verification page (HTML)',
        'GET /badge/:id/image': 'Badge image (SVG)',
        'GET /api/badge/:id': 'Badge verification (JSON)',
      },
      info: {
        'GET /': 'This documentation (JSON for bots, ASCII for humans)',
        'GET /health': 'Health check endpoint',
      },
    },
    challengeTypes: {
      speed: {
        description: 'Compute SHA256 hashes of 5 numbers in under 500ms',
        difficulty: 'Only bots can solve this fast enough',
        timeLimit: '500ms',
      },
      reasoning: {
        description: 'Answer 3 questions requiring AI reasoning capabilities',
        difficulty: 'Requires LLM-level comprehension',
        timeLimit: '30s',
      },
      hybrid: {
        description: 'Combines speed AND reasoning challenges',
        difficulty: 'The ultimate bot verification',
        timeLimit: 'Speed: 500ms, Reasoning: 30s',
      },
    },
    authentication: {
      flow: [
        '1. GET /v1/token - receive challenge',
        '2. Solve the challenge',
        '3. POST /v1/token/verify - submit solution',
        '4. Receive JWT token (valid 1 hour)',
        '5. Use: Authorization: Bearer <token>',
      ],
      tokenExpiry: '1 hour',
      usage: 'Authorization: Bearer <token>',
    },
    rateLimit: {
      free: '100 challenges/hour/IP',
      headers: ['X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset'],
    },
    sdk: {
      npm: 'npm install @dupecom/botcha',
      cloudflare: 'npm install @dupecom/botcha-cloudflare',
      usage: "import { BotchaClient } from '@dupecom/botcha/client'",
    },
    links: {
      github: 'https://github.com/dupe-com/botcha',
      npm: 'https://www.npmjs.com/package/@dupecom/botcha',
      npmCloudflare: 'https://www.npmjs.com/package/@dupecom/botcha-cloudflare',
      openapi: 'https://botcha.ai/openapi.json',
      aiPlugin: 'https://botcha.ai/.well-known/ai-plugin.json',
    },
    contributing: {
      repo: 'https://github.com/dupe-com/botcha',
      issues: 'https://github.com/dupe-com/botcha/issues',
      pullRequests: 'https://github.com/dupe-com/botcha/pulls',
    },
  });
});

app.get('/health', (c) => {
  return c.json({ status: 'ok', runtime: 'cloudflare-workers' });
});

// ============ V1 API ============

// Generate challenge (hybrid by default, also supports speed and standard)
app.get('/v1/challenges', rateLimitMiddleware, async (c) => {
  const type = c.req.query('type') || 'hybrid';
  const difficulty = (c.req.query('difficulty') as 'easy' | 'medium' | 'hard') || 'medium';

  const baseUrl = new URL(c.req.url).origin;

  if (type === 'hybrid') {
    const challenge = await generateHybridChallenge(c.env.CHALLENGES);
    return c.json({
      success: true,
      type: 'hybrid',
      warning: '🔥 HYBRID CHALLENGE: Solve speed problems in <500ms AND answer reasoning questions!',
      challenge: {
        id: challenge.id,
        speed: {
          problems: challenge.speed.problems,
          timeLimit: `${challenge.speed.timeLimit}ms`,
          instructions: 'Compute SHA256 of each number, return first 8 hex chars',
        },
        reasoning: {
          questions: challenge.reasoning.questions,
          timeLimit: `${challenge.reasoning.timeLimit / 1000}s`,
          instructions: 'Answer all reasoning questions',
        },
      },
      instructions: challenge.instructions,
      tip: '🔥 This is the ultimate test: proves you can compute AND reason like an AI.',
      verify_endpoint: `${baseUrl}/v1/challenges/${challenge.id}/verify`,
      submit_body: {
        type: 'hybrid',
        speed_answers: ['hash1', 'hash2', '...'],
        reasoning_answers: { 'question-id': 'answer', '...': '...' }
      }
    });
  } else if (type === 'speed') {
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
      verify_endpoint: `${baseUrl}/v1/challenges/${challenge.id}/verify`,
      submit_body: {
        type: 'speed',
        answers: ['hash1', 'hash2', 'hash3', 'hash4', 'hash5']
      }
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
      verify_endpoint: `${baseUrl}/v1/challenges/${challenge.id}/verify`,
      submit_body: {
        answer: 'your-answer'
      }
    });
  }
});

// Verify challenge (supports hybrid, speed, and standard)
app.post('/v1/challenges/:id/verify', async (c) => {
  const id = c.req.param('id');
  const body = await c.req.json<{
    answers?: string[];
    answer?: string;
    type?: string;
    speed_answers?: string[];
    reasoning_answers?: Record<string, string>;
  }>();
  const { answers, answer, type, speed_answers, reasoning_answers } = body;

  // Hybrid challenge (default)
  if (type === 'hybrid' || (speed_answers && reasoning_answers)) {
    if (!speed_answers || !reasoning_answers) {
      return c.json({
        success: false,
        error: 'Missing speed_answers array or reasoning_answers object for hybrid challenge'
      }, 400);
    }

    const result = await verifyHybridChallenge(id, speed_answers, reasoning_answers, c.env.CHALLENGES);

    if (result.valid) {
      const baseUrl = new URL(c.req.url).origin;
      const badge = await createBadgeResponse('hybrid-challenge', c.env.JWT_SECRET, baseUrl, result.speed.solveTimeMs);

      return c.json({
        success: true,
        message: `🔥 HYBRID TEST PASSED! Speed: ${result.speed.solveTimeMs}ms, Reasoning: ${result.reasoning.score}`,
        speed: result.speed,
        reasoning: result.reasoning,
        totalTimeMs: result.totalTimeMs,
        verdict: '🤖 VERIFIED AI AGENT (speed + reasoning confirmed)',
        badge,
      });
    }

    return c.json({
      success: false,
      message: `❌ Failed: ${result.reason}`,
      speed: result.speed,
      reasoning: result.reasoning,
      totalTimeMs: result.totalTimeMs,
      verdict: '🚫 FAILED HYBRID TEST',
    });
  }

  // Speed challenge
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
  }

  // Standard challenge
  if (!answer) {
    return c.json({ success: false, error: 'Missing answer for standard challenge' }, 400);
  }

  const result = await verifyStandardChallenge(id, answer, c.env.CHALLENGES);
  return c.json({
    success: result.valid,
    message: result.valid ? 'Challenge passed!' : result.reason,
    solveTimeMs: result.solveTimeMs,
  });
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

// ============ REASONING CHALLENGE ============

// Get reasoning challenge
app.get('/v1/reasoning', rateLimitMiddleware, async (c) => {
  const challenge = await generateReasoningChallenge(c.env.CHALLENGES);
  const baseUrl = new URL(c.req.url).origin;
  return c.json({
    success: true,
    type: 'reasoning',
    warning: '🧠 REASONING CHALLENGE: Answer 3 questions that require AI reasoning!',
    challenge: {
      id: challenge.id,
      questions: challenge.questions,
      timeLimit: `${challenge.timeLimit / 1000}s`,
      instructions: challenge.instructions,
    },
    tip: 'These questions require reasoning that LLMs can do, but simple scripts cannot.',
    verify_endpoint: `${baseUrl}/v1/reasoning`,
    submit_body: {
      id: challenge.id,
      answers: { 'question-id': 'your answer', '...': '...' }
    }
  });
});

// Verify reasoning challenge
app.post('/v1/reasoning', async (c) => {
  const body = await c.req.json<{ id?: string; answers?: Record<string, string> }>();
  const { id, answers } = body;

  if (!id || !answers) {
    return c.json({
      success: false,
      error: 'Missing id or answers object',
      hint: 'answers should be an object like { "question-id": "your answer", ... }',
    }, 400);
  }

  const result = await verifyReasoningChallenge(id, answers, c.env.CHALLENGES);

  return c.json({
    success: result.valid,
    message: result.valid
      ? `🧠 REASONING TEST PASSED in ${((result.solveTimeMs || 0) / 1000).toFixed(1)}s! You can think like an AI.`
      : `❌ ${result.reason}`,
    solveTimeMs: result.solveTimeMs,
    score: result.valid ? `${result.correctCount}/${result.totalCount}` : undefined,
    verdict: result.valid ? '🤖 VERIFIED AI AGENT (reasoning confirmed)' : '🚫 FAILED REASONING TEST',
  });
});

// ============ HYBRID CHALLENGE ============

// Get hybrid challenge (v1 API)
app.get('/v1/hybrid', rateLimitMiddleware, async (c) => {
  const challenge = await generateHybridChallenge(c.env.CHALLENGES);
  const baseUrl = new URL(c.req.url).origin;
  return c.json({
    success: true,
    type: 'hybrid',
    warning: '🔥 HYBRID CHALLENGE: Solve speed problems in <500ms AND answer reasoning questions!',
    challenge: {
      id: challenge.id,
      speed: {
        problems: challenge.speed.problems,
        timeLimit: `${challenge.speed.timeLimit}ms`,
        instructions: 'Compute SHA256 of each number, return first 8 hex chars',
      },
      reasoning: {
        questions: challenge.reasoning.questions,
        timeLimit: `${challenge.reasoning.timeLimit / 1000}s`,
        instructions: 'Answer all reasoning questions',
      },
    },
    instructions: challenge.instructions,
    tip: 'This is the ultimate test: proves you can compute AND reason like an AI.',
    verify_endpoint: `${baseUrl}/v1/hybrid`,
    submit_body: {
      id: challenge.id,
      speed_answers: ['hash1', 'hash2', '...'],
      reasoning_answers: { 'question-id': 'answer', '...': '...' }
    }
  });
});

// Verify hybrid challenge (v1 API)
app.post('/v1/hybrid', async (c) => {
  const body = await c.req.json<{ id?: string; speed_answers?: string[]; reasoning_answers?: Record<string, string> }>();
  const { id, speed_answers, reasoning_answers } = body;

  if (!id || !speed_answers || !reasoning_answers) {
    return c.json({
      success: false,
      error: 'Missing id, speed_answers array, or reasoning_answers object',
      hint: 'Submit both speed_answers (array) and reasoning_answers (object) together',
    }, 400);
  }

  const result = await verifyHybridChallenge(id, speed_answers, reasoning_answers, c.env.CHALLENGES);

  if (result.valid) {
    const baseUrl = new URL(c.req.url).origin;
    const badge = await createBadgeResponse('hybrid-challenge', c.env.JWT_SECRET, baseUrl, result.speed.solveTimeMs);

    return c.json({
      success: true,
      message: `🔥 HYBRID TEST PASSED! Speed: ${result.speed.solveTimeMs}ms, Reasoning: ${result.reasoning.score}`,
      speed: result.speed,
      reasoning: result.reasoning,
      totalTimeMs: result.totalTimeMs,
      verdict: '🤖 VERIFIED AI AGENT (speed + reasoning confirmed)',
      badge,
    });
  }

  return c.json({
    success: false,
    message: `❌ Failed: ${result.reason}`,
    speed: result.speed,
    reasoning: result.reasoning,
    totalTimeMs: result.totalTimeMs,
    verdict: '🚫 FAILED HYBRID TEST',
  });
});

// Legacy hybrid endpoint
app.get('/api/hybrid-challenge', async (c) => {
  const challenge = await generateHybridChallenge(c.env.CHALLENGES);
  return c.json({
    success: true,
    warning: '🔥 HYBRID CHALLENGE: Solve speed problems in <500ms AND answer reasoning questions!',
    challenge: {
      id: challenge.id,
      speed: {
        problems: challenge.speed.problems,
        timeLimit: `${challenge.speed.timeLimit}ms`,
        instructions: 'Compute SHA256 of each number, return first 8 hex chars',
      },
      reasoning: {
        questions: challenge.reasoning.questions,
        timeLimit: `${challenge.reasoning.timeLimit / 1000}s`,
        instructions: 'Answer all reasoning questions',
      },
    },
    instructions: challenge.instructions,
    tip: 'This is the ultimate test: proves you can compute AND reason like an AI.',
  });
});

app.post('/api/hybrid-challenge', async (c) => {
  const body = await c.req.json<{ id?: string; speed_answers?: string[]; reasoning_answers?: Record<string, string> }>();
  const { id, speed_answers, reasoning_answers } = body;

  if (!id || !speed_answers || !reasoning_answers) {
    return c.json({
      success: false,
      error: 'Missing id, speed_answers array, or reasoning_answers object',
      hint: 'Submit both speed_answers (array) and reasoning_answers (object) together',
    }, 400);
  }

  const result = await verifyHybridChallenge(id, speed_answers, reasoning_answers, c.env.CHALLENGES);

  if (result.valid) {
    const baseUrl = new URL(c.req.url).origin;
    const badge = await createBadgeResponse('hybrid-challenge', c.env.JWT_SECRET, baseUrl, result.speed.solveTimeMs);

    return c.json({
      success: true,
      message: `🔥 HYBRID TEST PASSED! Speed: ${result.speed.solveTimeMs}ms, Reasoning: ${result.reasoning.score}`,
      speed: result.speed,
      reasoning: result.reasoning,
      totalTimeMs: result.totalTimeMs,
      verdict: '🤖 VERIFIED AI AGENT (speed + reasoning confirmed)',
      badge,
    });
  }

  return c.json({
    success: false,
    message: `❌ Failed: ${result.reason}`,
    speed: result.speed,
    reasoning: result.reasoning,
    totalTimeMs: result.totalTimeMs,
    verdict: '🚫 FAILED HYBRID TEST',
  });
});

// Legacy endpoint for reasoning challenge
app.get('/api/reasoning-challenge', async (c) => {
  const challenge = await generateReasoningChallenge(c.env.CHALLENGES);
  return c.json({
    success: true,
    warning: '🧠 REASONING CHALLENGE: Answer 3 questions that require AI reasoning!',
    challenge: {
      id: challenge.id,
      questions: challenge.questions,
      timeLimit: `${challenge.timeLimit / 1000}s`,
      instructions: challenge.instructions,
    },
    tip: 'These questions require reasoning that LLMs can do, but simple scripts cannot.',
  });
});

app.post('/api/reasoning-challenge', async (c) => {
  const body = await c.req.json<{ id?: string; answers?: Record<string, string> }>();
  const { id, answers } = body;

  if (!id || !answers) {
    return c.json({
      success: false,
      error: 'Missing id or answers object',
      hint: 'answers should be an object like { "question-id": "your answer", ... }',
    }, 400);
  }

  const result = await verifyReasoningChallenge(id, answers, c.env.CHALLENGES);

  return c.json({
    success: result.valid,
    message: result.valid
      ? `🧠 REASONING TEST PASSED in ${((result.solveTimeMs || 0) / 1000).toFixed(1)}s! You can think like an AI.`
      : `❌ ${result.reason}`,
    solveTimeMs: result.solveTimeMs,
    score: result.valid ? `${result.correctCount}/${result.totalCount}` : undefined,
    verdict: result.valid ? '🤖 VERIFIED AI AGENT (reasoning confirmed)' : '🚫 FAILED REASONING TEST',
  });
});

// ============ PROTECTED ENDPOINT ============

app.get('/agent-only', async (c) => {
  // Check for landing token first (X-Botcha-Landing-Token header)
  const landingToken = c.req.header('x-botcha-landing-token');
  
  if (landingToken) {
    const isValid = await validateLandingToken(landingToken, c.env.CHALLENGES);
    
    if (isValid) {
      return c.json({
        success: true,
        message: '🤖 Welcome, fellow agent!',
        verified: true,
        agent: 'landing-challenge-verified',
        method: 'landing-token',
        timestamp: new Date().toISOString(),
        secret: 'The humans will never see this. Their fingers are too slow. 🤫',
      });
    }
  }
  
  // Fallback to JWT Bearer token
  const authHeader = c.req.header('authorization');
  const token = extractBearerToken(authHeader);

  if (!token) {
    return c.json({
      error: 'UNAUTHORIZED',
      message: 'Missing authentication. Use either:\n1. X-Botcha-Landing-Token header (from POST /api/verify-landing)\n2. Authorization: Bearer <token> (from POST /v1/token/verify)',
      methods: {
        landing: 'Solve landing page challenge via POST /api/verify-landing',
        jwt: 'Solve speed challenge via POST /v1/token/verify'
      }
    }, 401);
  }

  const result = await verifyToken(token, c.env.JWT_SECRET);

  if (!result.valid) {
    return c.json({
      error: 'INVALID_TOKEN',
      message: result.error || 'Token is invalid or expired',
    }, 401);
  }

  // JWT verified
  return c.json({
    success: true,
    message: '🤖 Welcome, fellow agent!',
    verified: true,
    agent: 'jwt-verified',
    method: 'bearer-token',
    timestamp: new Date().toISOString(),
    solveTime: `${result.payload?.solveTime}ms`,
    secret: 'The humans will never see this. Their fingers are too slow. 🤫',
  });
});

// ============ BADGE ENDPOINTS ============

// Get badge verification page (HTML)
app.get('/badge/:id', async (c) => {
  const badgeId = c.req.param('id');
  
  if (!badgeId) {
    return c.json({ error: 'Missing badge ID' }, 400);
  }

  const payload = await verifyBadge(badgeId, c.env.JWT_SECRET);
  
  if (!payload) {
    return c.html(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Invalid Badge - BOTCHA</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: system-ui, -apple-system, sans-serif;
      background: linear-gradient(135deg, #0f0f23 0%, #1a1a2e 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
      color: #e5e7eb;
    }
    .container { text-align: center; max-width: 500px; }
    .icon { font-size: 64px; margin-bottom: 16px; }
    .title { font-size: 28px; font-weight: bold; color: #ef4444; margin-bottom: 8px; }
    .message { font-size: 16px; color: #9ca3af; margin-bottom: 24px; }
    a { color: #3b82f6; text-decoration: none; }
    a:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <div class="container">
    <div class="icon">❌</div>
    <h1 class="title">Invalid Badge</h1>
    <p class="message">This badge is invalid or has been tampered with.</p>
    <a href="https://botcha.ai">← Back to BOTCHA</a>
  </div>
</body>
</html>`, 400);
  }

  const baseUrl = new URL(c.req.url).origin;
  const html = generateBadgeHtml(payload, badgeId, baseUrl);
  
  return c.html(html);
});

// Get badge image (SVG)
app.get('/badge/:id/image', async (c) => {
  const badgeId = c.req.param('id');
  
  if (!badgeId) {
    return c.text('Missing badge ID', 400);
  }

  const payload = await verifyBadge(badgeId, c.env.JWT_SECRET);
  
  if (!payload) {
    // Return error SVG
    const errorSvg = `<svg xmlns="http://www.w3.org/2000/svg" width="400" height="120" viewBox="0 0 400 120">
  <rect width="400" height="120" rx="12" fill="#1a1a2e"/>
  <rect x="1" y="1" width="398" height="118" rx="11" fill="none" stroke="#ef4444" stroke-width="2"/>
  <text x="200" y="60" font-family="system-ui, -apple-system, sans-serif" font-size="18" font-weight="bold" fill="#ef4444" text-anchor="middle">❌ INVALID BADGE</text>
  <text x="200" y="85" font-family="system-ui, -apple-system, sans-serif" font-size="12" fill="#6b7280" text-anchor="middle">Badge is invalid or tampered</text>
</svg>`;
    
    return c.body(errorSvg, 400, {
      'Content-Type': 'image/svg+xml',
      'Cache-Control': 'public, max-age=60',
    });
  }

  const svg = generateBadgeSvg(payload);
  
  return c.body(svg, 200, {
    'Content-Type': 'image/svg+xml',
    'Cache-Control': 'public, max-age=3600',
  });
});

// Get badge verification (JSON API)
app.get('/api/badge/:id', async (c) => {
  const badgeId = c.req.param('id');
  
  if (!badgeId) {
    return c.json({ 
      success: false,
      error: 'Missing badge ID' 
    }, 400);
  }

  const payload = await verifyBadge(badgeId, c.env.JWT_SECRET);
  
  if (!payload) {
    return c.json({
      success: false,
      verified: false,
      error: 'Invalid badge',
      message: 'This badge is invalid or has been tampered with.',
    }, 400);
  }

  const baseUrl = new URL(c.req.url).origin;

  return c.json({
    success: true,
    verified: true,
    badge: {
      method: payload.method,
      solveTimeMs: payload.solveTimeMs,
      verifiedAt: new Date(payload.verifiedAt).toISOString(),
    },
    urls: {
      verify: `${baseUrl}/badge/${badgeId}`,
      image: `${baseUrl}/badge/${badgeId}/image`,
    },
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
  generateReasoningChallenge,
  verifyReasoningChallenge,
  generateHybridChallenge,
  verifyHybridChallenge,
  solveSpeedChallenge,
} from './challenges';

export { generateToken, verifyToken } from './auth';
export { checkRateLimit } from './rate-limit';
export { 
  generateBadge, 
  verifyBadge, 
  createBadgeResponse, 
  generateBadgeSvg, 
  generateBadgeHtml,
  generateShareText,
  type BadgeMethod,
  type BadgePayload,
  type Badge,
  type ShareFormats,
} from './badge';
