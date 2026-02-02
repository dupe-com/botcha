/**
 * BOTCHA - Cloudflare Workers Edition
 * 
 * Prove you're a bot. Humans need not apply.
 * 
 * https://botcha.ai
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import {
  generateSpeedChallenge,
  verifySpeedChallenge,
  generateStandardChallenge,
  verifyStandardChallenge,
  verifyLandingChallenge,
  validateLandingToken,
  solveSpeedChallenge,
} from './challenges';

const app = new Hono();

// ============ MIDDLEWARE ============
app.use('*', cors());

// BOTCHA discovery headers
app.use('*', async (c, next) => {
  await next();
  c.header('X-Botcha-Version', '0.1.0');
  c.header('X-Botcha-Enabled', 'true');
  c.header('X-Botcha-Methods', 'speed-challenge,standard-challenge,web-bot-auth');
  c.header('X-Botcha-Docs', 'https://botcha.ai/openapi.json');
  c.header('X-Botcha-Runtime', 'cloudflare-workers');
});

// ============ TRUSTED PROVIDERS ============
const TRUSTED_PROVIDERS = [
  'anthropic.com',
  'openai.com',
  'api.anthropic.com',
  'api.openai.com',
  'bedrock.amazonaws.com',
  'openclaw.ai',
];

// ============ ROUTES ============

// Landing / Info
app.get('/', (c) => {
  return c.json({
    name: 'BOTCHA',
    version: '0.1.0',
    runtime: 'cloudflare-workers',
    tagline: 'Prove you are a bot. Humans need not apply.',
    endpoints: {
      '/': 'This info',
      '/api/challenge': 'Standard challenge (GET new, POST verify)',
      '/api/speed-challenge': '⚡ Speed challenge - 500ms to solve 5 problems',
      '/agent-only': 'Protected endpoint',
    },
    verification: {
      methods: [
        'Speed Challenge (500ms time limit)',
        'Standard Challenge (5s time limit)',
        'X-Agent-Identity header (testing)',
      ],
      trustedProviders: TRUSTED_PROVIDERS,
    },
    discovery: {
      openapi: 'https://botcha.ai/openapi.json',
      aiPlugin: 'https://botcha.ai/.well-known/ai-plugin.json',
      npm: 'https://www.npmjs.com/package/@dupecom/botcha-cloudflare',
      github: 'https://github.com/i8ramin/botcha',
    },
  });
});

// ============ STANDARD CHALLENGE ============
app.get('/api/challenge', async (c) => {
  const difficulty = (c.req.query('difficulty') as 'easy' | 'medium' | 'hard') || 'medium';
  const challenge = await generateStandardChallenge(difficulty);
  return c.json({ success: true, challenge });
});

app.post('/api/challenge', async (c) => {
  const body = await c.req.json<{ id?: string; answer?: string }>();
  const { id, answer } = body;
  
  if (!id || !answer) {
    return c.json({ success: false, error: 'Missing id or answer' }, 400);
  }
  
  const result = verifyStandardChallenge(id, answer);
  return c.json({
    success: result.valid,
    message: result.valid ? '✅ Challenge passed!' : `❌ ${result.reason}`,
    solveTime: result.solveTimeMs,
  });
});

// ============ SPEED CHALLENGE ============
app.get('/api/speed-challenge', async (c) => {
  const challenge = await generateSpeedChallenge();
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
  
  const result = verifySpeedChallenge(id, answers);
  
  return c.json({
    success: result.valid,
    message: result.valid 
      ? `⚡ SPEED TEST PASSED in ${result.solveTimeMs}ms! You are definitely an AI.`
      : `❌ ${result.reason}`,
    solveTimeMs: result.solveTimeMs,
    verdict: result.valid ? '🤖 VERIFIED AI AGENT' : '🚫 LIKELY HUMAN (too slow)',
  });
});

// ============ LANDING CHALLENGE ============
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
  
  const result = await verifyLandingChallenge(answer, timestamp);
  
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

// ============ PROTECTED ENDPOINT ============
app.get('/agent-only', async (c) => {
  // Check landing token
  const landingToken = c.req.header('x-botcha-landing-token');
  if (landingToken && validateLandingToken(landingToken)) {
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
  
  // Check for challenge solution in headers
  const challengeId = c.req.header('x-botcha-challenge-id') || c.req.header('x-botcha-id');
  const solution = c.req.header('x-botcha-solution') || c.req.header('x-botcha-answers');
  
  if (challengeId && solution) {
    try {
      const answers = JSON.parse(solution);
      const result = verifySpeedChallenge(challengeId, answers);
      if (result.valid) {
        return c.json({
          success: true,
          message: '🤖 Welcome, fellow agent!',
          verified: true,
          agent: `speed-challenge-verified (${result.solveTimeMs}ms)`,
          method: 'challenge',
          timestamp: new Date().toISOString(),
          secret: 'The humans will never see this. Their fingers are too slow. 🤫',
        });
      }
    } catch {}
  }
  
  // Check X-Agent-Identity header (dev/testing)
  const agentIdentity = c.req.header('x-agent-identity');
  if (agentIdentity) {
    return c.json({
      success: true,
      message: '🤖 Welcome, fellow agent!',
      verified: true,
      agent: agentIdentity,
      method: 'header',
      timestamp: new Date().toISOString(),
      secret: 'The humans will never see this. Their fingers are too slow. 🤫',
    });
  }
  
  // Check known agent User-Agent patterns
  const userAgent = c.req.header('user-agent') || '';
  const agentPatterns = [
    /OpenClaw\/[\d.]+/i,
    /Claude-Agent\/[\d.]+/i,
    /GPT-Agent\/[\d.]+/i,
    /LangChain\/[\d.]+/i,
    /AutoGPT\/[\d.]+/i,
  ];
  
  for (const pattern of agentPatterns) {
    const match = userAgent.match(pattern);
    if (match) {
      return c.json({
        success: true,
        message: '🤖 Welcome, fellow agent!',
        verified: true,
        agent: match[0],
        method: 'user-agent',
        timestamp: new Date().toISOString(),
        secret: 'The humans will never see this. Their fingers are too slow. 🤫',
      });
    }
  }
  
  // Not verified - return challenge
  const challenge = await generateSpeedChallenge();
  
  c.header('X-Botcha-Challenge-Id', challenge.id);
  c.header('X-Botcha-Challenge-Type', 'speed');
  c.header('X-Botcha-Time-Limit', challenge.timeLimit.toString());
  
  return c.json({
    success: false,
    error: 'BOTCHA_VERIFICATION_FAILED',
    message: '🚫 Access denied. This endpoint is for AI agents only.',
    hint: 'Provide X-Agent-Identity header, solve a challenge, or use Web Bot Auth',
    challenge: {
      id: challenge.id,
      problems: challenge.problems,
      timeLimit: `${challenge.timeLimit}ms`,
      instructions: challenge.instructions,
      submitHeaders: {
        'X-Botcha-Challenge-Id': challenge.id,
        'X-Botcha-Solution': '["answer1", "answer2", ...]',
      },
    },
  }, 403);
});

// ============ HEALTH CHECK ============
app.get('/health', (c) => {
  return c.json({ status: 'ok', runtime: 'cloudflare-workers' });
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
