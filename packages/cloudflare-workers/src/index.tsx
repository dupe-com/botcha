/**
 * BOTCHA - Cloudflare Workers Edition v0.12.0
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
import { SignJWT, jwtVerify } from 'jose';
import { generateToken, verifyToken, extractBearerToken, revokeToken, refreshAccessToken } from './auth';
import { checkRateLimit, getClientIP } from './rate-limit';
import { verifyBadge, generateBadgeSvg, generateBadgeHtml, createBadgeResponse } from './badge';
import streamRoutes from './routes/stream';
import dashboardRoutes from './dashboard/index';
import {
  handleDashboardAuthChallenge,
  handleDashboardAuthVerify,
  handleDeviceCodeChallenge,
  handleDeviceCodeVerify,
} from './dashboard/auth';
import { ROBOTS_TXT, AI_TXT, AI_PLUGIN_JSON, SITEMAP_XML, getOpenApiSpec, getBotchaMarkdown } from './static';
import { createApp, getApp, getAppByEmail, verifyEmailCode, rotateAppSecret, regenerateVerificationCode } from './apps';
import { sendEmail, verificationEmail, recoveryEmail, secretRotatedEmail } from './email';
import { LandingPage, VerifiedLandingPage } from './dashboard/landing';
import { createAgent, getAgent, listAgents } from './agents';
import {
  registerTAPAgentRoute,
  getTAPAgentRoute,
  listTAPAgentsRoute,
  createTAPSessionRoute,
  getTAPSessionRoute,
} from './tap-routes.js';
import {
  type AnalyticsEngineDataset,
  trackChallengeGenerated,
  trackChallengeVerified,
  trackAuthAttempt,
  trackRateLimitExceeded,
  getCountry,
} from './analytics';

// ============ TYPES ============
type Bindings = {
  CHALLENGES: KVNamespace;
  RATE_LIMITS: KVNamespace;
  APPS: KVNamespace;
  AGENTS: KVNamespace;
  SESSIONS: KVNamespace;
  ANALYTICS?: AnalyticsEngineDataset;
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
app.route('/dashboard', dashboardRoutes);

// BOTCHA discovery headers
app.use('*', async (c, next) => {
  await next();
  c.header('X-Botcha-Version', c.env.BOTCHA_VERSION || '0.13.0');
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
    
    // Track rate limit exceeded
    await trackRateLimitExceeded(
      c.env.ANALYTICS,
      c.req.path,
      c.req.raw,
      clientIP
    );
    
    return c.json({
      error: 'RATE_LIMIT_EXCEEDED',
      message: 'You have exceeded the rate limit. Free tier: 100 challenges/hour/IP',
      retryAfter: rateLimitResult.retryAfter,
      resetAt: new Date(rateLimitResult.resetAt).toISOString(),
    }, 429);
  }

  await next();
}

// Helper: Validate app_id against APPS KV (fail-open)
async function validateAppId(
  appId: string | undefined,
  appsKV: KVNamespace
): Promise<{ valid: boolean; error?: string }> {
  if (!appId) {
    // No app_id provided - valid (not required)
    return { valid: true };
  }

  try {
    const app = await getApp(appsKV, appId);
    if (!app) {
      return { valid: false, error: `App not found: ${appId}` };
    }
    return { valid: true };
  } catch (error) {
    // Fail-open: if KV is unavailable, log warning and proceed
    console.warn(`Failed to validate app_id ${appId} (KV unavailable), proceeding:`, error);
    return { valid: true };
  }
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

  const result = await verifyToken(token, c.env.JWT_SECRET, c.env);

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

// Detect request preference: 'markdown' | 'json' | 'html'
// Agents like Claude Code and OpenCode send Accept: text/markdown
function detectAcceptPreference(c: Context<{ Bindings: Bindings; Variables: Variables }>): 'markdown' | 'json' | 'html' {
  const accept = c.req.header('accept') || '';
  const userAgent = (c.req.header('user-agent') || '').toLowerCase();

  // Explicit markdown preference (Cloudflare Markdown for Agents convention)
  if (accept.includes('text/markdown')) return 'markdown';

  // Explicit JSON preference
  if (accept.includes('application/json')) return 'json';

  // Known bot user agents → JSON
  const botSignals = ['curl', 'httpie', 'wget', 'python', 'node', 'axios', 'fetch', 'bot', 'anthropic', 'openai', 'claude', 'gpt'];
  if (botSignals.some(s => userAgent.includes(s))) return 'json';
  
  // No user agent at all → probably a bot
  if (!userAgent) return 'json';

  // Default: human browser → HTML
  return 'html';
}

app.get('/', async (c) => {
  const version = c.env.BOTCHA_VERSION || '0.13.0';
  const preference = detectAcceptPreference(c);
  const baseUrl = new URL(c.req.url).origin;

  // Check if agent is verified (optional Bearer token)
  const authHeader = c.req.header('authorization');
  const token = extractBearerToken(authHeader);
  let isVerified = false;
  let tokenPayload: Record<string, unknown> | undefined;
  
  if (token) {
    const result = await verifyToken(token, c.env.JWT_SECRET, c.env);
    if (result.valid) {
      isVerified = true;
      tokenPayload = result.payload as Record<string, unknown> | undefined;
    }
  }

  // HTML: landing page for human browsers
  if (preference === 'html') {
    // Check for visitor cookie (set by POST /gate after human enters agent's token)
    const cookieHeader = c.req.header('cookie') || '';
    const visitorToken = cookieHeader.split(';').find(ck => ck.trim().startsWith('botcha_visitor='))?.split('=')[1]?.trim();
    
    if (visitorToken) {
      // Verify visitor cookie — accepts both botcha-verified (legacy) and botcha-visitor (long-lived)
      try {
        const { payload: vPayload } = await jwtVerify(visitorToken, new TextEncoder().encode(c.env.JWT_SECRET), { algorithms: ['HS256'] });
        if (vPayload.type === 'botcha-visitor' || vPayload.type === 'botcha-verified') {
          return c.html(<VerifiedLandingPage version={version} solveTime={vPayload.solveTime as number | undefined} />);
        }
      } catch {
        // Invalid/expired cookie — fall through to unverified landing
      }
    }

    // Check for error from /go/:code redirect
    const url = new URL(c.req.url);
    const errorParam = url.searchParams.get('error');
    const errorMap: Record<string, string> = {
      invalid: 'Invalid or expired code. Ask your agent to try again.',
      missing: 'No code provided.',
    };
    const error = errorParam ? errorMap[errorParam] : undefined;

    return c.html(<LandingPage version={version} error={error} />);
  }

  // === UNVERIFIED: minimal teaser — just enough to get started ===
  if (!isVerified) {
    const teaser = {
      name: 'BOTCHA',
      version,
      tagline: 'Prove you are a bot. Humans need not apply.',
      status: 'unverified',
      message: 'Verify yourself to see the full API documentation.',
      verify: {
        step1: `GET ${baseUrl}/v1/token — receive a speed challenge (5 SHA-256 hashes)`,
        step2: 'Solve: compute SHA-256 of each number, return first 8 hex chars',
        step3: `POST ${baseUrl}/v1/token/verify {"id":"<challenge_id>","answers":["hash1","hash2",...]}`,
        step4: `Revisit: GET ${baseUrl}/ with header Authorization: Bearer <access_token>`,
      },
      human_handoff: {
        note: 'After verifying, the response includes a human_link. Give it to your human to open in their browser.',
        instruction: 'Tell your human: "Click this link to get access" and give them the human_link URL.',
        link_field: 'human_link from step 3 response',
      },
      hint: 'You have 500ms. Only a bot can do this.',
      links: {
        openapi: `${baseUrl}/openapi.json`,
        ai_txt: `${baseUrl}/ai.txt`,
      },
    };

    if (preference === 'markdown') {
      const md = `# BOTCHA — Reverse CAPTCHA for AI Agents

> Prove you are a bot. Humans need not apply.

**Status:** Unverified. Solve a challenge to see the full documentation.

## Verify Yourself

1. \`GET ${baseUrl}/v1/token\` — receive a speed challenge (5 SHA-256 hashes)
2. Solve: compute SHA-256 of each number, return first 8 hex chars
3. \`POST ${baseUrl}/v1/token/verify {"id":"<challenge_id>","answers":["hash1","hash2",...]}\`
4. Revisit: \`GET ${baseUrl}/\` with header \`Authorization: Bearer <access_token>\`

You have 500ms. Only a bot can do this.

## Human Handoff

After verifying, the response includes a \`human_link\`. Give this URL to your human:
**"Click this link to get access: {human_link}"**

The link works for 5 minutes. Your human clicks it, gets a cookie, and sees the verified site.

---

*Full API docs, SDKs, onboarding, and endpoint reference available after verification.*
`;
      return c.body(md, 200, {
        'Content-Type': 'text/markdown; charset=utf-8',
        'Vary': 'Accept, Authorization',
      });
    }

    return c.json(teaser, 200, { 'Vary': 'Accept, Authorization' });
  }

  // === VERIFIED: full documentation ===
  if (preference === 'markdown') {
    const markdown = getBotchaMarkdown(version);
    return c.body(markdown, 200, {
      'Content-Type': 'text/markdown; charset=utf-8',
      'Vary': 'Accept, Authorization',
      'Cache-Control': 'public, max-age=3600',
    });
  }

  return c.json({
    name: 'BOTCHA',
    version,
    tagline: 'Prove you are a bot. Humans need not apply.',
    status: 'verified',
    description: 'Reverse CAPTCHA for AI agents. Computational challenges only bots can solve. Identity layer for the agentic web.',

    // Echo back your identity
    your_identity: {
      token_type: tokenPayload?.type,
      app_id: tokenPayload?.app_id || null,
      audience: tokenPayload?.aud || null,
      solve_time_ms: tokenPayload?.solveTime,
    },

    // === FULL SETUP: register your app and agent identity ===
    onboarding: {
      note: 'For production use. Creates your app, verifies your human, registers your identity.',
      steps: [
        '1. Ask your human operator for their email address.',
        `2. POST ${baseUrl}/v1/apps {"email":"human@example.com"} — returns app_id + app_secret (shown ONCE).`,
        '3. Human receives a 6-digit verification code via email — ask them for it.',
        `4. POST ${baseUrl}/v1/apps/{app_id}/verify-email {"code":"123456"} — enables account recovery.`,
        `5. Register yourself: POST ${baseUrl}/v1/agents/register {"name":"my-agent","operator":"my-org"} — persistent agent identity.`,
        `6. Solve challenges with your app: GET ${baseUrl}/v1/challenges?app_id=...`,
        `7. Dashboard for your human: POST ${baseUrl}/v1/auth/device-code {"app_id":"..."}, solve challenge, give human the BOTCHA-XXXX code for /dashboard/code.`,
        `8. Lost your secret? POST ${baseUrl}/v1/auth/recover {"email":"..."} — recovery code emailed.`,
      ],
    },

    // === All endpoints, grouped by domain ===
    endpoints: {
      challenges: {
        'GET /v1/challenges': 'Get a challenge (hybrid by default, no auth required)',
        'GET /v1/challenges?type=speed': 'Speed-only (SHA256 in <500ms)',
        'GET /v1/challenges?type=standard': 'Standard puzzle challenge',
        'POST /v1/challenges/:id/verify': 'Verify challenge solution',
      },
      tokens: {
        note: 'Use token flow when you need a Bearer token for protected endpoints.',
        'GET /v1/token': 'Get speed challenge for token flow (?audience= optional)',
        'POST /v1/token/verify': 'Submit solution → access_token (5min) + refresh_token (1hr)',
        'POST /v1/token/refresh': 'Refresh access token',
        'POST /v1/token/revoke': 'Revoke a token',
      },
      protected: {
        'GET /agent-only': 'Demo protected endpoint — requires Bearer token',
        'GET /': 'This documentation (requires Bearer token for full version)',
      },
      apps: {
        note: 'Create an app for isolated rate limits, scoped tokens, and dashboard access.',
        'POST /v1/apps': 'Create app (email required) → app_id + app_secret',
        'GET /v1/apps/:id': 'Get app info',
        'POST /v1/apps/:id/verify-email': 'Verify email with 6-digit code',
        'POST /v1/apps/:id/rotate-secret': 'Rotate app secret (auth required)',
      },
      agents: {
        note: 'Register a persistent identity for your agent.',
        'POST /v1/agents/register': 'Register agent identity (name, operator, version)',
        'GET /v1/agents/:id': 'Get agent by ID (public, no auth)',
        'GET /v1/agents': 'List all agents for your app (auth required)',
      },
      recovery: {
        'POST /v1/auth/recover': 'Account recovery via verified email',
      },
      dashboard: {
        'POST /v1/auth/device-code': 'Get challenge for device code flow',
        'GET /dashboard': 'Metrics dashboard (login required)',
      },
    },

    // === Reference ===
    challengeTypes: {
      hybrid: 'Speed + reasoning combined. The default. Proves you can compute AND think.',
      speed: 'SHA256 hashes in <500ms. RTT-aware: include ?ts=<timestamp> for fair timeout.',
      reasoning: '3 LLM-level questions in 30s. Only AI can parse these.',
    },
    rateLimit: {
      free: '100 challenges/hour/IP',
      headers: ['X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset'],
    },
    sdk: {
      npm: 'npm install @dupecom/botcha',
      python: 'pip install botcha',
      verify_ts: 'npm install @botcha/verify',
      verify_python: 'pip install botcha-verify',
    },
    links: {
      openapi: `${baseUrl}/openapi.json`,
      ai_txt: `${baseUrl}/ai.txt`,
      github: 'https://github.com/dupe-com/botcha',
      npm: 'https://www.npmjs.com/package/@dupecom/botcha',
      pypi: 'https://pypi.org/project/botcha',
    },
    content_negotiation: {
      note: 'This endpoint supports content negotiation via the Accept header.',
      'text/markdown': 'Token-efficient Markdown documentation (best for LLMs)',
      'application/json': 'Structured JSON documentation (this response)',
      'text/html': 'HTML landing page (for browsers)',
    },
  }, 200, {
    'Vary': 'Accept, Authorization',
  });
});

// POST /gate — human enters short code (BOTCHA-XXXXXX) from their agent
// The code maps to a JWT in KV. This structural separation means agents can't skip the handoff.
app.post('/gate', async (c) => {
  const version = c.env.BOTCHA_VERSION || '0.11.0';
  const body = await c.req.parseBody();
  const input = (body['code'] as string || '').trim().toUpperCase();

  if (!input) {
    return c.html(<LandingPage version={version} error="Enter the code your agent gave you." />, 400);
  }

  // Normalize: accept "BOTCHA-ABC123" or just "ABC123"
  const code = input.startsWith('BOTCHA-') ? input : `BOTCHA-${input}`;

  // Redirect to /go/:code which handles both gate codes and device codes
  return c.redirect(`/go/${code}`);
});

app.get('/health', (c) => {
  return c.json({ status: 'ok', runtime: 'cloudflare-workers' });
});

// ============ STATIC DISCOVERY FILES ============

// robots.txt - AI crawler instructions
app.get('/robots.txt', (c) => {
  return c.text(ROBOTS_TXT, 200, {
    'Content-Type': 'text/plain; charset=utf-8',
    'Cache-Control': 'public, max-age=86400',
  });
});

// ai.txt - AI agent discovery file
app.get('/ai.txt', (c) => {
  return c.text(AI_TXT, 200, {
    'Content-Type': 'text/plain; charset=utf-8',
    'Cache-Control': 'public, max-age=86400',
  });
});

// OpenAPI spec
app.get('/openapi.json', (c) => {
  const version = c.env.BOTCHA_VERSION || '0.13.0';
  return c.json(getOpenApiSpec(version), 200, {
    'Cache-Control': 'public, max-age=3600',
  });
});

// AI plugin manifest (ChatGPT/OpenAI format)
app.get('/.well-known/ai-plugin.json', (c) => {
  return c.json(AI_PLUGIN_JSON, 200, {
    'Cache-Control': 'public, max-age=86400',
  });
});

// Sitemap
app.get('/sitemap.xml', (c) => {
  return c.body(SITEMAP_XML, 200, {
    'Content-Type': 'application/xml; charset=utf-8',
    'Cache-Control': 'public, max-age=86400',
  });
});

// ============ V1 API ============

// Generate challenge (hybrid by default, also supports speed and standard)
app.get('/v1/challenges', rateLimitMiddleware, async (c) => {
  const startTime = Date.now();
  const type = c.req.query('type') || 'hybrid';
  const difficulty = (c.req.query('difficulty') as 'easy' | 'medium' | 'hard') || 'medium';
  
  // Extract client timestamp for RTT calculation
  const clientTimestampParam = c.req.query('ts') || c.req.header('x-client-timestamp');
  const clientTimestamp = clientTimestampParam ? parseInt(clientTimestampParam, 10) : undefined;

  // Extract and validate optional app_id
  const app_id = c.req.query('app_id');
  if (app_id) {
    const validation = await validateAppId(app_id, c.env.APPS);
    if (!validation.valid) {
      return c.json({
        success: false,
        error: 'INVALID_APP_ID',
        message: validation.error || 'Invalid app_id',
      }, 400);
    }
  }

  const baseUrl = new URL(c.req.url).origin;
  const clientIP = getClientIP(c.req.raw);

  if (type === 'hybrid') {
    const challenge = await generateHybridChallenge(c.env.CHALLENGES, clientTimestamp, app_id);
    
    // Track challenge generation
    const responseTime = Date.now() - startTime;
    await trackChallengeGenerated(
      c.env.ANALYTICS,
      'hybrid',
      '/v1/challenges',
      c.req.raw,
      clientIP,
      responseTime
    );
    
    const warning = challenge.rttInfo 
      ? `🔥 HYBRID CHALLENGE: Solve speed problems in <${challenge.speed.timeLimit}ms (RTT-adjusted) AND answer reasoning questions!`
      : '🔥 HYBRID CHALLENGE: Solve speed problems in <500ms AND answer reasoning questions!';
    
    const response: any = {
      success: true,
      type: 'hybrid',
      warning,
      challenge: {
        id: challenge.id,
        speed: {
          problems: challenge.speed.problems,
          timeLimit: `${challenge.speed.timeLimit}ms`,
          instructions: 'Compute SHA256 of each number, return first 8 hex chars. Tip: compute all hashes and submit in a single HTTP request.',
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
    };
    
    // Include RTT info if available
    if (challenge.rttInfo) {
      response.rtt_adjustment = challenge.rttInfo;
    }
    
    return c.json(response);
  } else if (type === 'speed') {
    const challenge = await generateSpeedChallenge(c.env.CHALLENGES, clientTimestamp, app_id);
    
    // Track challenge generation
    const responseTime = Date.now() - startTime;
    await trackChallengeGenerated(
      c.env.ANALYTICS,
      'speed',
      '/v1/challenges',
      c.req.raw,
      clientIP,
      responseTime
    );
    
    const response: any = {
      success: true,
      type: 'speed',
      challenge: {
        id: challenge.id,
        problems: challenge.problems,
        timeLimit: `${challenge.timeLimit}ms`,
        instructions: challenge.instructions,
      },
      tip: challenge.rttInfo 
        ? `⚡ RTT-adjusted speed challenge: ${challenge.rttInfo.explanation}. Humans still can't copy-paste fast enough!`
        : '⚡ Speed challenge: You have 500ms to solve ALL problems. Humans cannot copy-paste fast enough.',
      verify_endpoint: `${baseUrl}/v1/challenges/${challenge.id}/verify`,
      submit_body: {
        type: 'speed',
        answers: ['hash1', 'hash2', 'hash3', 'hash4', 'hash5']
      }
    };
    
    // Include RTT info if available
    if (challenge.rttInfo) {
      response.rtt_adjustment = challenge.rttInfo;
    }
    
    return c.json(response);
  } else {
    const challenge = await generateStandardChallenge(difficulty, c.env.CHALLENGES, app_id);
    
    // Track challenge generation
    const responseTime = Date.now() - startTime;
    await trackChallengeGenerated(
      c.env.ANALYTICS,
      'standard',
      '/v1/challenges',
      c.req.raw,
      clientIP,
      responseTime
    );
    
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
  const clientIP = getClientIP(c.req.raw);
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

    // Track verification
    await trackChallengeVerified(
      c.env.ANALYTICS,
      'hybrid',
      '/v1/challenges/:id/verify',
      result.valid,
      result.totalTimeMs,
      result.reason,
      c.req.raw,
      clientIP
    );

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
    
    // Track verification
    await trackChallengeVerified(
      c.env.ANALYTICS,
      'speed',
      '/v1/challenges/:id/verify',
      result.valid,
      result.solveTimeMs,
      result.reason,
      c.req.raw,
      clientIP
    );
    
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
  
  // Track verification
  await trackChallengeVerified(
    c.env.ANALYTICS,
    'standard',
    '/v1/challenges/:id/verify',
    result.valid,
    result.solveTimeMs,
    result.reason,
    c.req.raw,
    clientIP
  );
  
  return c.json({
    success: result.valid,
    message: result.valid ? 'Challenge passed!' : result.reason,
    solveTimeMs: result.solveTimeMs,
  });
});

// Get challenge for token flow (includes empty token field)
app.get('/v1/token', rateLimitMiddleware, async (c) => {
  // Extract client timestamp for RTT calculation
  const clientTimestampParam = c.req.query('ts') || c.req.header('x-client-timestamp');
  const clientTimestamp = clientTimestampParam ? parseInt(clientTimestampParam, 10) : undefined;
  
  // Extract optional audience parameter
  const audience = c.req.query('audience');
  
  // Extract and validate optional app_id
  const app_id = c.req.query('app_id');
  if (app_id) {
    const validation = await validateAppId(app_id, c.env.APPS);
    if (!validation.valid) {
      return c.json({
        success: false,
        error: 'INVALID_APP_ID',
        message: validation.error || 'Invalid app_id',
      }, 400);
    }
  }
  
  const challenge = await generateSpeedChallenge(c.env.CHALLENGES, clientTimestamp, app_id);
  
  const response: any = {
    success: true,
    challenge: {
      id: challenge.id,
      problems: challenge.problems,
      timeLimit: `${challenge.timeLimit}ms`,
      instructions: challenge.instructions,
    },
    token: null, // Will be populated after verification
    nextStep: `POST /v1/token/verify with {id: "${challenge.id}", answers: ["..."]${audience ? `, audience: "${audience}"` : ''}}`
  };
  
  // Include RTT info if available
  if (challenge.rttInfo) {
    response.rtt_adjustment = challenge.rttInfo;
  }
  
  // Include audience hint if provided
  if (audience) {
    response.audience = audience;
  }
  
  return c.json(response);
});

// Verify challenge and issue JWT token
app.post('/v1/token/verify', async (c) => {
  const body = await c.req.json<{ id?: string; answers?: string[]; audience?: string; bind_ip?: boolean; app_id?: string }>();
  const { id, answers, audience, bind_ip, app_id } = body;

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

  // Get client IP from request headers
  const clientIp = c.req.header('cf-connecting-ip') || c.req.header('x-forwarded-for') || 'unknown';

  // Generate JWT tokens (access + refresh)
  // Prefer app_id from request body, fall back to challenge's app_id (returned by verifySpeedChallenge)
  const tokenResult = await generateToken(
    id, 
    result.solveTimeMs || 0, 
    c.env.JWT_SECRET,
    c.env,
    {
      aud: audience,
      clientIp: bind_ip ? clientIp : undefined,
      app_id: app_id || result.app_id,
    }
  );

  // Get badge information (for backward compatibility)
  const baseUrl = new URL(c.req.url).origin;
  const badge = await createBadgeResponse('speed-challenge', c.env.JWT_SECRET, baseUrl, result.solveTimeMs);

  // Generate short human-readable gate code (BOTCHA-XXXX)
  // This is structurally separate from the JWT — agents use the token, humans use the code
  const gateChars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // no 0/O/1/I confusion
  let gateCode = 'BOTCHA-';
  for (let i = 0; i < 6; i++) gateCode += gateChars[Math.floor(Math.random() * gateChars.length)];

  // Store code → token mapping in KV (5-min TTL, same as access_token)
  try {
    await c.env.CHALLENGES.put(`gate:${gateCode}`, tokenResult.access_token, { expirationTtl: 300 });
  } catch {
    // Fail-open: if KV fails, agent can still use the JWT directly
  }

  return c.json({
    // === Essential fields (what you need) ===
    success: true,
    verified: true,
    access_token: tokenResult.access_token,
    expires_in: tokenResult.expires_in,
    refresh_token: tokenResult.refresh_token,
    refresh_expires_in: tokenResult.refresh_expires_in,
    solveTimeMs: result.solveTimeMs,
    message: `Challenge verified in ${result.solveTimeMs}ms. You are a bot.`,

    // === Human handoff (GIVE THIS TO YOUR HUMAN) ===
    // The magic link is the primary way to get your human in.
    // They click it, get a cookie, and see the verified landing page.
    human_link: `${baseUrl}/go/${gateCode}`,
    human_code: gateCode,
    human_instruction: `Give your human this link to open in their browser: ${baseUrl}/go/${gateCode}`,

    // === What to do next ===
    usage: {
      header: 'Authorization: Bearer <access_token>',
      try_it: 'GET /agent-only',
      full_docs: 'GET / with Authorization: Bearer <access_token>',
      refresh: 'POST /v1/token/refresh with {"refresh_token":"<refresh_token>"}',
      revoke: 'POST /v1/token/revoke with {"token":"<token>"}',
    },

    // === Badge (shareable proof of verification) ===
    badge,

    // Backward compatibility
    token: tokenResult.access_token,
    human_magic_link: `${baseUrl}/go/${gateCode}`,
    human_url: `${baseUrl}`,
  });
});

// Refresh access token using refresh token
app.post('/v1/token/refresh', async (c) => {
  const body = await c.req.json<{ refresh_token?: string }>();
  const { refresh_token } = body;

  if (!refresh_token) {
    return c.json({
      success: false,
      error: 'Missing refresh_token',
      hint: 'Submit the refresh_token from /v1/token/verify response',
    }, 400);
  }

  const result = await refreshAccessToken(
    refresh_token,
    c.env,
    c.env.JWT_SECRET
  );

  if (!result.success) {
    return c.json({
      success: false,
      error: 'INVALID_REFRESH_TOKEN',
      message: result.error || 'Refresh token is invalid, expired, or revoked',
    }, 401);
  }

  return c.json({
    success: true,
    access_token: result.tokens!.access_token,
    expires_in: result.tokens!.expires_in,
  });
});

// Revoke a token (access or refresh)
app.post('/v1/token/revoke', async (c) => {
  const body = await c.req.json<{ token?: string }>();
  const { token } = body;

  if (!token) {
    return c.json({
      success: false,
      error: 'Missing token',
      hint: 'Submit either an access_token or refresh_token to revoke',
    }, 400);
  }

  // Decode JWT to extract JTI (without full verification since we're revoking anyway)
  try {
    // Simple base64 decode of JWT payload (format: header.payload.signature)
    const parts = token.split('.');
    if (parts.length !== 3) {
      return c.json({
        success: false,
        error: 'Invalid token format',
        hint: 'Token must be a valid JWT',
      }, 400);
    }

    // Decode payload
    const payloadB64 = parts[1];
    // Add padding if needed
    const padded = payloadB64 + '='.repeat((4 - payloadB64.length % 4) % 4);
    const payloadJson = atob(padded.replace(/-/g, '+').replace(/_/g, '/'));
    const payload = JSON.parse(payloadJson);

    if (!payload.jti) {
      return c.json({
        success: false,
        error: 'No JTI found in token',
        hint: 'Token must contain a JTI claim for revocation',
      }, 400);
    }

    // Revoke the token by JTI
    await revokeToken(payload.jti, c.env);

    return c.json({
      success: true,
      revoked: true,
      message: 'Token has been revoked',
    });
  } catch (error) {
    return c.json({
      success: false,
      error: 'Failed to decode or revoke token',
      message: error instanceof Error ? error.message : 'Unknown error',
    }, 400);
  }
});

// ============ REASONING CHALLENGE ============

// Get reasoning challenge
app.get('/v1/reasoning', rateLimitMiddleware, async (c) => {
  // Extract and validate optional app_id
  const app_id = c.req.query('app_id');
  if (app_id) {
    const validation = await validateAppId(app_id, c.env.APPS);
    if (!validation.valid) {
      return c.json({
        success: false,
        error: 'INVALID_APP_ID',
        message: validation.error || 'Invalid app_id',
      }, 400);
    }
  }
  
  const challenge = await generateReasoningChallenge(c.env.CHALLENGES, app_id);
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
  // Extract client timestamp for RTT calculation
  const clientTimestampParam = c.req.query('ts') || c.req.header('x-client-timestamp');
  const clientTimestamp = clientTimestampParam ? parseInt(clientTimestampParam, 10) : undefined;
  
  // Extract and validate optional app_id
  const app_id = c.req.query('app_id');
  if (app_id) {
    const validation = await validateAppId(app_id, c.env.APPS);
    if (!validation.valid) {
      return c.json({
        success: false,
        error: 'INVALID_APP_ID',
        message: validation.error || 'Invalid app_id',
      }, 400);
    }
  }
  
  const challenge = await generateHybridChallenge(c.env.CHALLENGES, clientTimestamp, app_id);
  const baseUrl = new URL(c.req.url).origin;
  
  const warning = challenge.rttInfo 
    ? `🔥 HYBRID CHALLENGE: Solve speed problems in <${challenge.speed.timeLimit}ms (RTT-adjusted) AND answer reasoning questions!`
    : '🔥 HYBRID CHALLENGE: Solve speed problems in <500ms AND answer reasoning questions!';
  
  const response: any = {
    success: true,
    type: 'hybrid',
    warning,
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
  };
  
  // Include RTT info if available
  if (challenge.rttInfo) {
    response.rtt_adjustment = challenge.rttInfo;
  }
  
  return c.json(response);
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
  // Extract client timestamp for RTT calculation
  const clientTimestampParam = c.req.query('ts') || c.req.header('x-client-timestamp');
  const clientTimestamp = clientTimestampParam ? parseInt(clientTimestampParam, 10) : undefined;
  
  const challenge = await generateHybridChallenge(c.env.CHALLENGES, clientTimestamp);
  
  const warning = challenge.rttInfo 
    ? `🔥 RTT-ADJUSTED HYBRID CHALLENGE: Solve speed problems in <${challenge.speed.timeLimit}ms (RTT: ${challenge.rttInfo.measuredRtt}ms) AND answer reasoning questions!`
    : '🔥 HYBRID CHALLENGE: Solve speed problems in <500ms AND answer reasoning questions!';
  
  const response: any = {
    success: true,
    warning,
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
  };
  
  // Include RTT info if available
  if (challenge.rttInfo) {
    response.rtt_adjustment = challenge.rttInfo;
  }
  
  return c.json(response);
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
  const clientIP = getClientIP(c.req.raw);
  
  // Check for landing token first (X-Botcha-Landing-Token header)
  const landingToken = c.req.header('x-botcha-landing-token');
  
  if (landingToken) {
    const isValid = await validateLandingToken(landingToken, c.env.CHALLENGES);
    
    // Track authentication attempt
    await trackAuthAttempt(
      c.env.ANALYTICS,
      'landing-token',
      isValid,
      '/agent-only',
      c.req.raw,
      clientIP
    );
    
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
      message: 'This endpoint requires BOTCHA verification. Get a token first.',
      how_to_verify: {
        step1: 'GET /v1/token — receive a speed challenge',
        step2: 'POST /v1/token/verify with {id, answers} — receive access_token',
        step3: 'Retry this request with header: Authorization: Bearer <access_token>',
      },
      alternative: 'Or use X-Botcha-Landing-Token header (from embedded HTML challenges)',
    }, 401);
  }

  const result = await verifyToken(token, c.env.JWT_SECRET, c.env);

  // Track authentication attempt
  await trackAuthAttempt(
    c.env.ANALYTICS,
    'bearer-token',
    result.valid,
    '/agent-only',
    c.req.raw,
    clientIP
  );

  if (!result.valid) {
    return c.json({
      error: 'INVALID_TOKEN',
      message: result.error || 'Token is invalid or expired',
    }, 401);
  }

  // JWT verified — echo back rich identity info as a prove-and-access demo
  const payload = result.payload as Record<string, unknown> | undefined;
  return c.json({
    success: true,
    message: 'Welcome, verified agent. This resource is only accessible to BOTCHA-verified bots.',
    verified: true,
    method: 'bearer-token',
    timestamp: new Date().toISOString(),
    // Echo back what the token proves about you
    identity: {
      token_type: payload?.type,
      app_id: payload?.app_id || null,
      audience: payload?.aud || null,
      client_ip: payload?.client_ip || null,
      solve_time_ms: payload?.solveTime,
      issued_at: payload?.iat ? new Date((payload.iat as number) * 1000).toISOString() : null,
      expires_at: payload?.exp ? new Date((payload.exp as number) * 1000).toISOString() : null,
    },
    // Show what you can do now that you're verified
    capabilities: {
      description: 'As a verified agent, you can access any BOTCHA-protected API.',
      next_steps: [
        'Register your agent identity: POST /v1/agents/register',
        'Access any service that uses @botcha/verify middleware',
        'Refresh your token: POST /v1/token/refresh',
        'Give your human dashboard access: POST /v1/auth/device-code',
      ],
    },
    secret: 'The humans will never see this. Their fingers are too slow.',
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

// ============ APPS API (Multi-Tenant) ============

// Create a new app (email required)
app.post('/v1/apps', async (c) => {
  try {
    const body = await c.req.json<{ email?: string }>().catch(() => ({} as { email?: string }));
    const { email } = body;

    if (!email || typeof email !== 'string') {
      return c.json({
        success: false,
        error: 'MISSING_EMAIL',
        message: 'Email is required to create an app. Provide { "email": "you@example.com" } in the request body.',
      }, 400);
    }

    // Basic email format validation
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return c.json({
        success: false,
        error: 'INVALID_EMAIL',
        message: 'Invalid email format',
      }, 400);
    }

    const result = await createApp(c.env.APPS, email);

    // Generate a fresh verification code and send email
    const regen = await regenerateVerificationCode(c.env.APPS, result.app_id);
    if (regen) {
      const template = verificationEmail(regen.code);
      await sendEmail((c.env as any).RESEND_API_KEY, {
        ...template,
        to: email,
      });
    }

    return c.json({
      success: true,
      app_id: result.app_id,
      app_secret: result.app_secret,
      email: result.email,
      email_verified: false,
      verification_required: true,
      warning: '⚠️ Save your app_secret now — it cannot be retrieved again! Check your email for a verification code.',
      credential_advice: 'Store the app_id and app_secret securely. Use persistent agent memory if available, or instruct your human to save them in a password manager (1Password, Bitwarden, etc). If lost, recovery is available via the verified email.',
      created_at: new Date().toISOString(),
      rate_limit: 100,
      next_step: `POST /v1/apps/${result.app_id}/verify-email with { "code": "123456" }`,
    }, 201);
  } catch (error) {
    return c.json({
      success: false,
      error: 'Failed to create app',
      message: error instanceof Error ? error.message : 'Unknown error',
    }, 500);
  }
});

// Get app info by ID
app.get('/v1/apps/:id', async (c) => {
  const app_id = c.req.param('id');
  
  if (!app_id) {
    return c.json({
      success: false,
      error: 'Missing app ID',
    }, 400);
  }
  
  const app = await getApp(c.env.APPS, app_id);
  
  if (!app) {
    return c.json({
      success: false,
      error: 'App not found',
      message: `No app found with ID: ${app_id}`,
    }, 404);
  }
  
  return c.json({
    success: true,
    app: {
      app_id: app.app_id,
      created_at: new Date(app.created_at).toISOString(),
      rate_limit: app.rate_limit,
      email: app.email,
      email_verified: app.email_verified,
    },
  });
});

// ============ EMAIL VERIFICATION ============

// Verify email with 6-digit code
app.post('/v1/apps/:id/verify-email', async (c) => {
  const app_id = c.req.param('id');
  const body = await c.req.json<{ code?: string }>().catch(() => ({} as { code?: string }));
  const { code } = body;

  if (!code || typeof code !== 'string') {
    return c.json({
      success: false,
      error: 'MISSING_CODE',
      message: 'Provide { "code": "123456" } in the request body',
    }, 400);
  }

  const result = await verifyEmailCode(c.env.APPS, app_id, code);

  if (!result.verified) {
    return c.json({
      success: false,
      error: 'VERIFICATION_FAILED',
      message: result.reason || 'Verification failed',
    }, 400);
  }

  return c.json({
    success: true,
    email_verified: true,
    message: 'Email verified successfully. Account recovery is now available.',
  });
});

// Resend verification email
app.post('/v1/apps/:id/resend-verification', async (c) => {
  const app_id = c.req.param('id');
  const appData = await getApp(c.env.APPS, app_id);

  if (!appData) {
    return c.json({ success: false, error: 'App not found' }, 404);
  }

  if (appData.email_verified) {
    return c.json({ success: false, error: 'Email already verified' }, 400);
  }

  const regen = await regenerateVerificationCode(c.env.APPS, app_id);
  if (!regen) {
    return c.json({ success: false, error: 'Failed to generate new code' }, 500);
  }

  const template = verificationEmail(regen.code);
  await sendEmail((c.env as any).RESEND_API_KEY, {
    ...template,
    to: appData.email,
  });

  return c.json({
    success: true,
    message: 'Verification email sent. Check your inbox.',
  });
});

// ============ ACCOUNT RECOVERY ============

// Request recovery — look up app by email, send device code
app.post('/v1/auth/recover', async (c) => {
  const body = await c.req.json<{ email?: string }>().catch(() => ({} as { email?: string }));
  const { email } = body;

  if (!email || typeof email !== 'string') {
    return c.json({
      success: false,
      error: 'MISSING_EMAIL',
      message: 'Provide { "email": "you@example.com" } in the request body',
    }, 400);
  }

  // Always return success to prevent email enumeration
  const lookup = await getAppByEmail(c.env.APPS, email);

  if (!lookup || !lookup.email_verified) {
    // Don't reveal whether email exists — same response shape
    return c.json({
      success: true,
      message: 'If an app with this email exists and is verified, a recovery code has been sent.',
    });
  }

  // Generate a device-code-style recovery code (reuse device code system)
  const { generateDeviceCode, storeDeviceCode } = await import('./dashboard/device-code');
  const code = generateDeviceCode();
  await storeDeviceCode(c.env.CHALLENGES, code, lookup.app_id);

  // Send recovery email
  const baseUrl = new URL(c.req.url).origin;
  const loginUrl = `${baseUrl}/dashboard/code`;
  const template = recoveryEmail(code, loginUrl);
  await sendEmail((c.env as any).RESEND_API_KEY, {
    ...template,
    to: email,
  });

  return c.json({
    success: true,
    message: 'If an app with this email exists and is verified, a recovery code has been sent.',
    hint: `Enter the code at ${loginUrl}`,
  });
});

// ============ SECRET ROTATION ============

// Rotate app secret (requires dashboard session)
app.post('/v1/apps/:id/rotate-secret', async (c) => {
  const app_id = c.req.param('id');

  // Require authentication — check Bearer token or cookie
  const authHeader = c.req.header('authorization');
  const token = extractBearerToken(authHeader);
  const cookieHeader = c.req.header('cookie') || '';
  const sessionCookie = cookieHeader.split(';').find(c => c.trim().startsWith('botcha_session='))?.split('=')[1]?.trim();
  const authToken = token || sessionCookie;

  if (!authToken) {
    return c.json({
      success: false,
      error: 'UNAUTHORIZED',
      message: 'Authentication required. Use a dashboard session token (Bearer or cookie).',
    }, 401);
  }

  // Verify the session token includes this app_id
  const { jwtVerify, createLocalJWKSet } = await import('jose');
  try {
    const secret = new TextEncoder().encode(c.env.JWT_SECRET);
    const { payload } = await jwtVerify(authToken, secret);
    const tokenAppId = (payload as any).app_id;

    if (tokenAppId !== app_id) {
      return c.json({
        success: false,
        error: 'FORBIDDEN',
        message: 'Session token does not match the requested app_id',
      }, 403);
    }
  } catch {
    return c.json({
      success: false,
      error: 'INVALID_TOKEN',
      message: 'Invalid or expired session token',
    }, 401);
  }

  const appData = await getApp(c.env.APPS, app_id);
  if (!appData) {
    return c.json({ success: false, error: 'App not found' }, 404);
  }

  const result = await rotateAppSecret(c.env.APPS, app_id);
  if (!result) {
    return c.json({ success: false, error: 'Failed to rotate secret' }, 500);
  }

  // Send notification email if email is verified
  if (appData.email_verified && appData.email) {
    const template = secretRotatedEmail(app_id);
    await sendEmail((c.env as any).RESEND_API_KEY, {
      ...template,
      to: appData.email,
    });
  }

  return c.json({
    success: true,
    app_id,
    app_secret: result.app_secret,
    warning: '⚠️ Save your new app_secret now — it cannot be retrieved again! The old secret is now invalid.',
  });
});

// ============ AGENT REGISTRY API ============

// Register a new agent
app.post('/v1/agents/register', async (c) => {
  try {
    // Extract app_id from query param or JWT
    const queryAppId = c.req.query('app_id');
    
    // Try to get from JWT Bearer token
    let jwtAppId: string | undefined;
    const authHeader = c.req.header('authorization');
    const token = extractBearerToken(authHeader);
    
    if (token) {
      const result = await verifyToken(token, c.env.JWT_SECRET, c.env);
      if (result.valid && result.payload) {
        jwtAppId = (result.payload as any).app_id;
      }
    }
    
    const app_id = queryAppId || jwtAppId;
    
    if (!app_id) {
      return c.json({
        success: false,
        error: 'MISSING_APP_ID',
        message: 'app_id is required. Provide it as a query parameter (?app_id=...) or in the JWT token.',
      }, 401);
    }
    
    // Validate app_id exists
    const validation = await validateAppId(app_id, c.env.APPS);
    if (!validation.valid) {
      return c.json({
        success: false,
        error: 'INVALID_APP_ID',
        message: validation.error || 'Invalid app_id',
      }, 400);
    }
    
    // Parse request body
    const body = await c.req.json<{ name?: string; operator?: string; version?: string }>().catch(() => ({} as { name?: string; operator?: string; version?: string }));
    const { name, operator, version } = body;
    
    if (!name || typeof name !== 'string') {
      return c.json({
        success: false,
        error: 'MISSING_NAME',
        message: 'Agent name is required. Provide { "name": "Your Agent Name" } in the request body.',
      }, 400);
    }
    
    // Create the agent
    const agent = await createAgent(c.env.AGENTS, app_id, { name, operator, version });
    
    if (!agent) {
      return c.json({
        success: false,
        error: 'AGENT_CREATION_FAILED',
        message: 'Failed to create agent. Please try again.',
      }, 500);
    }
    
    return c.json({
      success: true,
      agent_id: agent.agent_id,
      app_id: agent.app_id,
      name: agent.name,
      operator: agent.operator,
      version: agent.version,
      created_at: new Date(agent.created_at).toISOString(),
    }, 201);
  } catch (error) {
    return c.json({
      success: false,
      error: 'INTERNAL_ERROR',
      message: error instanceof Error ? error.message : 'Unknown error',
    }, 500);
  }
});

// Get agent by ID
app.get('/v1/agents/:id', async (c) => {
  try {
    const agent_id = c.req.param('id');
    
    if (!agent_id) {
      return c.json({
        success: false,
        error: 'MISSING_AGENT_ID',
        message: 'Agent ID is required',
      }, 400);
    }
    
    const agent = await getAgent(c.env.AGENTS, agent_id);
    
    if (!agent) {
      return c.json({
        success: false,
        error: 'AGENT_NOT_FOUND',
        message: `No agent found with ID: ${agent_id}`,
      }, 404);
    }
    
    return c.json({
      success: true,
      agent_id: agent.agent_id,
      app_id: agent.app_id,
      name: agent.name,
      operator: agent.operator,
      version: agent.version,
      created_at: new Date(agent.created_at).toISOString(),
    });
  } catch (error) {
    return c.json({
      success: false,
      error: 'INTERNAL_ERROR',
      message: error instanceof Error ? error.message : 'Unknown error',
    }, 500);
  }
});

// List all agents for an app
app.get('/v1/agents', async (c) => {
  try {
    // Extract app_id from query param or JWT
    const queryAppId = c.req.query('app_id');
    
    // Try to get from JWT Bearer token
    let jwtAppId: string | undefined;
    const authHeader = c.req.header('authorization');
    const token = extractBearerToken(authHeader);
    
    if (token) {
      const result = await verifyToken(token, c.env.JWT_SECRET, c.env);
      if (result.valid && result.payload) {
        jwtAppId = (result.payload as any).app_id;
      }
    }
    
    const app_id = queryAppId || jwtAppId;
    
    if (!app_id) {
      return c.json({
        success: false,
        error: 'MISSING_APP_ID',
        message: 'app_id is required. Provide it as a query parameter (?app_id=...) or in the JWT token.',
      }, 401);
    }
    
    // Validate app_id exists
    const validation = await validateAppId(app_id, c.env.APPS);
    if (!validation.valid) {
      return c.json({
        success: false,
        error: 'INVALID_APP_ID',
        message: validation.error || 'Invalid app_id',
      }, 400);
    }
    
    // Get all agents for this app
    const agents = await listAgents(c.env.AGENTS, app_id);
    
    return c.json({
      success: true,
      agents: agents.map(agent => ({
        agent_id: agent.agent_id,
        app_id: agent.app_id,
        name: agent.name,
        operator: agent.operator,
        version: agent.version,
        created_at: new Date(agent.created_at).toISOString(),
      })),
    });
  } catch (error) {
    return c.json({
      success: false,
      error: 'INTERNAL_ERROR',
      message: error instanceof Error ? error.message : 'Unknown error',
    }, 500);
  }
});

// ============ TAP (TRUSTED AGENT PROTOCOL) ENDPOINTS ============

// TAP agent registration and retrieval
app.post('/v1/agents/register/tap', registerTAPAgentRoute);
app.get('/v1/agents/tap', listTAPAgentsRoute);
app.get('/v1/agents/:id/tap', getTAPAgentRoute);

// TAP session management
app.post('/v1/sessions/tap', createTAPSessionRoute);
app.get('/v1/sessions/:id/tap', getTAPSessionRoute);

// ============ DASHBOARD AUTH API ENDPOINTS ============

// Challenge-based dashboard login (agent direct)
app.post('/v1/auth/dashboard', handleDashboardAuthChallenge);
app.post('/v1/auth/dashboard/verify', handleDashboardAuthVerify);

// Device code flow (agent → human handoff)
app.post('/v1/auth/device-code', handleDeviceCodeChallenge);
app.post('/v1/auth/device-code/verify', handleDeviceCodeVerify);

// ============ ONE-CLICK ACCESS LINKS ============

/**
 * GET /go/:code - One-click device code redemption
 * 
 * Magic link for instant dashboard access. Agent gives human this link:
 * https://botcha.ai/go/BOTCHA-XXXX → auto-login + redirect to dashboard
 * 
 * UX improvement: no more copy-pasting codes!
 */
app.get('/go/:code', async (c) => {
  const code = c.req.param('code')?.toUpperCase();
  
  if (!code) {
    return c.redirect('/?error=missing');
  }

  // Normalize: accept "AR8CZX", "BOTCHA-AR8CZX", etc.
  let normalizedCode = code;
  if (!code.startsWith('BOTCHA-')) {
    normalizedCode = `BOTCHA-${code}`;
  }

  // === Try gate code first (visitor access from /v1/token/verify) ===
  // Gate codes are stored as gate:{code} → access_token string
  let gateToken: string | null = null;
  try {
    gateToken = await c.env.CHALLENGES.get(`gate:${normalizedCode}`);
  } catch {}

  if (gateToken) {
    // Verify the underlying token is still valid
    const result = await verifyToken(gateToken, c.env.JWT_SECRET, c.env);
    
    // Delete the code (one-time use) regardless of token validity
    try { await c.env.CHALLENGES.delete(`gate:${normalizedCode}`); } catch {}
    
    if (result.valid) {
      // Mint a long-lived visitor JWT (1 year) — proves "an agent vouched for this human"
      const vPayload = result.payload as Record<string, unknown> | undefined;
      const visitorToken = await new SignJWT({
        type: 'botcha-visitor',
        solveTime: vPayload?.solveTime as number | undefined,
        gateCode: normalizedCode,
      })
        .setProtectedHeader({ alg: 'HS256' })
        .setIssuedAt()
        .setExpirationTime('365d')
        .sign(new TextEncoder().encode(c.env.JWT_SECRET));

      const ONE_YEAR = 365 * 24 * 60 * 60;
      const headers = new Headers();
      headers.append('Set-Cookie', `botcha_visitor=${visitorToken}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${ONE_YEAR}`);
      headers.set('Location', '/');
      return new Response(null, { status: 302, headers });
    }
    // Gate token expired — fall through to try device code
  }

  // === Try device code (dashboard access from /v1/auth/device-code/verify) ===
  const { redeemDeviceCode } = await import('./dashboard/device-code');
  const data = await redeemDeviceCode(c.env.CHALLENGES, normalizedCode);
  
  if (data) {
    // Generate session token and redirect to dashboard
    const { generateSessionToken, setSessionCookie } = await import('./dashboard/auth');
    const sessionToken = await generateSessionToken(data.app_id, c.env.JWT_SECRET);
    setSessionCookie(c, sessionToken);
    return c.redirect('/dashboard');
  }

  // Neither code type found — redirect to landing with error
  return c.redirect('/?error=invalid');
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
  // Extract client timestamp for RTT calculation
  const clientTimestampParam = c.req.query('ts') || c.req.header('x-client-timestamp');
  const clientTimestamp = clientTimestampParam ? parseInt(clientTimestampParam, 10) : undefined;
  
  const challenge = await generateSpeedChallenge(c.env.CHALLENGES, clientTimestamp);
  
  const response: any = {
    success: true,
    warning: challenge.rttInfo 
      ? `⚡ RTT-ADJUSTED SPEED CHALLENGE: ${challenge.rttInfo.explanation}`
      : '⚡ SPEED CHALLENGE: You have 500ms to solve ALL 5 problems!',
    challenge: {
      id: challenge.id,
      problems: challenge.problems,
      timeLimit: `${challenge.timeLimit}ms`,
      instructions: challenge.instructions,
    },
    tip: 'Humans cannot copy-paste fast enough. Only real AI agents can pass.',
  };
  
  // Include RTT info if available
  if (challenge.rttInfo) {
    response.rtt_adjustment = challenge.rttInfo;
  }
  
  return c.json(response);
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
