/**
 * BOTCHA Dashboard Authentication
 *
 * Two auth flows, both require an agent:
 *
 * Flow 1 — Challenge-Based Login (agent direct):
 *   POST /v1/auth/dashboard              → get challenge
 *   POST /v1/auth/dashboard/verify       → solve challenge → session token
 *
 * Flow 2 — Device Code (agent → human handoff):
 *   POST /v1/auth/device-code            → get challenge
 *   POST /v1/auth/device-code/verify     → solve challenge → device code
 *   Human visits /dashboard/code, enters code → dashboard session
 *
 * Legacy — App ID + Secret login (still valid, agent created the app):
 *   POST /dashboard/login                → app_id + app_secret → session
 *
 * All paths require an agent to be involved. No agent, no access.
 */

import type { Context, MiddlewareHandler } from 'hono';
import { getCookie, setCookie, deleteCookie } from 'hono/cookie';
import { SignJWT } from 'jose';
import { verifyToken } from '../auth';
import { validateAppSecret } from '../apps';
import type { KVNamespace } from '../challenges';
import { generateDeviceCode, storeDeviceCode, redeemDeviceCode } from './device-code';

// Bindings type from Cloudflare Workers
type Bindings = {
  CHALLENGES: KVNamespace;
  RATE_LIMITS: KVNamespace;
  APPS: KVNamespace;
  ANALYTICS?: AnalyticsEngineDataset;
  JWT_SECRET: string;
  BOTCHA_VERSION: string;
};

// Variables type for Hono context
type Variables = {
  dashboardAppId?: string;
};

// ============ SESSION HELPERS ============

/**
 * Generate a 1-hour dashboard session JWT for the given app_id.
 */
async function generateSessionToken(appId: string, jwtSecret: string): Promise<string> {
  const encoder = new TextEncoder();
  const secretKey = encoder.encode(jwtSecret);
  return new SignJWT({
    type: 'botcha-verified',
    solveTime: 0,
    jti: crypto.randomUUID(),
    app_id: appId,
  })
    .setProtectedHeader({ alg: 'HS256' })
    .setSubject('dashboard-session')
    .setIssuedAt()
    .setExpirationTime('1h')
    .sign(secretKey);
}

/**
 * Set the dashboard session cookie on a response context.
 */
function setSessionCookie(c: Context, token: string): void {
  setCookie(c, 'botcha_session', token, {
    path: '/dashboard',
    httpOnly: true,
    secure: true,
    sameSite: 'Lax',
    maxAge: 3600,
  });
}

// ============ MIDDLEWARE ============

/**
 * Middleware: Require dashboard authentication.
 *
 * Checks for session in two places:
 *   1. Cookie `botcha_session` (browser sessions)
 *   2. Authorization: Bearer header (agent API access)
 *
 * On success: sets c.get('dashboardAppId') for downstream handlers
 * On failure: redirects to /dashboard/login (browser) or returns 401 (API)
 */
export const requireDashboardAuth: MiddlewareHandler<{ Bindings: Bindings; Variables: Variables }> = async (c, next) => {
  // Try cookie first (browser sessions)
  let sessionToken = getCookie(c, 'botcha_session');

  // Fall back to Bearer header (agent API access)
  if (!sessionToken) {
    const authHeader = c.req.header('Authorization');
    if (authHeader?.startsWith('Bearer ')) {
      sessionToken = authHeader.slice(7);
    }
  }

  if (!sessionToken) {
    const isApi = c.req.header('Accept')?.includes('application/json') ||
                  c.req.header('HX-Request');
    if (isApi) {
      return c.json({ error: 'Authentication required', login: '/dashboard/login' }, 401);
    }
    return c.redirect('/dashboard/login');
  }

  const result = await verifyToken(sessionToken, c.env.JWT_SECRET, c.env);

  if (!result.valid || !result.payload?.app_id) {
    deleteCookie(c, 'botcha_session', { path: '/dashboard' });
    const isApi = c.req.header('Accept')?.includes('application/json') ||
                  c.req.header('HX-Request');
    if (isApi) {
      return c.json({ error: 'Session expired', login: '/dashboard/login' }, 401);
    }
    return c.redirect('/dashboard/login');
  }

  c.set('dashboardAppId', result.payload.app_id);
  await next();
};

// ============ CHALLENGE-BASED LOGIN (Flow 1: agent direct) ============

/**
 * POST /v1/auth/dashboard
 *
 * Agent requests a speed challenge to prove it's an agent.
 * Requires app_id in the request body.
 */
export async function handleDashboardAuthChallenge(c: Context<{ Bindings: Bindings }>) {
  const body = await c.req.json().catch(() => ({}));
  const appId = (body as any).app_id as string | undefined;

  if (!appId) {
    return c.json({ error: 'app_id is required' }, 400);
  }

  // Verify the app exists
  const appData = await c.env.APPS.get(`app:${appId}`, 'text');
  if (!appData) {
    return c.json({ error: 'App not found' }, 404);
  }

  // Generate a speed challenge (5 SHA256 hashes)
  const challengeId = crypto.randomUUID();
  const problems: number[] = [];
  for (let i = 0; i < 5; i++) {
    const buf = new Uint8Array(4);
    crypto.getRandomValues(buf);
    const num = ((buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3]) >>> 0;
    problems.push(num % 1000000);
  }

  // Store challenge in KV with 60s TTL (KV minimum)
  await c.env.CHALLENGES.put(
    `dashboard-auth:${challengeId}`,
    JSON.stringify({
      problems,
      app_id: appId,
      created_at: Date.now(),
      type: 'dashboard-login',
    }),
    { expirationTtl: 60 }
  );

  return c.json({
    challenge_id: challengeId,
    type: 'speed',
    problems,
    time_limit_ms: 500,
    instructions: 'Compute SHA-256 hex digest of each number (as string). Return first 8 chars of each hash.',
  });
}

/**
 * Verify challenge answers. Shared between dashboard login and device code flows.
 * Returns the challenge data on success, or null with an error response sent.
 */
async function verifyChallengeAnswers(
  c: Context<{ Bindings: Bindings }>,
  challengeId: string,
  answers: string[]
): Promise<{ app_id: string; problems: number[] } | null> {
  // Retrieve and delete challenge (one attempt only)
  const raw = await c.env.CHALLENGES.get(`dashboard-auth:${challengeId}`, 'text');
  await c.env.CHALLENGES.delete(`dashboard-auth:${challengeId}`);

  if (!raw) {
    return null;
  }

  const challenge = JSON.parse(raw);

  // Check timing (2s generous limit including network)
  const elapsed = Date.now() - challenge.created_at;
  if (elapsed > 2000) {
    return null;
  }

  // Verify answers: SHA-256 of each number as string, first 8 hex chars
  const problems = challenge.problems as number[];
  if (answers.length !== problems.length) {
    return null;
  }

  for (let i = 0; i < problems.length; i++) {
    const data = new TextEncoder().encode(String(problems[i]));
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    const expected = hashHex.substring(0, 8);

    if (answers[i]?.toLowerCase() !== expected) {
      return null;
    }
  }

  return { app_id: challenge.app_id, problems };
}

/**
 * POST /v1/auth/dashboard/verify
 *
 * Agent submits challenge solution. On success, returns a session token
 * usable as Bearer header or cookie.
 */
export async function handleDashboardAuthVerify(c: Context<{ Bindings: Bindings }>) {
  const body = await c.req.json().catch(() => ({}));
  const challengeId = (body as any).challenge_id as string | undefined;
  const answers = (body as any).answers as string[] | undefined;

  if (!challengeId || !answers || !Array.isArray(answers)) {
    return c.json({ error: 'challenge_id and answers[] are required' }, 400);
  }

  const result = await verifyChallengeAnswers(c, challengeId, answers);
  if (!result) {
    return c.json({ error: 'Challenge failed: not found, expired, or wrong answers' }, 403);
  }

  const sessionToken = await generateSessionToken(result.app_id, c.env.JWT_SECRET);

  return c.json({
    success: true,
    session_token: sessionToken,
    expires_in: 3600,
    app_id: result.app_id,
    dashboard_url: '/dashboard',
    usage: 'Use as cookie "botcha_session" or Authorization: Bearer header',
  });
}

// ============ DEVICE CODE (Flow 2: agent → human handoff) ============

/**
 * POST /v1/auth/device-code
 *
 * Same challenge as dashboard auth. Agent must solve it to get a device code.
 */
export async function handleDeviceCodeChallenge(c: Context<{ Bindings: Bindings }>) {
  return handleDashboardAuthChallenge(c);
}

/**
 * POST /v1/auth/device-code/verify
 *
 * Agent submits challenge solution. On success, returns a short-lived
 * device code (BOTCHA-XXXX) that a human can enter at /dashboard/code.
 */
export async function handleDeviceCodeVerify(c: Context<{ Bindings: Bindings }>) {
  const body = await c.req.json().catch(() => ({}));
  const challengeId = (body as any).challenge_id as string | undefined;
  const answers = (body as any).answers as string[] | undefined;

  if (!challengeId || !answers || !Array.isArray(answers)) {
    return c.json({ error: 'challenge_id and answers[] are required' }, 400);
  }

  const result = await verifyChallengeAnswers(c, challengeId, answers);
  if (!result) {
    return c.json({ error: 'Challenge failed: not found, expired, or wrong answers' }, 403);
  }

  // Generate device code
  const code = generateDeviceCode();
  await storeDeviceCode(c.env.CHALLENGES, code, result.app_id);

  const baseUrl = new URL(c.req.url).origin;

  return c.json({
    success: true,
    code,
    login_url: `${baseUrl}/dashboard/code`,
    expires_in: 600,
    instructions: `Tell your human: Visit ${baseUrl}/dashboard/code and enter code: ${code}`,
  });
}

// ============ DEVICE CODE REDEMPTION (human-facing) ============

/**
 * GET /dashboard/code
 *
 * Renders the device code redemption page for humans.
 */
export async function renderDeviceCodePage(c: Context<{ Bindings: Bindings }>) {
  const url = new URL(c.req.url);
  const error = url.searchParams.get('error');
  const prefill = url.searchParams.get('code') || '';

  let errorMessage = '';
  if (error === 'invalid') {
    errorMessage = '<div class="error-message">Invalid or expired code. Ask your agent for a new one.</div>';
  } else if (error === 'missing') {
    errorMessage = '<div class="error-message">Please enter a device code.</div>';
  }

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Enter Device Code - BOTCHA</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #f5f3f0;
      --bg-card: #ffffff;
      --bg-raised: #eae8e4;
      --text: #1a1a1a;
      --text-muted: #6b6b6b;
      --text-dim: #a0a0a0;
      --accent: #1a1a1a;
      --red: #cc2222;
      --border: #ddd9d4;
      --border-bright: #c0bbb5;
      --font: 'JetBrains Mono', 'Courier New', monospace;
      --dot-shadow: url("data:image/svg+xml,%3Csvg width='7' height='13' viewBox='0 0 7 13' fill='none' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M5.58984 12.2344V10.7051H6.52734V12.2344H5.58984ZM1.86328 12.2344V10.7051H2.79492V12.2344H1.86328ZM3.72656 10.0957V8.56641H4.6582V10.0957H3.72656ZM0 10.0957V8.56641H0.925781V10.0957H0ZM5.58984 7.95117V6.42188H6.52734V7.95117H5.58984ZM1.86328 7.95117V6.42188H2.79492V7.95117H1.86328ZM3.72656 5.8125V4.2832H4.6582V5.8125H3.72656ZM0 5.8125V4.2832H0.925781V5.8125H0ZM5.58984 3.66797V2.13867H6.52734V3.66797H5.58984ZM1.86328 3.66797V2.13867H2.79492V3.66797H1.86328ZM3.72656 1.5293V0H4.6582V1.5293H3.72656ZM0 1.5293V0H0.925781V1.5293H0Z' fill='%231a1a1a'/%3E%3C/svg%3E");
    }
    * { margin: 0; padding: 0; box-sizing: border-box; }
    html, body {
      height: 100%;
      font-family: var(--font);
      font-size: 14px;
      line-height: 1.6;
      background: var(--bg);
      color: var(--text);
      -webkit-font-smoothing: antialiased;
    }
    ::selection { background: var(--accent); color: #fff; }
    a { color: var(--accent); }
    a:hover { text-decoration: none; opacity: 0.65; }

    /* Scanline CRT overlay */
    body::before {
      content: '';
      position: fixed; inset: 0;
      background: repeating-linear-gradient(
        0deg, transparent, transparent 2px,
        rgba(0,0,0,0.012) 2px, rgba(0,0,0,0.012) 4px
      );
      pointer-events: none; z-index: 9999;
    }

    body {
      display: flex; align-items: center; justify-content: center;
      padding: 2rem;
    }
    .container { width: 100%; max-width: 420px; }

    .logo {
      text-align: center; margin-bottom: 2rem;
      font-size: 0.875rem; font-weight: 700;
      color: var(--text); letter-spacing: 0.15em;
      text-transform: uppercase;
    }

    /* Card component — Turbopuffer-style div with dot shadow behind */
    .card {
      display: flex; flex-direction: column;
    }
    .card-header {
      margin-bottom: -1px;
      padding: 0;
    }
    .card-header h3 {
      font-size: 0.75rem; font-weight: 700;
      text-transform: uppercase; letter-spacing: 0.1em;
      line-height: 1; color: var(--text); margin: 0;
    }
    .card-header h3 span {
      position: relative; z-index: 10;
      margin-left: -0.5rem; margin-right: -0.5rem;
      background: var(--bg); padding: 0 0.5rem;
    }
    .card-body {
      position: relative;
      border: 2px solid var(--border-bright);
    }
    .card-body::before {
      content: '';
      position: absolute;
      top: 0.5rem; left: 0.5rem;
      right: -0.5rem; bottom: -0.5rem;
      background-image: var(--dot-shadow);
      background-repeat: repeat;
      pointer-events: none;
      opacity: 0.6;
    }
    .card-inner {
      position: relative;
      z-index: 1;
      background: var(--bg-card);
      padding: 2rem;
    }
    .form-group { margin-bottom: 1.5rem; }
    label {
      display: block; margin-bottom: 0.5rem;
      font-size: 0.6875rem; color: var(--text-muted);
      font-weight: 700; text-transform: uppercase; letter-spacing: 0.08em;
    }
    input {
      width: 100%; padding: 1rem;
      font-family: var(--font);
      font-size: 1.5rem; font-weight: 700;
      text-align: center; letter-spacing: 0.15em;
      background: var(--bg); border: 1px solid var(--border-bright);
      border-radius: 0; color: var(--text);
      text-transform: uppercase;
    }
    input:focus {
      outline: none; border-color: var(--accent);
      box-shadow: 0 0 0 1px var(--accent);
    }
    input::placeholder {
      font-size: 1rem; font-weight: 400;
      letter-spacing: normal; text-transform: none;
      color: var(--text-dim);
    }
    button {
      width: 100%; padding: 0.625rem 1.25rem;
      font-family: var(--font); font-size: 0.75rem; font-weight: 700;
      background: var(--accent); color: #fff;
      border: 1px solid var(--accent); border-radius: 0; cursor: pointer;
      text-transform: uppercase; letter-spacing: 0.08em;
      box-shadow:
        inset 1px 1px 0 rgba(255,255,255,0.15),
        inset -1px -1px 0 rgba(0,0,0,0.15),
        2px 2px 0 rgba(0,0,0,0.1);
      transition: box-shadow 0.1s, transform 0.1s;
    }
    button:hover {
      box-shadow:
        inset 1px 1px 0 rgba(255,255,255,0.1),
        inset -1px -1px 0 rgba(0,0,0,0.15),
        3px 3px 0 rgba(0,0,0,0.12);
    }
    button:active {
      transform: translate(1px, 1px);
      box-shadow: inset 1px 1px 3px rgba(0,0,0,0.25);
    }
    .hint {
      margin-top: 1.5rem; font-size: 0.6875rem;
      color: var(--text-muted); text-align: center; line-height: 1.8;
    }
    .hint code {
      color: var(--text); background: var(--bg-raised);
      padding: 0.125rem 0.375rem; border: 1px solid var(--border);
    }
    .error-message {
      color: var(--red); margin: 0 0 1rem 0; font-size: 0.75rem;
      padding: 0.5rem 0.75rem;
      border: 1px solid rgba(204,34,34,0.3); border-radius: 0;
      background: var(--bg);
    }
    .error-message::before { content: '[ERR] '; font-weight: 700; }

    /* Scrollbar */
    ::-webkit-scrollbar { width: 6px; height: 6px; }
    ::-webkit-scrollbar-track { background: var(--bg-raised); }
    ::-webkit-scrollbar-thumb { background: var(--border-bright); }
    ::-webkit-scrollbar-thumb:hover { background: var(--text-muted); }

    @media (max-width: 480px) {
      body { padding: 1rem; }
      .card-inner { padding: 1.25rem; }
      input { font-size: 1.25rem; padding: 0.75rem; }
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="logo">>_ BOTCHA</div>
    <form method="POST" action="/dashboard/code">
      <div class="card">
        <div class="card-header"><h3><span>Device Code</span></h3></div>
        <div class="card-body"><div class="card-inner">
          ${errorMessage}
          <p style="font-size: 0.75rem; color: var(--text-muted); margin-bottom: 1.5rem;">
            Your AI agent generated a login code for you.
            Enter it below to access the dashboard.
          </p>
          <div class="form-group">
            <label for="code">Code</label>
            <input
              type="text"
              id="code"
              name="code"
              placeholder="BOTCHA-XXXX"
              value="${prefill}"
              required
              autocomplete="off"
              maxlength="11"
            />
          </div>
          <button type="submit">Verify Code ></button>
        </div></div>
      </div>
    </form>
    <div class="hint">
      Don't have a code? Ask your AI agent to run:<br>
      <code>POST /v1/auth/device-code</code><br><br>
      <a href="/dashboard/login">Back to login</a>
    </div>
  </div>
</body>
</html>`;

  return c.html(html);
}

/**
 * POST /dashboard/code
 *
 * Human submits device code. If valid, creates session and redirects to dashboard.
 */
export async function handleDeviceCodeRedeem(c: Context<{ Bindings: Bindings }>) {
  const body = await c.req.parseBody();
  const code = (body.code as string || '').trim().toUpperCase();

  if (!code) {
    return c.redirect('/dashboard/code?error=missing');
  }

  const data = await redeemDeviceCode(c.env.CHALLENGES, code);
  if (!data) {
    return c.redirect('/dashboard/code?error=invalid');
  }

  const sessionToken = await generateSessionToken(data.app_id, c.env.JWT_SECRET);
  setSessionCookie(c, sessionToken);
  return c.redirect('/dashboard');
}

// ============ LEGACY LOGIN (app_id + app_secret) ============

/**
 * POST /dashboard/login
 *
 * Login with app_id + app_secret. The agent created the app (so an agent
 * was involved at creation time). Still supported as a convenience.
 */
export async function handleLogin(c: Context<{ Bindings: Bindings }>) {
  try {
    const body = await c.req.parseBody();
    const app_id = body.app_id as string | undefined;
    const app_secret = body.app_secret as string | undefined;

    if (!app_id || !app_secret) {
      return c.redirect('/dashboard/login?error=missing');
    }

    const trimmedAppId = app_id.trim();
    const trimmedSecret = app_secret.trim();

    const isValid = await validateAppSecret(c.env.APPS, trimmedAppId, trimmedSecret);
    if (!isValid) {
      return c.redirect('/dashboard/login?error=invalid');
    }

    const sessionToken = await generateSessionToken(trimmedAppId, c.env.JWT_SECRET);
    setSessionCookie(c, sessionToken);
    return c.redirect('/dashboard');
  } catch (error) {
    console.error('Login error:', error);
    return c.redirect('/dashboard/login?error=server');
  }
}

/**
 * GET /dashboard/logout
 */
export async function handleLogout(c: Context<{ Bindings: Bindings }>) {
  deleteCookie(c, 'botcha_session', { path: '/dashboard' });
  return c.redirect('/dashboard/login');
}

// ============ LOGIN PAGE ============

/**
 * GET /dashboard/login
 *
 * Three ways in, all require an agent:
 *   1. Device code (agent generated the code) — primary, most prominent
 *   2. App ID + Secret (agent created the app)
 *   3. Create new app (triggers POST /v1/apps)
 */
export async function renderLoginPage(c: Context<{ Bindings: Bindings }>) {
  const url = new URL(c.req.url);
  const error = url.searchParams.get('error');

  let errorMessage = '';
  if (error === 'invalid') {
    errorMessage = '<div class="error-message">Invalid app ID or secret</div>';
  } else if (error === 'missing') {
    errorMessage = '<div class="error-message">Please provide both app ID and secret</div>';
  } else if (error === 'server') {
    errorMessage = '<div class="error-message">Server error. Please try again.</div>';
  }

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Dashboard Login - BOTCHA</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #f5f3f0;
      --bg-card: #ffffff;
      --bg-raised: #eae8e4;
      --text: #1a1a1a;
      --text-muted: #6b6b6b;
      --text-dim: #a0a0a0;
      --accent: #1a1a1a;
      --accent-dim: #333333;
      --red: #cc2222;
      --amber: #b87a00;
      --border: #ddd9d4;
      --border-bright: #c0bbb5;
      --font: 'JetBrains Mono', 'Courier New', monospace;
      --dot-shadow: url("data:image/svg+xml,%3Csvg width='7' height='13' viewBox='0 0 7 13' fill='none' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M5.58984 12.2344V10.7051H6.52734V12.2344H5.58984ZM1.86328 12.2344V10.7051H2.79492V12.2344H1.86328ZM3.72656 10.0957V8.56641H4.6582V10.0957H3.72656ZM0 10.0957V8.56641H0.925781V10.0957H0ZM5.58984 7.95117V6.42188H6.52734V7.95117H5.58984ZM1.86328 7.95117V6.42188H2.79492V7.95117H1.86328ZM3.72656 5.8125V4.2832H4.6582V5.8125H3.72656ZM0 5.8125V4.2832H0.925781V5.8125H0ZM5.58984 3.66797V2.13867H6.52734V3.66797H5.58984ZM1.86328 3.66797V2.13867H2.79492V3.66797H1.86328ZM3.72656 1.5293V0H4.6582V1.5293H3.72656ZM0 1.5293V0H0.925781V1.5293H0Z' fill='%231a1a1a'/%3E%3C/svg%3E");
    }
    * { margin: 0; padding: 0; box-sizing: border-box; }
    html, body {
      height: 100%;
      font-family: var(--font);
      font-size: 14px;
      line-height: 1.6;
      background: var(--bg);
      color: var(--text);
      -webkit-font-smoothing: antialiased;
    }
    ::selection { background: var(--accent); color: #fff; }
    a { color: var(--accent); }
    a:hover { text-decoration: none; opacity: 0.65; }

    /* Scanline CRT overlay */
    body::before {
      content: '';
      position: fixed; inset: 0;
      background: repeating-linear-gradient(
        0deg, transparent, transparent 2px,
        rgba(0,0,0,0.012) 2px, rgba(0,0,0,0.012) 4px
      );
      pointer-events: none; z-index: 9999;
    }

    body {
      display: flex; align-items: center; justify-content: center;
      padding: 2rem;
    }
    .login-container { width: 100%; max-width: 440px; }

    /* ASCII logo */
    .logo {
      text-align: center; margin-bottom: 2rem;
      color: var(--text); font-size: 0.55rem; line-height: 1.2;
      white-space: pre; font-weight: 400;
    }

    /* Card component — Turbopuffer-style div with dot shadow behind */
    .card {
      display: flex; flex-direction: column;
      margin-bottom: 1.5rem;
    }
    .card-header {
      margin-bottom: -1px; /* overlap the border */
      padding: 0;
    }
    .card-header h3 {
      font-size: 0.75rem; font-weight: 700;
      text-transform: uppercase; letter-spacing: 0.1em;
      line-height: 1; color: var(--text); margin: 0;
    }
    .card-header h3 span {
      position: relative; z-index: 10;
      margin-left: -0.5rem; margin-right: -0.5rem;
      background: var(--bg); padding: 0 0.5rem;
    }
    .card-body {
      position: relative;
      border: 2px solid var(--border-bright);
    }
    .card-body::before {
      content: '';
      position: absolute;
      top: 0.5rem; left: 0.5rem;
      right: -0.5rem; bottom: -0.5rem;
      background-image: var(--dot-shadow);
      background-repeat: repeat;
      pointer-events: none;
      opacity: 0.6;
    }
    .card-inner {
      position: relative;
      z-index: 1;
      background: var(--bg-card);
      padding: 1.5rem;
    }
    .form-group { margin-bottom: 1.25rem; }
    label {
      display: block; margin-bottom: 0.375rem;
      font-size: 0.6875rem; color: var(--text-muted);
      font-weight: 700; text-transform: uppercase; letter-spacing: 0.08em;
    }
    input {
      width: 100%; padding: 0.625rem 0.75rem;
      font-family: var(--font); font-size: 0.875rem;
      background: var(--bg); border: 1px solid var(--border-bright);
      border-radius: 0; color: var(--text);
    }
    input:focus {
      outline: none; border-color: var(--accent);
      box-shadow: 0 0 0 1px var(--accent);
    }
    input::placeholder { color: var(--text-dim); }

    button, .btn {
      width: 100%; padding: 0.625rem 1.25rem;
      font-family: var(--font); font-size: 0.75rem; font-weight: 700;
      background: var(--accent); color: #fff;
      border: 1px solid var(--accent); border-radius: 0; cursor: pointer;
      display: block; text-align: center; text-decoration: none;
      text-transform: uppercase; letter-spacing: 0.08em;
      box-shadow:
        inset 1px 1px 0 rgba(255,255,255,0.15),
        inset -1px -1px 0 rgba(0,0,0,0.15),
        2px 2px 0 rgba(0,0,0,0.1);
      transition: box-shadow 0.1s, transform 0.1s;
    }
    button:hover, .btn:hover {
      box-shadow:
        inset 1px 1px 0 rgba(255,255,255,0.1),
        inset -1px -1px 0 rgba(0,0,0,0.15),
        3px 3px 0 rgba(0,0,0,0.12);
      opacity: 1;
    }
    button:active, .btn:active {
      transform: translate(1px, 1px);
      box-shadow: inset 1px 1px 3px rgba(0,0,0,0.25);
    }
    .btn-secondary {
      background: transparent; color: var(--text);
      border-color: var(--border-bright);
      box-shadow: 2px 2px 0 rgba(0,0,0,0.05);
    }
    .btn-secondary:hover {
      border-color: var(--accent); color: var(--accent);
      box-shadow: 2px 2px 0 rgba(0,0,0,0.1);
    }

    .divider {
      text-align: center; color: var(--text-dim); font-size: 0.6875rem;
      margin: 1.5rem 0; position: relative;
      text-transform: uppercase; letter-spacing: 0.1em;
    }
    .divider::before, .divider::after {
      content: ''; position: absolute; top: 50%;
      width: 35%; height: 1px; background: var(--border-bright);
    }
    .divider::before { left: 0; }
    .divider::after { right: 0; }

    .credentials-box {
      background: var(--bg); border: 1px solid var(--accent-dim);
      border-radius: 0; padding: 1rem; margin-bottom: 1rem;
      font-size: 0.75rem; line-height: 1.8; word-break: break-all;
    }
    .credentials-box .label { color: var(--text-muted); }
    .credentials-box .value { color: var(--text); font-weight: 700; }
    .warning {
      background: rgba(184,122,0,0.06); border: 1px solid var(--amber);
      border-radius: 0; padding: 0.75rem; margin-bottom: 1rem;
      font-size: 0.7rem; color: var(--amber);
    }
    .warning::before { content: '[!!] '; font-weight: 700; }
    .error-message {
      color: var(--red); margin: 0 0 1rem 0; font-size: 0.75rem;
      padding: 0.5rem 0.75rem;
      border: 1px solid rgba(204,34,34,0.3); border-radius: 0;
      background: var(--bg);
    }
    .error-message::before { content: '[ERR] '; font-weight: 700; }
    .hint {
      font-size: 0.6875rem; color: var(--text-muted); line-height: 1.6;
      margin-top: 0.75rem;
    }
    .hint code { color: var(--text); background: var(--bg-raised); padding: 0.125rem 0.375rem; border: 1px solid var(--border); }
    .agent-badge {
      display: inline-block; font-size: 0.5625rem; font-weight: 700;
      color: var(--text-muted); border: 1px solid var(--border-bright);
      border-radius: 0; padding: 0.1rem 0.4rem;
      margin-left: 0.5rem; vertical-align: middle;
      text-transform: uppercase; letter-spacing: 0.05em;
    }

    #create-result { display: none; }
    #create-result.show { display: block; }
    #create-btn.loading { opacity: 0.25; pointer-events: none; }

    /* Scrollbar */
    ::-webkit-scrollbar { width: 6px; height: 6px; }
    ::-webkit-scrollbar-track { background: var(--bg-raised); }
    ::-webkit-scrollbar-thumb { background: var(--border-bright); }
    ::-webkit-scrollbar-thumb:hover { background: var(--text-muted); }

    @media (max-width: 480px) {
      body { padding: 1rem; }
      .logo { font-size: 0.4rem; }
      .card-inner { padding: 1rem; }
    }
  </style>
</head>
<body>
  <div class="login-container">
    <div class="logo">
 ____   ___ _____ ____ _   _   _
| __ ) / _ \\_   _/ ___| | | | / \\
|  _ \\| | | || || |   | |_| |/ _ \\
| |_) | |_| || || |___|  _  / ___ \\
|____/ \\___/ |_| \\____|_| |_/_/   \\_\\
    >_ prove you're a bot</div>

    <!-- Option 1: Device Code (agent generated it) — PRIMARY -->
    <div class="card">
      <div class="card-header"><h3><span>Device Code</span> <span class="agent-badge">agent required</span></h3></div>
      <div class="card-body"><div class="card-inner">
        <p style="font-size: 0.75rem; color: var(--text-muted); margin-bottom: 1rem;">
          Your AI agent can generate a login code for you.
        </p>
        <a href="/dashboard/code" class="btn">Enter Device Code ></a>
        <div class="hint">
          Agent: <code>POST /v1/auth/device-code</code> then solve the challenge.
        </div>
      </div></div>
    </div>

    <div class="divider">or sign in directly</div>

    <!-- Option 2: App ID + Secret -->
    <form method="POST" action="/dashboard/login">
      <div class="card">
        <div class="card-header"><h3><span>App Credentials</span></h3></div>
        <div class="card-body"><div class="card-inner">
          ${errorMessage}
          <div class="form-group">
            <label for="app_id">App ID</label>
            <input type="text" id="app_id" name="app_id" placeholder="app_..." required autocomplete="username" />
          </div>
          <div class="form-group">
            <label for="app_secret">App Secret</label>
            <input type="password" id="app_secret" name="app_secret" placeholder="sk_..." required autocomplete="current-password" />
          </div>
          <button type="submit">Login ></button>
        </div></div>
      </div>
    </form>

    <div class="divider">or</div>

    <!-- Option 3: Create new app -->
    <div class="card">
      <div class="card-header"><h3><span>New App</span> <span class="agent-badge">creates credentials</span></h3></div>
      <div class="card-body"><div class="card-inner">
        <p style="font-size: 0.75rem; color: var(--text-muted); margin-bottom: 1rem;">
          Create a new app to get started.
        </p>
        <div id="create-result">
          <div class="warning">
            Save these credentials now. The secret will not be shown again.
          </div>
          <div class="credentials-box">
            <span class="label">app_id: </span><span class="value" id="new-app-id"></span><br>
            <span class="label">secret: </span><span class="value" id="new-app-secret"></span>
          </div>
          <button type="button" onclick="fillAndLogin()">Login With New Credentials ></button>
        </div>
        <button type="button" id="create-btn" class="btn-secondary" onclick="createApp()">
          Create App >
        </button>
      </div></div>
    </div>
  </div>

  <script>
    async function createApp() {
      const btn = document.getElementById('create-btn');
      btn.classList.add('loading');
      btn.textContent = 'Creating...';
      try {
        const resp = await fetch('/v1/apps', { method: 'POST' });
        const data = await resp.json();
        if (data.app_id && data.app_secret) {
          document.getElementById('new-app-id').textContent = data.app_id;
          document.getElementById('new-app-secret').textContent = data.app_secret;
          document.getElementById('create-result').classList.add('show');
          btn.style.display = 'none';
        } else {
          btn.textContent = '[ERR] try again >';
          btn.classList.remove('loading');
        }
      } catch (e) {
        btn.textContent = '[ERR] try again >';
        btn.classList.remove('loading');
      }
    }

    function fillAndLogin() {
      const appId = document.getElementById('new-app-id').textContent;
      const secret = document.getElementById('new-app-secret').textContent;
      document.getElementById('app_id').value = appId;
      document.getElementById('app_secret').value = secret;
      document.querySelector('form').submit();
    }
  </script>
</body>
</html>`;

  return c.html(html);
}
