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
import { validateAppSecret, getAppByEmail } from '../apps';
import { sendEmail, recoveryEmail } from '../email';
import type { KVNamespace } from '../challenges';
import { generateDeviceCode, storeDeviceCode, redeemDeviceCode } from './device-code';
import { LoginLayout, Card, Divider } from './layout';

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
export async function generateSessionToken(appId: string, jwtSecret: string): Promise<string> {
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
export function setSessionCookie(c: Context, token: string): void {
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
    magic_link: `${baseUrl}/go/${code}`,
    expires_in: 600,
    instructions: `Give your human this link: ${baseUrl}/go/${code} (or visit ${baseUrl}/dashboard/code and enter code: ${code})`,
  });
}

// ============ DEVICE CODE REDEMPTION (human-facing) ============

/**
 * GET /dashboard/code
 * GET /dashboard/code/:code
 *
 * Renders the device code redemption page for humans.
 * Supports pre-filled codes from URL path or query params.
 */
export async function renderDeviceCodePage(c: Context<{ Bindings: Bindings }>) {
  const url = new URL(c.req.url);
  const error = url.searchParams.get('error');
  const emailSent = url.searchParams.get('email_sent') === '1';
  
  // Get prefill code from URL path or query params
  const pathCode = c.req.param('code')?.toUpperCase() || '';
  const queryCode = url.searchParams.get('code') || '';
  let prefill = pathCode || queryCode;
  
  // Strip BOTCHA- prefix if present (form only needs the suffix)
  if (prefill.startsWith('BOTCHA-')) {
    prefill = prefill.slice(7);
  }

  const errorMap: Record<string, string> = {
    invalid: 'Invalid or expired code. Ask your agent for a new one.',
    missing: 'Please enter a device code.',
  };

  return c.html(
    <LoginLayout title="Enter Device Code - BOTCHA">
      <div style="font-size: 0.875rem; font-weight: 700; letter-spacing: 0.15em; text-transform: uppercase; text-align: center; margin-bottom: 2rem;">
        {'>'}_&nbsp;BOTCHA
      </div>
      <form method="post" action="/dashboard/code">
        <Card title="Device Code">
          {emailSent && (
            <div class="success-message" style="background: #f0faf0; border: 1px solid #1a8a2a; color: #1a6a1a; padding: 0.75rem; font-size: 0.75rem; margin-bottom: 1rem;">
              If an account with that email exists, a login code has been sent. Check your inbox.
            </div>
          )}
          {error && errorMap[error] && (
            <div class="error-message">{errorMap[error]}</div>
          )}
          <p class="text-muted mb-2" style="font-size: 0.75rem;">
            {emailSent
              ? 'Enter the code from your email below.'
              : 'Your AI agent generated a login code for you. Enter it below to access the dashboard.'}
          </p>
          <div class="form-group">
            <label for="code">Code</label>
            <div style="display: flex; align-items: stretch; gap: 0;">
              <span style="display: flex; align-items: center; font-size: 1.5rem; font-weight: 700; letter-spacing: 0.15em; padding: 0 0.25rem 0 1rem; border: 1px solid var(--border); border-right: none; background: var(--bg-raised); color: var(--text-muted);">BOTCHA-</span>
              <input
                type="text"
                id="code"
                name="code"
                placeholder="XXXX"
                value={prefill}
                required
                autocomplete="off"
                maxlength={11}
                style="font-size: 1.5rem; font-weight: 700; text-align: center; letter-spacing: 0.15em; padding: 1rem; flex: 1; border-left: none;"
              />
            </div>
          </div>
          <script dangerouslySetInnerHTML={{ __html: `
            document.getElementById('code').addEventListener('input', function(e) {
              var v = e.target.value.toUpperCase().replace(/[^A-Z0-9-]/g, '');
              if (v.startsWith('BOTCHA-')) v = v.slice(7);
              else if (v.startsWith('BOTCHA')) v = v.slice(6);
              e.target.value = v.slice(0, 4);
            });
          `}} />
          <button type="submit">Verify Code {'>'}</button>
        </Card>
      </form>
      <div class="hint" style="text-align: center; line-height: 1.8; margin-top: 1.5rem;">
        Don't have a code? Ask your AI agent to run:<br />
        <code>POST /v1/auth/device-code</code><br /><br />
        <a href="/dashboard/login">Back to login</a>
      </div>
    </LoginLayout>
  );
}

/**
 * POST /dashboard/code
 *
 * Human submits device code. If valid, creates session and redirects to dashboard.
 */
export async function handleDeviceCodeRedeem(c: Context<{ Bindings: Bindings }>) {
  const body = await c.req.parseBody();
  let code = (body.code as string || '').trim().toUpperCase();

  if (!code) {
    return c.redirect('/dashboard/code?error=missing');
  }

  // Normalize: accept both "AR8C" and "BOTCHA-AR8C", always look up with prefix
  if (!code.startsWith('BOTCHA-')) {
    code = `BOTCHA-${code}`;
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

// ============ EMAIL LOGIN (session re-entry) ============

/**
 * POST /dashboard/email-login
 *
 * Human enters their email. If a verified app exists for that email,
 * a device code is generated and emailed. The human then enters the
 * code at /dashboard/code to get a session.
 *
 * This doesn't violate agent-first: the agent was involved at account
 * creation and email verification. This is just session resumption.
 *
 * Anti-enumeration: always shows the same "check your email" message
 * regardless of whether the email exists.
 */
export async function handleEmailLogin(c: Context<{ Bindings: Bindings }>) {
  const body = await c.req.parseBody();
  const email = (body.email as string || '').trim().toLowerCase();

  if (!email) {
    return c.redirect('/dashboard/login?error=email_missing');
  }

  // Look up app by email — but always show same response (anti-enumeration)
  const lookup = await getAppByEmail(c.env.APPS, email);

  if (lookup && lookup.email_verified) {
    // Generate a device code and email it
    const code = generateDeviceCode();
    await storeDeviceCode(c.env.CHALLENGES, code, lookup.app_id);

    const baseUrl = new URL(c.req.url).origin;
    const loginUrl = `${baseUrl}/dashboard/code`;
    const template = recoveryEmail(code, loginUrl);
    await sendEmail((c.env as any).RESEND_API_KEY, {
      ...template,
      to: email,
    });
  }

  // Always redirect to code page with success message (anti-enumeration)
  return c.redirect('/dashboard/code?email_sent=1');
}

// ============ LOGIN PAGE ============

/**
 * GET /dashboard/login
 *
 * Four ways in:
 *   1. Device code (agent generated the code) — primary
 *   2. Email login (returning users — code emailed to verified address)
 *   3. App ID + Secret (agent created the app)
 *   4. Create new app (triggers POST /v1/apps)
 */
export async function renderLoginPage(c: Context<{ Bindings: Bindings }>) {
  const url = new URL(c.req.url);
  const error = url.searchParams.get('error');

  const errorMap: Record<string, string> = {
    invalid: 'Invalid app ID or secret',
    missing: 'Please provide both app ID and secret',
    server: 'Server error. Please try again.',
    email_missing: 'Please enter your email address.',
  };

  const CREATE_APP_SCRIPT = `
    async function createApp() {
      var btn = document.getElementById('create-btn');
      btn.classList.add('loading');
      btn.textContent = 'Creating...';
      try {
        var resp = await fetch('/v1/apps', { method: 'POST' });
        var data = await resp.json();
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
      var appId = document.getElementById('new-app-id').textContent;
      var secret = document.getElementById('new-app-secret').textContent;
      document.getElementById('app_id').value = appId;
      document.getElementById('app_secret').value = secret;
      document.querySelector('form').submit();
    }
  `;

  return c.html(
    <LoginLayout title="Dashboard Login - BOTCHA">
      <a href="/" class="ascii-logo">{
`██████╗  ██████╗ ████████╗ ██████╗██╗  ██╗ █████╗
██╔══██╗██╔═══██╗╚══██╔══╝██╔════╝██║  ██║██╔══██╗
██████╔╝██║   ██║   ██║   ██║     ███████║███████║
██╔══██╗██║   ██║   ██║   ██║     ██╔══██║██╔══██║
██████╔╝╚██████╔╝   ██║   ╚██████╗██║  ██║██║  ██║
╚═════╝  ╚═════╝    ╚═╝    ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝`
      }</a>
      <p class="text-muted" style="text-align: center; font-size: 0.75rem; margin: -1rem 0 2rem;">
        {'>'}_&nbsp;prove you're a bot
      </p>

      {/* Option 1: Device Code (agent generated it) — PRIMARY */}
      <Card title="Device Code" badge="agent required">
        <p class="text-muted mb-2" style="font-size: 0.75rem;">
          Your AI agent can generate a login code for you.
        </p>
        <a href="/dashboard/code" class="button btn">Enter Device Code {'>'}</a>
        <div class="hint">
          Agent: <code>POST /v1/auth/device-code</code> then solve the challenge.
        </div>
      </Card>

      <Divider text="or" />

      {/* Option 2: Email Login (returning users — no agent needed) */}
      <form method="post" action="/dashboard/email-login">
        <Card title="Email Login" badge="returning users">
          {error === 'email_missing' && (
            <div class="error-message">{errorMap[error]}</div>
          )}
          <p class="text-muted mb-2" style="font-size: 0.75rem;">
            Enter the email you used when creating your app.
            We'll send a login code to your inbox.
          </p>
          <div class="form-group">
            <label for="email">Email</label>
            <input type="email" id="email" name="email" placeholder="you@example.com" required autocomplete="email" />
          </div>
          <button type="submit">Email Me a Code {'>'}</button>
        </Card>
      </form>

      <Divider text="or sign in with credentials" />

      {/* Option 3: App ID + Secret / Create New App */}
      <form method="post" action="/dashboard/login">
        <Card title="App Credentials">
          {error && error !== 'email_missing' && errorMap[error] && (
            <div class="error-message">{errorMap[error]}</div>
          )}
          <div id="create-result">
            <div class="warning">
              Save these credentials now. The secret will not be shown again.
            </div>
            <div class="credentials-box">
              <span class="label">app_id: </span><span class="value" id="new-app-id"></span><br />
              <span class="label">secret: </span><span class="value" id="new-app-secret"></span>
            </div>
            <button type="button" onclick="fillAndLogin()" style="width: 100%; margin-bottom: 1rem;">Login With New Credentials {'>'}</button>
          </div>
          <div class="form-group">
            <label for="app_id">App ID</label>
            <input type="text" id="app_id" name="app_id" placeholder="app_..." required autocomplete="username" />
          </div>
          <div class="form-group">
            <label for="app_secret">App Secret</label>
            <input type="password" id="app_secret" name="app_secret" placeholder="sk_..." required autocomplete="current-password" />
          </div>
          <div style="display: flex; gap: 0.75rem; align-items: center;">
            <button type="submit">Login {'>'}</button>
            <button type="button" id="create-btn" class="btn-secondary" onclick="createApp()">
              Create App {'>'}
            </button>
          </div>
        </Card>
      </form>

      <script dangerouslySetInnerHTML={{ __html: CREATE_APP_SCRIPT }} />
    </LoginLayout>
  );
}
