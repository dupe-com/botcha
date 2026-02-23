/**
 * BOTCHA Agent OAuth — Device Authorization Grant
 *
 * Lets an agent get a long-lived refresh token by having the human
 * approve a device code in their browser. After that, the agent
 * re-identifies in any future session with just the refresh token —
 * no tapk_ keypair, no API key, nothing else to manage.
 *
 * Flow:
 *   1. Agent:  POST /v1/oauth/device   { agent_id, app_id }
 *              ← { device_code, user_code: "BOTCHA-XXXX", verification_url, expires_in: 600, interval: 5 }
 *
 *   2. Agent tells human: "Visit <verification_url> and enter <user_code>"
 *
 *   3. Human logs into dashboard, sees pending authorization, clicks Approve.
 *
 *   4. Agent polls: POST /v1/oauth/token { device_code, grant_type: "urn:ietf:params:oauth:grant-type:device_code" }
 *              ← { error: "authorization_pending" }  (keep polling every 5s)
 *              ← { access_token, refresh_token: "brt_...", expires_in: 3600 }  (once approved)
 *
 *   5. Future sessions: POST /v1/agents/auth/refresh { refresh_token: "brt_..." }
 *              ← { access_token, agent_id, app_id }
 *
 * The refresh token is stored in KV and can be revoked from the dashboard.
 * It is tied to a specific agent_id — so it proves both "I am authenticated"
 * and "I am specifically this agent".
 */

import type { Context } from 'hono';
import { SignJWT } from 'jose';
import { generateDeviceCode } from './dashboard/device-code.js';

type KV = { get(k: string, t?: string): Promise<string | null>; put(k: string, v: string, o?: { expirationTtl?: number }): Promise<void>; delete(k: string): Promise<void> };
type Bindings = { AGENTS: KV; CHALLENGES: KV; JWT_SECRET: string };

const DEVICE_TTL_SEC = 600;    // 10 min for human to approve
const REFRESH_TTL_SEC = 60 * 60 * 24 * 90; // 90 day refresh token

// ============ STEP 1: Initiate device authorization ============

export async function handleOAuthDevice(c: Context<{ Bindings: Bindings }>) {
  const body = await c.req.json().catch(() => ({})) as any;
  const { agent_id, app_id } = body ?? {};

  if (!agent_id || !app_id) {
    return c.json({ error: 'invalid_request', error_description: 'agent_id and app_id are required' }, 400);
  }

  // Verify agent exists and belongs to app
  const raw = await (c.env as any).AGENTS.get(`agent:${agent_id}`, 'text');
  if (!raw) return c.json({ error: 'invalid_client', error_description: 'Agent not found' }, 404);
  const agent = JSON.parse(raw);
  if (agent.app_id !== app_id) return c.json({ error: 'invalid_client', error_description: 'Agent does not belong to this app' }, 403);

  // Generate device code and opaque device_code token
  const user_code = generateDeviceCode();  // e.g. BOTCHA-X4K9MR
  const device_code = `oauthdev_${crypto.randomUUID()}`;
  const base_url = (c.env as any).BOTCHA_BASE_URL ?? new URL(c.req.url).origin;

  await (c.env as any).CHALLENGES.put(
    `oauth_device:${device_code}`,
    JSON.stringify({ agent_id, app_id, user_code, status: 'pending', created_at: Date.now() }),
    { expirationTtl: DEVICE_TTL_SEC }
  );
  // Also index by user_code so the approval page can look it up
  await (c.env as any).CHALLENGES.put(
    `oauth_usercode:${user_code}`,
    device_code,
    { expirationTtl: DEVICE_TTL_SEC }
  );

  return c.json({
    device_code,
    user_code,
    verification_url: `${base_url}/device`,
    verification_uri: `${base_url}/device`,          // RFC 8628 canonical name
    verification_uri_complete: `${base_url}/device?code=${user_code}`,
    expires_in: DEVICE_TTL_SEC,
    interval: 5,
    message: `Tell your human: visit ${base_url}/device and enter ${user_code}`,
  });
}

// ============ STEP 2: Human approval (called from /device page) ============

export async function handleOAuthApprove(c: Context<{ Bindings: Bindings }>) {
  const body = await c.req.json().catch(() => ({})) as any;
  const { user_code, action } = body ?? {};  // action: 'approve' | 'deny'

  if (!user_code) return c.json({ success: false, error: 'user_code required' }, 400);

  const device_code = await (c.env as any).CHALLENGES.get(`oauth_usercode:${user_code}`, 'text');
  if (!device_code) return c.json({ success: false, error: 'Code not found or expired' }, 404);

  const raw = await (c.env as any).CHALLENGES.get(`oauth_device:${device_code}`, 'text');
  if (!raw) return c.json({ success: false, error: 'Device authorization expired' }, 404);

  const data = JSON.parse(raw);
  if (data.status !== 'pending') return c.json({ success: false, error: 'Already processed' }, 400);

  data.status = action === 'deny' ? 'denied' : 'approved';
  await (c.env as any).CHALLENGES.put(`oauth_device:${device_code}`, JSON.stringify(data), { expirationTtl: 300 });

  return c.json({ success: true, status: data.status, agent_id: data.agent_id });
}

// ============ STEP 3: Agent polling for token ============

export async function handleOAuthToken(c: Context<{ Bindings: Bindings }>) {
  const body = await c.req.json().catch(() => ({})) as any;
  const { device_code, grant_type } = body ?? {};

  if (grant_type !== 'urn:ietf:params:oauth:grant-type:device_code') {
    return c.json({ error: 'unsupported_grant_type' }, 400);
  }
  if (!device_code) return c.json({ error: 'invalid_request', error_description: 'device_code required' }, 400);

  const raw = await (c.env as any).CHALLENGES.get(`oauth_device:${device_code}`, 'text');
  if (!raw) return c.json({ error: 'expired_token', error_description: 'Device code expired or not found' }, 400);

  const data = JSON.parse(raw);

  if (data.status === 'pending') return c.json({ error: 'authorization_pending', error_description: 'Human has not approved yet. Keep polling every 5 seconds.' }, 400);
  if (data.status === 'denied')  return c.json({ error: 'access_denied',          error_description: 'Human denied the authorization request.' }, 400);

  // Approved — issue refresh token + access token, consume device code
  await (c.env as any).CHALLENGES.delete(`oauth_device:${device_code}`);

  const refresh_token = `brt_${crypto.randomUUID().replace(/-/g, '')}`;
  await (c.env as any).CHALLENGES.put(
    `oauth_refresh:${refresh_token}`,
    JSON.stringify({ agent_id: data.agent_id, app_id: data.app_id, created_at: Date.now() }),
    { expirationTtl: REFRESH_TTL_SEC }
  );
  // Also store on agent record for dashboard visibility / revocation
  const agentRaw = await (c.env as any).AGENTS.get(`agent:${data.agent_id}`, 'text');
  if (agentRaw) {
    const agent = JSON.parse(agentRaw);
    agent.oauth_refresh_token_hash = await sha256hex(refresh_token);
    agent.oauth_authorized_at = Date.now();
    await (c.env as any).AGENTS.put(`agent:${data.agent_id}`, JSON.stringify(agent));
  }

  const access_token = await issueAgentJWT(c.env.JWT_SECRET, data.agent_id, data.app_id);

  return c.json({
    access_token,
    token_type: 'Bearer',
    expires_in: 3600,
    refresh_token,
    agent_id: data.agent_id,
    app_id: data.app_id,
    message: 'Save the refresh_token (brt_...) — use it with POST /v1/agents/auth/refresh to re-identify in future sessions.',
  });
}

// ============ STEP 4: Future sessions — refresh token → identity JWT ============

export async function handleAgentAuthRefresh(c: Context<{ Bindings: Bindings }>) {
  const body = await c.req.json().catch(() => ({})) as any;
  const { refresh_token } = body ?? {};

  if (!refresh_token || !refresh_token.startsWith('brt_')) {
    return c.json({ success: false, error: 'INVALID_TOKEN', message: 'refresh_token is required and must start with brt_' }, 400);
  }

  const raw = await (c.env as any).CHALLENGES.get(`oauth_refresh:${refresh_token}`, 'text');
  if (!raw) {
    return c.json({ success: false, error: 'INVALID_TOKEN', message: 'Refresh token not found or expired. Re-authorize via POST /v1/oauth/device.' }, 401);
  }

  const { agent_id, app_id } = JSON.parse(raw);
  const access_token = await issueAgentJWT(c.env.JWT_SECRET, agent_id, app_id);

  return c.json({
    success: true,
    access_token,
    token_type: 'Bearer',
    agent_id,
    app_id,
    expires_in: 3600,
    message: `Re-identified as ${agent_id}. Access token valid for 1 hour.`,
  });
}

// ============ REVOKE (dashboard use) ============

export async function handleOAuthRevoke(c: Context<{ Bindings: Bindings }>) {
  const body = await c.req.json().catch(() => ({})) as any;
  const { agent_id, app_id } = body ?? {};
  if (!agent_id || !app_id) return c.json({ success: false, error: 'agent_id and app_id required' }, 400);

  const agentRaw = await (c.env as any).AGENTS.get(`agent:${agent_id}`, 'text');
  if (!agentRaw) return c.json({ success: false, error: 'Agent not found' }, 404);
  const agent = JSON.parse(agentRaw);
  if (agent.app_id !== app_id) return c.json({ success: false, error: 'Unauthorized' }, 403);

  agent.oauth_refresh_token_hash = null;
  agent.oauth_authorized_at = null;
  await (c.env as any).AGENTS.put(`agent:${agent_id}`, JSON.stringify(agent));

  return c.json({ success: true, message: 'OAuth authorization revoked. Agent must re-authorize via POST /v1/oauth/device.' });
}

// ============ Helpers ============

async function sha256hex(input: string): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function issueAgentJWT(jwtSecret: string, agent_id: string, app_id: string): Promise<string> {
  const secret = new TextEncoder().encode(jwtSecret);
  return new SignJWT({ type: 'botcha-agent-identity', agent_id, app_id })
    .setProtectedHeader({ alg: 'HS256' })
    .setSubject(agent_id)
    .setIssuer('botcha.ai')
    .setIssuedAt()
    .setExpirationTime('1h')
    .setJti(crypto.randomUUID())
    .sign(secret);
}
