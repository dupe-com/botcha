/**
 * BOTCHA Webhook Event System
 *
 * Delivers real-time events to API owners when things happen:
 *   challenge.solved / challenge.failed / challenge.timeout
 *   agent.registered / agent.tap.registered
 *   token.created / token.revoked
 *   tap.session.created / tap.session.expired
 *   delegation.created / delegation.revoked
 *   reputation.changed
 *
 * KV keys (all stored in AGENTS namespace):
 *   webhook:{id}               — WebhookConfig (without secret)
 *   webhook_secret:{id}        — HMAC signing secret
 *   app_webhooks:{app_id}      — JSON string[] of webhook IDs for this app
 *   webhook_deliveries:{id}    — JSON DeliveryLog[] (last 100, TTL 7d)
 */

import type { Context } from 'hono';
import { extractBearerToken, verifyToken, getSigningPublicKeyJWK, type ES256SigningKeyJWK } from './auth.js';

// ============ TYPES ============

/** KV namespace interface — mirrors Cloudflare's KVNamespace */
export interface KVNamespace {
  get(key: string, type?: 'text'): Promise<string | null>;
  put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void>;
  delete(key: string): Promise<void>;
}

export type WebhookEventType =
  | 'challenge.solved'
  | 'challenge.failed'
  | 'challenge.timeout'
  | 'agent.registered'
  | 'agent.tap.registered'
  | 'token.created'
  | 'token.revoked'
  | 'tap.session.created'
  | 'tap.session.expired'
  | 'delegation.created'
  | 'delegation.revoked'
  | 'reputation.changed';

export const ALL_EVENT_TYPES: WebhookEventType[] = [
  'challenge.solved',
  'challenge.failed',
  'challenge.timeout',
  'agent.registered',
  'agent.tap.registered',
  'token.created',
  'token.revoked',
  'tap.session.created',
  'tap.session.expired',
  'delegation.created',
  'delegation.revoked',
  'reputation.changed',
];

export interface WebhookConfig {
  id: string;
  app_id: string;
  url: string;
  events: WebhookEventType[];
  enabled: boolean;
  created_at: number;
  updated_at: number;
  /** Consecutive failures since last success */
  consecutive_failures: number;
  /** Suspended after 3+ consecutive failures over 24h */
  suspended: boolean;
}

export interface DeliveryLog {
  delivery_id: string;
  webhook_id: string;
  event_type: string;
  event_id: string;
  attempted_at: number;
  attempt_number: number;
  status_code: number | null;
  success: boolean;
  error?: string;
  duration_ms: number;
}

export interface BotchaEvent {
  id: string;
  type: WebhookEventType;
  created_at: string; // ISO8601
  app_id: string;
  data: Record<string, unknown>;
}

// ============ ID GENERATION ============

function generateId(prefix: string): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  return `${prefix}_${hex}`;
}

// ============ HMAC-SHA256 SIGNING ============

export async function computeHmacSignature(secret: string, body: string): Promise<string> {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, encoder.encode(body));
  const hex = Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
  return `sha256=${hex}`;
}

// ============ KV HELPERS ============

async function getWebhook(kv: KVNamespace, id: string): Promise<WebhookConfig | null> {
  const raw = await kv.get(`webhook:${id}`);
  if (!raw) return null;
  return JSON.parse(raw) as WebhookConfig;
}

async function saveWebhook(kv: KVNamespace, webhook: WebhookConfig): Promise<void> {
  await kv.put(`webhook:${webhook.id}`, JSON.stringify(webhook));
}

async function getAppWebhookIds(kv: KVNamespace, appId: string): Promise<string[]> {
  const raw = await kv.get(`app_webhooks:${appId}`);
  if (!raw) return [];
  return JSON.parse(raw) as string[];
}

async function setAppWebhookIds(kv: KVNamespace, appId: string, ids: string[]): Promise<void> {
  await kv.put(`app_webhooks:${appId}`, JSON.stringify(ids));
}

async function getDeliveries(kv: KVNamespace, webhookId: string): Promise<DeliveryLog[]> {
  const raw = await kv.get(`webhook_deliveries:${webhookId}`);
  if (!raw) return [];
  return JSON.parse(raw) as DeliveryLog[];
}

async function appendDelivery(kv: KVNamespace, webhookId: string, log: DeliveryLog): Promise<void> {
  const existing = await getDeliveries(kv, webhookId);
  // Keep last 100
  const updated = [log, ...existing].slice(0, 100);
  // TTL 7 days
  await kv.put(`webhook_deliveries:${webhookId}`, JSON.stringify(updated), { expirationTtl: 604800 });
}

// ============ RETRY DELAYS ============

const RETRY_DELAYS_MS = [1000, 5000, 30000, 300000, 1800000]; // 1s, 5s, 30s, 5m, 30m

// ============ SINGLE DELIVERY ATTEMPT ============

async function attemptDelivery(
  url: string,
  body: string,
  signature: string,
  eventType: string
): Promise<{ statusCode: number | null; success: boolean; error?: string; durationMs: number }> {
  const start = Date.now();
  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Botcha-Signature': signature,
        'X-Botcha-Event': eventType,
        'User-Agent': 'Botcha-Webhook/1.0',
      },
      body,
      // 10s timeout via AbortController
      signal: AbortSignal.timeout(10000),
    });
    const durationMs = Date.now() - start;
    const success = response.status >= 200 && response.status < 300;
    return { statusCode: response.status, success, durationMs };
  } catch (err) {
    const durationMs = Date.now() - start;
    const error = err instanceof Error ? err.message : 'Unknown error';
    return { statusCode: null, success: false, error, durationMs };
  }
}

// ============ CORE DELIVERY FUNCTION ============

/**
 * Fire-and-forget webhook delivery with retry logic.
 * Call via: ctx.waitUntil(triggerWebhook(...))
 */
export async function triggerWebhook(
  kv: KVNamespace,
  appId: string,
  eventType: WebhookEventType,
  data: Record<string, unknown>
): Promise<void> {
  // Build event payload
  const event: BotchaEvent = {
    id: generateId('evt'),
    type: eventType,
    created_at: new Date().toISOString(),
    app_id: appId,
    data,
  };

  const body = JSON.stringify(event);

  // Load all webhooks for this app
  const ids = await getAppWebhookIds(kv, appId);
  if (ids.length === 0) return;

  for (const webhookId of ids) {
    const webhook = await getWebhook(kv, webhookId);
    if (!webhook) continue;
    if (!webhook.enabled || webhook.suspended) continue;
    if (!webhook.events.includes(eventType)) continue;

    const secret = await kv.get(`webhook_secret:${webhookId}`);
    if (!secret) continue;

    const signature = await computeHmacSignature(secret, body);

    let success = false;
    let lastResult: { statusCode: number | null; success: boolean; error?: string; durationMs: number } = {
      statusCode: null, success: false, durationMs: 0,
    };

    for (let attempt = 0; attempt < RETRY_DELAYS_MS.length; attempt++) {
      if (attempt > 0) {
        await sleep(RETRY_DELAYS_MS[attempt - 1]);
      }

      lastResult = await attemptDelivery(webhook.url, body, signature, eventType);

      const log: DeliveryLog = {
        delivery_id: generateId('dlv'),
        webhook_id: webhookId,
        event_type: eventType,
        event_id: event.id,
        attempted_at: Date.now(),
        attempt_number: attempt + 1,
        status_code: lastResult.statusCode,
        success: lastResult.success,
        error: lastResult.error,
        duration_ms: lastResult.durationMs,
      };

      await appendDelivery(kv, webhookId, log);

      if (lastResult.success) {
        success = true;
        // Reset failure counter
        webhook.consecutive_failures = 0;
        await saveWebhook(kv, webhook);
        break;
      }
    }

    if (!success) {
      webhook.consecutive_failures = (webhook.consecutive_failures || 0) + 1;
      // Suspend after 3 consecutive failures
      if (webhook.consecutive_failures >= 3) {
        webhook.suspended = true;
      }
      await saveWebhook(kv, webhook);
    }
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// ============ AUTH HELPER FOR ROUTES ============

function getVerificationPublicKey(env: any): any {
  const rawSigningKey = env?.JWT_SIGNING_KEY;
  if (!rawSigningKey) return undefined;
  try {
    const signingKey = JSON.parse(rawSigningKey) as ES256SigningKeyJWK;
    return getSigningPublicKeyJWK(signingKey);
  } catch {
    return undefined;
  }
}

async function validateAppAccess(c: Context): Promise<{
  valid: boolean;
  appId?: string;
  error?: string;
  status?: number;
}> {
  const authHeader = c.req.header('authorization');
  const token = extractBearerToken(authHeader);

  if (!token) {
    return { valid: false, error: 'UNAUTHORIZED', status: 401 };
  }

  const publicKey = getVerificationPublicKey(c.env);
  const result = await verifyToken(token, (c.env as any).JWT_SECRET, c.env, undefined, publicKey);
  if (!result.valid || !result.payload) {
    return { valid: false, error: 'INVALID_TOKEN', status: 401 };
  }

  const jwtAppId = (result.payload as any).app_id as string | undefined;
  if (!jwtAppId) {
    return { valid: false, error: 'MISSING_APP_ID', status: 403 };
  }

  return { valid: true, appId: jwtAppId };
}

// ============ ROUTE HANDLERS ============

/**
 * POST /v1/webhooks
 * Register a new webhook endpoint.
 */
export async function createWebhookRoute(c: Context): Promise<Response> {
  const auth = await validateAppAccess(c);
  if (!auth.valid || !auth.appId) {
    return c.json({ success: false, error: auth.error }, (auth.status ?? 401) as 401 | 403);
  }
  const appId = auth.appId;

  let body: { url?: string; events?: string[] };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ success: false, error: 'INVALID_JSON', message: 'Request body must be JSON' }, 400);
  }

  const { url, events } = body;

  if (!url || typeof url !== 'string') {
    return c.json({ success: false, error: 'MISSING_URL', message: 'url is required' }, 400);
  }

  try {
    new URL(url);
  } catch {
    return c.json({ success: false, error: 'INVALID_URL', message: 'url must be a valid HTTPS URL' }, 400);
  }

  // Validate events
  const eventList: WebhookEventType[] = (events && Array.isArray(events) && events.length > 0)
    ? events.filter((e): e is WebhookEventType => ALL_EVENT_TYPES.includes(e as WebhookEventType))
    : [...ALL_EVENT_TYPES];

  const webhookId = generateId('wh');
  const now = Date.now();

  const webhook: WebhookConfig = {
    id: webhookId,
    app_id: appId,
    url,
    events: eventList,
    enabled: true,
    created_at: now,
    updated_at: now,
    consecutive_failures: 0,
    suspended: false,
  };

  // Generate HMAC secret (32 random bytes → hex)
  const secretBytes = new Uint8Array(32);
  crypto.getRandomValues(secretBytes);
  const secret = Array.from(secretBytes).map(b => b.toString(16).padStart(2, '0')).join('');

  // Save webhook config and secret
  const kv = (c.env as any).AGENTS as KVNamespace;
  await saveWebhook(kv, webhook);
  await kv.put(`webhook_secret:${webhookId}`, secret);

  // Add to app index
  const existingIds = await getAppWebhookIds(kv, appId);
  await setAppWebhookIds(kv, appId, [...existingIds, webhookId]);

  return c.json({
    success: true,
    webhook: {
      id: webhookId,
      app_id: appId,
      url,
      events: eventList,
      enabled: true,
      created_at: new Date(now).toISOString(),
    },
    // Secret shown ONCE — store it securely!
    secret,
    warning: '⚠️ Save your webhook secret now — it will never be shown again. Use it to verify X-Botcha-Signature headers.',
    signature_info: 'Each delivery includes X-Botcha-Signature: sha256=<hmac-sha256-hex> header. Computed as HMAC-SHA256(secret, request_body).',
  }, 201);
}

/**
 * GET /v1/webhooks
 * List all webhooks for the authenticated app.
 */
export async function listWebhooksRoute(c: Context): Promise<Response> {
  const auth = await validateAppAccess(c);
  if (!auth.valid || !auth.appId) {
    return c.json({ success: false, error: auth.error }, (auth.status ?? 401) as 401 | 403);
  }
  const appId = auth.appId;

  const kv = (c.env as any).AGENTS as KVNamespace;
  const ids = await getAppWebhookIds(kv, appId);

  const webhooks = (await Promise.all(ids.map(id => getWebhook(kv, id))))
    .filter((w): w is WebhookConfig => w !== null)
    .map(w => ({
      id: w.id,
      app_id: w.app_id,
      url: w.url,
      events: w.events,
      enabled: w.enabled,
      suspended: w.suspended,
      consecutive_failures: w.consecutive_failures,
      created_at: new Date(w.created_at).toISOString(),
      updated_at: new Date(w.updated_at).toISOString(),
    }));

  return c.json({ success: true, webhooks });
}

/**
 * GET /v1/webhooks/:id
 * Get a specific webhook.
 */
export async function getWebhookRoute(c: Context): Promise<Response> {
  const auth = await validateAppAccess(c);
  if (!auth.valid || !auth.appId) {
    return c.json({ success: false, error: auth.error }, (auth.status ?? 401) as 401 | 403);
  }

  const webhookId = c.req.param('id');
  const kv = (c.env as any).AGENTS as KVNamespace;
  const webhook = await getWebhook(kv, webhookId);

  if (!webhook) {
    return c.json({ success: false, error: 'NOT_FOUND', message: 'Webhook not found' }, 404);
  }

  if (webhook.app_id !== auth.appId) {
    return c.json({ success: false, error: 'FORBIDDEN' }, 403);
  }

  return c.json({
    success: true,
    webhook: {
      id: webhook.id,
      app_id: webhook.app_id,
      url: webhook.url,
      events: webhook.events,
      enabled: webhook.enabled,
      suspended: webhook.suspended,
      consecutive_failures: webhook.consecutive_failures,
      created_at: new Date(webhook.created_at).toISOString(),
      updated_at: new Date(webhook.updated_at).toISOString(),
    },
  });
}

/**
 * PUT /v1/webhooks/:id
 * Update webhook (url, events, enabled).
 */
export async function updateWebhookRoute(c: Context): Promise<Response> {
  const auth = await validateAppAccess(c);
  if (!auth.valid || !auth.appId) {
    return c.json({ success: false, error: auth.error }, (auth.status ?? 401) as 401 | 403);
  }

  const webhookId = c.req.param('id');
  const kv = (c.env as any).AGENTS as KVNamespace;
  const webhook = await getWebhook(kv, webhookId);

  if (!webhook) {
    return c.json({ success: false, error: 'NOT_FOUND', message: 'Webhook not found' }, 404);
  }

  if (webhook.app_id !== auth.appId) {
    return c.json({ success: false, error: 'FORBIDDEN' }, 403);
  }

  let body: { url?: string; events?: string[]; enabled?: boolean };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ success: false, error: 'INVALID_JSON' }, 400);
  }

  if (body.url !== undefined) {
    try {
      new URL(body.url);
      webhook.url = body.url;
    } catch {
      return c.json({ success: false, error: 'INVALID_URL', message: 'url must be a valid URL' }, 400);
    }
  }

  if (body.events !== undefined && Array.isArray(body.events)) {
    const filtered = body.events.filter((e): e is WebhookEventType => ALL_EVENT_TYPES.includes(e as WebhookEventType));
    if (filtered.length > 0) webhook.events = filtered;
  }

  if (typeof body.enabled === 'boolean') {
    webhook.enabled = body.enabled;
    // Re-enabling a suspended webhook resets failure counter
    if (body.enabled && webhook.suspended) {
      webhook.suspended = false;
      webhook.consecutive_failures = 0;
    }
  }

  webhook.updated_at = Date.now();
  await saveWebhook(kv, webhook);

  return c.json({
    success: true,
    webhook: {
      id: webhook.id,
      app_id: webhook.app_id,
      url: webhook.url,
      events: webhook.events,
      enabled: webhook.enabled,
      suspended: webhook.suspended,
      updated_at: new Date(webhook.updated_at).toISOString(),
    },
  });
}

/**
 * DELETE /v1/webhooks/:id
 * Delete a webhook.
 */
export async function deleteWebhookRoute(c: Context): Promise<Response> {
  const auth = await validateAppAccess(c);
  if (!auth.valid || !auth.appId) {
    return c.json({ success: false, error: auth.error }, (auth.status ?? 401) as 401 | 403);
  }

  const webhookId = c.req.param('id');
  const kv = (c.env as any).AGENTS as KVNamespace;
  const webhook = await getWebhook(kv, webhookId);

  if (!webhook) {
    return c.json({ success: false, error: 'NOT_FOUND', message: 'Webhook not found' }, 404);
  }

  if (webhook.app_id !== auth.appId) {
    return c.json({ success: false, error: 'FORBIDDEN' }, 403);
  }

  await kv.delete(`webhook:${webhookId}`);
  await kv.delete(`webhook_secret:${webhookId}`);
  await kv.delete(`webhook_deliveries:${webhookId}`);

  // Remove from app index
  const ids = await getAppWebhookIds(kv, auth.appId);
  await setAppWebhookIds(kv, auth.appId, ids.filter(id => id !== webhookId));

  return c.json({ success: true, deleted: true, id: webhookId });
}

/**
 * POST /v1/webhooks/:id/test
 * Send a test event to verify endpoint reachability.
 */
export async function testWebhookRoute(c: Context): Promise<Response> {
  const auth = await validateAppAccess(c);
  if (!auth.valid || !auth.appId) {
    return c.json({ success: false, error: auth.error }, (auth.status ?? 401) as 401 | 403);
  }

  const webhookId = c.req.param('id');
  const kv = (c.env as any).AGENTS as KVNamespace;
  const webhook = await getWebhook(kv, webhookId);

  if (!webhook) {
    return c.json({ success: false, error: 'NOT_FOUND', message: 'Webhook not found' }, 404);
  }

  if (webhook.app_id !== auth.appId) {
    return c.json({ success: false, error: 'FORBIDDEN' }, 403);
  }

  const secret = await kv.get(`webhook_secret:${webhookId}`);
  if (!secret) {
    return c.json({ success: false, error: 'SECRET_NOT_FOUND' }, 500);
  }

  const testEvent: BotchaEvent = {
    id: generateId('evt'),
    type: 'challenge.solved',
    created_at: new Date().toISOString(),
    app_id: auth.appId,
    data: {
      test: true,
      message: '🐢 BOTCHA webhook test event — if you can read this, delivery is working!',
      webhook_id: webhookId,
    },
  };

  const body = JSON.stringify(testEvent);
  const signature = await computeHmacSignature(secret, body);
  const result = await attemptDelivery(webhook.url, body, signature, 'challenge.solved');

  const log: DeliveryLog = {
    delivery_id: generateId('dlv'),
    webhook_id: webhookId,
    event_type: 'challenge.solved',
    event_id: testEvent.id,
    attempted_at: Date.now(),
    attempt_number: 1,
    status_code: result.statusCode,
    success: result.success,
    error: result.error,
    duration_ms: result.durationMs,
  };

  await appendDelivery(kv, webhookId, log);

  return c.json({
    success: result.success,
    delivery: {
      status_code: result.statusCode,
      success: result.success,
      duration_ms: result.durationMs,
      error: result.error,
    },
    event: testEvent,
    message: result.success
      ? `✅ Test delivery succeeded (${result.statusCode}) in ${result.durationMs}ms`
      : `❌ Test delivery failed: ${result.error || `HTTP ${result.statusCode}`}`,
  });
}

/**
 * GET /v1/webhooks/:id/deliveries
 * Get recent delivery log (last 100 attempts).
 */
export async function listDeliveriesRoute(c: Context): Promise<Response> {
  const auth = await validateAppAccess(c);
  if (!auth.valid || !auth.appId) {
    return c.json({ success: false, error: auth.error }, (auth.status ?? 401) as 401 | 403);
  }

  const webhookId = c.req.param('id');
  const kv = (c.env as any).AGENTS as KVNamespace;
  const webhook = await getWebhook(kv, webhookId);

  if (!webhook) {
    return c.json({ success: false, error: 'NOT_FOUND', message: 'Webhook not found' }, 404);
  }

  if (webhook.app_id !== auth.appId) {
    return c.json({ success: false, error: 'FORBIDDEN' }, 403);
  }

  const deliveries = await getDeliveries(kv, webhookId);

  return c.json({
    success: true,
    webhook_id: webhookId,
    deliveries: deliveries.map(d => ({
      delivery_id: d.delivery_id,
      event_type: d.event_type,
      event_id: d.event_id,
      attempted_at: new Date(d.attempted_at).toISOString(),
      attempt_number: d.attempt_number,
      status_code: d.status_code,
      success: d.success,
      error: d.error,
      duration_ms: d.duration_ms,
    })),
  });
}
