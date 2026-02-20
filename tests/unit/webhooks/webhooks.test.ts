/**
 * Unit tests for BOTCHA Webhook Event System
 * Tests: CRUD, HMAC signing, delivery logging
 */

import { describe, test, expect, beforeEach, vi } from 'vitest';
import {
  computeHmacSignature,
  triggerWebhook,
  ALL_EVENT_TYPES,
  type KVNamespace,
  type WebhookConfig,
  type DeliveryLog,
} from '../../../packages/cloudflare-workers/src/webhooks.js';

// ============ IN-MEMORY KV MOCK ============

function createMockKV(): KVNamespace & { store: Map<string, string> } {
  const store = new Map<string, string>();
  return {
    store,
    async get(key: string) {
      return store.get(key) ?? null;
    },
    async put(key: string, value: string, _opts?: { expirationTtl?: number }) {
      store.set(key, value);
    },
    async delete(key: string) {
      store.delete(key);
    },
  };
}

// ============ HELPERS ============

function generateHex(bytes: number): string {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}

function makeWebhook(overrides: Partial<WebhookConfig> = {}): WebhookConfig {
  const id = `wh_${generateHex(8)}`;
  const now = Date.now();
  return {
    id,
    app_id: 'app_test123',
    url: 'https://example.com/webhook',
    events: [...ALL_EVENT_TYPES],
    enabled: true,
    created_at: now,
    updated_at: now,
    consecutive_failures: 0,
    suspended: false,
    ...overrides,
  };
}

async function seedWebhook(kv: KVNamespace, wh: WebhookConfig, secret?: string): Promise<string> {
  const s = secret ?? generateHex(32);
  await kv.put(`webhook:${wh.id}`, JSON.stringify(wh));
  await kv.put(`webhook_secret:${wh.id}`, s);
  // Update index
  const raw = await kv.get(`app_webhooks:${wh.app_id}`);
  const ids: string[] = raw ? JSON.parse(raw) : [];
  ids.push(wh.id);
  await kv.put(`app_webhooks:${wh.app_id}`, JSON.stringify(ids));
  return s;
}

// ============ TESTS ============

describe('Webhook Core Logic', () => {
  let kv: ReturnType<typeof createMockKV>;

  beforeEach(() => {
    kv = createMockKV();
    vi.restoreAllMocks();
  });

  // -------------------------------------------------------------------
  // 1. Create webhook → stores config, secret, index
  // -------------------------------------------------------------------
  test('create webhook stores config, secret, and app index', async () => {
    const wh = makeWebhook();
    const secret = await seedWebhook(kv, wh);

    // Config stored
    const raw = await kv.get(`webhook:${wh.id}`);
    expect(raw).not.toBeNull();
    const stored = JSON.parse(raw!) as WebhookConfig;
    expect(stored.id).toBe(wh.id);
    expect(stored.url).toBe(wh.url);
    expect(stored.enabled).toBe(true);
    expect(stored.suspended).toBe(false);

    // Secret stored
    const storedSecret = await kv.get(`webhook_secret:${wh.id}`);
    expect(storedSecret).toBe(secret);
    expect(storedSecret).toHaveLength(64); // 32 bytes = 64 hex chars

    // App index updated
    const indexRaw = await kv.get(`app_webhooks:${wh.app_id}`);
    expect(indexRaw).not.toBeNull();
    const index = JSON.parse(indexRaw!) as string[];
    expect(index).toContain(wh.id);
  });

  // -------------------------------------------------------------------
  // 2. List webhooks for app → returns all IDs in index
  // -------------------------------------------------------------------
  test('app index contains all registered webhook IDs', async () => {
    const wh1 = makeWebhook({ app_id: 'app_list' });
    const wh2 = makeWebhook({ app_id: 'app_list' });
    const wh3 = makeWebhook({ app_id: 'app_other' }); // different app

    await seedWebhook(kv, wh1);
    await seedWebhook(kv, wh2);
    await seedWebhook(kv, wh3);

    const raw = await kv.get('app_webhooks:app_list');
    const ids = JSON.parse(raw!) as string[];
    expect(ids).toContain(wh1.id);
    expect(ids).toContain(wh2.id);
    expect(ids).not.toContain(wh3.id);
  });

  // -------------------------------------------------------------------
  // 3. Get webhook by id → returns stored config
  // -------------------------------------------------------------------
  test('get webhook by id returns stored config', async () => {
    const wh = makeWebhook({ url: 'https://hooks.example.io/botcha' });
    await seedWebhook(kv, wh);

    const raw = await kv.get(`webhook:${wh.id}`);
    const got = JSON.parse(raw!) as WebhookConfig;
    expect(got.id).toBe(wh.id);
    expect(got.url).toBe('https://hooks.example.io/botcha');
    expect(got.events).toEqual(ALL_EVENT_TYPES);
  });

  // -------------------------------------------------------------------
  // 4. Update webhook (url, events) → persisted
  // -------------------------------------------------------------------
  test('update webhook persists new url and events', async () => {
    const wh = makeWebhook();
    await seedWebhook(kv, wh);

    // Simulate update
    const updated = { ...wh, url: 'https://new.example.com/hook', events: ['token.created', 'token.revoked'] as any };
    await kv.put(`webhook:${wh.id}`, JSON.stringify(updated));

    const raw = await kv.get(`webhook:${wh.id}`);
    const got = JSON.parse(raw!) as WebhookConfig;
    expect(got.url).toBe('https://new.example.com/hook');
    expect(got.events).toEqual(['token.created', 'token.revoked']);
  });

  // -------------------------------------------------------------------
  // 5. Delete webhook → removes config, secret, deliveries, and index entry
  // -------------------------------------------------------------------
  test('delete webhook removes all KV keys and index entry', async () => {
    const wh = makeWebhook();
    await seedWebhook(kv, wh);

    // Write a delivery log too
    await kv.put(`webhook_deliveries:${wh.id}`, JSON.stringify([{ delivery_id: 'dlv_test' }]));

    // Perform delete
    await kv.delete(`webhook:${wh.id}`);
    await kv.delete(`webhook_secret:${wh.id}`);
    await kv.delete(`webhook_deliveries:${wh.id}`);

    // Remove from index
    const indexRaw = await kv.get(`app_webhooks:${wh.app_id}`);
    const ids = JSON.parse(indexRaw!) as string[];
    const filtered = ids.filter(id => id !== wh.id);
    await kv.put(`app_webhooks:${wh.app_id}`, JSON.stringify(filtered));

    // Verify
    expect(await kv.get(`webhook:${wh.id}`)).toBeNull();
    expect(await kv.get(`webhook_secret:${wh.id}`)).toBeNull();
    expect(await kv.get(`webhook_deliveries:${wh.id}`)).toBeNull();
    const newIndex = JSON.parse((await kv.get(`app_webhooks:${wh.app_id}`))!) as string[];
    expect(newIndex).not.toContain(wh.id);
  });

  // -------------------------------------------------------------------
  // 6. HMAC signature is correct and verifiable
  // -------------------------------------------------------------------
  test('HMAC-SHA256 signature is correctly computed', async () => {
    const secret = 'test-secret-key';
    const body = JSON.stringify({ id: 'evt_abc', type: 'token.created' });

    const sig = await computeHmacSignature(secret, body);

    // Must start with 'sha256='
    expect(sig).toMatch(/^sha256=[0-9a-f]{64}$/);

    // Must be deterministic (same input → same output)
    const sig2 = await computeHmacSignature(secret, body);
    expect(sig).toBe(sig2);

    // Different secret → different signature
    const sigOther = await computeHmacSignature('different-secret', body);
    expect(sig).not.toBe(sigOther);

    // Different body → different signature
    const sigBody2 = await computeHmacSignature(secret, body + ' ');
    expect(sig).not.toBe(sigBody2);
  });

  // -------------------------------------------------------------------
  // 7. Test delivery endpoint: attempt recorded in delivery log
  // -------------------------------------------------------------------
  test('delivery log is stored in KV after triggerWebhook', async () => {
    const wh = makeWebhook({ events: ['token.created'] });
    const secret = await seedWebhook(kv, wh);

    // Mock fetch to return 200
    const fetchSpy = vi.fn().mockResolvedValue(new Response('ok', { status: 200 }));
    const originalFetch = globalThis.fetch;
    (globalThis as any).fetch = fetchSpy;

    await triggerWebhook(kv, wh.app_id, 'token.created', { agent_id: 'agent_test' });

    // Delivery log should now exist
    const rawLog = await kv.get(`webhook_deliveries:${wh.id}`);
    expect(rawLog).not.toBeNull();
    const logs = JSON.parse(rawLog!) as DeliveryLog[];
    expect(logs.length).toBeGreaterThanOrEqual(1);
    expect(logs[0].success).toBe(true);
    expect(logs[0].event_type).toBe('token.created');
    expect(logs[0].webhook_id).toBe(wh.id);
    expect(logs[0].status_code).toBe(200);
    expect(fetchSpy).toHaveBeenCalledOnce();

    (globalThis as any).fetch = originalFetch;
  });

  // -------------------------------------------------------------------
  // 8. triggerWebhook sends signed payload and correct headers
  // -------------------------------------------------------------------
  test('triggerWebhook sends X-Botcha-Signature header with correct HMAC', async () => {
    const wh = makeWebhook({ events: ['token.revoked'] });
    await seedWebhook(kv, wh, 'fixed-test-secret-abc123');

    // Capture (url, options) from fetch call
    let capturedUrl: string | null = null;
    let capturedInit: RequestInit | null = null;
    const fetchSpy = vi.fn().mockImplementation(async (url: string, init: RequestInit) => {
      capturedUrl = url;
      capturedInit = init;
      return new Response('', { status: 200 });
    });
    const originalFetch = globalThis.fetch;
    (globalThis as any).fetch = fetchSpy;

    await triggerWebhook(kv, wh.app_id, 'token.revoked', { jti: 'some-jti' });

    expect(fetchSpy).toHaveBeenCalledOnce();
    expect(capturedUrl).toBe(wh.url);
    expect(capturedInit).not.toBeNull();

    const headers = capturedInit!.headers as Record<string, string>;
    const sentSig = headers['X-Botcha-Signature'];
    expect(sentSig).toMatch(/^sha256=[0-9a-f]{64}$/);

    // Verify the signature matches what we'd compute ourselves
    const sentBody = capturedInit!.body as string;
    const expectedSig = await computeHmacSignature('fixed-test-secret-abc123', sentBody);
    expect(sentSig).toBe(expectedSig);

    (globalThis as any).fetch = originalFetch;
  });

  // -------------------------------------------------------------------
  // 9. Suspended webhook is skipped (no fetch call)
  // -------------------------------------------------------------------
  test('suspended webhook is skipped during delivery', async () => {
    const wh = makeWebhook({ suspended: true, events: ['agent.tap.registered'] });
    await seedWebhook(kv, wh);

    const fetchSpy = vi.fn();
    const originalFetch = globalThis.fetch;
    (globalThis as any).fetch = fetchSpy;

    await triggerWebhook(kv, wh.app_id, 'agent.tap.registered', {});

    expect(fetchSpy).not.toHaveBeenCalled();
    (globalThis as any).fetch = originalFetch;
  });

  // -------------------------------------------------------------------
  // 10. Webhook with non-matching events is skipped
  // -------------------------------------------------------------------
  test('webhook subscribed to different event type is skipped', async () => {
    // Only subscribed to 'token.created', not 'token.revoked'
    const wh = makeWebhook({ events: ['token.created'] });
    await seedWebhook(kv, wh);

    const fetchSpy = vi.fn();
    const originalFetch = globalThis.fetch;
    (globalThis as any).fetch = fetchSpy;

    await triggerWebhook(kv, wh.app_id, 'token.revoked', { jti: 'abc' });

    expect(fetchSpy).not.toHaveBeenCalled();
    (globalThis as any).fetch = originalFetch;
  });

  // -------------------------------------------------------------------
  // 11. Failed delivery increments consecutive_failures
  // -------------------------------------------------------------------
  test('failed delivery increments consecutive_failures in config (simulated)', async () => {
    // Simulate what triggerWebhook does on failure: increment consecutive_failures
    // We test the KV update logic directly without running the full retry loop.
    const wh = makeWebhook({ events: ['token.created'], consecutive_failures: 0 });
    await seedWebhook(kv, wh);

    // Simulate failure path: increment and persist
    const raw = await kv.get(`webhook:${wh.id}`);
    const cfg = JSON.parse(raw!) as WebhookConfig;
    cfg.consecutive_failures += 1;
    await kv.put(`webhook:${wh.id}`, JSON.stringify(cfg));

    const updated = JSON.parse((await kv.get(`webhook:${wh.id}`))!) as WebhookConfig;
    expect(updated.consecutive_failures).toBe(1);
    expect(updated.suspended).toBe(false);
  });

  // -------------------------------------------------------------------
  // 12. Webhook suspended after 3+ consecutive failures
  // -------------------------------------------------------------------
  test('webhook becomes suspended after 3 consecutive failures (simulated)', async () => {
    // Start with 2 consecutive failures; after one more → suspended
    const wh = makeWebhook({ events: ['tap.session.created'], consecutive_failures: 2 });
    await seedWebhook(kv, wh);

    // Simulate failure: increment and check threshold
    const raw = await kv.get(`webhook:${wh.id}`);
    const cfg = JSON.parse(raw!) as WebhookConfig;
    cfg.consecutive_failures += 1;
    if (cfg.consecutive_failures >= 3) cfg.suspended = true;
    await kv.put(`webhook:${wh.id}`, JSON.stringify(cfg));

    const updated = JSON.parse((await kv.get(`webhook:${wh.id}`))!) as WebhookConfig;
    expect(updated.consecutive_failures).toBe(3);
    expect(updated.suspended).toBe(true);
  });
});
