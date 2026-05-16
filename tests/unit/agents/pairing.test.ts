import { describe, test, expect, beforeEach } from 'vitest';
import {
  createPairCode,
  consumePairCode,
  updateAppRegistrationPolicy,
  getApp,
  type AppConfig,
} from '../../../packages/cloudflare-workers/src/apps.js';

// ============ Mock KV ============

class MockKV {
  private store = new Map<string, string>();

  async get(key: string, _type?: string): Promise<string | null> {
    return this.store.get(key) ?? null;
  }

  async put(key: string, value: string, _opts?: { expirationTtl?: number }): Promise<void> {
    this.store.set(key, value);
  }

  async delete(key: string): Promise<void> {
    this.store.delete(key);
  }

  has(key: string): boolean {
    return this.store.has(key);
  }

  getRaw(key: string): string | undefined {
    return this.store.get(key);
  }
}

const TEST_APP_ID = 'app_1234567890abcdef';
const OTHER_APP_ID = 'app_fedcba0987654321';

// Seed an app record in the APPS KV
async function seedApp(kv: MockKV, app_id: string, policy: 'open' | 'paired' = 'open') {
  const config: AppConfig = {
    app_id,
    secret_hash: 'deadbeef'.repeat(8),
    created_at: Date.now(),
    rate_limit: 100,
    email: 'test@example.com',
    email_verified: true,
    registration_policy: policy,
  };
  await kv.put(`app:${app_id}`, JSON.stringify(config));
}

// ============ Pair Code Tests ============

describe('createPairCode()', () => {
  let challengesKv: MockKV;

  beforeEach(() => {
    challengesKv = new MockKV();
  });

  test('returns a PAIR-XXXXXX formatted code', async () => {
    const code = await createPairCode(challengesKv as any, TEST_APP_ID);
    expect(code).toMatch(/^PAIR-[23456789ABCDEFGHJKMNPQRSTUVWXYZ]{6}$/);
  });

  test('stores code in KV under pair_code:{code}', async () => {
    const code = await createPairCode(challengesKv as any, TEST_APP_ID);
    expect(challengesKv.has(`pair_code:${code}`)).toBe(true);
    const raw = JSON.parse(challengesKv.getRaw(`pair_code:${code}`)!);
    expect(raw.app_id).toBe(TEST_APP_ID);
    expect(raw.used).toBe(false);
  });

  test('generates unique codes on each call', async () => {
    const codes = new Set<string>();
    for (let i = 0; i < 20; i++) {
      codes.add(await createPairCode(challengesKv as any, TEST_APP_ID));
    }
    expect(codes.size).toBe(20);
  });
});

describe('consumePairCode()', () => {
  let challengesKv: MockKV;

  beforeEach(() => {
    challengesKv = new MockKV();
  });

  test('returns true and marks code as used on first consumption', async () => {
    const code = await createPairCode(challengesKv as any, TEST_APP_ID);
    const result = await consumePairCode(challengesKv as any, code, TEST_APP_ID);
    expect(result).toBe(true);
    const raw = JSON.parse(challengesKv.getRaw(`pair_code:${code}`)!);
    expect(raw.used).toBe(true);
  });

  test('returns false on second consumption (single-use)', async () => {
    const code = await createPairCode(challengesKv as any, TEST_APP_ID);
    await consumePairCode(challengesKv as any, code, TEST_APP_ID);
    const second = await consumePairCode(challengesKv as any, code, TEST_APP_ID);
    expect(second).toBe(false);
  });

  test('returns false when code does not exist', async () => {
    const result = await consumePairCode(challengesKv as any, 'PAIR-NOTREAL', TEST_APP_ID);
    expect(result).toBe(false);
  });

  test('returns false when app_id does not match', async () => {
    const code = await createPairCode(challengesKv as any, TEST_APP_ID);
    const result = await consumePairCode(challengesKv as any, code, OTHER_APP_ID);
    expect(result).toBe(false);
  });

  test('code is still present under its key after consumption (TTL reduced)', async () => {
    const code = await createPairCode(challengesKv as any, TEST_APP_ID);
    await consumePairCode(challengesKv as any, code, TEST_APP_ID);
    // The key should still exist (marked used, not deleted)
    expect(challengesKv.has(`pair_code:${code}`)).toBe(true);
  });
});

// ============ Registration Policy Tests ============

describe('updateAppRegistrationPolicy()', () => {
  let appsKv: MockKV;

  beforeEach(async () => {
    appsKv = new MockKV();
    await seedApp(appsKv, TEST_APP_ID, 'open');
  });

  test('sets policy to paired', async () => {
    const ok = await updateAppRegistrationPolicy(appsKv as any, TEST_APP_ID, 'paired');
    expect(ok).toBe(true);
    const app = await getApp(appsKv as any, TEST_APP_ID);
    expect(app?.registration_policy).toBe('paired');
  });

  test('sets policy back to open', async () => {
    await updateAppRegistrationPolicy(appsKv as any, TEST_APP_ID, 'paired');
    const ok = await updateAppRegistrationPolicy(appsKv as any, TEST_APP_ID, 'open');
    expect(ok).toBe(true);
    const app = await getApp(appsKv as any, TEST_APP_ID);
    expect(app?.registration_policy).toBe('open');
  });

  test('returns false for unknown app_id', async () => {
    const ok = await updateAppRegistrationPolicy(appsKv as any, OTHER_APP_ID, 'paired');
    expect(ok).toBe(false);
  });
});

describe('getApp() registration_policy default', () => {
  test('returns open for apps without the field set', async () => {
    const kv = new MockKV();
    // Store an app without registration_policy (simulates pre-existing record)
    const legacy: Partial<AppConfig> = {
      app_id: TEST_APP_ID,
      secret_hash: 'aabb',
      created_at: Date.now(),
      rate_limit: 100,
      email: 'x@y.com',
      email_verified: false,
    };
    await kv.put(`app:${TEST_APP_ID}`, JSON.stringify(legacy));
    const app = await getApp(kv as any, TEST_APP_ID);
    expect(app?.registration_policy).toBe('open');
  });
});
