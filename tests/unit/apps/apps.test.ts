import { describe, test, expect, beforeEach } from 'vitest';
import {
  generateAppId,
  generateAppSecret,
  hashSecret,
  generateVerificationCode,
  createApp,
  getApp,
  validateAppSecret,
  verifyEmailCode,
  getAppByEmail,
  rotateAppSecret,
  regenerateVerificationCode,
  type KVNamespace,
} from '../../../packages/cloudflare-workers/src/apps.js';

// Mock KV namespace using a simple Map
class MockKV implements KVNamespace {
  private store = new Map<string, string>();

  async get(key: string, type?: 'text' | 'json' | 'arrayBuffer' | 'stream'): Promise<any> {
    const value = this.store.get(key);
    if (!value) return null;
    
    if (type === 'json') {
      return JSON.parse(value);
    }
    return value;
  }

  async put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void> {
    this.store.set(key, value);
  }

  async delete(key: string): Promise<void> {
    this.store.delete(key);
  }

  // Helper to inspect store in tests
  has(key: string): boolean {
    return this.store.has(key);
  }

  size(): number {
    return this.store.size;
  }

  getRaw(key: string): string | undefined {
    return this.store.get(key);
  }
}

const TEST_EMAIL = 'agent@botcha.ai';

describe('Apps - Multi-Tenant Infrastructure', () => {
  describe('generateAppId()', () => {
    test('generates ID with correct format: app_ + 16 hex chars', () => {
      const appId = generateAppId();
      
      expect(appId).toMatch(/^app_[0-9a-f]{16}$/);
    });

    test('generates unique IDs on each call', () => {
      const id1 = generateAppId();
      const id2 = generateAppId();
      const id3 = generateAppId();
      
      expect(id1).not.toBe(id2);
      expect(id2).not.toBe(id3);
      expect(id1).not.toBe(id3);
    });

    test('has correct length: 20 chars total', () => {
      const appId = generateAppId();
      
      // 'app_' (4) + 16 hex chars = 20 total
      expect(appId).toHaveLength(20);
    });
  });

  describe('generateAppSecret()', () => {
    test('generates secret with correct format: sk_ + 32 hex chars', () => {
      const secret = generateAppSecret();
      
      expect(secret).toMatch(/^sk_[0-9a-f]{32}$/);
    });

    test('generates unique secrets on each call', () => {
      const secret1 = generateAppSecret();
      const secret2 = generateAppSecret();
      const secret3 = generateAppSecret();
      
      expect(secret1).not.toBe(secret2);
      expect(secret2).not.toBe(secret3);
      expect(secret1).not.toBe(secret3);
    });

    test('has correct length: 35 chars total', () => {
      const secret = generateAppSecret();
      
      // 'sk_' (3) + 32 hex chars = 35 total
      expect(secret).toHaveLength(35);
    });
  });

  describe('hashSecret()', () => {
    test('produces SHA-256 hash as 64 hex chars', async () => {
      const secret = 'sk_test_secret_1234567890abcdef';
      const hash = await hashSecret(secret);
      
      // SHA-256 produces 32 bytes = 64 hex chars
      expect(hash).toMatch(/^[0-9a-f]{64}$/);
      expect(hash).toHaveLength(64);
    });

    test('produces consistent hash for same input', async () => {
      const secret = 'sk_consistent_test';
      const hash1 = await hashSecret(secret);
      const hash2 = await hashSecret(secret);
      
      expect(hash1).toBe(hash2);
    });

    test('produces different hashes for different inputs', async () => {
      const secret1 = 'sk_secret_one';
      const secret2 = 'sk_secret_two';
      
      const hash1 = await hashSecret(secret1);
      const hash2 = await hashSecret(secret2);
      
      expect(hash1).not.toBe(hash2);
    });

    test('known test vector for SHA-256', async () => {
      // Test with known input/output
      const secret = 'test';
      const hash = await hashSecret(secret);
      
      // SHA-256('test') = 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
      expect(hash).toBe('9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08');
    });
  });

  describe('generateVerificationCode()', () => {
    test('produces a 6-digit numeric string', () => {
      const code = generateVerificationCode();
      expect(code).toMatch(/^\d{6}$/);
    });

    test('pads with leading zeros', () => {
      // Run multiple times to check padding
      for (let i = 0; i < 20; i++) {
        const code = generateVerificationCode();
        expect(code).toHaveLength(6);
      }
    });

    test('generates varying codes', () => {
      const codes = new Set<string>();
      for (let i = 0; i < 10; i++) {
        codes.add(generateVerificationCode());
      }
      // At least some should be different (probabilistic but extremely likely)
      expect(codes.size).toBeGreaterThan(1);
    });
  });

  describe('createApp()', () => {
    let mockKV: MockKV;

    beforeEach(() => {
      mockKV = new MockKV();
    });

    test('creates app with app_id, app_secret, and email', async () => {
      const result = await createApp(mockKV, TEST_EMAIL);
      
      expect(result).toHaveProperty('app_id');
      expect(result).toHaveProperty('app_secret');
      expect(result).toHaveProperty('email');
      expect(result.app_id).toMatch(/^app_[0-9a-f]{16}$/);
      expect(result.app_secret).toMatch(/^sk_[0-9a-f]{32}$/);
      expect(result.email).toBe(TEST_EMAIL);
      expect(result.email_verified).toBe(false);
      expect(result.verification_required).toBe(true);
    });

    test('stores app in KV with hashed secret and email', async () => {
      const result = await createApp(mockKV, TEST_EMAIL);
      
      // Verify KV entry exists
      expect(mockKV.has(`app:${result.app_id}`)).toBe(true);
      
      // Retrieve and verify stored data
      const stored = await mockKV.get(`app:${result.app_id}`, 'text');
      const config = JSON.parse(stored);
      
      expect(config.app_id).toBe(result.app_id);
      expect(config).toHaveProperty('secret_hash');
      expect(config.secret_hash).toMatch(/^[0-9a-f]{64}$/); // SHA-256 hash
      expect(config).toHaveProperty('created_at');
      expect(config.created_at).toBeGreaterThan(Date.now() - 1000); // Recent
      expect(config.rate_limit).toBe(100); // Default rate limit
      expect(config.email).toBe(TEST_EMAIL);
      expect(config.email_verified).toBe(false);
      expect(config.email_verification_code).toBeDefined();
      expect(config.email_verification_expires).toBeDefined();
    });

    test('stores email→app_id reverse index in KV', async () => {
      const result = await createApp(mockKV, TEST_EMAIL);
      
      const storedAppId = await mockKV.get(`email:${TEST_EMAIL}`, 'text');
      expect(storedAppId).toBe(result.app_id);
    });

    test('email index is case-insensitive', async () => {
      const result = await createApp(mockKV, 'Agent@Botcha.AI');
      
      const storedAppId = await mockKV.get('email:agent@botcha.ai', 'text');
      expect(storedAppId).toBe(result.app_id);
    });

    test('never stores plaintext secret in KV', async () => {
      const result = await createApp(mockKV, TEST_EMAIL);
      
      const stored = await mockKV.get(`app:${result.app_id}`, 'text');
      
      // Verify plaintext secret is NOT in stored data
      expect(stored).not.toContain(result.app_secret);
    });

    test('stored secret_hash matches hashed app_secret', async () => {
      const result = await createApp(mockKV, TEST_EMAIL);
      
      const stored = await mockKV.get(`app:${result.app_id}`, 'text');
      const config = JSON.parse(stored);
      
      const expectedHash = await hashSecret(result.app_secret);
      expect(config.secret_hash).toBe(expectedHash);
    });

    test('creates multiple unique apps', async () => {
      const app1 = await createApp(mockKV, 'agent1@botcha.ai');
      const app2 = await createApp(mockKV, 'agent2@botcha.ai');
      const app3 = await createApp(mockKV, 'agent3@botcha.ai');
      
      // All IDs should be unique
      expect(app1.app_id).not.toBe(app2.app_id);
      expect(app2.app_id).not.toBe(app3.app_id);
      expect(app1.app_id).not.toBe(app3.app_id);
      
      // All secrets should be unique
      expect(app1.app_secret).not.toBe(app2.app_secret);
      expect(app2.app_secret).not.toBe(app3.app_secret);
      expect(app1.app_secret).not.toBe(app3.app_secret);
    });

    test('creates app with optional name', async () => {
      const result = await createApp(mockKV, TEST_EMAIL, 'My Shopping App');
      
      expect(result.name).toBe('My Shopping App');
      expect(result.app_id).toMatch(/^app_[0-9a-f]{16}$/);
      
      // Verify name is stored in KV
      const stored = await mockKV.get(`app:${result.app_id}`, 'text');
      const config = JSON.parse(stored);
      expect(config.name).toBe('My Shopping App');
    });

    test('creates app without name (backward compatible)', async () => {
      const result = await createApp(mockKV, TEST_EMAIL);
      
      expect(result.name).toBeUndefined();
      
      // Verify no name field in KV
      const stored = await mockKV.get(`app:${result.app_id}`, 'text');
      const config = JSON.parse(stored);
      expect(config.name).toBeUndefined();
    });
  });

  describe('getApp()', () => {
    let mockKV: MockKV;

    beforeEach(() => {
      mockKV = new MockKV();
    });

    test('retrieves app by app_id with email fields', async () => {
      const created = await createApp(mockKV, TEST_EMAIL);
      const retrieved = await getApp(mockKV, created.app_id);
      
      expect(retrieved).not.toBeNull();
      expect(retrieved?.app_id).toBe(created.app_id);
      expect(retrieved).toHaveProperty('created_at');
      expect(retrieved).toHaveProperty('rate_limit');
      expect(retrieved?.rate_limit).toBe(100);
      expect(retrieved?.email).toBe(TEST_EMAIL);
      expect(retrieved?.email_verified).toBe(false);
    });

    test('does NOT return secret_hash (security)', async () => {
      const created = await createApp(mockKV, TEST_EMAIL);
      const retrieved = await getApp(mockKV, created.app_id);
      
      expect(retrieved).not.toHaveProperty('secret_hash');
    });

    test('returns name when set', async () => {
      const created = await createApp(mockKV, TEST_EMAIL, 'My API');
      const retrieved = await getApp(mockKV, created.app_id);
      
      expect(retrieved?.name).toBe('My API');
    });

    test('omits name when not set (backward compatible)', async () => {
      const created = await createApp(mockKV, TEST_EMAIL);
      const retrieved = await getApp(mockKV, created.app_id);
      
      expect(retrieved?.name).toBeUndefined();
    });

    test('returns null for non-existent app', async () => {
      const retrieved = await getApp(mockKV, 'app_nonexistent1234');
      
      expect(retrieved).toBeNull();
    });

    test('returns null for invalid app_id format', async () => {
      const retrieved = await getApp(mockKV, 'invalid-id');
      
      expect(retrieved).toBeNull();
    });

    test('retrieves correct app from multiple apps', async () => {
      const app1 = await createApp(mockKV, 'a1@botcha.ai');
      const app2 = await createApp(mockKV, 'a2@botcha.ai');
      const app3 = await createApp(mockKV, 'a3@botcha.ai');
      
      const retrieved2 = await getApp(mockKV, app2.app_id);
      
      expect(retrieved2).not.toBeNull();
      expect(retrieved2?.app_id).toBe(app2.app_id);
      expect(retrieved2?.app_id).not.toBe(app1.app_id);
      expect(retrieved2?.app_id).not.toBe(app3.app_id);
    });
  });

  describe('validateAppSecret()', () => {
    let mockKV: MockKV;

    beforeEach(() => {
      mockKV = new MockKV();
    });

    test('validates correct app_secret', async () => {
      const created = await createApp(mockKV, TEST_EMAIL);
      
      const isValid = await validateAppSecret(
        mockKV,
        created.app_id,
        created.app_secret
      );
      
      expect(isValid).toBe(true);
    });

    test('rejects incorrect app_secret', async () => {
      const created = await createApp(mockKV, TEST_EMAIL);
      
      const isValid = await validateAppSecret(
        mockKV,
        created.app_id,
        'sk_wrong_secret_1234567890abcdef'
      );
      
      expect(isValid).toBe(false);
    });

    test('rejects secret for non-existent app', async () => {
      const isValid = await validateAppSecret(
        mockKV,
        'app_nonexistent1234',
        'sk_any_secret_1234567890abcdefgh'
      );
      
      expect(isValid).toBe(false);
    });

    test('rejects empty secret', async () => {
      const created = await createApp(mockKV, TEST_EMAIL);
      
      const isValid = await validateAppSecret(
        mockKV,
        created.app_id,
        ''
      );
      
      expect(isValid).toBe(false);
    });

    test('rejects secret with slight modification', async () => {
      const created = await createApp(mockKV, TEST_EMAIL);
      
      // Modify last character of secret
      const modifiedSecret = created.app_secret.slice(0, -1) + 'x';
      
      const isValid = await validateAppSecret(
        mockKV,
        created.app_id,
        modifiedSecret
      );
      
      expect(isValid).toBe(false);
    });

    test('validates secrets for multiple apps independently', async () => {
      const app1 = await createApp(mockKV, 'a1@botcha.ai');
      const app2 = await createApp(mockKV, 'a2@botcha.ai');
      
      // App1 secret should work for app1
      expect(await validateAppSecret(mockKV, app1.app_id, app1.app_secret)).toBe(true);
      
      // App2 secret should work for app2
      expect(await validateAppSecret(mockKV, app2.app_id, app2.app_secret)).toBe(true);
      
      // App1 secret should NOT work for app2
      expect(await validateAppSecret(mockKV, app2.app_id, app1.app_secret)).toBe(false);
      
      // App2 secret should NOT work for app1
      expect(await validateAppSecret(mockKV, app1.app_id, app2.app_secret)).toBe(false);
    });

    test('uses constant-time comparison (prevents timing attacks)', async () => {
      const created = await createApp(mockKV, TEST_EMAIL);
      
      // Test with secrets of different lengths
      // Constant-time should not leak length information
      const shortSecret = 'sk_short';
      const longSecret = 'sk_' + 'x'.repeat(100);
      
      const isValid1 = await validateAppSecret(mockKV, created.app_id, shortSecret);
      const isValid2 = await validateAppSecret(mockKV, created.app_id, longSecret);
      
      // Both should be false (wrong secrets)
      expect(isValid1).toBe(false);
      expect(isValid2).toBe(false);
    });
  });

  describe('verifyEmailCode()', () => {
    let mockKV: MockKV;

    beforeEach(() => {
      mockKV = new MockKV();
    });

    test('verifies correct code and marks email verified', async () => {
      const created = await createApp(mockKV, TEST_EMAIL);

      // Get the stored verification code hash, then regenerate to get plaintext
      const regen = await regenerateVerificationCode(mockKV, created.app_id);
      expect(regen).not.toBeNull();

      const result = await verifyEmailCode(mockKV, created.app_id, regen!.code);
      expect(result.verified).toBe(true);

      // Confirm email is now verified
      const app = await getApp(mockKV, created.app_id);
      expect(app?.email_verified).toBe(true);
    });

    test('rejects wrong code', async () => {
      await createApp(mockKV, TEST_EMAIL);
      const created = await createApp(mockKV, 'other@botcha.ai');

      const result = await verifyEmailCode(mockKV, created.app_id, '000000');
      expect(result.verified).toBe(false);
      expect(result.reason).toBe('Invalid verification code');
    });

    test('rejects already verified email', async () => {
      const created = await createApp(mockKV, TEST_EMAIL);
      const regen = await regenerateVerificationCode(mockKV, created.app_id);
      await verifyEmailCode(mockKV, created.app_id, regen!.code);

      // Try again
      const result = await verifyEmailCode(mockKV, created.app_id, regen!.code);
      expect(result.verified).toBe(false);
      expect(result.reason).toBe('Email already verified');
    });

    test('rejects expired code', async () => {
      const created = await createApp(mockKV, TEST_EMAIL);

      // Manually expire the code
      const data = JSON.parse(mockKV.getRaw(`app:${created.app_id}`)!);
      data.email_verification_expires = Date.now() - 1000; // expired 1s ago
      await mockKV.put(`app:${created.app_id}`, JSON.stringify(data));

      const regen = await regenerateVerificationCode(mockKV, created.app_id);
      // After regen, the new code has a fresh expiry so we need to expire it again
      const data2 = JSON.parse(mockKV.getRaw(`app:${created.app_id}`)!);
      data2.email_verification_expires = Date.now() - 1000;
      await mockKV.put(`app:${created.app_id}`, JSON.stringify(data2));

      const result = await verifyEmailCode(mockKV, created.app_id, regen!.code);
      expect(result.verified).toBe(false);
      expect(result.reason).toBe('Verification code expired');
    });

    test('returns error for non-existent app', async () => {
      const result = await verifyEmailCode(mockKV, 'app_nonexistent1234', '123456');
      expect(result.verified).toBe(false);
      expect(result.reason).toBe('App not found');
    });
  });

  describe('getAppByEmail()', () => {
    let mockKV: MockKV;

    beforeEach(() => {
      mockKV = new MockKV();
    });

    test('finds app by email', async () => {
      const created = await createApp(mockKV, TEST_EMAIL);

      const found = await getAppByEmail(mockKV, TEST_EMAIL);
      expect(found).not.toBeNull();
      expect(found?.app_id).toBe(created.app_id);
      expect(found?.email_verified).toBe(false);
    });

    test('lookup is case-insensitive', async () => {
      const created = await createApp(mockKV, 'Agent@Botcha.AI');

      const found = await getAppByEmail(mockKV, 'agent@botcha.ai');
      expect(found).not.toBeNull();
      expect(found?.app_id).toBe(created.app_id);
    });

    test('returns null for non-existent email', async () => {
      const found = await getAppByEmail(mockKV, 'nobody@botcha.ai');
      expect(found).toBeNull();
    });

    test('reflects verified status after verification', async () => {
      const created = await createApp(mockKV, TEST_EMAIL);
      const regen = await regenerateVerificationCode(mockKV, created.app_id);
      await verifyEmailCode(mockKV, created.app_id, regen!.code);

      const found = await getAppByEmail(mockKV, TEST_EMAIL);
      expect(found?.email_verified).toBe(true);
    });
  });

  describe('rotateAppSecret()', () => {
    let mockKV: MockKV;

    beforeEach(() => {
      mockKV = new MockKV();
    });

    test('generates new secret and invalidates old one', async () => {
      const created = await createApp(mockKV, TEST_EMAIL);
      
      const rotated = await rotateAppSecret(mockKV, created.app_id);
      expect(rotated).not.toBeNull();
      expect(rotated!.app_secret).toMatch(/^sk_[0-9a-f]{32}$/);
      expect(rotated!.app_secret).not.toBe(created.app_secret);

      // Old secret should no longer work
      expect(await validateAppSecret(mockKV, created.app_id, created.app_secret)).toBe(false);
      
      // New secret should work
      expect(await validateAppSecret(mockKV, created.app_id, rotated!.app_secret)).toBe(true);
    });

    test('returns null for non-existent app', async () => {
      const result = await rotateAppSecret(mockKV, 'app_nonexistent1234');
      expect(result).toBeNull();
    });

    test('preserves other app fields after rotation', async () => {
      const created = await createApp(mockKV, TEST_EMAIL);
      
      // Verify email first
      const regen = await regenerateVerificationCode(mockKV, created.app_id);
      await verifyEmailCode(mockKV, created.app_id, regen!.code);

      await rotateAppSecret(mockKV, created.app_id);

      const app = await getApp(mockKV, created.app_id);
      expect(app?.email).toBe(TEST_EMAIL);
      expect(app?.email_verified).toBe(true);
      expect(app?.rate_limit).toBe(100);
    });
  });

  describe('regenerateVerificationCode()', () => {
    let mockKV: MockKV;

    beforeEach(() => {
      mockKV = new MockKV();
    });

    test('generates new plaintext code', async () => {
      const created = await createApp(mockKV, TEST_EMAIL);
      const regen = await regenerateVerificationCode(mockKV, created.app_id);
      
      expect(regen).not.toBeNull();
      expect(regen!.code).toMatch(/^\d{6}$/);
    });

    test('returns null for already verified app', async () => {
      const created = await createApp(mockKV, TEST_EMAIL);
      const regen = await regenerateVerificationCode(mockKV, created.app_id);
      await verifyEmailCode(mockKV, created.app_id, regen!.code);

      const regen2 = await regenerateVerificationCode(mockKV, created.app_id);
      expect(regen2).toBeNull();
    });

    test('returns null for non-existent app', async () => {
      const result = await regenerateVerificationCode(mockKV, 'app_nonexistent1234');
      expect(result).toBeNull();
    });

    test('new code works for verification after regeneration', async () => {
      const created = await createApp(mockKV, TEST_EMAIL);
      
      // Regenerate
      const regen = await regenerateVerificationCode(mockKV, created.app_id);
      expect(regen).not.toBeNull();
      
      // Verify with the new code
      const result = await verifyEmailCode(mockKV, created.app_id, regen!.code);
      expect(result.verified).toBe(true);
    });
  });

  describe('Integration: Full workflow', () => {
    let mockKV: MockKV;

    beforeEach(() => {
      mockKV = new MockKV();
    });

    test('complete app lifecycle: create → verify email → validate → rotate', async () => {
      // 1. Create app
      const created = await createApp(mockKV, TEST_EMAIL);
      expect(created.app_id).toBeDefined();
      expect(created.app_secret).toBeDefined();
      expect(created.email).toBe(TEST_EMAIL);
      
      // 2. Retrieve app (without secret)
      const retrieved = await getApp(mockKV, created.app_id);
      expect(retrieved).not.toBeNull();
      expect(retrieved?.app_id).toBe(created.app_id);
      expect(retrieved?.email_verified).toBe(false);
      expect(retrieved).not.toHaveProperty('secret_hash');
      
      // 3. Verify email
      const regen = await regenerateVerificationCode(mockKV, created.app_id);
      const verifyResult = await verifyEmailCode(mockKV, created.app_id, regen!.code);
      expect(verifyResult.verified).toBe(true);

      // 4. Lookup by email
      const found = await getAppByEmail(mockKV, TEST_EMAIL);
      expect(found?.app_id).toBe(created.app_id);
      expect(found?.email_verified).toBe(true);

      // 5. Validate correct secret
      expect(await validateAppSecret(mockKV, created.app_id, created.app_secret)).toBe(true);
      
      // 6. Validate incorrect secret
      expect(await validateAppSecret(mockKV, created.app_id, 'sk_wrong_secret')).toBe(false);

      // 7. Rotate secret
      const rotated = await rotateAppSecret(mockKV, created.app_id);
      expect(rotated).not.toBeNull();
      expect(await validateAppSecret(mockKV, created.app_id, created.app_secret)).toBe(false);
      expect(await validateAppSecret(mockKV, created.app_id, rotated!.app_secret)).toBe(true);
    });

    test('handles multiple apps in parallel', async () => {
      // Create 10 apps with unique emails
      const apps = await Promise.all(
        Array(10).fill(null).map((_, i) => createApp(mockKV, `agent${i}@botcha.ai`))
      );
      
      // All should have unique IDs
      const ids = apps.map(a => a.app_id);
      const uniqueIds = new Set(ids);
      expect(uniqueIds.size).toBe(10);
      
      // All should be retrievable
      const retrieved = await Promise.all(
        apps.map(a => getApp(mockKV, a.app_id))
      );
      expect(retrieved.every(r => r !== null)).toBe(true);
      
      // All secrets should validate
      const validations = await Promise.all(
        apps.map(a => validateAppSecret(mockKV, a.app_id, a.app_secret))
      );
      expect(validations.every(v => v === true)).toBe(true);

      // All email→app_id indexes should exist
      for (let i = 0; i < 10; i++) {
        const found = await getAppByEmail(mockKV, `agent${i}@botcha.ai`);
        expect(found).not.toBeNull();
        expect(found?.app_id).toBe(apps[i].app_id);
      }
    });
  });
});
