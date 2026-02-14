import { describe, test, expect, beforeEach, vi } from 'vitest';
import {
  registerTAPAgent,
  getTAPAgent,
  updateAgentVerification,
  listTAPAgents,
  createTAPSession,
  getTAPSession,
  validateCapability,
  type TAPAgent,
  type TAPCapability,
  type TAPSession,
  type TAPIntent,
  TAP_VALID_ACTIONS,
} from '../../../packages/cloudflare-workers/src/tap-agents.js';
import type { KVNamespace } from '../../../packages/cloudflare-workers/src/agents.js';

// Mock KV namespace using a simple Map
class MockKV implements KVNamespace {
  private store = new Map<string, string>();
  private shouldFail = false;

  async get(key: string, type?: 'text' | 'json' | 'arrayBuffer' | 'stream'): Promise<any> {
    if (this.shouldFail) {
      throw new Error('KV get failed');
    }

    const value = this.store.get(key);
    if (!value) return null;
    
    if (type === 'json') {
      return JSON.parse(value);
    }
    return value;
  }

  async put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void> {
    if (this.shouldFail) {
      throw new Error('KV put failed');
    }
    this.store.set(key, value);
  }

  async delete(key: string): Promise<void> {
    if (this.shouldFail) {
      throw new Error('KV delete failed');
    }
    this.store.delete(key);
  }

  // Test helpers
  has(key: string): boolean {
    return this.store.has(key);
  }

  size(): number {
    return this.store.size;
  }

  getRaw(key: string): string | undefined {
    return this.store.get(key);
  }

  setShouldFail(fail: boolean): void {
    this.shouldFail = fail;
  }
}

const TEST_APP_ID = 'app_1234567890abcdef';
const TEST_APP_ID_2 = 'app_fedcba0987654321';

const VALID_ECDSA_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEW1BvqF+/ry4vKVHFHvZJBCqSUQr2
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
-----END PUBLIC KEY-----`;

const VALID_RSA_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw2xP0Jm2P2xP0Jm2P2xP
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
-----END PUBLIC KEY-----`;

describe('TAP Agents - Registration', () => {
  let mockKV: MockKV;

  beforeEach(() => {
    mockKV = new MockKV();
  });

  describe('registerTAPAgent()', () => {
    test('registers basic agent without TAP features', async () => {
      const result = await registerTAPAgent(mockKV, TEST_APP_ID, {
        name: 'BasicBot',
        operator: 'ACME Corp',
        version: '1.0.0',
      });

      expect(result.success).toBe(true);
      expect(result.agent).toBeDefined();
      expect(result.agent?.name).toBe('BasicBot');
      expect(result.agent?.operator).toBe('ACME Corp');
      expect(result.agent?.version).toBe('1.0.0');
      expect(result.agent?.tap_enabled).toBe(false);
      expect(result.agent?.capabilities).toEqual([]);
      expect(result.agent?.trust_level).toBe('basic');
    });

    test('registers TAP-enabled agent with ECDSA key', async () => {
      const result = await registerTAPAgent(mockKV, TEST_APP_ID, {
        name: 'TAPBot',
        public_key: VALID_ECDSA_PUBLIC_KEY,
        signature_algorithm: 'ecdsa-p256-sha256',
        capabilities: [
          { action: 'browse', scope: ['products'] },
          { action: 'purchase', scope: ['products'], restrictions: { max_amount: 1000 } },
        ],
        trust_level: 'verified',
        issuer: 'example.com',
      });

      expect(result.success).toBe(true);
      expect(result.agent).toBeDefined();
      expect(result.agent?.tap_enabled).toBe(true);
      expect(result.agent?.public_key).toBe(VALID_ECDSA_PUBLIC_KEY);
      expect(result.agent?.signature_algorithm).toBe('ecdsa-p256-sha256');
      expect(result.agent?.capabilities).toHaveLength(2);
      expect(result.agent?.trust_level).toBe('verified');
      expect(result.agent?.issuer).toBe('example.com');
      expect(result.agent?.key_created_at).toBeDefined();
      expect(result.agent?.last_verified_at).toBeUndefined();
    });

    test('registers TAP-enabled agent with RSA key', async () => {
      const result = await registerTAPAgent(mockKV, TEST_APP_ID, {
        name: 'RSABot',
        public_key: VALID_RSA_PUBLIC_KEY,
        signature_algorithm: 'rsa-pss-sha256',
      });

      expect(result.success).toBe(true);
      expect(result.agent?.tap_enabled).toBe(true);
      expect(result.agent?.signature_algorithm).toBe('rsa-pss-sha256');
    });

    test('fails when public_key provided without signature_algorithm', async () => {
      const result = await registerTAPAgent(mockKV, TEST_APP_ID, {
        name: 'InvalidBot',
        public_key: VALID_ECDSA_PUBLIC_KEY,
        // Missing signature_algorithm
      });

      expect(result.success).toBe(false);
      expect(result.error).toBe('signature_algorithm required when public_key provided');
      expect(result.agent).toBeUndefined();
    });

    test('fails when public_key has invalid PEM format', async () => {
      const result = await registerTAPAgent(mockKV, TEST_APP_ID, {
        name: 'InvalidKeyBot',
        public_key: 'not-a-valid-pem-key',
        signature_algorithm: 'ecdsa-p256-sha256',
      });

      expect(result.success).toBe(false);
      expect(result.error).toBe('Invalid public key format');
    });

    test('fails when public_key is too short', async () => {
      const result = await registerTAPAgent(mockKV, TEST_APP_ID, {
        name: 'ShortKeyBot',
        public_key: '-----BEGIN PUBLIC KEY-----\nshort\n-----END PUBLIC KEY-----',
        signature_algorithm: 'ecdsa-p256-sha256',
      });

      expect(result.success).toBe(false);
      expect(result.error).toBe('Invalid public key format');
    });

    test('stores agent in KV at agent:{agent_id}', async () => {
      const result = await registerTAPAgent(mockKV, TEST_APP_ID, {
        name: 'StoredBot',
        public_key: VALID_ECDSA_PUBLIC_KEY,
        signature_algorithm: 'ecdsa-p256-sha256',
      });

      expect(result.success).toBe(true);
      expect(mockKV.has(`agent:${result.agent?.agent_id}`)).toBe(true);
    });

    test('adds agent to app_agents index', async () => {
      const result1 = await registerTAPAgent(mockKV, TEST_APP_ID, { name: 'Bot1' });
      const result2 = await registerTAPAgent(mockKV, TEST_APP_ID, { name: 'Bot2' });

      expect(mockKV.has(`app_agents:${TEST_APP_ID}`)).toBe(true);
      const indexData = await mockKV.get(`app_agents:${TEST_APP_ID}`, 'text');
      const agentIds: string[] = JSON.parse(indexData);

      expect(agentIds).toHaveLength(2);
      expect(agentIds).toContain(result1.agent?.agent_id);
      expect(agentIds).toContain(result2.agent?.agent_id);
    });

    test('registers agent with all capability actions', async () => {
      const result = await registerTAPAgent(mockKV, TEST_APP_ID, {
        name: 'AllCapabilitiesBot',
        public_key: VALID_ECDSA_PUBLIC_KEY,
        signature_algorithm: 'ecdsa-p256-sha256',
        capabilities: [
          { action: 'browse' },
          { action: 'compare' },
          { action: 'purchase' },
          { action: 'audit' },
          { action: 'search' },
        ],
      });

      expect(result.success).toBe(true);
      expect(result.agent?.capabilities).toHaveLength(5);
      expect(result.agent?.capabilities?.map(c => c.action)).toEqual(
        expect.arrayContaining(['browse', 'compare', 'purchase', 'audit', 'search'])
      );
    });

    test('registers agent with enterprise trust level', async () => {
      const result = await registerTAPAgent(mockKV, TEST_APP_ID, {
        name: 'EnterpriseBot',
        public_key: VALID_ECDSA_PUBLIC_KEY,
        signature_algorithm: 'ecdsa-p256-sha256',
        trust_level: 'enterprise',
        issuer: 'enterprise-issuer.com',
      });

      expect(result.success).toBe(true);
      expect(result.agent?.trust_level).toBe('enterprise');
      expect(result.agent?.issuer).toBe('enterprise-issuer.com');
    });

    test('fail-open: returns error on KV storage failure', async () => {
      mockKV.setShouldFail(true);

      const result = await registerTAPAgent(mockKV, TEST_APP_ID, {
        name: 'FailBot',
      });

      expect(result.success).toBe(false);
      expect(result.error).toBe('Internal server error');
    });

    test('generates unique agent_id for each registration', async () => {
      const result1 = await registerTAPAgent(mockKV, TEST_APP_ID, { name: 'Bot1' });
      const result2 = await registerTAPAgent(mockKV, TEST_APP_ID, { name: 'Bot2' });
      const result3 = await registerTAPAgent(mockKV, TEST_APP_ID, { name: 'Bot3' });

      expect(result1.agent?.agent_id).not.toBe(result2.agent?.agent_id);
      expect(result2.agent?.agent_id).not.toBe(result3.agent?.agent_id);
      expect(result1.agent?.agent_id).not.toBe(result3.agent?.agent_id);
    });
  });

  describe('getTAPAgent()', () => {
    test('retrieves TAP-enabled agent by ID', async () => {
      const registered = await registerTAPAgent(mockKV, TEST_APP_ID, {
        name: 'RetrieveBot',
        public_key: VALID_ECDSA_PUBLIC_KEY,
        signature_algorithm: 'ecdsa-p256-sha256',
        capabilities: [{ action: 'browse' }],
        trust_level: 'verified',
      });

      const result = await getTAPAgent(mockKV, registered.agent!.agent_id);

      expect(result.success).toBe(true);
      expect(result.agent).toBeDefined();
      expect(result.agent?.agent_id).toBe(registered.agent?.agent_id);
      expect(result.agent?.name).toBe('RetrieveBot');
      expect(result.agent?.tap_enabled).toBe(true);
      expect(result.agent?.capabilities).toHaveLength(1);
    });

    test('retrieves basic (non-TAP) agent by ID', async () => {
      const registered = await registerTAPAgent(mockKV, TEST_APP_ID, {
        name: 'BasicBot',
      });

      const result = await getTAPAgent(mockKV, registered.agent!.agent_id);

      expect(result.success).toBe(true);
      expect(result.agent?.tap_enabled).toBe(false);
      expect(result.agent?.public_key).toBeUndefined();
    });

    test('returns error for non-existent agent', async () => {
      const result = await getTAPAgent(mockKV, 'agent_nonexistent1234');

      expect(result.success).toBe(false);
      expect(result.error).toBe('Agent not found');
      expect(result.agent).toBeUndefined();
    });

    test('fail-open: returns error on KV fetch failure', async () => {
      const registered = await registerTAPAgent(mockKV, TEST_APP_ID, { name: 'TestBot' });
      
      mockKV.setShouldFail(true);
      
      const result = await getTAPAgent(mockKV, registered.agent!.agent_id);

      expect(result.success).toBe(false);
      expect(result.error).toBe('Internal server error');
    });
  });

  describe('updateAgentVerification()', () => {
    test('updates last_verified_at on successful verification', async () => {
      const registered = await registerTAPAgent(mockKV, TEST_APP_ID, {
        name: 'VerifyBot',
        public_key: VALID_ECDSA_PUBLIC_KEY,
        signature_algorithm: 'ecdsa-p256-sha256',
      });

      const beforeUpdate = Date.now();
      await updateAgentVerification(mockKV, registered.agent!.agent_id, true);
      const afterUpdate = Date.now();

      const result = await getTAPAgent(mockKV, registered.agent!.agent_id);

      expect(result.success).toBe(true);
      expect(result.agent?.last_verified_at).toBeDefined();
      expect(result.agent?.last_verified_at).toBeGreaterThanOrEqual(beforeUpdate);
      expect(result.agent?.last_verified_at).toBeLessThanOrEqual(afterUpdate);
    });

    test('does not update last_verified_at on failed verification', async () => {
      const registered = await registerTAPAgent(mockKV, TEST_APP_ID, {
        name: 'FailVerifyBot',
        public_key: VALID_ECDSA_PUBLIC_KEY,
        signature_algorithm: 'ecdsa-p256-sha256',
      });

      await updateAgentVerification(mockKV, registered.agent!.agent_id, false);

      const result = await getTAPAgent(mockKV, registered.agent!.agent_id);

      expect(result.success).toBe(true);
      expect(result.agent?.last_verified_at).toBeUndefined();
    });

    test('updates last_verified_at multiple times', async () => {
      const registered = await registerTAPAgent(mockKV, TEST_APP_ID, {
        name: 'MultiVerifyBot',
        public_key: VALID_ECDSA_PUBLIC_KEY,
        signature_algorithm: 'ecdsa-p256-sha256',
      });

      await updateAgentVerification(mockKV, registered.agent!.agent_id, true);
      const firstResult = await getTAPAgent(mockKV, registered.agent!.agent_id);
      const firstTimestamp = firstResult.agent?.last_verified_at;

      // Wait a bit to ensure timestamp difference
      await new Promise(resolve => setTimeout(resolve, 10));

      await updateAgentVerification(mockKV, registered.agent!.agent_id, true);
      const secondResult = await getTAPAgent(mockKV, registered.agent!.agent_id);
      const secondTimestamp = secondResult.agent?.last_verified_at;

      expect(secondTimestamp).toBeGreaterThan(firstTimestamp!);
    });

    test('fail-open: silently fails for non-existent agent', async () => {
      // Should not throw
      await expect(
        updateAgentVerification(mockKV, 'agent_nonexistent1234', true)
      ).resolves.toBeUndefined();
    });

    test('fail-open: silently fails on KV errors', async () => {
      const registered = await registerTAPAgent(mockKV, TEST_APP_ID, { name: 'TestBot' });
      
      mockKV.setShouldFail(true);
      
      // Should not throw
      await expect(
        updateAgentVerification(mockKV, registered.agent!.agent_id, true)
      ).resolves.toBeUndefined();
    });
  });

  describe('listTAPAgents()', () => {
    test('lists all agents for an app (tapOnly=false)', async () => {
      await registerTAPAgent(mockKV, TEST_APP_ID, {
        name: 'TAPBot1',
        public_key: VALID_ECDSA_PUBLIC_KEY,
        signature_algorithm: 'ecdsa-p256-sha256',
      });
      await registerTAPAgent(mockKV, TEST_APP_ID, {
        name: 'BasicBot',
      });
      await registerTAPAgent(mockKV, TEST_APP_ID, {
        name: 'TAPBot2',
        public_key: VALID_RSA_PUBLIC_KEY,
        signature_algorithm: 'rsa-pss-sha256',
      });

      const result = await listTAPAgents(mockKV, TEST_APP_ID, false);

      expect(result.success).toBe(true);
      expect(result.agents).toHaveLength(3);
      expect(result.agents?.map(a => a.name)).toEqual(
        expect.arrayContaining(['TAPBot1', 'BasicBot', 'TAPBot2'])
      );
    });

    test('lists only TAP-enabled agents (tapOnly=true)', async () => {
      await registerTAPAgent(mockKV, TEST_APP_ID, {
        name: 'TAPBot1',
        public_key: VALID_ECDSA_PUBLIC_KEY,
        signature_algorithm: 'ecdsa-p256-sha256',
      });
      await registerTAPAgent(mockKV, TEST_APP_ID, {
        name: 'BasicBot',
      });
      await registerTAPAgent(mockKV, TEST_APP_ID, {
        name: 'TAPBot2',
        public_key: VALID_RSA_PUBLIC_KEY,
        signature_algorithm: 'rsa-pss-sha256',
      });

      const result = await listTAPAgents(mockKV, TEST_APP_ID, true);

      expect(result.success).toBe(true);
      expect(result.agents).toHaveLength(2);
      expect(result.agents?.every(a => a.tap_enabled)).toBe(true);
      expect(result.agents?.map(a => a.name)).toEqual(
        expect.arrayContaining(['TAPBot1', 'TAPBot2'])
      );
      expect(result.agents?.map(a => a.name)).not.toContain('BasicBot');
    });

    test('returns empty array for app with no agents', async () => {
      const result = await listTAPAgents(mockKV, 'app_noagents123456');

      expect(result.success).toBe(true);
      expect(result.agents).toEqual([]);
    });

    test('filters agents by app_id', async () => {
      await registerTAPAgent(mockKV, TEST_APP_ID, { name: 'App1Bot' });
      await registerTAPAgent(mockKV, TEST_APP_ID_2, { name: 'App2Bot' });

      const result1 = await listTAPAgents(mockKV, TEST_APP_ID);
      const result2 = await listTAPAgents(mockKV, TEST_APP_ID_2);

      expect(result1.agents).toHaveLength(1);
      expect(result2.agents).toHaveLength(1);
      expect(result1.agents?.[0].name).toBe('App1Bot');
      expect(result2.agents?.[0].name).toBe('App2Bot');
    });

    test('fail-open: returns error on KV failure', async () => {
      await registerTAPAgent(mockKV, TEST_APP_ID, { name: 'TestBot' });
      
      mockKV.setShouldFail(true);
      
      const result = await listTAPAgents(mockKV, TEST_APP_ID);

      expect(result.success).toBe(false);
      expect(result.error).toBe('Internal server error');
    });
  });
});

describe('TAP Agents - Sessions', () => {
  let mockKV: MockKV;

  beforeEach(() => {
    mockKV = new MockKV();
  });

  describe('createTAPSession()', () => {
    const testCapabilities: TAPCapability[] = [
      { action: 'browse', scope: ['products'] },
      { action: 'purchase', scope: ['products'], restrictions: { max_amount: 500 } },
    ];

    const testIntent: TAPIntent = {
      action: 'purchase',
      resource: 'products/123',
      scope: ['products'],
      duration: 3600,
    };

    test('creates session with default 1 hour duration', async () => {
      const result = await createTAPSession(
        mockKV,
        'agent_test123456789',
        TEST_APP_ID,
        'user_hash_abc123',
        testCapabilities,
        { ...testIntent, duration: undefined }
      );

      expect(result.success).toBe(true);
      expect(result.session).toBeDefined();
      expect(result.session?.session_id).toMatch(/^[0-9a-f]{32}$/);
      expect(result.session?.agent_id).toBe('agent_test123456789');
      expect(result.session?.app_id).toBe(TEST_APP_ID);
      expect(result.session?.user_context).toBe('user_hash_abc123');
      expect(result.session?.capabilities).toEqual(testCapabilities);
      expect(result.session?.intent).toBeDefined();
      expect(result.session?.created_at).toBeDefined();
      expect(result.session?.expires_at).toBeDefined();
      
      // Check ~1 hour duration (3600 seconds)
      const duration = (result.session!.expires_at - result.session!.created_at) / 1000;
      expect(duration).toBeCloseTo(3600, -2); // Within ~100s
    });

    test('creates session with custom duration', async () => {
      const result = await createTAPSession(
        mockKV,
        'agent_test123456789',
        TEST_APP_ID,
        'user_hash_abc123',
        testCapabilities,
        { ...testIntent, duration: 7200 } // 2 hours
      );

      expect(result.success).toBe(true);
      
      const duration = (result.session!.expires_at - result.session!.created_at) / 1000;
      expect(duration).toBeCloseTo(7200, -2);
    });

    test('caps session duration at 86400 seconds (24 hours)', async () => {
      const result = await createTAPSession(
        mockKV,
        'agent_test123456789',
        TEST_APP_ID,
        'user_hash_abc123',
        testCapabilities,
        { ...testIntent, duration: 172800 } // 48 hours requested
      );

      expect(result.success).toBe(true);
      
      const duration = (result.session!.expires_at - result.session!.created_at) / 1000;
      expect(duration).toBeCloseTo(86400, -2); // Capped at 24 hours
      expect(duration).toBeLessThanOrEqual(86400);
    });

    test('stores session in KV with TTL', async () => {
      const result = await createTAPSession(
        mockKV,
        'agent_test123456789',
        TEST_APP_ID,
        'user_hash_abc123',
        testCapabilities,
        testIntent
      );

      expect(result.success).toBe(true);
      expect(mockKV.has(`session:${result.session?.session_id}`)).toBe(true);
    });

    test('generates unique session IDs', async () => {
      const result1 = await createTAPSession(mockKV, 'agent_1', TEST_APP_ID, 'user1', testCapabilities, testIntent);
      const result2 = await createTAPSession(mockKV, 'agent_2', TEST_APP_ID, 'user2', testCapabilities, testIntent);
      const result3 = await createTAPSession(mockKV, 'agent_3', TEST_APP_ID, 'user3', testCapabilities, testIntent);

      expect(result1.session?.session_id).not.toBe(result2.session?.session_id);
      expect(result2.session?.session_id).not.toBe(result3.session?.session_id);
      expect(result1.session?.session_id).not.toBe(result3.session?.session_id);
    });

    test('stores full intent details', async () => {
      const complexIntent: TAPIntent = {
        action: 'purchase',
        resource: 'products/123',
        scope: ['products', 'orders'],
        duration: 1800,
      };

      const result = await createTAPSession(
        mockKV,
        'agent_test123456789',
        TEST_APP_ID,
        'user_hash_abc123',
        testCapabilities,
        complexIntent
      );

      expect(result.success).toBe(true);
      expect(result.session?.intent).toEqual(complexIntent);
    });

    test('fail-open: returns error on KV failure', async () => {
      mockKV.setShouldFail(true);

      const result = await createTAPSession(
        mockKV,
        'agent_test123456789',
        TEST_APP_ID,
        'user_hash_abc123',
        testCapabilities,
        testIntent
      );

      expect(result.success).toBe(false);
      expect(result.error).toBe('Internal server error');
    });
  });

  describe('getTAPSession()', () => {
    const testCapabilities: TAPCapability[] = [
      { action: 'browse', scope: ['products'] },
    ];

    const testIntent: TAPIntent = {
      action: 'browse',
      duration: 3600,
    };

    test('retrieves valid session by ID', async () => {
      const created = await createTAPSession(
        mockKV,
        'agent_test123456789',
        TEST_APP_ID,
        'user_hash_abc123',
        testCapabilities,
        testIntent
      );

      const result = await getTAPSession(mockKV, created.session!.session_id);

      expect(result.success).toBe(true);
      expect(result.session).toBeDefined();
      expect(result.session?.session_id).toBe(created.session?.session_id);
      expect(result.session?.agent_id).toBe('agent_test123456789');
      expect(result.session?.app_id).toBe(TEST_APP_ID);
      expect(result.session?.capabilities).toEqual(testCapabilities);
    });

    test('returns error for non-existent session', async () => {
      const result = await getTAPSession(mockKV, 'session_nonexistent1234567890ab');

      expect(result.success).toBe(false);
      expect(result.error).toBe('Session not found or expired');
      expect(result.session).toBeUndefined();
    });

    test('returns error for expired session', async () => {
      // Create a session that expires immediately
      const expiredSession: TAPSession = {
        session_id: 'expired_session_12345678',
        agent_id: 'agent_test',
        app_id: TEST_APP_ID,
        user_context: 'user_hash',
        capabilities: testCapabilities,
        intent: testIntent,
        created_at: Date.now() - 7200000, // 2 hours ago
        expires_at: Date.now() - 3600000,  // 1 hour ago (expired)
      };

      await mockKV.put(`session:${expiredSession.session_id}`, JSON.stringify(expiredSession));

      const result = await getTAPSession(mockKV, expiredSession.session_id);

      expect(result.success).toBe(false);
      expect(result.error).toBe('Session expired');
    });

    test('validates session expiration at retrieval time', async () => {
      const now = Date.now();
      const shortLivedSession: TAPSession = {
        session_id: 'shortlived_session_123',
        agent_id: 'agent_test',
        app_id: TEST_APP_ID,
        user_context: 'user_hash',
        capabilities: testCapabilities,
        intent: testIntent,
        created_at: now,
        expires_at: now + 100, // 100ms in future
      };

      await mockKV.put(`session:${shortLivedSession.session_id}`, JSON.stringify(shortLivedSession));

      // Should be valid now
      const result1 = await getTAPSession(mockKV, shortLivedSession.session_id);
      expect(result1.success).toBe(true);

      // Wait for expiration
      await new Promise(resolve => setTimeout(resolve, 150));

      // Should be expired now
      const result2 = await getTAPSession(mockKV, shortLivedSession.session_id);
      expect(result2.success).toBe(false);
      expect(result2.error).toBe('Session expired');
    });

    test('fail-open: returns error on KV failure', async () => {
      const created = await createTAPSession(
        mockKV,
        'agent_test123456789',
        TEST_APP_ID,
        'user_hash_abc123',
        testCapabilities,
        testIntent
      );

      mockKV.setShouldFail(true);

      const result = await getTAPSession(mockKV, created.session!.session_id);

      expect(result.success).toBe(false);
      expect(result.error).toBe('Internal server error');
    });
  });
});

describe('TAP Agents - Capability Validation', () => {
  describe('validateCapability()', () => {
    test('validates action exists in agent capabilities', () => {
      const capabilities: TAPCapability[] = [
        { action: 'browse' },
        { action: 'search' },
      ];

      const result1 = validateCapability(capabilities, 'browse');
      expect(result1.valid).toBe(true);

      const result2 = validateCapability(capabilities, 'search');
      expect(result2.valid).toBe(true);
    });

    test('rejects action not in agent capabilities', () => {
      const capabilities: TAPCapability[] = [
        { action: 'browse' },
      ];

      const result = validateCapability(capabilities, 'purchase');

      expect(result.valid).toBe(false);
      expect(result.error).toBe('Agent lacks capability: purchase');
    });

    test('validates action with matching scope', () => {
      const capabilities: TAPCapability[] = [
        { action: 'browse', scope: ['products', 'orders'] },
      ];

      const result = validateCapability(capabilities, 'browse', 'products');

      expect(result.valid).toBe(true);
    });

    test('rejects action with missing scope', () => {
      const capabilities: TAPCapability[] = [
        { action: 'browse', scope: ['products'] },
      ];

      const result = validateCapability(capabilities, 'browse', 'orders');

      expect(result.valid).toBe(false);
      expect(result.error).toBe("Agent lacks scope 'orders' for action 'browse'");
    });

    test('allows any scope when capability has wildcard scope', () => {
      const capabilities: TAPCapability[] = [
        { action: 'browse', scope: ['*'] },
      ];

      const result1 = validateCapability(capabilities, 'browse', 'products');
      expect(result1.valid).toBe(true);

      const result2 = validateCapability(capabilities, 'browse', 'orders');
      expect(result2.valid).toBe(true);

      const result3 = validateCapability(capabilities, 'browse', 'anything');
      expect(result3.valid).toBe(true);
    });

    test('allows any scope when capability has no scope defined', () => {
      const capabilities: TAPCapability[] = [
        { action: 'browse' }, // No scope = wildcard
      ];

      const result1 = validateCapability(capabilities, 'browse', 'products');
      expect(result1.valid).toBe(true);

      const result2 = validateCapability(capabilities, 'browse', 'anything');
      expect(result2.valid).toBe(true);
    });

    test('validates action without scope requirement', () => {
      const capabilities: TAPCapability[] = [
        { action: 'browse', scope: ['products'] },
      ];

      // No requiredScope parameter = no scope check
      const result = validateCapability(capabilities, 'browse');

      expect(result.valid).toBe(true);
    });

    test('handles multiple capabilities with same action', () => {
      const capabilities: TAPCapability[] = [
        { action: 'browse', scope: ['products'] },
        { action: 'browse', scope: ['orders'] },
        { action: 'browse', scope: ['catalog'] },
      ];

      const result1 = validateCapability(capabilities, 'browse', 'products');
      expect(result1.valid).toBe(true);

      const result2 = validateCapability(capabilities, 'browse', 'orders');
      expect(result2.valid).toBe(true);

      const result3 = validateCapability(capabilities, 'browse', 'unknown');
      expect(result3.valid).toBe(false);
    });

    test('validates all TAP actions', () => {
      const capabilities: TAPCapability[] = TAP_VALID_ACTIONS.map(action => ({
        action,
      }));

      for (const action of TAP_VALID_ACTIONS) {
        const result = validateCapability(capabilities, action);
        expect(result.valid).toBe(true);
      }
    });

    test('rejects empty capabilities array', () => {
      const result = validateCapability([], 'browse');

      expect(result.valid).toBe(false);
      expect(result.error).toBe('Agent lacks capability: browse');
    });

    test('validates purchase capability with restrictions', () => {
      const capabilities: TAPCapability[] = [
        {
          action: 'purchase',
          scope: ['products'],
          restrictions: { max_amount: 1000 },
        },
      ];

      const result = validateCapability(capabilities, 'purchase', 'products');
      expect(result.valid).toBe(true);
    });

    test('validates audit capability', () => {
      const capabilities: TAPCapability[] = [
        { action: 'audit', scope: ['orders', 'transactions'] },
      ];

      const result = validateCapability(capabilities, 'audit', 'orders');
      expect(result.valid).toBe(true);
    });

    test('validates compare capability with multiple scopes', () => {
      const capabilities: TAPCapability[] = [
        { action: 'compare', scope: ['products', 'prices', 'reviews'] },
      ];

      const result1 = validateCapability(capabilities, 'compare', 'products');
      expect(result1.valid).toBe(true);

      const result2 = validateCapability(capabilities, 'compare', 'prices');
      expect(result2.valid).toBe(true);

      const result3 = validateCapability(capabilities, 'compare', 'shipping');
      expect(result3.valid).toBe(false);
    });
  });
});

describe('TAP Agents - Integration Tests', () => {
  let agentsKV: MockKV;
  let sessionsKV: MockKV;

  beforeEach(() => {
    agentsKV = new MockKV();
    sessionsKV = new MockKV();
  });

  test('complete TAP workflow: register → verify → create session → validate', async () => {
    // 1. Register TAP-enabled agent
    const registered = await registerTAPAgent(agentsKV, TEST_APP_ID, {
      name: 'WorkflowBot',
      public_key: VALID_ECDSA_PUBLIC_KEY,
      signature_algorithm: 'ecdsa-p256-sha256',
      capabilities: [
        { action: 'browse', scope: ['products'] },
        { action: 'purchase', scope: ['products'], restrictions: { max_amount: 500 } },
      ],
      trust_level: 'verified',
      issuer: 'example.com',
    });

    expect(registered.success).toBe(true);

    // 2. Simulate successful verification
    await updateAgentVerification(agentsKV, registered.agent!.agent_id, true);

    const verified = await getTAPAgent(agentsKV, registered.agent!.agent_id);
    expect(verified.agent?.last_verified_at).toBeDefined();

    // 3. Create session after verification
    const session = await createTAPSession(
      sessionsKV,
      registered.agent!.agent_id,
      TEST_APP_ID,
      'user_hash_abc123',
      registered.agent!.capabilities!,
      {
        action: 'purchase',
        resource: 'products/123',
        scope: ['products'],
        duration: 3600,
      }
    );

    expect(session.success).toBe(true);
    expect(session.session?.agent_id).toBe(registered.agent?.agent_id);

    // 4. Validate capabilities
    const validation1 = validateCapability(
      registered.agent!.capabilities!,
      'browse',
      'products'
    );
    expect(validation1.valid).toBe(true);

    const validation2 = validateCapability(
      registered.agent!.capabilities!,
      'purchase',
      'products'
    );
    expect(validation2.valid).toBe(true);

    const validation3 = validateCapability(
      registered.agent!.capabilities!,
      'audit',
      'products'
    );
    expect(validation3.valid).toBe(false);
  });

  test('multiple agents with different trust levels', async () => {
    const basic = await registerTAPAgent(agentsKV, TEST_APP_ID, {
      name: 'BasicBot',
      trust_level: 'basic',
    });

    const verified = await registerTAPAgent(agentsKV, TEST_APP_ID, {
      name: 'VerifiedBot',
      public_key: VALID_ECDSA_PUBLIC_KEY,
      signature_algorithm: 'ecdsa-p256-sha256',
      trust_level: 'verified',
    });

    const enterprise = await registerTAPAgent(agentsKV, TEST_APP_ID, {
      name: 'EnterpriseBot',
      public_key: VALID_RSA_PUBLIC_KEY,
      signature_algorithm: 'rsa-pss-sha256',
      trust_level: 'enterprise',
      issuer: 'enterprise.com',
    });

    const allAgents = await listTAPAgents(agentsKV, TEST_APP_ID, false);
    expect(allAgents.agents).toHaveLength(3);

    const tapOnlyAgents = await listTAPAgents(agentsKV, TEST_APP_ID, true);
    expect(tapOnlyAgents.agents).toHaveLength(2);
    expect(tapOnlyAgents.agents?.map(a => a.name)).toEqual(
      expect.arrayContaining(['VerifiedBot', 'EnterpriseBot'])
    );
  });

  test('session lifecycle with expiration', async () => {
    const agent = await registerTAPAgent(agentsKV, TEST_APP_ID, {
      name: 'SessionBot',
      public_key: VALID_ECDSA_PUBLIC_KEY,
      signature_algorithm: 'ecdsa-p256-sha256',
      capabilities: [{ action: 'browse' }],
    });

    // Create short-lived session
    const created = await createTAPSession(
      sessionsKV,
      agent.agent!.agent_id,
      TEST_APP_ID,
      'user_hash',
      agent.agent!.capabilities!,
      { action: 'browse', duration: 1 } // 1 second
    );

    expect(created.success).toBe(true);

    // Should be valid immediately
    const valid = await getTAPSession(sessionsKV, created.session!.session_id);
    expect(valid.success).toBe(true);

    // Wait for expiration
    await new Promise(resolve => setTimeout(resolve, 1500));

    // Should be expired
    const expired = await getTAPSession(sessionsKV, created.session!.session_id);
    expect(expired.success).toBe(false);
    expect(expired.error).toBe('Session expired');
  });
});
