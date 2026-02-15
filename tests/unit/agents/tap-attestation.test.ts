import { describe, test, expect, beforeEach } from 'vitest';
import {
  issueAttestation,
  getAttestation,
  revokeAttestation,
  verifyAttestationToken,
  verifyAndCheckCapability,
  checkCapability,
  matchesPattern,
  normalizeCapability,
  isValidCapabilityPattern,
  requireCapability,
  type IssueAttestationOptions,
} from '../../../packages/cloudflare-workers/src/tap-attestation.js';
import {
  registerTAPAgent,
  type TAPCapability,
} from '../../../packages/cloudflare-workers/src/tap-agents.js';
import type { KVNamespace } from '../../../packages/cloudflare-workers/src/agents.js';

// ============ Mock KV ============

class MockKV implements KVNamespace {
  private store = new Map<string, string>();
  private shouldFail = false;

  async get(key: string, type?: 'text' | 'json' | 'arrayBuffer' | 'stream'): Promise<any> {
    if (this.shouldFail) throw new Error('KV get failed');
    const value = this.store.get(key);
    if (!value) return null;
    if (type === 'json') return JSON.parse(value);
    return value;
  }

  async put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void> {
    if (this.shouldFail) throw new Error('KV put failed');
    this.store.set(key, value);
  }

  async delete(key: string): Promise<void> {
    if (this.shouldFail) throw new Error('KV delete failed');
    this.store.delete(key);
  }

  has(key: string): boolean { return this.store.has(key); }
  size(): number { return this.store.size; }
  getRaw(key: string): string | undefined { return this.store.get(key); }
  setShouldFail(fail: boolean): void { this.shouldFail = fail; }
  clear(): void { this.store.clear(); }
}

// ============ Test Helpers ============

const TEST_APP_ID = 'app_attestation_test_01';
const TEST_SECRET = 'test-jwt-secret-for-attestation-tests-32chars!!';
const VALID_ED25519_KEY = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';

async function createTestAgent(
  agents: MockKV,
  name: string,
  capabilities: TAPCapability[] = [{ action: 'browse' }],
): Promise<string> {
  const result = await registerTAPAgent(agents, TEST_APP_ID, {
    name,
    public_key: VALID_ED25519_KEY,
    signature_algorithm: 'ed25519',
    capabilities,
    trust_level: 'basic',
  });
  if (!result.success || !result.agent) throw new Error(`Failed to create agent: ${result.error}`);
  return result.agent.agent_id;
}

// ============ Tests ============

describe('TAP Capability Attestation', () => {
  let agents: MockKV;
  let sessions: MockKV;

  beforeEach(() => {
    agents = new MockKV();
    sessions = new MockKV();
  });

  // ============ Permission Matching (Pure Functions) ============

  describe('normalizeCapability', () => {
    test('passes through action:resource format', () => {
      expect(normalizeCapability('read:invoices')).toBe('read:invoices');
    });

    test('expands bare action to action:*', () => {
      expect(normalizeCapability('browse')).toBe('browse:*');
    });

    test('handles wildcard patterns', () => {
      expect(normalizeCapability('*:*')).toBe('*:*');
      expect(normalizeCapability('*')).toBe('*:*');
    });
  });

  describe('matchesPattern', () => {
    test('exact match', () => {
      expect(matchesPattern('read:invoices', 'read:invoices')).toBe(true);
    });

    test('action wildcard', () => {
      expect(matchesPattern('*:invoices', 'read:invoices')).toBe(true);
      expect(matchesPattern('*:invoices', 'write:invoices')).toBe(true);
    });

    test('resource wildcard', () => {
      expect(matchesPattern('read:*', 'read:invoices')).toBe(true);
      expect(matchesPattern('read:*', 'read:orders')).toBe(true);
    });

    test('full wildcard', () => {
      expect(matchesPattern('*:*', 'read:invoices')).toBe(true);
      expect(matchesPattern('*:*', 'write:orders')).toBe(true);
    });

    test('no match', () => {
      expect(matchesPattern('read:invoices', 'write:invoices')).toBe(false);
      expect(matchesPattern('read:invoices', 'read:orders')).toBe(false);
    });

    test('bare action pattern matching', () => {
      expect(matchesPattern('browse', 'browse:products')).toBe(true);
      expect(matchesPattern('browse', 'browse:*')).toBe(true);
    });
  });

  describe('isValidCapabilityPattern', () => {
    test('valid patterns', () => {
      expect(isValidCapabilityPattern('read:invoices')).toBe(true);
      expect(isValidCapabilityPattern('*:*')).toBe(true);
      expect(isValidCapabilityPattern('browse')).toBe(true);
      expect(isValidCapabilityPattern('read:*')).toBe(true);
      expect(isValidCapabilityPattern('my-action:my-resource')).toBe(true);
    });

    test('invalid patterns', () => {
      expect(isValidCapabilityPattern('')).toBe(false);
      expect(isValidCapabilityPattern('read:inv oices')).toBe(false);
      expect(isValidCapabilityPattern('read:')).toBe(false);
      expect(isValidCapabilityPattern(':invoices')).toBe(false);
    });
  });

  describe('checkCapability', () => {
    test('allows matching rule', () => {
      const result = checkCapability(['read:invoices'], [], 'read', 'invoices');
      expect(result.allowed).toBe(true);
      expect(result.matched_rule).toBe('read:invoices');
    });

    test('denies when no matching allow rule', () => {
      const result = checkCapability(['read:invoices'], [], 'write', 'invoices');
      expect(result.allowed).toBe(false);
    });

    test('deny takes precedence over allow', () => {
      const result = checkCapability(['*:*'], ['write:transfers'], 'write', 'transfers');
      expect(result.allowed).toBe(false);
      expect(result.matched_rule).toBe('write:transfers');
    });

    test('wildcard allow covers multiple resources', () => {
      const result = checkCapability(['read:*'], [], 'read', 'invoices');
      expect(result.allowed).toBe(true);
    });

    test('bare action check without resource', () => {
      const result = checkCapability(['browse:*'], [], 'browse');
      expect(result.allowed).toBe(true);
    });

    test('empty cannot list means no denies', () => {
      const result = checkCapability(['read:invoices'], [], 'read', 'invoices');
      expect(result.allowed).toBe(true);
    });

    test('default deny when empty can list', () => {
      const result = checkCapability([], [], 'read', 'invoices');
      expect(result.allowed).toBe(false);
    });
  });

  // ============ Attestation Issuance ============

  describe('issueAttestation', () => {
    test('issues attestation with valid agent', async () => {
      const agentId = await createTestAgent(agents, 'attestation-agent');

      const result = await issueAttestation(agents, sessions, TEST_APP_ID, TEST_SECRET, {
        agent_id: agentId,
        can: ['read:invoices', 'browse:*'],
      });

      expect(result.success).toBe(true);
      expect(result.attestation).toBeDefined();
      expect(result.attestation!.attestation_id).toBeTruthy();
      expect(result.attestation!.agent_id).toBe(agentId);
      expect(result.attestation!.app_id).toBe(TEST_APP_ID);
      expect(result.attestation!.can).toEqual(['read:invoices', 'browse:*']);
      expect(result.attestation!.cannot).toEqual([]);
      expect(result.attestation!.token).toBeTruthy();
      expect(result.token).toBeTruthy();
    });

    test('includes cannot rules', async () => {
      const agentId = await createTestAgent(agents, 'deny-agent');

      const result = await issueAttestation(agents, sessions, TEST_APP_ID, TEST_SECRET, {
        agent_id: agentId,
        can: ['*:*'],
        cannot: ['write:transfers', 'purchase:*'],
      });

      expect(result.success).toBe(true);
      expect(result.attestation!.cannot).toEqual(['write:transfers', 'purchase:*']);
    });

    test('includes restrictions and metadata', async () => {
      const agentId = await createTestAgent(agents, 'restricted-agent');

      const result = await issueAttestation(agents, sessions, TEST_APP_ID, TEST_SECRET, {
        agent_id: agentId,
        can: ['read:invoices'],
        restrictions: { max_amount: 1000, rate_limit: 60 },
        metadata: { purpose: 'invoice-reader' },
      });

      expect(result.success).toBe(true);
      expect(result.attestation!.restrictions).toEqual({ max_amount: 1000, rate_limit: 60 });
      expect(result.attestation!.metadata).toEqual({ purpose: 'invoice-reader' });
    });

    test('rejects missing agent_id', async () => {
      const result = await issueAttestation(agents, sessions, TEST_APP_ID, TEST_SECRET, {
        agent_id: '',
        can: ['read:invoices'],
      });
      expect(result.success).toBe(false);
      expect(result.error).toContain('agent_id');
    });

    test('rejects empty can list', async () => {
      const agentId = await createTestAgent(agents, 'no-can-agent');

      const result = await issueAttestation(agents, sessions, TEST_APP_ID, TEST_SECRET, {
        agent_id: agentId,
        can: [],
      });
      expect(result.success).toBe(false);
      expect(result.error).toContain('"can" rule');
    });

    test('rejects invalid capability pattern', async () => {
      const agentId = await createTestAgent(agents, 'bad-pattern-agent');

      const result = await issueAttestation(agents, sessions, TEST_APP_ID, TEST_SECRET, {
        agent_id: agentId,
        can: ['read:inv oices'],
      });
      expect(result.success).toBe(false);
      expect(result.error).toContain('Invalid capability pattern');
    });

    test('rejects nonexistent agent', async () => {
      const result = await issueAttestation(agents, sessions, TEST_APP_ID, TEST_SECRET, {
        agent_id: 'nonexistent-agent-id',
        can: ['read:invoices'],
      });
      expect(result.success).toBe(false);
      expect(result.error).toContain('not found');
    });

    test('rejects agent from different app', async () => {
      const agentId = await createTestAgent(agents, 'wrong-app-agent');

      const result = await issueAttestation(agents, sessions, 'different_app_id', TEST_SECRET, {
        agent_id: agentId,
        can: ['read:invoices'],
      });
      expect(result.success).toBe(false);
      expect(result.error).toContain('does not belong');
    });

    test('enforces max rules limit', async () => {
      const agentId = await createTestAgent(agents, 'too-many-rules-agent');

      const tooManyCan = Array.from({ length: 101 }, (_, i) => `action${i}:resource`);
      const result = await issueAttestation(agents, sessions, TEST_APP_ID, TEST_SECRET, {
        agent_id: agentId,
        can: tooManyCan,
      });
      expect(result.success).toBe(false);
      expect(result.error).toContain('Too many rules');
    });

    test('respects custom duration', async () => {
      const agentId = await createTestAgent(agents, 'custom-duration-agent');

      const result = await issueAttestation(agents, sessions, TEST_APP_ID, TEST_SECRET, {
        agent_id: agentId,
        can: ['read:invoices'],
        duration_seconds: 60,
      });

      expect(result.success).toBe(true);
      const att = result.attestation!;
      const duration = att.expires_at - att.created_at;
      expect(duration).toBe(60_000);
    });

    test('stores attestation in KV', async () => {
      const agentId = await createTestAgent(agents, 'stored-agent');

      const result = await issueAttestation(agents, sessions, TEST_APP_ID, TEST_SECRET, {
        agent_id: agentId,
        can: ['read:invoices'],
      });

      expect(result.success).toBe(true);
      const stored = sessions.getRaw(`attestation:${result.attestation!.attestation_id}`);
      expect(stored).toBeTruthy();
    });

    test('updates agent attestation index', async () => {
      const agentId = await createTestAgent(agents, 'indexed-agent');

      const result = await issueAttestation(agents, sessions, TEST_APP_ID, TEST_SECRET, {
        agent_id: agentId,
        can: ['read:invoices'],
      });

      expect(result.success).toBe(true);
      const index = sessions.getRaw(`agent_attestations:${agentId}`);
      expect(index).toBeTruthy();
      const ids = JSON.parse(index!);
      expect(ids).toContain(result.attestation!.attestation_id);
    });
  });

  // ============ Attestation Retrieval ============

  describe('getAttestation', () => {
    test('retrieves existing attestation', async () => {
      const agentId = await createTestAgent(agents, 'get-agent');
      const issued = await issueAttestation(agents, sessions, TEST_APP_ID, TEST_SECRET, {
        agent_id: agentId,
        can: ['read:invoices'],
      });

      const result = await getAttestation(sessions, issued.attestation!.attestation_id);

      expect(result.success).toBe(true);
      expect(result.attestation!.attestation_id).toBe(issued.attestation!.attestation_id);
      expect(result.attestation!.agent_id).toBe(agentId);
    });

    test('returns error for nonexistent attestation', async () => {
      const result = await getAttestation(sessions, 'nonexistent-id');
      expect(result.success).toBe(false);
      expect(result.error).toContain('not found');
    });
  });

  // ============ Attestation Revocation ============

  describe('revokeAttestation', () => {
    test('revokes existing attestation', async () => {
      const agentId = await createTestAgent(agents, 'revoke-agent');
      const issued = await issueAttestation(agents, sessions, TEST_APP_ID, TEST_SECRET, {
        agent_id: agentId,
        can: ['read:invoices'],
      });

      const result = await revokeAttestation(sessions, issued.attestation!.attestation_id, 'abuse');

      expect(result.success).toBe(true);
      expect(result.attestation!.revoked).toBe(true);
      expect(result.attestation!.revocation_reason).toBe('abuse');
      expect(result.attestation!.revoked_at).toBeTruthy();
    });

    test('idempotent revocation', async () => {
      const agentId = await createTestAgent(agents, 'double-revoke-agent');
      const issued = await issueAttestation(agents, sessions, TEST_APP_ID, TEST_SECRET, {
        agent_id: agentId,
        can: ['read:invoices'],
      });

      await revokeAttestation(sessions, issued.attestation!.attestation_id, 'first');
      const second = await revokeAttestation(sessions, issued.attestation!.attestation_id, 'second');

      expect(second.success).toBe(true);
      expect(second.attestation!.revoked).toBe(true);
    });

    test('returns error for nonexistent attestation', async () => {
      const result = await revokeAttestation(sessions, 'nonexistent-id');
      expect(result.success).toBe(false);
    });
  });

  // ============ Token Verification ============

  describe('verifyAttestationToken', () => {
    test('verifies valid token', async () => {
      const agentId = await createTestAgent(agents, 'verify-agent');
      const issued = await issueAttestation(agents, sessions, TEST_APP_ID, TEST_SECRET, {
        agent_id: agentId,
        can: ['read:invoices', 'browse:*'],
        cannot: ['write:transfers'],
      });

      const result = await verifyAttestationToken(sessions, issued.token!, TEST_SECRET);

      expect(result.valid).toBe(true);
      expect(result.payload).toBeDefined();
      expect(result.payload!.sub).toBe(agentId);
      expect(result.payload!.iss).toBe(TEST_APP_ID);
      expect(result.payload!.type).toBe('botcha-attestation');
      expect(result.payload!.can).toEqual(['read:invoices', 'browse:*']);
      expect(result.payload!.cannot).toEqual(['write:transfers']);
    });

    test('rejects invalid token', async () => {
      const result = await verifyAttestationToken(sessions, 'invalid.token.here', TEST_SECRET);
      expect(result.valid).toBe(false);
    });

    test('rejects token with wrong secret', async () => {
      const agentId = await createTestAgent(agents, 'wrong-secret-agent');
      const issued = await issueAttestation(agents, sessions, TEST_APP_ID, TEST_SECRET, {
        agent_id: agentId,
        can: ['read:invoices'],
      });

      const result = await verifyAttestationToken(sessions, issued.token!, 'wrong-secret-completely-different!!');
      expect(result.valid).toBe(false);
    });

    test('rejects revoked token', async () => {
      const agentId = await createTestAgent(agents, 'revoked-token-agent');
      const issued = await issueAttestation(agents, sessions, TEST_APP_ID, TEST_SECRET, {
        agent_id: agentId,
        can: ['read:invoices'],
      });

      await revokeAttestation(sessions, issued.attestation!.attestation_id, 'revoked');

      const result = await verifyAttestationToken(sessions, issued.token!, TEST_SECRET);
      expect(result.valid).toBe(false);
      expect(result.error).toContain('revoked');
    });
  });

  // ============ Combined Verify + Check ============

  describe('verifyAndCheckCapability', () => {
    test('allows matching capability', async () => {
      const agentId = await createTestAgent(agents, 'check-allow-agent');
      const issued = await issueAttestation(agents, sessions, TEST_APP_ID, TEST_SECRET, {
        agent_id: agentId,
        can: ['read:invoices', 'browse:*'],
      });

      const result = await verifyAndCheckCapability(
        sessions, issued.token!, TEST_SECRET, 'read', 'invoices'
      );

      expect(result.allowed).toBe(true);
      expect(result.agent_id).toBe(agentId);
    });

    test('denies non-matching capability', async () => {
      const agentId = await createTestAgent(agents, 'check-deny-agent');
      const issued = await issueAttestation(agents, sessions, TEST_APP_ID, TEST_SECRET, {
        agent_id: agentId,
        can: ['read:invoices'],
      });

      const result = await verifyAndCheckCapability(
        sessions, issued.token!, TEST_SECRET, 'write', 'invoices'
      );

      expect(result.allowed).toBe(false);
    });

    test('deny rules override allow', async () => {
      const agentId = await createTestAgent(agents, 'check-override-agent');
      const issued = await issueAttestation(agents, sessions, TEST_APP_ID, TEST_SECRET, {
        agent_id: agentId,
        can: ['*:*'],
        cannot: ['write:transfers'],
      });

      const result = await verifyAndCheckCapability(
        sessions, issued.token!, TEST_SECRET, 'write', 'transfers'
      );

      expect(result.allowed).toBe(false);
      expect(result.agent_id).toBe(agentId);
    });

    test('fails with invalid token', async () => {
      const result = await verifyAndCheckCapability(
        sessions, 'invalid-token', TEST_SECRET, 'read', 'invoices'
      );

      expect(result.allowed).toBe(false);
      expect(result.error).toBeTruthy();
    });
  });

  // ============ Enforcement Middleware ============

  describe('requireCapability middleware', () => {
    test('blocks request without attestation token', async () => {
      const middleware = requireCapability('read:invoices');
      let nextCalled = false;

      const mockContext = {
        req: {
          header: (_name: string) => undefined,
        },
        json: (body: any, status: number) => ({ body, status }),
        env: { SESSIONS: sessions, JWT_SECRET: TEST_SECRET },
        set: () => {},
      };

      const result = await middleware(mockContext, async () => { nextCalled = true; });
      expect(nextCalled).toBe(false);
      expect(result.status).toBe(401);
      expect(result.body.error).toBe('ATTESTATION_REQUIRED');
    });

    test('blocks request with invalid token', async () => {
      const middleware = requireCapability('read:invoices');
      let nextCalled = false;

      const mockContext = {
        req: {
          header: (name: string) => name === 'x-botcha-attestation' ? 'invalid-token' : undefined,
        },
        json: (body: any, status: number) => ({ body, status }),
        env: { SESSIONS: sessions, JWT_SECRET: TEST_SECRET },
        set: () => {},
      };

      const result = await middleware(mockContext, async () => { nextCalled = true; });
      expect(nextCalled).toBe(false);
      expect(result.status).toBe(403);
    });

    test('allows request with valid attestation token', async () => {
      const agentId = await createTestAgent(agents, 'middleware-agent');
      const issued = await issueAttestation(agents, sessions, TEST_APP_ID, TEST_SECRET, {
        agent_id: agentId,
        can: ['read:invoices'],
      });

      const middleware = requireCapability('read:invoices');
      let nextCalled = false;
      const setValues: Record<string, string> = {};

      const mockContext = {
        req: {
          header: (name: string) => name === 'x-botcha-attestation' ? issued.token! : undefined,
        },
        json: (body: any, status: number) => ({ body, status }),
        env: { SESSIONS: sessions, JWT_SECRET: TEST_SECRET },
        set: (key: string, value: string) => { setValues[key] = value; },
      };

      await middleware(mockContext, async () => { nextCalled = true; });
      expect(nextCalled).toBe(true);
      expect(setValues['attestation_agent_id']).toBe(agentId);
      expect(setValues['attestation_capability']).toBe('read:invoices');
    });

    test('extracts token from Authorization Bearer header', async () => {
      const agentId = await createTestAgent(agents, 'bearer-agent');
      const issued = await issueAttestation(agents, sessions, TEST_APP_ID, TEST_SECRET, {
        agent_id: agentId,
        can: ['browse:*'],
      });

      const middleware = requireCapability('browse:products');
      let nextCalled = false;

      const mockContext = {
        req: {
          header: (name: string) => {
            if (name === 'x-botcha-attestation') return undefined;
            if (name === 'authorization') return `Bearer ${issued.token!}`;
            return undefined;
          },
        },
        json: (body: any, status: number) => ({ body, status }),
        env: { SESSIONS: sessions, JWT_SECRET: TEST_SECRET },
        set: () => {},
      };

      await middleware(mockContext, async () => { nextCalled = true; });
      expect(nextCalled).toBe(true);
    });

    test('denies when capability not granted', async () => {
      const agentId = await createTestAgent(agents, 'no-cap-agent');
      const issued = await issueAttestation(agents, sessions, TEST_APP_ID, TEST_SECRET, {
        agent_id: agentId,
        can: ['read:invoices'],
      });

      const middleware = requireCapability('write:transfers');
      let nextCalled = false;

      const mockContext = {
        req: {
          header: (name: string) => name === 'x-botcha-attestation' ? issued.token! : undefined,
        },
        json: (body: any, status: number) => ({ body, status }),
        env: { SESSIONS: sessions, JWT_SECRET: TEST_SECRET },
        set: () => {},
      };

      const result = await middleware(mockContext, async () => { nextCalled = true; });
      expect(nextCalled).toBe(false);
      expect(result.status).toBe(403);
      expect(result.body.error).toBe('CAPABILITY_DENIED');
    });
  });

  // ============ Delegation Integration ============

  describe('delegation_id linkage', () => {
    test('attestation can link to delegation', async () => {
      const agentId = await createTestAgent(agents, 'delegation-link-agent');

      const result = await issueAttestation(agents, sessions, TEST_APP_ID, TEST_SECRET, {
        agent_id: agentId,
        can: ['read:invoices'],
        delegation_id: 'delegation_abc123',
      });

      expect(result.success).toBe(true);
      expect(result.attestation!.delegation_id).toBe('delegation_abc123');

      // Verify token also contains delegation_id
      const verification = await verifyAttestationToken(sessions, result.token!, TEST_SECRET);
      expect(verification.payload!.delegation_id).toBe('delegation_abc123');
    });
  });
});
