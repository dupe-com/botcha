import { describe, test, expect, beforeEach } from 'vitest';
import {
  createDelegation,
  getDelegation,
  listDelegations,
  revokeDelegation,
  verifyDelegationChain,
  isCapabilitySubset,
  type Delegation,
  type CreateDelegationOptions,
} from '../../../packages/cloudflare-workers/src/tap-delegation.js';
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

const TEST_APP_ID = 'app_delegation_test_01';

const VALID_ED25519_KEY = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='; // 32-byte base64

async function createTestAgent(
  agents: MockKV,
  name: string,
  capabilities: TAPCapability[],
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

describe('TAP Delegation Chains', () => {
  let agents: MockKV;
  let sessions: MockKV;

  beforeEach(() => {
    agents = new MockKV();
    sessions = new MockKV();
  });

  // ============ isCapabilitySubset ============

  describe('isCapabilitySubset', () => {
    test('allows exact same capabilities', () => {
      const caps: TAPCapability[] = [{ action: 'browse', scope: ['products'] }];
      const result = isCapabilitySubset(caps, caps);
      expect(result.valid).toBe(true);
    });

    test('allows narrower scope', () => {
      const parent: TAPCapability[] = [{ action: 'browse', scope: ['products', 'orders'] }];
      const child: TAPCapability[] = [{ action: 'browse', scope: ['products'] }];
      expect(isCapabilitySubset(parent, child).valid).toBe(true);
    });

    test('rejects broader scope', () => {
      const parent: TAPCapability[] = [{ action: 'browse', scope: ['products'] }];
      const child: TAPCapability[] = [{ action: 'browse', scope: ['products', 'orders'] }];
      expect(isCapabilitySubset(parent, child).valid).toBe(false);
    });

    test('allows fewer actions', () => {
      const parent: TAPCapability[] = [
        { action: 'browse', scope: ['*'] },
        { action: 'purchase', scope: ['*'] },
      ];
      const child: TAPCapability[] = [{ action: 'browse', scope: ['*'] }];
      expect(isCapabilitySubset(parent, child).valid).toBe(true);
    });

    test('rejects action not in parent', () => {
      const parent: TAPCapability[] = [{ action: 'browse' }];
      const child: TAPCapability[] = [{ action: 'purchase' }];
      const result = isCapabilitySubset(parent, child);
      expect(result.valid).toBe(false);
      expect(result.error).toContain('purchase');
    });

    test('rejects wildcard scope when parent has restricted scope', () => {
      const parent: TAPCapability[] = [{ action: 'browse', scope: ['products'] }];
      const child: TAPCapability[] = [{ action: 'browse', scope: ['*'] }];
      expect(isCapabilitySubset(parent, child).valid).toBe(false);
    });

    test('allows any child scope when parent has wildcard', () => {
      const parent: TAPCapability[] = [{ action: 'browse', scope: ['*'] }];
      const child: TAPCapability[] = [{ action: 'browse', scope: ['products'] }];
      expect(isCapabilitySubset(parent, child).valid).toBe(true);
    });

    test('allows child scope when parent has no scope (unrestricted)', () => {
      const parent: TAPCapability[] = [{ action: 'browse' }];
      const child: TAPCapability[] = [{ action: 'browse', scope: ['products'] }];
      expect(isCapabilitySubset(parent, child).valid).toBe(true);
    });

    test('rejects less restrictive max_amount', () => {
      const parent: TAPCapability[] = [{
        action: 'purchase',
        restrictions: { max_amount: 100 }
      }];
      const child: TAPCapability[] = [{
        action: 'purchase',
        restrictions: { max_amount: 200 }
      }];
      expect(isCapabilitySubset(parent, child).valid).toBe(false);
    });

    test('allows stricter max_amount', () => {
      const parent: TAPCapability[] = [{
        action: 'purchase',
        restrictions: { max_amount: 200 }
      }];
      const child: TAPCapability[] = [{
        action: 'purchase',
        restrictions: { max_amount: 100 }
      }];
      expect(isCapabilitySubset(parent, child).valid).toBe(true);
    });

    test('rejects missing restrictions when parent has them', () => {
      const parent: TAPCapability[] = [{
        action: 'purchase',
        restrictions: { max_amount: 100 }
      }];
      const child: TAPCapability[] = [{
        action: 'purchase'
      }];
      expect(isCapabilitySubset(parent, child).valid).toBe(false);
    });

    test('rejects less restrictive rate_limit', () => {
      const parent: TAPCapability[] = [{
        action: 'browse',
        restrictions: { rate_limit: 50 }
      }];
      const child: TAPCapability[] = [{
        action: 'browse',
        restrictions: { rate_limit: 100 }
      }];
      expect(isCapabilitySubset(parent, child).valid).toBe(false);
    });

    test('empty child capabilities is always valid', () => {
      const parent: TAPCapability[] = [{ action: 'browse' }];
      expect(isCapabilitySubset(parent, []).valid).toBe(true);
    });
  });

  // ============ createDelegation ============

  describe('createDelegation', () => {
    test('creates basic delegation between two agents', async () => {
      const grantorId = await createTestAgent(agents, 'Grantor', [
        { action: 'browse', scope: ['products', 'orders'] }
      ]);
      const granteeId = await createTestAgent(agents, 'Grantee', []);

      const result = await createDelegation(agents, sessions, TEST_APP_ID, {
        grantor_id: grantorId,
        grantee_id: granteeId,
        capabilities: [{ action: 'browse', scope: ['products'] }],
      });

      expect(result.success).toBe(true);
      expect(result.delegation).toBeDefined();
      expect(result.delegation!.delegation_id).toMatch(/^del_/);
      expect(result.delegation!.grantor_id).toBe(grantorId);
      expect(result.delegation!.grantee_id).toBe(granteeId);
      expect(result.delegation!.chain).toEqual([grantorId, granteeId]);
      expect(result.delegation!.depth).toBe(0);
      expect(result.delegation!.revoked).toBe(false);
    });

    test('rejects delegation to self', async () => {
      const agentId = await createTestAgent(agents, 'Self', [{ action: 'browse' }]);
      const result = await createDelegation(agents, sessions, TEST_APP_ID, {
        grantor_id: agentId,
        grantee_id: agentId,
        capabilities: [{ action: 'browse' }],
      });
      expect(result.success).toBe(false);
      expect(result.error).toContain('self');
    });

    test('rejects missing required fields', async () => {
      const result = await createDelegation(agents, sessions, TEST_APP_ID, {
        grantor_id: '',
        grantee_id: '',
        capabilities: [],
      });
      expect(result.success).toBe(false);
    });

    test('rejects capability escalation', async () => {
      const grantorId = await createTestAgent(agents, 'Grantor', [
        { action: 'browse', scope: ['products'] }
      ]);
      const granteeId = await createTestAgent(agents, 'Grantee', []);

      const result = await createDelegation(agents, sessions, TEST_APP_ID, {
        grantor_id: grantorId,
        grantee_id: granteeId,
        capabilities: [{ action: 'purchase' }], // grantor doesn't have purchase
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain('purchase');
    });

    test('rejects scope escalation', async () => {
      const grantorId = await createTestAgent(agents, 'Grantor', [
        { action: 'browse', scope: ['products'] }
      ]);
      const granteeId = await createTestAgent(agents, 'Grantee', []);

      const result = await createDelegation(agents, sessions, TEST_APP_ID, {
        grantor_id: grantorId,
        grantee_id: granteeId,
        capabilities: [{ action: 'browse', scope: ['products', 'orders'] }],
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain('orders');
    });

    test('rejects nonexistent grantor', async () => {
      const granteeId = await createTestAgent(agents, 'Grantee', []);
      const result = await createDelegation(agents, sessions, TEST_APP_ID, {
        grantor_id: 'agent_doesnotexist',
        grantee_id: granteeId,
        capabilities: [{ action: 'browse' }],
      });
      expect(result.success).toBe(false);
      expect(result.error).toContain('Grantor');
    });

    test('rejects nonexistent grantee', async () => {
      const grantorId = await createTestAgent(agents, 'Grantor', [{ action: 'browse' }]);
      const result = await createDelegation(agents, sessions, TEST_APP_ID, {
        grantor_id: grantorId,
        grantee_id: 'agent_doesnotexist',
        capabilities: [{ action: 'browse' }],
      });
      expect(result.success).toBe(false);
      expect(result.error).toContain('Grantee');
    });

    test('rejects cross-app delegation', async () => {
      const grantorId = await createTestAgent(agents, 'Grantor', [{ action: 'browse' }]);
      const granteeId = await createTestAgent(agents, 'Grantee', []);

      const result = await createDelegation(agents, sessions, 'app_different_app', {
        grantor_id: grantorId,
        grantee_id: granteeId,
        capabilities: [{ action: 'browse' }],
      });
      expect(result.success).toBe(false);
      expect(result.error).toContain('does not belong');
    });

    test('respects custom duration', async () => {
      const grantorId = await createTestAgent(agents, 'Grantor', [{ action: 'browse' }]);
      const granteeId = await createTestAgent(agents, 'Grantee', []);

      const result = await createDelegation(agents, sessions, TEST_APP_ID, {
        grantor_id: grantorId,
        grantee_id: granteeId,
        capabilities: [{ action: 'browse' }],
        duration_seconds: 7200, // 2 hours
      });

      expect(result.success).toBe(true);
      const del = result.delegation!;
      const durationMs = del.expires_at - del.created_at;
      expect(durationMs).toBe(7200 * 1000);
    });

    test('stores metadata', async () => {
      const grantorId = await createTestAgent(agents, 'Grantor', [{ action: 'browse' }]);
      const granteeId = await createTestAgent(agents, 'Grantee', []);

      const result = await createDelegation(agents, sessions, TEST_APP_ID, {
        grantor_id: grantorId,
        grantee_id: granteeId,
        capabilities: [{ action: 'browse' }],
        metadata: { purpose: 'product-search', requestor: 'human-operator' },
      });

      expect(result.success).toBe(true);
      expect(result.delegation!.metadata).toEqual({
        purpose: 'product-search',
        requestor: 'human-operator',
      });
    });

    test('rejects invalid capability action', async () => {
      const grantorId = await createTestAgent(agents, 'Grantor', [{ action: 'browse' }]);
      const granteeId = await createTestAgent(agents, 'Grantee', []);

      const result = await createDelegation(agents, sessions, TEST_APP_ID, {
        grantor_id: grantorId,
        grantee_id: granteeId,
        capabilities: [{ action: 'hack' as any }],
      });
      expect(result.success).toBe(false);
      expect(result.error).toContain('Invalid capability action');
    });
  });

  // ============ Sub-Delegation (Chaining) ============

  describe('sub-delegation (chaining)', () => {
    test('creates a two-level delegation chain (A→B→C)', async () => {
      const agentA = await createTestAgent(agents, 'Agent A', [
        { action: 'browse', scope: ['products', 'orders', 'users'] }
      ]);
      const agentB = await createTestAgent(agents, 'Agent B', []);
      const agentC = await createTestAgent(agents, 'Agent C', []);

      // A delegates to B
      const delAB = await createDelegation(agents, sessions, TEST_APP_ID, {
        grantor_id: agentA,
        grantee_id: agentB,
        capabilities: [{ action: 'browse', scope: ['products', 'orders'] }],
      });
      expect(delAB.success).toBe(true);

      // B sub-delegates to C (narrower)
      const delBC = await createDelegation(agents, sessions, TEST_APP_ID, {
        grantor_id: agentB,
        grantee_id: agentC,
        capabilities: [{ action: 'browse', scope: ['products'] }],
        parent_delegation_id: delAB.delegation!.delegation_id,
      });

      expect(delBC.success).toBe(true);
      expect(delBC.delegation!.depth).toBe(1);
      expect(delBC.delegation!.chain).toEqual([agentA, agentB, agentC]);
      expect(delBC.delegation!.parent_delegation_id).toBe(delAB.delegation!.delegation_id);
    });

    test('rejects sub-delegation that escalates parent capabilities', async () => {
      const agentA = await createTestAgent(agents, 'Agent A', [
        { action: 'browse', scope: ['products', 'orders'] }
      ]);
      const agentB = await createTestAgent(agents, 'Agent B', []);
      const agentC = await createTestAgent(agents, 'Agent C', []);

      // A delegates browse:products to B
      const delAB = await createDelegation(agents, sessions, TEST_APP_ID, {
        grantor_id: agentA,
        grantee_id: agentB,
        capabilities: [{ action: 'browse', scope: ['products'] }],
      });

      // B tries to sub-delegate browse:orders to C (B doesn't have orders via delegation)
      const delBC = await createDelegation(agents, sessions, TEST_APP_ID, {
        grantor_id: agentB,
        grantee_id: agentC,
        capabilities: [{ action: 'browse', scope: ['orders'] }],
        parent_delegation_id: delAB.delegation!.delegation_id,
      });

      expect(delBC.success).toBe(false);
      expect(delBC.error).toContain('orders');
    });

    test('rejects exceeding max depth', async () => {
      const agentA = await createTestAgent(agents, 'A', [{ action: 'browse' }]);
      const agentB = await createTestAgent(agents, 'B', []);
      const agentC = await createTestAgent(agents, 'C', []);
      const agentD = await createTestAgent(agents, 'D', []);

      // A→B with max_depth=2
      const delAB = await createDelegation(agents, sessions, TEST_APP_ID, {
        grantor_id: agentA,
        grantee_id: agentB,
        capabilities: [{ action: 'browse' }],
        max_depth: 2,
      });

      // B→C (depth 1, ok)
      const delBC = await createDelegation(agents, sessions, TEST_APP_ID, {
        grantor_id: agentB,
        grantee_id: agentC,
        capabilities: [{ action: 'browse' }],
        parent_delegation_id: delAB.delegation!.delegation_id,
      });
      expect(delBC.success).toBe(true);
      expect(delBC.delegation!.depth).toBe(1);

      // C→D (depth 2, at limit — should fail)
      const delCD = await createDelegation(agents, sessions, TEST_APP_ID, {
        grantor_id: agentC,
        grantee_id: agentD,
        capabilities: [{ action: 'browse' }],
        parent_delegation_id: delBC.delegation!.delegation_id,
      });
      expect(delCD.success).toBe(false);
      expect(delCD.error).toContain('depth limit');
    });

    test('rejects cycle in chain', async () => {
      const agentA = await createTestAgent(agents, 'A', [{ action: 'browse' }]);
      const agentB = await createTestAgent(agents, 'B', []);

      // A→B
      const delAB = await createDelegation(agents, sessions, TEST_APP_ID, {
        grantor_id: agentA,
        grantee_id: agentB,
        capabilities: [{ action: 'browse' }],
      });

      // B→A (cycle!) via sub-delegation
      const delBA = await createDelegation(agents, sessions, TEST_APP_ID, {
        grantor_id: agentB,
        grantee_id: agentA,
        capabilities: [{ action: 'browse' }],
        parent_delegation_id: delAB.delegation!.delegation_id,
      });
      expect(delBA.success).toBe(false);
      expect(delBA.error).toContain('cycle');
    });

    test('sub-delegation grantor must be parent grantee', async () => {
      const agentA = await createTestAgent(agents, 'A', [{ action: 'browse' }]);
      const agentB = await createTestAgent(agents, 'B', []);
      const agentC = await createTestAgent(agents, 'C', []);

      // A→B
      const delAB = await createDelegation(agents, sessions, TEST_APP_ID, {
        grantor_id: agentA,
        grantee_id: agentB,
        capabilities: [{ action: 'browse' }],
      });

      // C tries to sub-delegate from delAB (C is not B)
      const delCX = await createDelegation(agents, sessions, TEST_APP_ID, {
        grantor_id: agentC,
        grantee_id: agentA,
        capabilities: [{ action: 'browse' }],
        parent_delegation_id: delAB.delegation!.delegation_id,
      });
      expect(delCX.success).toBe(false);
      expect(delCX.error).toContain('not the grantee');
    });
  });

  // ============ getDelegation ============

  describe('getDelegation', () => {
    test('retrieves existing delegation', async () => {
      const grantorId = await createTestAgent(agents, 'Grantor', [{ action: 'browse' }]);
      const granteeId = await createTestAgent(agents, 'Grantee', []);

      const created = await createDelegation(agents, sessions, TEST_APP_ID, {
        grantor_id: grantorId,
        grantee_id: granteeId,
        capabilities: [{ action: 'browse' }],
      });

      const result = await getDelegation(sessions, created.delegation!.delegation_id);
      expect(result.success).toBe(true);
      expect(result.delegation!.delegation_id).toBe(created.delegation!.delegation_id);
    });

    test('returns error for nonexistent delegation', async () => {
      const result = await getDelegation(sessions, 'del_doesnotexist');
      expect(result.success).toBe(false);
      expect(result.error).toContain('not found');
    });
  });

  // ============ listDelegations ============

  describe('listDelegations', () => {
    test('lists outbound delegations for an agent', async () => {
      const agentA = await createTestAgent(agents, 'A', [{ action: 'browse' }, { action: 'search' }]);
      const agentB = await createTestAgent(agents, 'B', []);
      const agentC = await createTestAgent(agents, 'C', []);

      await createDelegation(agents, sessions, TEST_APP_ID, {
        grantor_id: agentA,
        grantee_id: agentB,
        capabilities: [{ action: 'browse' }],
      });

      await createDelegation(agents, sessions, TEST_APP_ID, {
        grantor_id: agentA,
        grantee_id: agentC,
        capabilities: [{ action: 'search' }],
      });

      const result = await listDelegations(sessions, {
        agent_id: agentA,
        direction: 'out',
      });

      expect(result.success).toBe(true);
      expect(result.delegations!.length).toBe(2);
    });

    test('lists inbound delegations for an agent', async () => {
      const agentA = await createTestAgent(agents, 'A', [{ action: 'browse' }]);
      const agentB = await createTestAgent(agents, 'B', []);

      await createDelegation(agents, sessions, TEST_APP_ID, {
        grantor_id: agentA,
        grantee_id: agentB,
        capabilities: [{ action: 'browse' }],
      });

      const result = await listDelegations(sessions, {
        agent_id: agentB,
        direction: 'in',
      });

      expect(result.success).toBe(true);
      expect(result.delegations!.length).toBe(1);
      expect(result.delegations![0].grantee_id).toBe(agentB);
    });

    test('filters out revoked delegations by default', async () => {
      const agentA = await createTestAgent(agents, 'A', [{ action: 'browse' }]);
      const agentB = await createTestAgent(agents, 'B', []);

      const del = await createDelegation(agents, sessions, TEST_APP_ID, {
        grantor_id: agentA,
        grantee_id: agentB,
        capabilities: [{ action: 'browse' }],
      });

      await revokeDelegation(sessions, del.delegation!.delegation_id);

      // Without include_revoked
      const filtered = await listDelegations(sessions, {
        agent_id: agentA,
        direction: 'out',
      });
      expect(filtered.delegations!.length).toBe(0);

      // With include_revoked
      const unfiltered = await listDelegations(sessions, {
        agent_id: agentA,
        direction: 'out',
        include_revoked: true,
      });
      expect(unfiltered.delegations!.length).toBe(1);
    });

    test('returns empty list for agent with no delegations', async () => {
      const agentA = await createTestAgent(agents, 'A', [{ action: 'browse' }]);
      const result = await listDelegations(sessions, { agent_id: agentA });
      expect(result.success).toBe(true);
      expect(result.delegations!.length).toBe(0);
    });
  });

  // ============ revokeDelegation ============

  describe('revokeDelegation', () => {
    test('revokes a delegation', async () => {
      const agentA = await createTestAgent(agents, 'A', [{ action: 'browse' }]);
      const agentB = await createTestAgent(agents, 'B', []);

      const del = await createDelegation(agents, sessions, TEST_APP_ID, {
        grantor_id: agentA,
        grantee_id: agentB,
        capabilities: [{ action: 'browse' }],
      });

      const result = await revokeDelegation(sessions, del.delegation!.delegation_id, 'testing');
      expect(result.success).toBe(true);
      expect(result.delegation!.revoked).toBe(true);
      expect(result.delegation!.revoked_at).toBeDefined();
      expect(result.delegation!.revocation_reason).toBe('testing');
    });

    test('revocation is idempotent', async () => {
      const agentA = await createTestAgent(agents, 'A', [{ action: 'browse' }]);
      const agentB = await createTestAgent(agents, 'B', []);

      const del = await createDelegation(agents, sessions, TEST_APP_ID, {
        grantor_id: agentA,
        grantee_id: agentB,
        capabilities: [{ action: 'browse' }],
      });

      const id = del.delegation!.delegation_id;
      await revokeDelegation(sessions, id);
      const result = await revokeDelegation(sessions, id);
      expect(result.success).toBe(true);
      expect(result.delegation!.revoked).toBe(true);
    });

    test('cascades revocation to sub-delegations', async () => {
      const agentA = await createTestAgent(agents, 'A', [{ action: 'browse' }]);
      const agentB = await createTestAgent(agents, 'B', []);
      const agentC = await createTestAgent(agents, 'C', []);

      const delAB = await createDelegation(agents, sessions, TEST_APP_ID, {
        grantor_id: agentA,
        grantee_id: agentB,
        capabilities: [{ action: 'browse' }],
      });

      const delBC = await createDelegation(agents, sessions, TEST_APP_ID, {
        grantor_id: agentB,
        grantee_id: agentC,
        capabilities: [{ action: 'browse' }],
        parent_delegation_id: delAB.delegation!.delegation_id,
      });

      // Revoke the root
      await revokeDelegation(sessions, delAB.delegation!.delegation_id, 'root revoked');

      // Sub-delegation should also be revoked
      const child = await getDelegation(sessions, delBC.delegation!.delegation_id);
      expect(child.success).toBe(true);
      expect(child.delegation!.revoked).toBe(true);
    });

    test('returns error for nonexistent delegation', async () => {
      const result = await revokeDelegation(sessions, 'del_doesnotexist');
      expect(result.success).toBe(false);
    });
  });

  // ============ verifyDelegationChain ============

  describe('verifyDelegationChain', () => {
    test('validates a simple delegation', async () => {
      const agentA = await createTestAgent(agents, 'A', [{ action: 'browse', scope: ['products'] }]);
      const agentB = await createTestAgent(agents, 'B', []);

      const del = await createDelegation(agents, sessions, TEST_APP_ID, {
        grantor_id: agentA,
        grantee_id: agentB,
        capabilities: [{ action: 'browse', scope: ['products'] }],
      });

      const result = await verifyDelegationChain(agents, sessions, del.delegation!.delegation_id);
      expect(result.valid).toBe(true);
      expect(result.chain!.length).toBe(1);
      expect(result.effective_capabilities!.length).toBe(1);
      expect(result.effective_capabilities![0].action).toBe('browse');
    });

    test('validates a multi-level chain (A→B→C)', async () => {
      const agentA = await createTestAgent(agents, 'A', [
        { action: 'browse', scope: ['products', 'orders'] }
      ]);
      const agentB = await createTestAgent(agents, 'B', []);
      const agentC = await createTestAgent(agents, 'C', []);

      const delAB = await createDelegation(agents, sessions, TEST_APP_ID, {
        grantor_id: agentA,
        grantee_id: agentB,
        capabilities: [{ action: 'browse', scope: ['products', 'orders'] }],
      });

      const delBC = await createDelegation(agents, sessions, TEST_APP_ID, {
        grantor_id: agentB,
        grantee_id: agentC,
        capabilities: [{ action: 'browse', scope: ['products'] }],
        parent_delegation_id: delAB.delegation!.delegation_id,
      });

      const result = await verifyDelegationChain(agents, sessions, delBC.delegation!.delegation_id);
      expect(result.valid).toBe(true);
      expect(result.chain!.length).toBe(2);
      // Effective capabilities should be the leaf's (most restricted)
      expect(result.effective_capabilities![0].scope).toEqual(['products']);
    });

    test('rejects revoked chain', async () => {
      const agentA = await createTestAgent(agents, 'A', [{ action: 'browse' }]);
      const agentB = await createTestAgent(agents, 'B', []);

      const del = await createDelegation(agents, sessions, TEST_APP_ID, {
        grantor_id: agentA,
        grantee_id: agentB,
        capabilities: [{ action: 'browse' }],
      });

      await revokeDelegation(sessions, del.delegation!.delegation_id);

      const result = await verifyDelegationChain(agents, sessions, del.delegation!.delegation_id);
      expect(result.valid).toBe(false);
      expect(result.error).toContain('revoked');
    });

    test('rejects nonexistent delegation', async () => {
      const result = await verifyDelegationChain(agents, sessions, 'del_doesnotexist');
      expect(result.valid).toBe(false);
      expect(result.error).toContain('not found');
    });
  });

  // ============ Edge Cases ============

  describe('edge cases', () => {
    test('multiple capabilities can be delegated at once', async () => {
      const agentA = await createTestAgent(agents, 'A', [
        { action: 'browse', scope: ['*'] },
        { action: 'compare', scope: ['*'] },
        { action: 'purchase', scope: ['*'], restrictions: { max_amount: 1000 } },
      ]);
      const agentB = await createTestAgent(agents, 'B', []);

      const result = await createDelegation(agents, sessions, TEST_APP_ID, {
        grantor_id: agentA,
        grantee_id: agentB,
        capabilities: [
          { action: 'browse', scope: ['products'] },
          { action: 'compare', scope: ['products'] },
          { action: 'purchase', scope: ['products'], restrictions: { max_amount: 500 } },
        ],
      });

      expect(result.success).toBe(true);
      expect(result.delegation!.capabilities.length).toBe(3);
    });

    test('delegation stores in KV and can be retrieved', async () => {
      const agentA = await createTestAgent(agents, 'A', [{ action: 'browse' }]);
      const agentB = await createTestAgent(agents, 'B', []);

      const created = await createDelegation(agents, sessions, TEST_APP_ID, {
        grantor_id: agentA,
        grantee_id: agentB,
        capabilities: [{ action: 'browse' }],
      });

      // Verify it's in the KV store
      const raw = sessions.getRaw(`delegation:${created.delegation!.delegation_id}`);
      expect(raw).toBeDefined();
      const parsed = JSON.parse(raw!);
      expect(parsed.delegation_id).toBe(created.delegation!.delegation_id);
    });

    test('delegation indexes are updated', async () => {
      const agentA = await createTestAgent(agents, 'A', [{ action: 'browse' }]);
      const agentB = await createTestAgent(agents, 'B', []);

      const del = await createDelegation(agents, sessions, TEST_APP_ID, {
        grantor_id: agentA,
        grantee_id: agentB,
        capabilities: [{ action: 'browse' }],
      });

      // Check outbound index
      const outRaw = sessions.getRaw(`agent_delegations_out:${agentA}`);
      expect(outRaw).toBeDefined();
      const outIds = JSON.parse(outRaw!);
      expect(outIds).toContain(del.delegation!.delegation_id);

      // Check inbound index
      const inRaw = sessions.getRaw(`agent_delegations_in:${agentB}`);
      expect(inRaw).toBeDefined();
      const inIds = JSON.parse(inRaw!);
      expect(inIds).toContain(del.delegation!.delegation_id);
    });

    test('sub-delegation cannot outlive parent', async () => {
      const agentA = await createTestAgent(agents, 'A', [{ action: 'browse' }]);
      const agentB = await createTestAgent(agents, 'B', []);
      const agentC = await createTestAgent(agents, 'C', []);

      // Parent: 1 hour
      const delAB = await createDelegation(agents, sessions, TEST_APP_ID, {
        grantor_id: agentA,
        grantee_id: agentB,
        capabilities: [{ action: 'browse' }],
        duration_seconds: 3600,
      });

      // Child requests 24 hours — should be capped to parent's expiry
      const delBC = await createDelegation(agents, sessions, TEST_APP_ID, {
        grantor_id: agentB,
        grantee_id: agentC,
        capabilities: [{ action: 'browse' }],
        parent_delegation_id: delAB.delegation!.delegation_id,
        duration_seconds: 86400,
      });

      expect(delBC.success).toBe(true);
      expect(delBC.delegation!.expires_at).toBeLessThanOrEqual(delAB.delegation!.expires_at);
    });

    test('rejects sub-delegation from revoked parent', async () => {
      const agentA = await createTestAgent(agents, 'A', [{ action: 'browse' }]);
      const agentB = await createTestAgent(agents, 'B', []);
      const agentC = await createTestAgent(agents, 'C', []);

      const delAB = await createDelegation(agents, sessions, TEST_APP_ID, {
        grantor_id: agentA,
        grantee_id: agentB,
        capabilities: [{ action: 'browse' }],
      });

      await revokeDelegation(sessions, delAB.delegation!.delegation_id);

      const delBC = await createDelegation(agents, sessions, TEST_APP_ID, {
        grantor_id: agentB,
        grantee_id: agentC,
        capabilities: [{ action: 'browse' }],
        parent_delegation_id: delAB.delegation!.delegation_id,
      });

      expect(delBC.success).toBe(false);
      expect(delBC.error).toContain('revoked');
    });
  });
});
