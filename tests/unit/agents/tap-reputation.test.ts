import { describe, test, expect, beforeEach } from 'vitest';
import {
  getReputationScore,
  recordReputationEvent,
  listReputationEvents,
  resetReputation,
  getTier,
  applyDecay,
  isValidCategoryAction,
  isValidCategory,
  isValidAction,
  type RecordEventOptions,
  type ReputationScore,
  type ReputationEventCategory,
  type ReputationEventAction,
} from '../../../packages/cloudflare-workers/src/tap-reputation.js';
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

const TEST_APP_ID = 'app_reputation_test_01';
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

describe('TAP Agent Reputation Scoring', () => {
  let agents: MockKV;
  let sessions: MockKV;

  beforeEach(() => {
    agents = new MockKV();
    sessions = new MockKV();
  });

  // ============ Tier Logic ============

  describe('getTier', () => {
    test('returns untrusted for scores 0-199', () => {
      expect(getTier(0)).toBe('untrusted');
      expect(getTier(100)).toBe('untrusted');
      expect(getTier(199)).toBe('untrusted');
    });

    test('returns low for scores 200-399', () => {
      expect(getTier(200)).toBe('low');
      expect(getTier(300)).toBe('low');
      expect(getTier(399)).toBe('low');
    });

    test('returns neutral for scores 400-599', () => {
      expect(getTier(400)).toBe('neutral');
      expect(getTier(500)).toBe('neutral');
      expect(getTier(599)).toBe('neutral');
    });

    test('returns good for scores 600-799', () => {
      expect(getTier(600)).toBe('good');
      expect(getTier(700)).toBe('good');
      expect(getTier(799)).toBe('good');
    });

    test('returns excellent for scores 800-1000', () => {
      expect(getTier(800)).toBe('excellent');
      expect(getTier(900)).toBe('excellent');
      expect(getTier(1000)).toBe('excellent');
    });
  });

  // ============ Decay ============

  describe('applyDecay', () => {
    test('no decay when last_event_at is null', () => {
      const score: ReputationScore = {
        agent_id: 'test',
        app_id: TEST_APP_ID,
        score: 800,
        tier: 'excellent',
        event_count: 10,
        positive_events: 10,
        negative_events: 0,
        last_event_at: null,
        created_at: Date.now(),
        updated_at: Date.now(),
        category_scores: { verification: 0, attestation: 0, delegation: 0, session: 0, violation: 0, endorsement: 0 },
      };
      const result = applyDecay(score);
      expect(result.score).toBe(800);
    });

    test('no decay for recent activity (< 7 days)', () => {
      const score: ReputationScore = {
        agent_id: 'test',
        app_id: TEST_APP_ID,
        score: 800,
        tier: 'excellent',
        event_count: 10,
        positive_events: 10,
        negative_events: 0,
        last_event_at: Date.now() - 5 * 24 * 3600 * 1000, // 5 days ago
        created_at: Date.now(),
        updated_at: Date.now(),
        category_scores: { verification: 0, attestation: 0, delegation: 0, session: 0, violation: 0, endorsement: 0 },
      };
      const result = applyDecay(score);
      expect(result.score).toBe(800);
    });

    test('decays toward base score after inactivity', () => {
      const score: ReputationScore = {
        agent_id: 'test',
        app_id: TEST_APP_ID,
        score: 800,
        tier: 'excellent',
        event_count: 10,
        positive_events: 10,
        negative_events: 0,
        last_event_at: Date.now() - 70 * 24 * 3600 * 1000, // 70 days ago (~10 periods)
        created_at: Date.now(),
        updated_at: Date.now(),
        category_scores: { verification: 0, attestation: 0, delegation: 0, session: 0, violation: 0, endorsement: 0 },
      };
      const result = applyDecay(score);
      // 10 decay periods: score should be closer to 500
      expect(result.score).toBeLessThan(800);
      expect(result.score).toBeGreaterThan(500);
    });

    test('decays low scores back toward base', () => {
      const score: ReputationScore = {
        agent_id: 'test',
        app_id: TEST_APP_ID,
        score: 100,
        tier: 'untrusted',
        event_count: 10,
        positive_events: 0,
        negative_events: 10,
        last_event_at: Date.now() - 70 * 24 * 3600 * 1000,
        created_at: Date.now(),
        updated_at: Date.now(),
        category_scores: { verification: 0, attestation: 0, delegation: 0, session: 0, violation: 0, endorsement: 0 },
      };
      const result = applyDecay(score);
      expect(result.score).toBeGreaterThan(100);
      expect(result.score).toBeLessThan(500);
    });
  });

  // ============ Validation ============

  describe('isValidCategory', () => {
    test('accepts all valid categories', () => {
      expect(isValidCategory('verification')).toBe(true);
      expect(isValidCategory('attestation')).toBe(true);
      expect(isValidCategory('delegation')).toBe(true);
      expect(isValidCategory('session')).toBe(true);
      expect(isValidCategory('violation')).toBe(true);
      expect(isValidCategory('endorsement')).toBe(true);
    });

    test('rejects invalid categories', () => {
      expect(isValidCategory('foo')).toBe(false);
      expect(isValidCategory('')).toBe(false);
      expect(isValidCategory('VERIFICATION')).toBe(false);
    });
  });

  describe('isValidAction', () => {
    test('accepts all valid actions', () => {
      expect(isValidAction('challenge_solved')).toBe(true);
      expect(isValidAction('attestation_issued')).toBe(true);
      expect(isValidAction('endorsement_received')).toBe(true);
      expect(isValidAction('abuse_detected')).toBe(true);
    });

    test('rejects invalid actions', () => {
      expect(isValidAction('foo')).toBe(false);
      expect(isValidAction('')).toBe(false);
    });
  });

  describe('isValidCategoryAction', () => {
    test('accepts matching category+action pairs', () => {
      expect(isValidCategoryAction('verification', 'challenge_solved')).toBe(true);
      expect(isValidCategoryAction('verification', 'auth_failure')).toBe(true);
      expect(isValidCategoryAction('attestation', 'attestation_issued')).toBe(true);
      expect(isValidCategoryAction('delegation', 'delegation_granted')).toBe(true);
      expect(isValidCategoryAction('session', 'session_created')).toBe(true);
      expect(isValidCategoryAction('violation', 'rate_limit_exceeded')).toBe(true);
      expect(isValidCategoryAction('endorsement', 'endorsement_received')).toBe(true);
    });

    test('rejects mismatched category+action pairs', () => {
      expect(isValidCategoryAction('verification', 'attestation_issued')).toBe(false);
      expect(isValidCategoryAction('endorsement', 'challenge_solved')).toBe(false);
      expect(isValidCategoryAction('delegation', 'abuse_detected')).toBe(false);
    });
  });

  // ============ Get Reputation Score ============

  describe('getReputationScore', () => {
    test('returns default score for new agent', async () => {
      const agentId = await createTestAgent(agents, 'new-agent');

      const result = await getReputationScore(sessions, agents, agentId, TEST_APP_ID);
      expect(result.success).toBe(true);
      expect(result.score).toBeDefined();
      expect(result.score!.score).toBe(500);
      expect(result.score!.tier).toBe('neutral');
      expect(result.score!.event_count).toBe(0);
      expect(result.score!.positive_events).toBe(0);
      expect(result.score!.negative_events).toBe(0);
      expect(result.score!.last_event_at).toBeNull();
    });

    test('returns stored score for existing agent', async () => {
      const agentId = await createTestAgent(agents, 'existing-agent');

      // Record an event to create a stored score
      await recordReputationEvent(sessions, agents, TEST_APP_ID, {
        agent_id: agentId,
        category: 'verification',
        action: 'challenge_solved',
      });

      const result = await getReputationScore(sessions, agents, agentId, TEST_APP_ID);
      expect(result.success).toBe(true);
      expect(result.score!.score).toBe(505); // 500 + 5
      expect(result.score!.event_count).toBe(1);
    });

    test('fails for non-existent agent', async () => {
      const result = await getReputationScore(sessions, agents, 'agent_nonexistent', TEST_APP_ID);
      expect(result.success).toBe(false);
      expect(result.error).toContain('not found');
    });

    test('returns graceful error on KV failure', async () => {
      const agentId = await createTestAgent(agents, 'kv-fail-agent');
      sessions.setShouldFail(true);

      const result = await getReputationScore(sessions, agents, agentId, TEST_APP_ID);
      expect(result.success).toBe(false);
      expect(result.error).toBe('Internal server error');
    });
  });

  // ============ Record Events ============

  describe('recordReputationEvent', () => {
    test('records a positive verification event', async () => {
      const agentId = await createTestAgent(agents, 'verify-agent');

      const result = await recordReputationEvent(sessions, agents, TEST_APP_ID, {
        agent_id: agentId,
        category: 'verification',
        action: 'challenge_solved',
      });

      expect(result.success).toBe(true);
      expect(result.event).toBeDefined();
      expect(result.event!.category).toBe('verification');
      expect(result.event!.action).toBe('challenge_solved');
      expect(result.event!.delta).toBe(5);
      expect(result.event!.score_before).toBe(500);
      expect(result.event!.score_after).toBe(505);
      expect(result.score!.score).toBe(505);
      expect(result.score!.tier).toBe('neutral');
      expect(result.score!.positive_events).toBe(1);
    });

    test('records a negative violation event', async () => {
      const agentId = await createTestAgent(agents, 'violation-agent');

      const result = await recordReputationEvent(sessions, agents, TEST_APP_ID, {
        agent_id: agentId,
        category: 'violation',
        action: 'abuse_detected',
      });

      expect(result.success).toBe(true);
      expect(result.event!.delta).toBe(-50);
      expect(result.event!.score_before).toBe(500);
      expect(result.event!.score_after).toBe(450);
      expect(result.score!.negative_events).toBe(1);
    });

    test('clamps score to min 0', async () => {
      const agentId = await createTestAgent(agents, 'min-clamp-agent');

      // Record many abuse events to push below 0
      for (let i = 0; i < 15; i++) {
        await recordReputationEvent(sessions, agents, TEST_APP_ID, {
          agent_id: agentId,
          category: 'violation',
          action: 'abuse_detected', // -50 each
        });
      }

      const result = await getReputationScore(sessions, agents, agentId, TEST_APP_ID);
      expect(result.success).toBe(true);
      expect(result.score!.score).toBe(0);
      expect(result.score!.tier).toBe('untrusted');
    });

    test('clamps score to max 1000', async () => {
      const agentId = await createTestAgent(agents, 'max-clamp-agent');

      // Record many endorsement events to push above 1000
      const sourceAgentId = await createTestAgent(agents, 'endorser-agent');
      for (let i = 0; i < 50; i++) {
        await recordReputationEvent(sessions, agents, TEST_APP_ID, {
          agent_id: agentId,
          category: 'endorsement',
          action: 'endorsement_received', // +20 each
          source_agent_id: sourceAgentId,
        });
      }

      const result = await getReputationScore(sessions, agents, agentId, TEST_APP_ID);
      expect(result.success).toBe(true);
      expect(result.score!.score).toBe(1000);
      expect(result.score!.tier).toBe('excellent');
    });

    test('accumulates multiple events', async () => {
      const agentId = await createTestAgent(agents, 'multi-event-agent');

      await recordReputationEvent(sessions, agents, TEST_APP_ID, {
        agent_id: agentId,
        category: 'verification',
        action: 'challenge_solved', // +5
      });
      await recordReputationEvent(sessions, agents, TEST_APP_ID, {
        agent_id: agentId,
        category: 'attestation',
        action: 'attestation_issued', // +8
      });
      await recordReputationEvent(sessions, agents, TEST_APP_ID, {
        agent_id: agentId,
        category: 'verification',
        action: 'auth_failure', // -5
      });

      const result = await getReputationScore(sessions, agents, agentId, TEST_APP_ID);
      expect(result.success).toBe(true);
      expect(result.score!.score).toBe(508); // 500 + 5 + 8 - 5
      expect(result.score!.event_count).toBe(3);
      expect(result.score!.positive_events).toBe(2);
      expect(result.score!.negative_events).toBe(1);
    });

    test('tracks category scores', async () => {
      const agentId = await createTestAgent(agents, 'category-agent');

      await recordReputationEvent(sessions, agents, TEST_APP_ID, {
        agent_id: agentId,
        category: 'verification',
        action: 'challenge_solved', // +5
      });
      await recordReputationEvent(sessions, agents, TEST_APP_ID, {
        agent_id: agentId,
        category: 'attestation',
        action: 'attestation_issued', // +8
      });

      const result = await getReputationScore(sessions, agents, agentId, TEST_APP_ID);
      expect(result.score!.category_scores.verification).toBe(5);
      expect(result.score!.category_scores.attestation).toBe(8);
      expect(result.score!.category_scores.delegation).toBe(0);
    });

    test('stores event with metadata', async () => {
      const agentId = await createTestAgent(agents, 'metadata-agent');

      const result = await recordReputationEvent(sessions, agents, TEST_APP_ID, {
        agent_id: agentId,
        category: 'session',
        action: 'session_created',
        metadata: { session_id: 'ses_123', context: 'browsing' },
      });

      expect(result.success).toBe(true);
      expect(result.event!.metadata).toEqual({ session_id: 'ses_123', context: 'browsing' });
    });

    test('records endorsement with source agent', async () => {
      const agentId = await createTestAgent(agents, 'endorsed-agent');
      const endorserAgent = await createTestAgent(agents, 'endorser');

      const result = await recordReputationEvent(sessions, agents, TEST_APP_ID, {
        agent_id: agentId,
        category: 'endorsement',
        action: 'endorsement_received',
        source_agent_id: endorserAgent,
      });

      expect(result.success).toBe(true);
      expect(result.event!.source_agent_id).toBe(endorserAgent);
      expect(result.event!.delta).toBe(20);
    });

    test('rejects self-endorsement', async () => {
      const agentId = await createTestAgent(agents, 'self-endorse-agent');

      const result = await recordReputationEvent(sessions, agents, TEST_APP_ID, {
        agent_id: agentId,
        category: 'endorsement',
        action: 'endorsement_received',
        source_agent_id: agentId,
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain('cannot endorse itself');
    });

    test('rejects non-existent agent', async () => {
      const result = await recordReputationEvent(sessions, agents, TEST_APP_ID, {
        agent_id: 'agent_nonexistent',
        category: 'verification',
        action: 'challenge_solved',
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain('not found');
    });

    test('rejects agent from different app', async () => {
      // Create agent under a different app
      const result = await registerTAPAgent(agents, 'app_other', {
        name: 'other-app-agent',
        public_key: VALID_ED25519_KEY,
        signature_algorithm: 'ed25519',
        capabilities: [{ action: 'browse' }],
        trust_level: 'basic',
      });
      const otherAgentId = result.agent!.agent_id;

      const eventResult = await recordReputationEvent(sessions, agents, TEST_APP_ID, {
        agent_id: otherAgentId,
        category: 'verification',
        action: 'challenge_solved',
      });

      expect(eventResult.success).toBe(false);
      expect(eventResult.error).toContain('does not belong');
    });

    test('rejects mismatched category/action', async () => {
      const agentId = await createTestAgent(agents, 'mismatch-agent');

      const result = await recordReputationEvent(sessions, agents, TEST_APP_ID, {
        agent_id: agentId,
        category: 'verification',
        action: 'attestation_issued' as ReputationEventAction,
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain('does not belong to category');
    });

    test('rejects non-existent source agent', async () => {
      const agentId = await createTestAgent(agents, 'bad-source-agent');

      const result = await recordReputationEvent(sessions, agents, TEST_APP_ID, {
        agent_id: agentId,
        category: 'endorsement',
        action: 'endorsement_received',
        source_agent_id: 'agent_nonexistent',
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain('Source agent not found');
    });

    test('handles KV failure gracefully', async () => {
      const agentId = await createTestAgent(agents, 'kv-fail-event-agent');
      sessions.setShouldFail(true);

      const result = await recordReputationEvent(sessions, agents, TEST_APP_ID, {
        agent_id: agentId,
        category: 'verification',
        action: 'challenge_solved',
      });

      expect(result.success).toBe(false);
      expect(result.error).toBe('Internal server error');
    });
  });

  // ============ List Events ============

  describe('listReputationEvents', () => {
    test('returns empty list for agent with no events', async () => {
      const agentId = await createTestAgent(agents, 'no-events-agent');

      const result = await listReputationEvents(sessions, agentId);
      expect(result.success).toBe(true);
      expect(result.events).toEqual([]);
      expect(result.count).toBe(0);
    });

    test('returns events in reverse chronological order', async () => {
      const agentId = await createTestAgent(agents, 'ordered-agent');

      await recordReputationEvent(sessions, agents, TEST_APP_ID, {
        agent_id: agentId,
        category: 'verification',
        action: 'challenge_solved',
      });
      await recordReputationEvent(sessions, agents, TEST_APP_ID, {
        agent_id: agentId,
        category: 'attestation',
        action: 'attestation_issued',
      });
      await recordReputationEvent(sessions, agents, TEST_APP_ID, {
        agent_id: agentId,
        category: 'session',
        action: 'session_created',
      });

      const result = await listReputationEvents(sessions, agentId);
      expect(result.success).toBe(true);
      expect(result.events!.length).toBe(3);
      // Most recent first
      expect(result.events![0].action).toBe('session_created');
      expect(result.events![1].action).toBe('attestation_issued');
      expect(result.events![2].action).toBe('challenge_solved');
    });

    test('filters by category', async () => {
      const agentId = await createTestAgent(agents, 'filter-agent');

      await recordReputationEvent(sessions, agents, TEST_APP_ID, {
        agent_id: agentId,
        category: 'verification',
        action: 'challenge_solved',
      });
      await recordReputationEvent(sessions, agents, TEST_APP_ID, {
        agent_id: agentId,
        category: 'attestation',
        action: 'attestation_issued',
      });
      await recordReputationEvent(sessions, agents, TEST_APP_ID, {
        agent_id: agentId,
        category: 'verification',
        action: 'auth_success',
      });

      const result = await listReputationEvents(sessions, agentId, { category: 'verification' });
      expect(result.success).toBe(true);
      expect(result.events!.length).toBe(2);
      expect(result.events!.every(e => e.category === 'verification')).toBe(true);
    });

    test('respects limit parameter', async () => {
      const agentId = await createTestAgent(agents, 'limit-agent');

      for (let i = 0; i < 10; i++) {
        await recordReputationEvent(sessions, agents, TEST_APP_ID, {
          agent_id: agentId,
          category: 'verification',
          action: 'challenge_solved',
        });
      }

      const result = await listReputationEvents(sessions, agentId, { limit: 3 });
      expect(result.success).toBe(true);
      expect(result.events!.length).toBe(3);
    });

    test('caps limit at 100', async () => {
      const agentId = await createTestAgent(agents, 'cap-agent');

      const result = await listReputationEvents(sessions, agentId, { limit: 500 });
      expect(result.success).toBe(true);
      // Just verify it doesn't crash — no events recorded
      expect(result.events).toEqual([]);
    });
  });

  // ============ Reset Reputation ============

  describe('resetReputation', () => {
    test('resets score to default', async () => {
      const agentId = await createTestAgent(agents, 'reset-agent');

      // Build up score
      for (let i = 0; i < 10; i++) {
        await recordReputationEvent(sessions, agents, TEST_APP_ID, {
          agent_id: agentId,
          category: 'verification',
          action: 'challenge_solved',
        });
      }

      // Verify score is elevated
      let result = await getReputationScore(sessions, agents, agentId, TEST_APP_ID);
      expect(result.score!.score).toBe(550); // 500 + 10*5

      // Reset
      const resetResult = await resetReputation(sessions, agents, agentId, TEST_APP_ID);
      expect(resetResult.success).toBe(true);
      expect(resetResult.score!.score).toBe(500);
      expect(resetResult.score!.tier).toBe('neutral');
      expect(resetResult.score!.event_count).toBe(0);

      // Verify score after reset
      result = await getReputationScore(sessions, agents, agentId, TEST_APP_ID);
      expect(result.score!.score).toBe(500);
      expect(result.score!.event_count).toBe(0);
    });

    test('clears event index', async () => {
      const agentId = await createTestAgent(agents, 'reset-events-agent');

      await recordReputationEvent(sessions, agents, TEST_APP_ID, {
        agent_id: agentId,
        category: 'verification',
        action: 'challenge_solved',
      });

      await resetReputation(sessions, agents, agentId, TEST_APP_ID);

      const events = await listReputationEvents(sessions, agentId);
      expect(events.success).toBe(true);
      expect(events.events).toEqual([]);
    });

    test('rejects non-existent agent', async () => {
      const result = await resetReputation(sessions, agents, 'agent_nonexistent', TEST_APP_ID);
      expect(result.success).toBe(false);
      expect(result.error).toContain('not found');
    });

    test('rejects agent from different app', async () => {
      const otherResult = await registerTAPAgent(agents, 'app_other', {
        name: 'other-reset-agent',
        public_key: VALID_ED25519_KEY,
        signature_algorithm: 'ed25519',
        capabilities: [{ action: 'browse' }],
        trust_level: 'basic',
      });

      const result = await resetReputation(sessions, agents, otherResult.agent!.agent_id, TEST_APP_ID);
      expect(result.success).toBe(false);
      expect(result.error).toContain('does not belong');
    });
  });

  // ============ Score Progression ============

  describe('score progression scenarios', () => {
    test('agent builds trust through consistent positive behavior', async () => {
      const agentId = await createTestAgent(agents, 'good-actor');

      // Solve challenges, create sessions, get attestations
      for (let i = 0; i < 20; i++) {
        await recordReputationEvent(sessions, agents, TEST_APP_ID, {
          agent_id: agentId,
          category: 'verification',
          action: 'challenge_solved', // +5
        });
      }
      for (let i = 0; i < 5; i++) {
        await recordReputationEvent(sessions, agents, TEST_APP_ID, {
          agent_id: agentId,
          category: 'attestation',
          action: 'attestation_issued', // +8
        });
      }

      const result = await getReputationScore(sessions, agents, agentId, TEST_APP_ID);
      // 500 + 20*5 + 5*8 = 500 + 100 + 40 = 640
      expect(result.score!.score).toBe(640);
      expect(result.score!.tier).toBe('good');
    });

    test('agent loses trust through violations', async () => {
      const agentId = await createTestAgent(agents, 'bad-actor');

      // Some good behavior first
      for (let i = 0; i < 5; i++) {
        await recordReputationEvent(sessions, agents, TEST_APP_ID, {
          agent_id: agentId,
          category: 'verification',
          action: 'challenge_solved', // +5
        });
      }

      // Then violations
      await recordReputationEvent(sessions, agents, TEST_APP_ID, {
        agent_id: agentId,
        category: 'violation',
        action: 'abuse_detected', // -50
      });
      await recordReputationEvent(sessions, agents, TEST_APP_ID, {
        agent_id: agentId,
        category: 'violation',
        action: 'rate_limit_exceeded', // -15
      });

      const result = await getReputationScore(sessions, agents, agentId, TEST_APP_ID);
      // 500 + 5*5 - 50 - 15 = 500 + 25 - 65 = 460
      expect(result.score!.score).toBe(460);
      expect(result.score!.tier).toBe('neutral');
    });

    test('endorsement provides significant boost', async () => {
      const agentId = await createTestAgent(agents, 'endorsed-prog');
      const sourceId = await createTestAgent(agents, 'endorser-prog');

      const result = await recordReputationEvent(sessions, agents, TEST_APP_ID, {
        agent_id: agentId,
        category: 'endorsement',
        action: 'endorsement_received', // +20
        source_agent_id: sourceId,
      });

      expect(result.score!.score).toBe(520);
    });

    test('all event types record correctly', async () => {
      const agentId = await createTestAgent(agents, 'all-events-agent');
      const sourceId = await createTestAgent(agents, 'all-events-source');

      const events: RecordEventOptions[] = [
        { agent_id: agentId, category: 'verification', action: 'challenge_solved' },
        { agent_id: agentId, category: 'verification', action: 'challenge_failed' },
        { agent_id: agentId, category: 'verification', action: 'auth_success' },
        { agent_id: agentId, category: 'verification', action: 'auth_failure' },
        { agent_id: agentId, category: 'attestation', action: 'attestation_issued' },
        { agent_id: agentId, category: 'attestation', action: 'attestation_verified' },
        { agent_id: agentId, category: 'attestation', action: 'attestation_revoked' },
        { agent_id: agentId, category: 'delegation', action: 'delegation_granted' },
        { agent_id: agentId, category: 'delegation', action: 'delegation_received' },
        { agent_id: agentId, category: 'delegation', action: 'delegation_revoked' },
        { agent_id: agentId, category: 'session', action: 'session_created' },
        { agent_id: agentId, category: 'session', action: 'session_expired' },
        { agent_id: agentId, category: 'session', action: 'session_terminated' },
        { agent_id: agentId, category: 'violation', action: 'rate_limit_exceeded' },
        { agent_id: agentId, category: 'violation', action: 'invalid_token' },
        { agent_id: agentId, category: 'violation', action: 'abuse_detected' },
        { agent_id: agentId, category: 'endorsement', action: 'endorsement_received', source_agent_id: sourceId },
        { agent_id: agentId, category: 'endorsement', action: 'endorsement_given' },
      ];

      for (const event of events) {
        const result = await recordReputationEvent(sessions, agents, TEST_APP_ID, event);
        expect(result.success).toBe(true);
      }

      const result = await getReputationScore(sessions, agents, agentId, TEST_APP_ID);
      expect(result.success).toBe(true);
      expect(result.score!.event_count).toBe(18);

      // Calculate expected: 5 - 3 + 3 - 5 + 8 + 4 - 10 + 6 + 10 - 8 + 2 + 1 - 5 - 15 - 10 - 50 + 20 + 3 = -44
      expect(result.score!.score).toBe(456); // 500 - 44
    });
  });

  // ============ KV Persistence ============

  describe('KV persistence', () => {
    test('stores reputation score in KV', async () => {
      const agentId = await createTestAgent(agents, 'persist-score-agent');

      await recordReputationEvent(sessions, agents, TEST_APP_ID, {
        agent_id: agentId,
        category: 'verification',
        action: 'challenge_solved',
      });

      const raw = sessions.getRaw(`reputation:${agentId}`);
      expect(raw).toBeDefined();
      const stored = JSON.parse(raw!);
      expect(stored.score).toBe(505);
      expect(stored.agent_id).toBe(agentId);
    });

    test('stores individual events in KV', async () => {
      const agentId = await createTestAgent(agents, 'persist-event-agent');

      const result = await recordReputationEvent(sessions, agents, TEST_APP_ID, {
        agent_id: agentId,
        category: 'verification',
        action: 'challenge_solved',
      });

      const eventId = result.event!.event_id;
      const raw = sessions.getRaw(`reputation_event:${eventId}`);
      expect(raw).toBeDefined();
      const stored = JSON.parse(raw!);
      expect(stored.action).toBe('challenge_solved');
    });

    test('updates event index in KV', async () => {
      const agentId = await createTestAgent(agents, 'persist-index-agent');

      const result1 = await recordReputationEvent(sessions, agents, TEST_APP_ID, {
        agent_id: agentId,
        category: 'verification',
        action: 'challenge_solved',
      });
      const result2 = await recordReputationEvent(sessions, agents, TEST_APP_ID, {
        agent_id: agentId,
        category: 'session',
        action: 'session_created',
      });

      const raw = sessions.getRaw(`reputation_events:${agentId}`);
      expect(raw).toBeDefined();
      const index = JSON.parse(raw!);
      expect(index).toHaveLength(2);
      expect(index).toContain(result1.event!.event_id);
      expect(index).toContain(result2.event!.event_id);
    });
  });
});
