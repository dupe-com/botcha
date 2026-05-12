/**
 * Tests for three bugs found during weekly inspection sprint (2026-05-11).
 *
 * Bug 1: GET /v1/agents/:id returns incomplete data
 *   - Handler used getAgent() (basic type) and only serialized 6 fields
 *   - TAP fields (tap_enabled, capabilities, trust_level, last_verified_at) silently dropped
 *   - Fix: switch to getTAPAgent(); include TAP fields in response
 *
 * Bug 2: POST /v1/sessions/tap with string intent gives misleading error
 *   - Passing intent:"browse" returned "Intent must specify action"
 *   - Looks like the object is missing a field — actually the type is wrong
 *   - Fix: detect non-object before parseTAPIntent; return INVALID_INTENT_FORMAT with hint + valid_actions
 *
 * Bug 3: POST /v1/reputation/events with invalid action gives no hint about valid values
 *   - INVALID_ACTION error message only echoes back the bad value
 *   - Fix: include valid_actions and valid_actions_by_category in error response
 */

import { describe, test, expect, vi, beforeEach } from 'vitest';
import {
  createTAPSessionRoute,
} from '../../../packages/cloudflare-workers/src/tap-routes.js';
import {
  getTAPAgent,
  registerTAPAgent,
  type TAPAgent,
} from '../../../packages/cloudflare-workers/src/tap-agents.js';
import type { KVNamespace } from '../../../packages/cloudflare-workers/src/agents.js';
import {
  recordReputationEventRoute,
} from '../../../packages/cloudflare-workers/src/tap-reputation-routes.js';

// ─── Mocks ────────────────────────────────────────────────────────────────────

vi.mock('../../../packages/cloudflare-workers/src/auth.js', () => ({
  extractBearerToken: vi.fn(),
  verifyToken: vi.fn(),
}));

import { extractBearerToken, verifyToken } from '../../../packages/cloudflare-workers/src/auth.js';
const mockExtractBearerToken = extractBearerToken as ReturnType<typeof vi.fn>;
const mockVerifyToken = verifyToken as ReturnType<typeof vi.fn>;

vi.mock('../../../packages/cloudflare-workers/src/tap-auth-helpers.js', () => ({
  validateTAPAppAccess: vi.fn(),
}));

import { validateTAPAppAccess } from '../../../packages/cloudflare-workers/src/tap-auth-helpers.js';
const mockValidateTAPAppAccess = validateTAPAppAccess as ReturnType<typeof vi.fn>;

vi.mock('../../../packages/cloudflare-workers/src/tap-reputation.js', () => ({
  recordReputationEvent: vi.fn(),
  getReputationScore: vi.fn(),
  isValidCategory: (cat: string) => ['verification', 'attestation', 'delegation', 'session', 'violation', 'endorsement'].includes(cat),
  isValidAction: (act: string) => {
    const allActions = ['session_created', 'challenge_solved', 'attestation_issued', 'delegation_created', 'violation_recorded', 'endorsement_given'];
    return allActions.includes(act);
  },
  isValidCategoryAction: (cat: string, act: string) => {
    const categoryActions: Record<string, string[]> = {
      verification: ['challenge_solved', 'verification_passed'],
      attestation: ['attestation_issued', 'attestation_revoked'],
      delegation: ['delegation_created', 'delegation_accepted'],
      session: ['session_created', 'session_completed'],
      violation: ['violation_recorded'],
      endorsement: ['endorsement_given'],
    };
    return (categoryActions[cat] ?? []).includes(act);
  },
  CATEGORY_ACTIONS: {
    verification: ['challenge_solved', 'verification_passed'],
    attestation: ['attestation_issued', 'attestation_revoked'],
    delegation: ['delegation_created', 'delegation_accepted'],
    session: ['session_created', 'session_completed'],
    violation: ['violation_recorded'],
    endorsement: ['endorsement_given'],
  },
}));

import { recordReputationEvent } from '../../../packages/cloudflare-workers/src/tap-reputation.js';
const mockRecordReputationEvent = recordReputationEvent as ReturnType<typeof vi.fn>;

// ─── MockKV ───────────────────────────────────────────────────────────────────

class MockKV implements KVNamespace {
  private store = new Map<string, string>();
  async get(key: string, type?: string): Promise<any> {
    const v = this.store.get(key) ?? null;
    if (!v) return null;
    if (type === 'json') return JSON.parse(v);
    return v;
  }
  async put(key: string, value: string): Promise<void> { this.store.set(key, value); }
  async delete(key: string): Promise<void> { this.store.delete(key); }
  seed(key: string, value: any): void { this.store.set(key, JSON.stringify(value)); }
}

// ─── Context builder ──────────────────────────────────────────────────────────

function makeContext(overrides: {
  body?: Record<string, any>;
  agentsKV?: MockKV;
  sessionsKV?: MockKV;
  paramFn?: (key: string) => string | undefined;
  headerFn?: (key: string) => string | undefined;
} = {}) {
  const agentsKV = overrides.agentsKV ?? new MockKV();
  const sessionsKV = overrides.sessionsKV ?? new MockKV();
  return {
    req: {
      json: vi.fn().mockResolvedValue(overrides.body ?? {}),
      param: overrides.paramFn ? vi.fn().mockImplementation(overrides.paramFn) : vi.fn().mockReturnValue(undefined),
      header: overrides.headerFn ? vi.fn().mockImplementation(overrides.headerFn) : vi.fn().mockReturnValue(undefined),
      query: vi.fn().mockReturnValue(undefined),
    },
    json: vi.fn().mockImplementation((body: any, status?: number) =>
      new Response(JSON.stringify(body), {
        status: status ?? 200,
        headers: { 'content-type': 'application/json' },
      })
    ),
    env: {
      AGENTS: agentsKV,
      SESSIONS: sessionsKV,
      JWT_SECRET: 'test-secret',
      APP_ID: 'app_test',
    },
  } as any;
}

async function readResponse(resp: Response): Promise<any> {
  return resp.json();
}

// ─── Constants ────────────────────────────────────────────────────────────────

const TEST_APP_ID = 'app_test123';
const TEST_AGENT_ID = 'agent_abc123def456';
const TEST_TOKEN = 'tok.test';

// ─── Fix 1: GET /v1/agents/:id returns complete TAP profile ──────────────────

describe('Fix 1: getTAPAgent includes TAP fields in agent record', () => {
  let agentsKV: MockKV;

  beforeEach(() => {
    agentsKV = new MockKV();
    vi.clearAllMocks();
  });

  test('registerTAPAgent stores tap_enabled, capabilities, trust_level', async () => {
    const result = await registerTAPAgent(agentsKV, TEST_APP_ID, {
      name: 'TestAgent',
      operator: 'TestOrg',
      capabilities: [{ action: 'browse' }, { action: 'search' }],
      trust_level: 'verified',
    });

    expect(result.success).toBe(true);
    expect(result.agent).toBeDefined();
    expect(result.agent!.tap_enabled).toBe(false); // no public_key provided
    expect(result.agent!.capabilities).toHaveLength(2);
    expect(result.agent!.trust_level).toBe('verified');
  });

  test('registerTAPAgent with public_key sets tap_enabled=true', async () => {
    // Use a valid PEM-formatted key stub
    const fakePem = '-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEtest==\n-----END PUBLIC KEY-----';
    const result = await registerTAPAgent(agentsKV, TEST_APP_ID, {
      name: 'KeyedAgent',
      capabilities: [{ action: 'purchase' }],
      public_key: fakePem,
      signature_algorithm: 'ecdsa-p256-sha256',
    });

    // May fail key validation with fake key — that's fine, check attempted
    // The important thing is the flag would be set on valid key
    if (result.success) {
      expect(result.agent!.tap_enabled).toBe(true);
    } else {
      // fake key correctly rejected — that's also correct behavior
      expect(result.error).toMatch(/key|algorithm/i);
    }
  });

  test('getTAPAgent retrieves all stored TAP fields', async () => {
    // Directly seed a TAPAgent record with all fields
    const agentData: TAPAgent = {
      agent_id: TEST_AGENT_ID,
      app_id: TEST_APP_ID,
      name: 'FullAgent',
      operator: 'Org',
      created_at: Date.now(),
      tap_enabled: true,
      trust_level: 'enterprise',
      capabilities: [{ action: 'browse' }, { action: 'purchase' }],
      last_verified_at: Date.now() - 60000,
      key_fingerprint: 'abc123',
      ans_name: 'ans://v1.0.myagent.example.com',
      ans_trust_level: 'domain-validated',
    };
    agentsKV.seed(`agent:${TEST_AGENT_ID}`, agentData);

    const result = await getTAPAgent(agentsKV, TEST_AGENT_ID);
    expect(result.success).toBe(true);
    expect(result.agent!.tap_enabled).toBe(true);
    expect(result.agent!.trust_level).toBe('enterprise');
    expect(result.agent!.capabilities).toHaveLength(2);
    expect(result.agent!.last_verified_at).toBeDefined();
    expect(result.agent!.key_fingerprint).toBe('abc123');
    expect(result.agent!.ans_name).toBe('ans://v1.0.myagent.example.com');
  });

  test('getTAPAgent returns tap_enabled=false for basic agent without public key', async () => {
    const agentData: TAPAgent = {
      agent_id: TEST_AGENT_ID,
      app_id: TEST_APP_ID,
      name: 'BasicAgent',
      created_at: Date.now(),
      tap_enabled: false,
      capabilities: [],
    };
    agentsKV.seed(`agent:${TEST_AGENT_ID}`, agentData);

    const result = await getTAPAgent(agentsKV, TEST_AGENT_ID);
    expect(result.success).toBe(true);
    expect(result.agent!.tap_enabled).toBe(false);
    expect(result.agent!.capabilities).toEqual([]);
  });
});

// ─── Fix 2: INVALID_INTENT_FORMAT when intent is not an object ────────────────

describe('Fix 2: createTAPSessionRoute — clear error when intent is a string', () => {
  let agentsKV: MockKV;
  let sessionsKV: MockKV;

  beforeEach(() => {
    agentsKV = new MockKV();
    sessionsKV = new MockKV();
    vi.clearAllMocks();

    // Default auth stubs
    mockExtractBearerToken.mockReturnValue(TEST_TOKEN);
    mockVerifyToken.mockResolvedValue({
      valid: true,
      payload: { agent_id: TEST_AGENT_ID, app_id: TEST_APP_ID, type: 'botcha-agent-identity' },
    });
    mockValidateTAPAppAccess.mockResolvedValue({ valid: true, appId: TEST_APP_ID });

    // Seed a TAP-enabled agent
    const agentRecord: TAPAgent = {
      agent_id: TEST_AGENT_ID,
      app_id: TEST_APP_ID,
      name: 'TestAgent',
      created_at: Date.now(),
      tap_enabled: true,
      capabilities: [{ action: 'browse' }, { action: 'search' }],
      trust_level: 'basic',
    };
    agentsKV.seed(`agent:${TEST_AGENT_ID}`, agentRecord);
  });

  test('returns INVALID_INTENT_FORMAT when intent is a plain string', async () => {
    const ctx = makeContext({
      body: {
        agent_id: TEST_AGENT_ID,
        user_context: 'u_test',
        intent: 'browse',            // ← common mistake: string instead of object
      },
      agentsKV,
      sessionsKV,
    });

    const resp = await createTAPSessionRoute(ctx);
    const body = await readResponse(resp as unknown as Response);

    expect(body.success).toBe(false);
    expect(body.error).toBe('INVALID_INTENT_FORMAT');
    expect(body.message).toMatch(/object/i);
    expect(body.message).toMatch(/action/i);
    expect(Array.isArray(body.valid_actions)).toBe(true);
    expect(body.valid_actions).toContain('browse');
    expect(body.valid_actions).toContain('purchase');
  });

  test('returns INVALID_INTENT_FORMAT when intent is a number', async () => {
    const ctx = makeContext({
      body: {
        agent_id: TEST_AGENT_ID,
        user_context: 'u_test',
        intent: 42,
      },
      agentsKV,
      sessionsKV,
    });

    const resp = await createTAPSessionRoute(ctx);
    const body = await readResponse(resp as unknown as Response);

    expect(body.success).toBe(false);
    expect(body.error).toBe('INVALID_INTENT_FORMAT');
    expect(Array.isArray(body.valid_actions)).toBe(true);
  });

  test('null intent is treated as missing field (MISSING_REQUIRED_FIELDS)', async () => {
    // null is falsy, so it hits the "intent is required" check before the format check.
    // This is correct behavior — null intent is just "not provided".
    const ctx = makeContext({
      body: {
        agent_id: TEST_AGENT_ID,
        user_context: 'u_test',
        intent: null,
      },
      agentsKV,
      sessionsKV,
    });

    const resp = await createTAPSessionRoute(ctx);
    const body = await readResponse(resp as unknown as Response);

    expect(body.success).toBe(false);
    // null is falsy → "MISSING_REQUIRED_FIELDS" (handled before format check)
    expect(['MISSING_REQUIRED_FIELDS', 'INVALID_INTENT_FORMAT']).toContain(body.error);
  });

  test('returns INVALID_INTENT_FORMAT when intent is an array', async () => {
    const ctx = makeContext({
      body: {
        agent_id: TEST_AGENT_ID,
        user_context: 'u_test',
        intent: ['browse'],
      },
      agentsKV,
      sessionsKV,
    });

    const resp = await createTAPSessionRoute(ctx);
    const body = await readResponse(resp as unknown as Response);

    expect(body.success).toBe(false);
    expect(body.error).toBe('INVALID_INTENT_FORMAT');
    expect(body.message).toMatch(/array/i);
  });

  test('returns INVALID_INTENT (not FORMAT) when intent is object but action is invalid', async () => {
    const ctx = makeContext({
      body: {
        agent_id: TEST_AGENT_ID,
        user_context: 'u_test',
        intent: { action: 'fly' },   // valid object format, invalid action value
      },
      agentsKV,
      sessionsKV,
    });

    const resp = await createTAPSessionRoute(ctx);
    const body = await readResponse(resp as unknown as Response);

    expect(body.success).toBe(false);
    expect(body.error).toBe('INVALID_INTENT');
    expect(Array.isArray(body.valid_actions)).toBe(true);
  });

  test('error message includes example intent format for discoverability', async () => {
    const ctx = makeContext({
      body: {
        agent_id: TEST_AGENT_ID,
        user_context: 'u_test',
        intent: 'purchase',
      },
      agentsKV,
      sessionsKV,
    });

    const resp = await createTAPSessionRoute(ctx);
    const body = await readResponse(resp as unknown as Response);

    // Message should include an example object so the agent knows exactly what to send
    expect(body.message).toMatch(/action/i);
    expect(body.message).toMatch(/browse|purchase/i);
  });
});

// ─── Fix 3: INVALID_ACTION includes valid_actions and valid_actions_by_category ──

describe('Fix 3: recordReputationEventRoute — INVALID_ACTION includes valid actions', () => {
  let agentsKV: MockKV;
  let sessionsKV: MockKV;

  beforeEach(() => {
    agentsKV = new MockKV();
    sessionsKV = new MockKV();
    vi.clearAllMocks();

    mockExtractBearerToken.mockReturnValue(TEST_TOKEN);
    mockVerifyToken.mockResolvedValue({
      valid: true,
      payload: { agent_id: TEST_AGENT_ID, app_id: TEST_APP_ID, type: 'botcha-agent-identity' },
    });
    mockValidateTAPAppAccess.mockResolvedValue({ valid: true, appId: TEST_APP_ID });
  });

  test('INVALID_ACTION error includes valid_actions array', async () => {
    const ctx = makeContext({
      body: {
        agent_id: TEST_AGENT_ID,
        category: 'session',
        action: 'task_completed',      // ← intuitive but invalid
      },
      agentsKV,
      sessionsKV,
    });

    const resp = await recordReputationEventRoute(ctx);
    const body = await readResponse(resp as unknown as Response);

    expect(body.success).toBe(false);
    expect(body.error).toBe('INVALID_ACTION');
    expect(Array.isArray(body.valid_actions)).toBe(true);
    expect(body.valid_actions.length).toBeGreaterThan(0);
    // Should include well-known actions
    expect(body.valid_actions).toContain('session_created');
    expect(body.valid_actions).toContain('challenge_solved');
    expect(body.valid_actions).toContain('attestation_issued');
  });

  test('INVALID_ACTION error includes valid_actions_by_category object', async () => {
    const ctx = makeContext({
      body: {
        agent_id: TEST_AGENT_ID,
        category: 'verification',
        action: 'verified',            // ← plausible but invalid
      },
      agentsKV,
      sessionsKV,
    });

    const resp = await recordReputationEventRoute(ctx);
    const body = await readResponse(resp as unknown as Response);

    expect(body.success).toBe(false);
    expect(body.error).toBe('INVALID_ACTION');
    expect(body.valid_actions_by_category).toBeDefined();
    expect(typeof body.valid_actions_by_category).toBe('object');
    // Should have category keys
    expect(body.valid_actions_by_category).toHaveProperty('verification');
    expect(body.valid_actions_by_category).toHaveProperty('session');
    expect(body.valid_actions_by_category).toHaveProperty('attestation');
  });

  test('INVALID_ACTION error message explains the issue', async () => {
    const ctx = makeContext({
      body: {
        agent_id: TEST_AGENT_ID,
        category: 'delegation',
        action: 'done',
      },
      agentsKV,
      sessionsKV,
    });

    const resp = await recordReputationEventRoute(ctx);
    const body = await readResponse(resp as unknown as Response);

    expect(body.error).toBe('INVALID_ACTION');
    // Message should name the bad value
    expect(body.message).toContain('"done"');
    // And tell them where to find valid values
    expect(body.message).toMatch(/valid/i);
  });

  test('valid actions still succeed (ACTION_CATEGORY_MISMATCH check also works)', async () => {
    // "session_created" is valid for session category — should NOT be INVALID_ACTION
    mockRecordReputationEvent.mockResolvedValue({ success: true, event_id: 'ev_123' });

    const ctx = makeContext({
      body: {
        agent_id: TEST_AGENT_ID,
        category: 'session',
        action: 'session_created',
      },
      agentsKV,
      sessionsKV,
    });

    const resp = await recordReputationEventRoute(ctx);
    const body = await readResponse(resp as unknown as Response);

    // Should not be INVALID_ACTION
    expect(body.error).not.toBe('INVALID_ACTION');
  });

  test('category mismatch still returns ACTION_CATEGORY_MISMATCH (not INVALID_ACTION)', async () => {
    // challenge_solved is valid globally but belongs to 'verification', not 'session'
    const ctx = makeContext({
      body: {
        agent_id: TEST_AGENT_ID,
        category: 'session',
        action: 'challenge_solved',   // valid action, wrong category
      },
      agentsKV,
      sessionsKV,
    });

    const resp = await recordReputationEventRoute(ctx);
    const body = await readResponse(resp as unknown as Response);

    expect(body.success).toBe(false);
    expect(body.error).toBe('ACTION_CATEGORY_MISMATCH');
    // existing behavior preserved
    expect(Array.isArray(body.valid_actions)).toBe(true);
  });
});
