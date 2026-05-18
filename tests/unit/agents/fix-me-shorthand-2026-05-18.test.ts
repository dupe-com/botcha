/**
 * Regression tests for "me" shorthand support on TAP sub-routes (2026-05-18).
 *
 * Bug: GET /v1/agents/me/tap and GET /v1/agents/me/reputation both returned
 *      AGENT_NOT_FOUND because the literal string "me" was passed to the KV
 *      lookup instead of being expanded to the authenticated agent's ID.
 *
 * Fix:
 *   - getTAPAgentRoute: if rawId === 'me', call validateTAPAppAccess and use
 *     appAccess.agentId
 *   - getReputationRoute: if rawId === 'me', expand to appAccess.agentId from
 *     the already-called validateTAPAppAccess result
 *
 * Both routes already require auth; the fix reuses the existing token to
 * extract the caller's agent_id rather than adding a second auth call.
 */

import { describe, test, expect, vi, beforeEach } from 'vitest';

// ─── Mock tap-auth-helpers before importing route handlers ──────────────────

vi.mock('../../../packages/cloudflare-workers/src/tap-auth-helpers.js', () => ({
  validateTAPAppAccess: vi.fn(),
}));

import { validateTAPAppAccess } from '../../../packages/cloudflare-workers/src/tap-auth-helpers.js';
const mockValidateTAPAppAccess = validateTAPAppAccess as ReturnType<typeof vi.fn>;

// ─── Mock KV stores used by route handlers ───────────────────────────────────

vi.mock('../../../packages/cloudflare-workers/src/tap-agents.js', () => ({
  getTAPAgent: vi.fn(),
  generateKeyFingerprint: vi.fn().mockResolvedValue('deadbeef'),
}));

import { getTAPAgent } from '../../../packages/cloudflare-workers/src/tap-agents.js';
const mockGetTAPAgent = getTAPAgent as ReturnType<typeof vi.fn>;

vi.mock('../../../packages/cloudflare-workers/src/tap-reputation.js', () => ({
  getReputationScore: vi.fn(),
}));

import { getReputationScore } from '../../../packages/cloudflare-workers/src/tap-reputation.js';
const mockGetReputationScore = getReputationScore as ReturnType<typeof vi.fn>;

// ─── Import the route handlers under test ───────────────────────────────────

import { getTAPAgentRoute } from '../../../packages/cloudflare-workers/src/tap-routes.js';
import { getReputationRoute } from '../../../packages/cloudflare-workers/src/tap-reputation-routes.js';

// ─── Constants ───────────────────────────────────────────────────────────────

const TEST_APP_ID = 'app_testme123';
const TEST_AGENT_ID = 'agent_testme456';
const SECRET = 'test-secret-key-12345';

// ─── Helper: minimal Hono context mock ──────────────────────────────────────

class MockKV {
  private store = new Map<string, string>();
  async get(key: string) { return this.store.get(key) ?? null; }
  async put(key: string, value: string) { this.store.set(key, value); }
  async delete(key: string) { this.store.delete(key); }
}

function createMockContext(paramValue: string, extraEnv: Record<string, any> = {}) {
  return {
    req: {
      json: vi.fn().mockResolvedValue({}),
      param: vi.fn().mockImplementation((key: string) =>
        key === 'id' ? paramValue : undefined
      ),
      header: vi.fn().mockReturnValue(undefined),
      query: vi.fn().mockReturnValue(undefined),
    },
    json: vi.fn().mockImplementation((body: any, status?: number) =>
      new Response(JSON.stringify(body), {
        status: status ?? 200,
        headers: { 'content-type': 'application/json' },
      })
    ),
    env: {
      AGENTS: new MockKV(),
      SESSIONS: new MockKV(),
      JWT_SECRET: SECRET,
      ...extraEnv,
    },
  } as any;
}

async function parseJson(response: Response) {
  return response.json();
}

// ─── getTAPAgentRoute — "me" shorthand ───────────────────────────────────────

describe('getTAPAgentRoute: "me" shorthand', () => {
  const fakeAgent = {
    agent_id: TEST_AGENT_ID,
    app_id: TEST_APP_ID,
    name: 'Test Agent',
    operator: 'Tester',
    created_at: Date.now(),
    tap_enabled: true,
    trust_level: 'basic',
    capabilities: [{ action: 'browse' }],
    signature_algorithm: 'ed25519',
    last_verified_at: Date.now(),
    public_key: 'fakepublickey==',
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  test('expands "me" to the authenticated agent_id from the token', async () => {
    mockValidateTAPAppAccess.mockResolvedValue({
      valid: true,
      appId: TEST_APP_ID,
      agentId: TEST_AGENT_ID,
    });
    mockGetTAPAgent.mockResolvedValue({ success: true, agent: fakeAgent });

    const ctx = createMockContext('me');
    const res = await getTAPAgentRoute(ctx);
    const body = await parseJson(res);

    expect(body.success).toBe(true);
    expect(body.agent_id).toBe(TEST_AGENT_ID);
    // Verify it looked up the real agent_id, not the literal "me"
    expect(mockGetTAPAgent).toHaveBeenCalledWith(expect.anything(), TEST_AGENT_ID);
  });

  test('returns 401 when no token is provided with "me"', async () => {
    mockValidateTAPAppAccess.mockResolvedValue({
      valid: false,
      error: 'UNAUTHORIZED',
      status: 401,
    });

    const ctx = createMockContext('me');
    const res = await getTAPAgentRoute(ctx);
    const body = await parseJson(res);

    expect(res.status).toBe(401);
    expect(body.success).toBe(false);
    expect(body.error).toBe('UNAUTHORIZED');
    // Should NOT have called getTAPAgent at all
    expect(mockGetTAPAgent).not.toHaveBeenCalled();
  });

  test('returns 401 when token is valid but carries no agent_id', async () => {
    // e.g. an app-level token (no agent_id claim)
    mockValidateTAPAppAccess.mockResolvedValue({
      valid: true,
      appId: TEST_APP_ID,
      agentId: undefined,
    });

    const ctx = createMockContext('me');
    const res = await getTAPAgentRoute(ctx);
    const body = await parseJson(res);

    expect(res.status).toBe(401);
    expect(body.success).toBe(false);
    expect(body.error).toBe('UNAUTHORIZED');
    expect(mockGetTAPAgent).not.toHaveBeenCalled();
  });

  test('still works with an explicit agent_id (non-"me" path unaffected)', async () => {
    mockGetTAPAgent.mockResolvedValue({ success: true, agent: fakeAgent });

    const ctx = createMockContext(TEST_AGENT_ID);
    const res = await getTAPAgentRoute(ctx);
    const body = await parseJson(res);

    expect(body.success).toBe(true);
    // validateTAPAppAccess should NOT have been called for a regular ID
    expect(mockValidateTAPAppAccess).not.toHaveBeenCalled();
    expect(mockGetTAPAgent).toHaveBeenCalledWith(expect.anything(), TEST_AGENT_ID);
  });
});

// ─── getReputationRoute — "me" shorthand ────────────────────────────────────

describe('getReputationRoute: "me" shorthand', () => {
  const fakeScore = {
    agent_id: TEST_AGENT_ID,
    app_id: TEST_APP_ID,
    score: 500,
    tier: 'neutral',
    event_count: 3,
    positive_events: 3,
    negative_events: 0,
    last_event_at: new Date().toISOString(),
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    category_scores: { verification: 5 },
  };

  function createRepMockContext(paramValue: string) {
    return {
      req: {
        json: vi.fn().mockResolvedValue({}),
        param: vi.fn().mockImplementation((key: string) => {
          if (key === 'id') return paramValue;
          if (key === 'agent_id') return undefined;
          return undefined;
        }),
        header: vi.fn().mockReturnValue(undefined),
        query: vi.fn().mockReturnValue(undefined),
      },
      json: vi.fn().mockImplementation((body: any, status?: number) =>
        new Response(JSON.stringify(body), {
          status: status ?? 200,
          headers: { 'content-type': 'application/json' },
        })
      ),
      env: {
        AGENTS: new MockKV(),
        SESSIONS: new MockKV(),
        JWT_SECRET: SECRET,
      },
    } as any;
  }

  beforeEach(() => {
    vi.clearAllMocks();
  });

  test('expands "me" to the authenticated agent_id from the token', async () => {
    mockValidateTAPAppAccess.mockResolvedValue({
      valid: true,
      appId: TEST_APP_ID,
      agentId: TEST_AGENT_ID,
    });
    mockGetReputationScore.mockResolvedValue({ success: true, score: fakeScore });

    const ctx = createRepMockContext('me');
    const res = await getReputationRoute(ctx);
    const body = await parseJson(res);

    expect(body.success).toBe(true);
    expect(body.agent_id).toBe(TEST_AGENT_ID);
    expect(mockGetReputationScore).toHaveBeenCalledWith(
      expect.anything(),
      expect.anything(),
      TEST_AGENT_ID,
      TEST_APP_ID
    );
  });

  test('returns 401 when token is valid but carries no agent_id', async () => {
    mockValidateTAPAppAccess.mockResolvedValue({
      valid: true,
      appId: TEST_APP_ID,
      agentId: undefined,  // no agent claim in token
    });

    const ctx = createRepMockContext('me');
    const res = await getReputationRoute(ctx);
    const body = await parseJson(res);

    expect(res.status).toBe(401);
    expect(body.success).toBe(false);
    expect(body.error).toBe('UNAUTHORIZED');
    expect(mockGetReputationScore).not.toHaveBeenCalled();
  });

  test('still works with an explicit :id param (via /v1/agents/:id/reputation alias)', async () => {
    mockValidateTAPAppAccess.mockResolvedValue({
      valid: true,
      appId: TEST_APP_ID,
      agentId: TEST_AGENT_ID,
    });
    mockGetReputationScore.mockResolvedValue({ success: true, score: fakeScore });

    const ctx = createRepMockContext(TEST_AGENT_ID);
    const res = await getReputationRoute(ctx);
    const body = await parseJson(res);

    expect(body.success).toBe(true);
    // Should use the explicit id, not the token's agent_id
    expect(mockGetReputationScore).toHaveBeenCalledWith(
      expect.anything(),
      expect.anything(),
      TEST_AGENT_ID,
      TEST_APP_ID
    );
  });

  test('returns 401 when no token provided with "me"', async () => {
    mockValidateTAPAppAccess.mockResolvedValue({
      valid: false,
      error: 'UNAUTHORIZED',
      status: 401,
    });

    const ctx = createRepMockContext('me');
    const res = await getReputationRoute(ctx);
    const body = await parseJson(res);

    expect(res.status).toBe(401);
    expect(body.success).toBe(false);
    expect(mockGetReputationScore).not.toHaveBeenCalled();
  });
});
