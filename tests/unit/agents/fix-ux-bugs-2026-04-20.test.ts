/**
 * Regression tests for UX bugs found during weekly inspection sprint (2026-04-20).
 *
 * Bug 1: GET /v1/agents/me rejected agent-identity tokens
 *   - verifyToken called with undefined options (defaulted to botcha-verified only)
 *   - Fix: pass { allowedTypes: ['botcha-verified', 'botcha-agent-identity'] }
 *
 * Bug 2: GET /v1/agents/:id/reputation alias route returned MISSING_AGENT_ID
 *   - getReputationRoute reads c.req.param('agent_id') but alias route uses :id param
 *   - Fix: try both c.req.param('agent_id') and c.req.param('id')
 *
 * Bug 3: POST /v1/delegations — string capabilities gave misleading error
 *   - Passing ["browse", "search"] returned "Invalid capability action. Valid: browse..."
 *   - Actual issue: capabilities must be [{action:"browse"}] objects, not plain strings
 *   - Fix: normalize string → {action: string} before validation; clearer error message
 */

import { describe, test, expect, vi, beforeEach } from 'vitest';
import { SignJWT } from 'jose';
import { verifyToken } from '../../../packages/cloudflare-workers/src/auth.js';
import {
  createDelegationRoute,
} from '../../../packages/cloudflare-workers/src/tap-delegation-routes.js';
import {
  getReputationRoute,
} from '../../../packages/cloudflare-workers/src/tap-reputation-routes.js';

// ─── Mocks ────────────────────────────────────────────────────────────────────

vi.mock('../../../packages/cloudflare-workers/src/tap-auth-helpers.js', () => ({
  validateTAPAppAccess: vi.fn(),
}));

import { validateTAPAppAccess } from '../../../packages/cloudflare-workers/src/tap-auth-helpers.js';
const mockValidateTAPAppAccess = validateTAPAppAccess as ReturnType<typeof vi.fn>;

vi.mock('../../../packages/cloudflare-workers/src/tap-delegation.js', () => ({
  createDelegation: vi.fn(),
}));

import { createDelegation } from '../../../packages/cloudflare-workers/src/tap-delegation.js';
const mockCreateDelegation = createDelegation as ReturnType<typeof vi.fn>;

vi.mock('../../../packages/cloudflare-workers/src/tap-reputation.js', () => ({
  getReputationScore: vi.fn(),
}));

import { getReputationScore } from '../../../packages/cloudflare-workers/src/tap-reputation.js';
const mockGetReputationScore = getReputationScore as ReturnType<typeof vi.fn>;

// ─── Helpers ──────────────────────────────────────────────────────────────────

const SECRET = 'test-secret-key-12345';
const TEST_APP_ID = 'app_test123';
const TEST_AGENT_ID = 'agent_abc123';

class MockKV {
  private store = new Map<string, string>();
  async get(key: string) { return this.store.get(key) ?? null; }
  async put(key: string, value: string) { this.store.set(key, value); }
  async delete(key: string) { this.store.delete(key); }
}

async function makeAgentIdentityToken(agentId: string, appId: string) {
  return new SignJWT({ type: 'botcha-agent-identity', agent_id: agentId, app_id: appId })
    .setProtectedHeader({ alg: 'HS256' })
    .setSubject(agentId)
    .setIssuer('botcha.ai')
    .setIssuedAt()
    .setExpirationTime('1h')
    .setJti('jti-' + Math.random())
    .sign(new TextEncoder().encode(SECRET));
}

function createMockContext(overrides: {
  paramFn?: (key: string) => string | undefined;
  body?: Record<string, any>;
  agentsKV?: MockKV;
  sessionsKV?: MockKV;
} = {}) {
  return {
    req: {
      json: vi.fn().mockResolvedValue(overrides.body ?? {}),
      param: vi.fn().mockImplementation(overrides.paramFn ?? (() => undefined)),
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
      AGENTS: overrides.agentsKV ?? new MockKV(),
      SESSIONS: overrides.sessionsKV ?? new MockKV(),
      JWT_SECRET: SECRET,
    },
  } as any;
}

// ─── Bug 1: GET /v1/agents/me — agent-identity token acceptance ───────────────

describe('Bug 1 fix: /v1/agents/me accepts agent-identity tokens', () => {
  test('verifyToken with allowedTypes accepts botcha-agent-identity', async () => {
    const token = await makeAgentIdentityToken(TEST_AGENT_ID, TEST_APP_ID);
    const result = await verifyToken(token, SECRET, undefined, {
      allowedTypes: ['botcha-verified', 'botcha-agent-identity'],
    });
    expect(result.valid).toBe(true);
    expect(result.payload?.type).toBe('botcha-agent-identity');
    expect(result.payload?.agent_id).toBe(TEST_AGENT_ID);
  });

  test('verifyToken WITHOUT allowedTypes REJECTS botcha-agent-identity (regression guard)', async () => {
    const token = await makeAgentIdentityToken(TEST_AGENT_ID, TEST_APP_ID);
    // Default (undefined options) only allows botcha-verified — agent-identity must be explicitly allowed
    const result = await verifyToken(token, SECRET, undefined, undefined);
    expect(result.valid).toBe(false);
  });

  test('the agents/me fix uses allowedTypes — agent_id is extractable from token', async () => {
    const token = await makeAgentIdentityToken(TEST_AGENT_ID, TEST_APP_ID);
    const result = await verifyToken(token, SECRET, undefined, {
      allowedTypes: ['botcha-verified', 'botcha-agent-identity'],
    });
    // The me route uses result.payload?.agent_id to look up the agent
    expect(result.payload?.agent_id).toBe(TEST_AGENT_ID);
  });
});

// ─── Bug 2: GET /v1/agents/:id/reputation alias route ────────────────────────

describe('Bug 2 fix: getReputationRoute reads both :agent_id and :id params', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockValidateTAPAppAccess.mockResolvedValue({
      valid: true,
      appId: TEST_APP_ID,
    });
    mockGetReputationScore.mockResolvedValue({
      success: true,
      score: {
        agent_id: TEST_AGENT_ID,
        app_id: TEST_APP_ID,
        score: 500,
        tier: 'neutral',
        event_count: 0,
        positive_events: 0,
        negative_events: 0,
        last_event_at: null,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
        category_scores: {},
      },
    });
  });

  test('works with :agent_id param (primary route /v1/reputation/:agent_id)', async () => {
    const ctx = createMockContext({
      paramFn: (key) => (key === 'agent_id' ? TEST_AGENT_ID : undefined),
    });
    const response = await getReputationRoute(ctx);
    const data = await response.json();
    expect(data.success).toBe(true);
    expect(data.agent_id).toBe(TEST_AGENT_ID);
  });

  test('works with :id param (alias route /v1/agents/:id/reputation)', async () => {
    const ctx = createMockContext({
      // The alias route provides :id, NOT :agent_id
      paramFn: (key) => (key === 'id' ? TEST_AGENT_ID : undefined),
    });
    const response = await getReputationRoute(ctx);
    const data = await response.json();
    // Before fix: data.success === false, error === 'MISSING_AGENT_ID'
    // After fix: resolves correctly
    expect(data.success).toBe(true);
    expect(data.agent_id).toBe(TEST_AGENT_ID);
  });

  test('returns MISSING_AGENT_ID when neither param is present', async () => {
    const ctx = createMockContext({
      paramFn: () => undefined,
    });
    const response = await getReputationRoute(ctx);
    const data = await response.json();
    expect(data.success).toBe(false);
    expect(data.error).toBe('MISSING_AGENT_ID');
  });
});

// ─── Bug 3: POST /v1/delegations — string capability normalization ────────────

describe('Bug 3 fix: delegation accepts string capabilities like ["browse", "search"]', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockValidateTAPAppAccess.mockResolvedValue({
      valid: true,
      appId: TEST_APP_ID,
    });
  });

  test('rejects missing capabilities with MISSING_CAPABILITIES', async () => {
    const ctx = createMockContext({
      body: { grantor_id: TEST_AGENT_ID, grantee_id: 'agent_other' },
    });
    const response = await createDelegationRoute(ctx);
    const data = await response.json();
    expect(data.success).toBe(false);
    expect(data.error).toBe('MISSING_CAPABILITIES');
  });

  test('normalizes string capabilities to objects before validation', async () => {
    mockCreateDelegation.mockResolvedValue({
      success: true,
      delegation: {
        delegation_id: 'del_abc',
        grantor_id: TEST_AGENT_ID,
        grantee_id: 'agent_other',
        capabilities: [{ action: 'browse' }, { action: 'search' }],
        depth: 1,
        created_at: Date.now(),
        expires_at: Date.now() + 3600000,
        revoked: false,
      },
    });

    const ctx = createMockContext({
      body: {
        grantor_id: TEST_AGENT_ID,
        grantee_id: 'agent_other',
        capabilities: ['browse', 'search'], // ← plain strings, not objects
      },
    });
    const response = await createDelegationRoute(ctx);
    const data = await response.json();

    // Before fix: INVALID_CAPABILITY with confusing message
    // After fix: normalization converts to [{action:'browse'}, {action:'search'}] and proceeds
    expect(data.error).not.toBe('INVALID_CAPABILITY');

    // createDelegation should have been called with normalized objects
    expect(mockCreateDelegation).toHaveBeenCalled();
    const callOptions = mockCreateDelegation.mock.calls[0][3]; // 4th arg is options
    expect(callOptions.capabilities).toEqual([{ action: 'browse' }, { action: 'search' }]);
  });

  test('rejects truly invalid capability action with clear error', async () => {
    const ctx = createMockContext({
      body: {
        grantor_id: TEST_AGENT_ID,
        grantee_id: 'agent_other',
        capabilities: ['fly', 'teleport'], // not valid TAP actions
      },
    });
    const response = await createDelegationRoute(ctx);
    const data = await response.json();
    expect(data.success).toBe(false);
    expect(data.error).toBe('INVALID_CAPABILITY');
    // Error message should name the bad action AND clarify accepted formats
    expect(data.message).toContain('fly');
    expect(data.message).toContain('{\"action\"');
  });

  test('still accepts object-format capabilities (no regression)', async () => {
    mockCreateDelegation.mockResolvedValue({
      success: true,
      delegation: {
        delegation_id: 'del_xyz',
        grantor_id: TEST_AGENT_ID,
        grantee_id: 'agent_other',
        capabilities: [{ action: 'browse' }],
        depth: 1,
        created_at: Date.now(),
        expires_at: Date.now() + 3600000,
        revoked: false,
      },
    });

    const ctx = createMockContext({
      body: {
        grantor_id: TEST_AGENT_ID,
        grantee_id: 'agent_other',
        capabilities: [{ action: 'browse' }], // ← object format, existing style
      },
    });
    const response = await createDelegationRoute(ctx);
    const data = await response.json();
    expect(data.error).not.toBe('INVALID_CAPABILITY');
    expect(mockCreateDelegation).toHaveBeenCalled();
  });
});
