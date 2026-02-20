import { describe, test, expect, vi, beforeEach } from 'vitest';
import {
  registerTAPAgentRoute,
  getTAPAgentRoute,
  listTAPAgentsRoute,
  createTAPSessionRoute,
  getTAPSessionRoute,
  rotateKeyRoute
} from '../../../packages/cloudflare-workers/src/tap-routes.js';
import type { TAPAgent } from '../../../packages/cloudflare-workers/src/tap-agents.js';
import type { KVNamespace } from '../../../packages/cloudflare-workers/src/agents.js';

// Mock the auth module
vi.mock('../../../packages/cloudflare-workers/src/auth.js', () => ({
  extractBearerToken: vi.fn(),
  verifyToken: vi.fn(),
}));

// Mock tap-verify to keep parseTAPIntent real but allow controlling verifyHTTPMessageSignature.
// The "real" crypto verification is tested in tap-verify.test.ts; here we test route logic.
vi.mock('../../../packages/cloudflare-workers/src/tap-verify.js', async (importOriginal) => {
  const original = await importOriginal<typeof import('../../../packages/cloudflare-workers/src/tap-verify.js')>();
  return {
    ...original,
    // Default: return valid so existing session-logic tests keep passing.
    // Override per-test in the RFC 9421 enforcement describe block.
    verifyHTTPMessageSignature: vi.fn().mockResolvedValue({ valid: true }),
  };
});

// Import mocked functions
import { extractBearerToken, verifyToken } from '../../../packages/cloudflare-workers/src/auth.js';
import { verifyHTTPMessageSignature } from '../../../packages/cloudflare-workers/src/tap-verify.js';

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

  // Helper to seed test data
  seed(key: string, value: any): void {
    this.store.set(key, JSON.stringify(value));
  }

  // Helper to get raw value for debugging
  getRaw(key: string): string | undefined {
    return this.store.get(key);
  }

  // Helper to clear all data
  clear(): void {
    this.store.clear();
  }
}

// Helper to create a mock Hono Context
// rawHeaders: optional key-value pairs that populate req.raw.headers for RFC 9421 tests
function createMockContext(overrides: any = {}) {
  const agentsKV = overrides.agentsKV || new MockKV();
  const sessionsKV = overrides.sessionsKV || new MockKV();
  const noncesKV = overrides.noncesKV || new MockKV();

  // Build a minimal Headers-like object from the rawHeaders map (or empty)
  const rawHeadersMap: Record<string, string> = overrides.rawHeaders || {};
  const mockHeaders = {
    forEach: (cb: (value: string, key: string) => void) => {
      for (const [k, v] of Object.entries(rawHeadersMap)) {
        cb(v, k);
      }
    },
    get: (key: string) => rawHeadersMap[key.toLowerCase()] ?? null,
  };

  return {
    req: {
      json: overrides.json || vi.fn().mockResolvedValue({}),
      query: overrides.query || vi.fn().mockReturnValue(undefined),
      param: overrides.param || vi.fn().mockReturnValue(undefined),
      header: overrides.header || vi.fn().mockReturnValue(undefined),
      method: overrides.method || 'POST',
      url: overrides.url || 'https://botcha.ai/v1/sessions/tap',
      raw: {
        headers: mockHeaders,
      },
    },
    json: vi.fn().mockImplementation((body, status) => {
      return new Response(JSON.stringify(body), { 
        status: status || 200,
        headers: { 'content-type': 'application/json' }
      });
    }),
    env: { 
      AGENTS: agentsKV, 
      SESSIONS: sessionsKV, 
      NONCES: noncesKV,
      JWT_SECRET: 'test-secret' 
    }
  } as any;
}

const TEST_APP_ID = 'app_test123456';
const TEST_AGENT_ID = 'agent_test12345678';
const TEST_SESSION_ID = 'session_test12345678';

describe('TAP Routes - registerTAPAgentRoute', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(extractBearerToken).mockReturnValue('mock-jwt-token');
    vi.mocked(verifyToken).mockResolvedValue({
      valid: true,
      payload: { app_id: TEST_APP_ID } as any,
    });
  });

  test('should register agent successfully with query param app_id', async () => {
    const mockContext = createMockContext({
      query: vi.fn((key: string) => key === 'app_id' ? TEST_APP_ID : undefined),
      json: vi.fn().mockResolvedValue({
        name: 'TestAgent',
        operator: 'test@example.com',
        version: '1.0.0',
      }),
    });

    const response = await registerTAPAgentRoute(mockContext);
    const data = await response.json();

    expect(response.status).toBe(201);
    expect(data.success).toBe(true);
    expect(data.agent_id).toBeDefined();
    expect(data.name).toBe('TestAgent');
    expect(data.operator).toBe('test@example.com');
    expect(data.version).toBe('1.0.0');
    expect(data.app_id).toBe(TEST_APP_ID);
    expect(data.tap_enabled).toBe(false);
    expect(data.trust_level).toBe('basic');
  });

  test('should register agent with JWT token authentication', async () => {
    vi.mocked(extractBearerToken).mockReturnValue('mock-jwt-token');
    vi.mocked(verifyToken).mockResolvedValue({
      valid: true,
      payload: { app_id: TEST_APP_ID } as any,
    });

    const mockContext = createMockContext({
      header: vi.fn((key: string) => key === 'authorization' ? 'Bearer mock-jwt-token' : undefined),
      json: vi.fn().mockResolvedValue({
        name: 'JWTAgent',
      }),
    });

    const response = await registerTAPAgentRoute(mockContext);
    const data = await response.json();

    expect(response.status).toBe(201);
    expect(data.success).toBe(true);
    expect(data.app_id).toBe(TEST_APP_ID);
    expect(vi.mocked(extractBearerToken)).toHaveBeenCalledWith('Bearer mock-jwt-token');
  });

  test('should register TAP-enabled agent with public key and capabilities', async () => {
    const mockContext = createMockContext({
      query: vi.fn((key: string) => key === 'app_id' ? TEST_APP_ID : undefined),
      json: vi.fn().mockResolvedValue({
        name: 'TAPAgent',
        // Must be > 100 chars for validation
        public_key: '-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEtestkeytestkeytestkeytestkeytestkeytestkeytestkeytestkey==\n-----END PUBLIC KEY-----',
        signature_algorithm: 'ecdsa-p256-sha256',
        capabilities: [
          { action: 'browse', scope: ['products'] },
          { action: 'compare', scope: ['prices'] }
        ],
        trust_level: 'verified',
        issuer: 'test-issuer'
      }),
    });

    const response = await registerTAPAgentRoute(mockContext);
    const data = await response.json();

    expect(response.status).toBe(201);
    expect(data.success).toBe(true);
    expect(data.tap_enabled).toBe(true);
    expect(data.trust_level).toBe('verified');
    expect(data.capabilities).toHaveLength(2);
    expect(data.signature_algorithm).toBe('ecdsa-p256-sha256');
    expect(data.issuer).toBe('test-issuer');
    expect(data.has_public_key).toBe(true);
    expect(data.key_fingerprint).toBeDefined();
  });

  test('should return 401 when no authentication provided', async () => {
    vi.mocked(extractBearerToken).mockReturnValue(null);
    
    const mockContext = createMockContext({
      header: vi.fn(() => undefined),
      query: vi.fn(() => undefined),
      json: vi.fn().mockResolvedValue({ name: 'TestAgent' }),
    });

    const response = await registerTAPAgentRoute(mockContext);
    const data = await response.json();

    expect(response.status).toBe(401);
    expect(data.success).toBe(false);
    expect(data.error).toBe('UNAUTHORIZED');
  });

  test('should return 400 when name is missing', async () => {
    const mockContext = createMockContext({
      query: vi.fn((key: string) => key === 'app_id' ? TEST_APP_ID : undefined),
      json: vi.fn().mockResolvedValue({ version: '1.0.0' }),
    });

    const response = await registerTAPAgentRoute(mockContext);
    const data = await response.json();

    expect(response.status).toBe(400);
    expect(data.success).toBe(false);
    expect(data.error).toBe('INVALID_REQUEST');
    expect(data.message).toContain('name is required');
  });

  test('should return 400 when public_key provided without signature_algorithm', async () => {
    const mockContext = createMockContext({
      query: vi.fn((key: string) => key === 'app_id' ? TEST_APP_ID : undefined),
      json: vi.fn().mockResolvedValue({
        name: 'TestAgent',
        public_key: '-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----',
      }),
    });

    const response = await registerTAPAgentRoute(mockContext);
    const data = await response.json();

    expect(response.status).toBe(400);
    expect(data.success).toBe(false);
    expect(data.message).toContain('signature_algorithm required');
  });

  test('should return 400 when signature_algorithm is invalid', async () => {
    const mockContext = createMockContext({
      query: vi.fn((key: string) => key === 'app_id' ? TEST_APP_ID : undefined),
      json: vi.fn().mockResolvedValue({
        name: 'TestAgent',
        public_key: '-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----',
        signature_algorithm: 'invalid-algorithm',
      }),
    });

    const response = await registerTAPAgentRoute(mockContext);
    const data = await response.json();

    expect(response.status).toBe(400);
    expect(data.success).toBe(false);
    expect(data.message).toContain('Unsupported algorithm');
  });

  test('should return 400 when public_key is not in PEM format', async () => {
    const mockContext = createMockContext({
      query: vi.fn((key: string) => key === 'app_id' ? TEST_APP_ID : undefined),
      json: vi.fn().mockResolvedValue({
        name: 'TestAgent',
        public_key: 'invalid-key-format',
        signature_algorithm: 'ecdsa-p256-sha256',
      }),
    });

    const response = await registerTAPAgentRoute(mockContext);
    const data = await response.json();

    expect(response.status).toBe(400);
    expect(data.success).toBe(false);
    expect(data.message).toContain('Invalid public key format');
  });

  test('should accept JWK object as public_key and store it as JSON string', async () => {
    const jwkPublic = {
      kty: 'EC',
      crv: 'P-256',
      x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
      y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
      use: 'sig',
      alg: 'ES256',
    };
    const agentsKV = new MockKV();
    const mockContext = createMockContext({
      agentsKV,
      query: vi.fn((key: string) => key === 'app_id' ? TEST_APP_ID : undefined),
      json: vi.fn().mockResolvedValue({
        name: 'JWK Agent',
        public_key: jwkPublic,
        signature_algorithm: 'ecdsa-p256-sha256',
      }),
    });

    const response = await registerTAPAgentRoute(mockContext);
    const data = await response.json();

    expect(response.status).toBe(201);
    expect(data.success).toBe(true);
    expect(data.has_public_key).toBe(true);
    expect(data.tap_enabled).toBe(true);

    // Verify the JWK object was serialized to a JSON string before storage
    const storedRaw = agentsKV.getRaw(`agent:${data.agent_id}`);
    expect(storedRaw).toBeDefined();
    const storedAgent = JSON.parse(storedRaw!);
    expect(typeof storedAgent.public_key).toBe('string');
    const storedJwk = JSON.parse(storedAgent.public_key);
    expect(storedJwk.kty).toBe('EC');
    expect(storedJwk.crv).toBe('P-256');
  });

  test('should accept JWK JSON string as public_key', async () => {
    const jwkJson = JSON.stringify({
      kty: 'EC',
      crv: 'P-256',
      x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
      y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
    });
    const mockContext = createMockContext({
      query: vi.fn((key: string) => key === 'app_id' ? TEST_APP_ID : undefined),
      json: vi.fn().mockResolvedValue({
        name: 'JWK String Agent',
        public_key: jwkJson,
        signature_algorithm: 'ecdsa-p256-sha256',
      }),
    });

    const response = await registerTAPAgentRoute(mockContext);
    const data = await response.json();

    expect(response.status).toBe(201);
    expect(data.success).toBe(true);
    expect(data.has_public_key).toBe(true);
  });

  test('should return 400 when capabilities is not an array', async () => {
    const mockContext = createMockContext({
      query: vi.fn((key: string) => key === 'app_id' ? TEST_APP_ID : undefined),
      json: vi.fn().mockResolvedValue({
        name: 'TestAgent',
        capabilities: 'not-an-array',
      }),
    });

    const response = await registerTAPAgentRoute(mockContext);
    const data = await response.json();

    expect(response.status).toBe(400);
    expect(data.success).toBe(false);
    expect(data.message).toContain('Capabilities must be an array');
  });

  test('should return 400 when capability has invalid action', async () => {
    const mockContext = createMockContext({
      query: vi.fn((key: string) => key === 'app_id' ? TEST_APP_ID : undefined),
      json: vi.fn().mockResolvedValue({
        name: 'TestAgent',
        capabilities: [{ action: 'invalid-action' }],
      }),
    });

    const response = await registerTAPAgentRoute(mockContext);
    const data = await response.json();

    expect(response.status).toBe(400);
    expect(data.success).toBe(false);
    expect(data.message).toContain('Invalid capability action');
  });

  test('should return 400 on JSON parse error', async () => {
    const mockContext = createMockContext({
      query: vi.fn((key: string) => key === 'app_id' ? TEST_APP_ID : undefined),
      json: vi.fn().mockResolvedValue({}), // Empty object = no name
    });

    const response = await registerTAPAgentRoute(mockContext);
    const data = await response.json();

    expect(response.status).toBe(400);
    expect(data.success).toBe(false);
    expect(data.error).toBe('INVALID_REQUEST');
  });
});

describe('TAP Routes - getTAPAgentRoute', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  test('should return agent by ID successfully', async () => {
    const agentsKV = new MockKV();
    const testAgent: TAPAgent = {
      agent_id: TEST_AGENT_ID,
      app_id: TEST_APP_ID,
      name: 'TestAgent',
      operator: 'test@example.com',
      version: '1.0.0',
      created_at: Date.now(),
      tap_enabled: true,
      trust_level: 'verified',
      capabilities: [{ action: 'browse', scope: ['products'] }],
      public_key: '-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----',
      signature_algorithm: 'ecdsa-p256-sha256',
    };
    agentsKV.seed(`agent:${TEST_AGENT_ID}`, testAgent);

    const mockContext = createMockContext({
      agentsKV,
      param: vi.fn((key: string) => key === 'id' ? TEST_AGENT_ID : undefined),
    });

    const response = await getTAPAgentRoute(mockContext);
    const data = await response.json();

    expect(response.status).toBe(200);
    expect(data.success).toBe(true);
    expect(data.agent_id).toBe(TEST_AGENT_ID);
    expect(data.name).toBe('TestAgent');
    expect(data.tap_enabled).toBe(true);
    expect(data.trust_level).toBe('verified');
    expect(data.capabilities).toHaveLength(1);
    expect(data.has_public_key).toBe(true);
    expect(data.key_fingerprint).toBeDefined();
    expect(data.public_key).toBeDefined(); // Public key should be included
  });

  test('should return 404 when agent not found', async () => {
    const mockContext = createMockContext({
      param: vi.fn((key: string) => key === 'id' ? 'nonexistent' : undefined),
    });

    const response = await getTAPAgentRoute(mockContext);
    const data = await response.json();

    expect(response.status).toBe(404);
    expect(data.success).toBe(false);
    expect(data.error).toBe('AGENT_NOT_FOUND');
  });

  test('should return 400 when agent ID is missing', async () => {
    const mockContext = createMockContext({
      param: vi.fn(() => undefined),
    });

    const response = await getTAPAgentRoute(mockContext);
    const data = await response.json();

    expect(response.status).toBe(400);
    expect(data.success).toBe(false);
    expect(data.error).toBe('MISSING_AGENT_ID');
  });

  test('should return 404 when KV throws error (fail-open)', async () => {
    const agentsKV = new MockKV();
    // Simulate KV error by making get throw - getTAPAgent catches and returns not found
    vi.spyOn(agentsKV, 'get').mockRejectedValue(new Error('KV error'));

    const mockContext = createMockContext({
      agentsKV,
      param: vi.fn((key: string) => key === 'id' ? TEST_AGENT_ID : undefined),
    });

    const response = await getTAPAgentRoute(mockContext);
    const data = await response.json();

    // getTAPAgent returns { success: false, error: 'Internal server error' }
    // which is mapped to 404 by the route handler
    expect(response.status).toBe(404);
    expect(data.success).toBe(false);
    expect(data.error).toBe('AGENT_NOT_FOUND');
  });
});

describe('TAP Routes - listTAPAgentsRoute', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(extractBearerToken).mockReturnValue('mock-jwt-token');
    vi.mocked(verifyToken).mockResolvedValue({
      valid: true,
      payload: { app_id: TEST_APP_ID } as any,
    });
  });

  test('should list all agents for app successfully', async () => {
    const agentsKV = new MockKV();
    const agent1: TAPAgent = {
      agent_id: 'agent_1',
      app_id: TEST_APP_ID,
      name: 'Agent1',
      created_at: Date.now(),
      tap_enabled: true,
      trust_level: 'verified',
      capabilities: [{ action: 'browse' }],
    };
    const agent2: TAPAgent = {
      agent_id: 'agent_2',
      app_id: TEST_APP_ID,
      name: 'Agent2',
      created_at: Date.now(),
      tap_enabled: false,
    };
    
    // Correct KV key format: app_agents:${appId}
    agentsKV.seed(`app_agents:${TEST_APP_ID}`, ['agent_1', 'agent_2']);
    agentsKV.seed('agent:agent_1', agent1);
    agentsKV.seed('agent:agent_2', agent2);

    const mockContext = createMockContext({
      agentsKV,
      query: vi.fn((key: string) => key === 'app_id' ? TEST_APP_ID : undefined),
    });

    const response = await listTAPAgentsRoute(mockContext);
    const data = await response.json();

    expect(response.status).toBe(200);
    expect(data.success).toBe(true);
    expect(data.agents).toHaveLength(2);
    expect(data.count).toBe(2);
    expect(data.tap_enabled_count).toBe(1);
  });

  test('should filter TAP-only agents when tap_only=true', async () => {
    const agentsKV = new MockKV();
    const agent1: TAPAgent = {
      agent_id: 'agent_1',
      app_id: TEST_APP_ID,
      name: 'TAPAgent',
      created_at: Date.now(),
      tap_enabled: true,
      trust_level: 'verified',
    };
    const agent2: TAPAgent = {
      agent_id: 'agent_2',
      app_id: TEST_APP_ID,
      name: 'RegularAgent',
      created_at: Date.now(),
      tap_enabled: false,
    };
    
    // Correct KV key format: app_agents:${appId}
    agentsKV.seed(`app_agents:${TEST_APP_ID}`, ['agent_1', 'agent_2']);
    agentsKV.seed('agent:agent_1', agent1);
    agentsKV.seed('agent:agent_2', agent2);

    const mockContext = createMockContext({
      agentsKV,
      query: vi.fn((key: string) => {
        if (key === 'app_id') return TEST_APP_ID;
        if (key === 'tap_only') return 'true';
        return undefined;
      }),
    });

    const response = await listTAPAgentsRoute(mockContext);
    const data = await response.json();

    expect(response.status).toBe(200);
    expect(data.success).toBe(true);
    expect(data.agents).toHaveLength(1);
    expect(data.agents[0].agent_id).toBe('agent_1');
    expect(data.agents[0].tap_enabled).toBe(true);
  });

  test('should return 401 when no authentication provided', async () => {
    vi.mocked(extractBearerToken).mockReturnValue(null);
    
    const agentsKV = new MockKV();
    // Empty list but still needs to return success with empty array
    agentsKV.seed(`app_agents:undefined`, []);
    
    const mockContext = createMockContext({
      agentsKV,
      header: vi.fn(() => undefined),
      query: vi.fn(() => undefined),
    });

    const response = await listTAPAgentsRoute(mockContext);
    const data = await response.json();

    expect(response.status).toBe(401);
    expect(data.success).toBe(false);
    expect(data.error).toBe('UNAUTHORIZED');
  });

  test('should authenticate with JWT token', async () => {
    const agentsKV = new MockKV();
    agentsKV.seed(`app:${TEST_APP_ID}:agents`, []);

    vi.mocked(extractBearerToken).mockReturnValue('mock-jwt-token');
    vi.mocked(verifyToken).mockResolvedValue({
      valid: true,
      payload: { app_id: TEST_APP_ID } as any,
    });

    const mockContext = createMockContext({
      agentsKV,
      header: vi.fn((key: string) => key === 'authorization' ? 'Bearer mock-jwt-token' : undefined),
    });

    const response = await listTAPAgentsRoute(mockContext);
    const data = await response.json();

    expect(response.status).toBe(200);
    expect(data.success).toBe(true);
  });

  test('should return 500 on KV error', async () => {
    const agentsKV = new MockKV();
    vi.spyOn(agentsKV, 'get').mockRejectedValue(new Error('KV error'));

    const mockContext = createMockContext({
      agentsKV,
      query: vi.fn((key: string) => key === 'app_id' ? TEST_APP_ID : undefined),
    });

    const response = await listTAPAgentsRoute(mockContext);
    const data = await response.json();

    expect(response.status).toBe(500);
    expect(data.success).toBe(false);
    // listTAPAgents catches errors and returns LIST_FAILED
    expect(data.error).toBe('LIST_FAILED');
  });
});

describe('TAP Routes - createTAPSessionRoute', () => {
  // Fake-but-present sig headers so existing tests pass the header gate.
  // The crypto check is mocked to return valid (module-level vi.mock above).
  const FAKE_SIG_HEADERS = {
    'signature': 'sig1=:ZmFrZXNpZ25hdHVyZQ==:',
    'signature-input': `sig1=("@method" "@path");created=${Math.floor(Date.now() / 1000)};keyid="k1";alg="ecdsa-p256-sha256"`,
  };

  beforeEach(() => {
    vi.clearAllMocks();
    // Re-apply default after clearAllMocks (clearAllMocks only clears call history,
    // NOT the implementation — but be explicit for safety)
    vi.mocked(verifyHTTPMessageSignature).mockResolvedValue({ valid: true });
  });

  test('should create TAP session successfully', async () => {
    const agentsKV = new MockKV();
    const sessionsKV = new MockKV();
    
    const testAgent: TAPAgent = {
      agent_id: TEST_AGENT_ID,
      app_id: TEST_APP_ID,
      name: 'TestAgent',
      created_at: Date.now(),
      tap_enabled: true,
      capabilities: [
        { action: 'browse', scope: ['products'] }
      ],
    };
    agentsKV.seed(`agent:${TEST_AGENT_ID}`, testAgent);

    const mockContext = createMockContext({
      agentsKV,
      sessionsKV,
      rawHeaders: FAKE_SIG_HEADERS,
      json: vi.fn().mockResolvedValue({
        agent_id: TEST_AGENT_ID,
        user_context: 'user_hash_123',
        intent: {
          action: 'browse',
          resource: 'products',
        },
      }),
    });

    const response = await createTAPSessionRoute(mockContext);
    const data = await response.json();

    expect(response.status).toBe(201);
    expect(data.success).toBe(true);
    expect(data.session_id).toBeDefined();
    expect(data.agent_id).toBe(TEST_AGENT_ID);
    expect(data.capabilities).toHaveLength(1);
    expect(data.intent.action).toBe('browse');
    expect(data.expires_at).toBeDefined();
  });

  test('should return 400 when required fields are missing', async () => {
    const mockContext = createMockContext({
      json: vi.fn().mockResolvedValue({ agent_id: TEST_AGENT_ID }),
    });

    const response = await createTAPSessionRoute(mockContext);
    const data = await response.json();

    expect(response.status).toBe(400);
    expect(data.success).toBe(false);
    expect(data.error).toBe('MISSING_REQUIRED_FIELDS');
    expect(data.message).toContain('agent_id, user_context, and intent are required');
  });

  test('should return 404 when agent not found', async () => {
    const mockContext = createMockContext({
      json: vi.fn().mockResolvedValue({
        agent_id: 'nonexistent',
        user_context: 'user_hash_123',
        intent: { action: 'browse' },
      }),
    });

    const response = await createTAPSessionRoute(mockContext);
    const data = await response.json();

    expect(response.status).toBe(404);
    expect(data.success).toBe(false);
    expect(data.error).toBe('AGENT_NOT_FOUND');
  });

  test('should return 400 when intent is invalid', async () => {
    const agentsKV = new MockKV();
    const testAgent: TAPAgent = {
      agent_id: TEST_AGENT_ID,
      app_id: TEST_APP_ID,
      name: 'TestAgent',
      created_at: Date.now(),
      tap_enabled: true, // must have TAP enabled to reach intent validation
      capabilities: [{ action: 'browse', scope: ['*'] }],
    };
    agentsKV.seed(`agent:${TEST_AGENT_ID}`, testAgent);

    const mockContext = createMockContext({
      agentsKV,
      rawHeaders: FAKE_SIG_HEADERS,
      json: vi.fn().mockResolvedValue({
        agent_id: TEST_AGENT_ID,
        user_context: 'user_hash_123',
        intent: 'invalid-json-string',
      }),
    });

    const response = await createTAPSessionRoute(mockContext);
    const data = await response.json();

    expect(response.status).toBe(400);
    expect(data.success).toBe(false);
    expect(data.error).toBe('INVALID_INTENT');
  });

  test('should return 400 when intent has invalid action', async () => {
    const agentsKV = new MockKV();
    const testAgent: TAPAgent = {
      agent_id: TEST_AGENT_ID,
      app_id: TEST_APP_ID,
      name: 'TestAgent',
      created_at: Date.now(),
      tap_enabled: true, // must have TAP enabled to reach intent validation
      capabilities: [{ action: 'browse', scope: ['*'] }],
    };
    agentsKV.seed(`agent:${TEST_AGENT_ID}`, testAgent);

    const mockContext = createMockContext({
      agentsKV,
      rawHeaders: FAKE_SIG_HEADERS,
      json: vi.fn().mockResolvedValue({
        agent_id: TEST_AGENT_ID,
        user_context: 'user_hash_123',
        intent: { action: 'invalid-action' },
      }),
    });

    const response = await createTAPSessionRoute(mockContext);
    const data = await response.json();

    expect(response.status).toBe(400);
    expect(data.success).toBe(false);
    expect(data.error).toBe('INVALID_INTENT');
  });

  test('should return 403 when agent lacks required capability', async () => {
    const agentsKV = new MockKV();
    const testAgent: TAPAgent = {
      agent_id: TEST_AGENT_ID,
      app_id: TEST_APP_ID,
      name: 'TestAgent',
      created_at: Date.now(),
      tap_enabled: true,
      capabilities: [
        { action: 'browse', scope: ['products'] }
      ],
    };
    agentsKV.seed(`agent:${TEST_AGENT_ID}`, testAgent);

    const mockContext = createMockContext({
      agentsKV,
      rawHeaders: FAKE_SIG_HEADERS,
      json: vi.fn().mockResolvedValue({
        agent_id: TEST_AGENT_ID,
        user_context: 'user_hash_123',
        intent: { action: 'purchase', resource: 'orders' },
      }),
    });

    const response = await createTAPSessionRoute(mockContext);
    const data = await response.json();

    expect(response.status).toBe(403);
    expect(data.success).toBe(false);
    expect(data.error).toBe('INSUFFICIENT_CAPABILITY');
  });

  test('should return 403 when agent lacks required scope', async () => {
    const agentsKV = new MockKV();
    const testAgent: TAPAgent = {
      agent_id: TEST_AGENT_ID,
      app_id: TEST_APP_ID,
      name: 'TestAgent',
      created_at: Date.now(),
      tap_enabled: true,
      capabilities: [
        { action: 'browse', scope: ['products'] }
      ],
    };
    agentsKV.seed(`agent:${TEST_AGENT_ID}`, testAgent);

    const mockContext = createMockContext({
      agentsKV,
      rawHeaders: FAKE_SIG_HEADERS,
      json: vi.fn().mockResolvedValue({
        agent_id: TEST_AGENT_ID,
        user_context: 'user_hash_123',
        intent: { action: 'browse', resource: 'orders' },
      }),
    });

    const response = await createTAPSessionRoute(mockContext);
    const data = await response.json();

    expect(response.status).toBe(403);
    expect(data.success).toBe(false);
    expect(data.error).toBe('INSUFFICIENT_CAPABILITY');
  });

  test('should return 404 when KV throws error getting agent', async () => {
    const agentsKV = new MockKV();
    vi.spyOn(agentsKV, 'get').mockRejectedValue(new Error('KV error'));

    const mockContext = createMockContext({
      agentsKV,
      json: vi.fn().mockResolvedValue({
        agent_id: TEST_AGENT_ID,
        user_context: 'user_hash_123',
        intent: { action: 'browse' },
      }),
    });

    const response = await createTAPSessionRoute(mockContext);
    const data = await response.json();

    // getTAPAgent catches error and returns not found
    expect(response.status).toBe(404);
    expect(data.success).toBe(false);
    expect(data.error).toBe('AGENT_NOT_FOUND');
  });

  // ── New tests for tap_enabled gate and last_verified_at update ──

  test('should return 403 TAP_NOT_ENABLED when agent has no public key (tap_enabled: false)', async () => {
    const agentsKV = new MockKV();
    const testAgent: TAPAgent = {
      agent_id: TEST_AGENT_ID,
      app_id: TEST_APP_ID,
      name: 'KeylessAgent',
      created_at: Date.now(),
      tap_enabled: false, // explicitly no TAP support — no public key
      capabilities: [{ action: 'browse', scope: ['*'] }],
    };
    agentsKV.seed(`agent:${TEST_AGENT_ID}`, testAgent);

    const mockContext = createMockContext({
      agentsKV,
      json: vi.fn().mockResolvedValue({
        agent_id: TEST_AGENT_ID,
        user_context: 'user_hash_abc',
        intent: { action: 'browse', resource: 'products' },
      }),
    });

    const response = await createTAPSessionRoute(mockContext);
    const data = await response.json();

    expect(response.status).toBe(403);
    expect(data.success).toBe(false);
    expect(data.error).toBe('TAP_NOT_ENABLED');
    expect(data.message).toContain('public key');
  });

  test('should return 403 TAP_NOT_ENABLED when agent has tap_enabled undefined', async () => {
    const agentsKV = new MockKV();
    const testAgent: TAPAgent = {
      agent_id: TEST_AGENT_ID,
      app_id: TEST_APP_ID,
      name: 'LegacyAgent',
      created_at: Date.now(),
      // tap_enabled not set (legacy agent registered before TAP)
    };
    agentsKV.seed(`agent:${TEST_AGENT_ID}`, testAgent);

    const mockContext = createMockContext({
      agentsKV,
      json: vi.fn().mockResolvedValue({
        agent_id: TEST_AGENT_ID,
        user_context: 'user_hash_xyz',
        intent: { action: 'browse' },
      }),
    });

    const response = await createTAPSessionRoute(mockContext);
    const data = await response.json();

    expect(response.status).toBe(403);
    expect(data.success).toBe(false);
    expect(data.error).toBe('TAP_NOT_ENABLED');
  });

  test('should update last_verified_at on agent after successful session creation', async () => {
    const agentsKV = new MockKV();
    const sessionsKV = new MockKV();

    const testAgent: TAPAgent = {
      agent_id: TEST_AGENT_ID,
      app_id: TEST_APP_ID,
      name: 'KeyedAgent',
      created_at: Date.now(),
      tap_enabled: true,
      last_verified_at: undefined, // not set yet
      capabilities: [{ action: 'browse', scope: ['*'] }],
    };
    agentsKV.seed(`agent:${TEST_AGENT_ID}`, testAgent);

    const mockContext = createMockContext({
      agentsKV,
      sessionsKV,
      rawHeaders: FAKE_SIG_HEADERS,
      json: vi.fn().mockResolvedValue({
        agent_id: TEST_AGENT_ID,
        user_context: 'user_hash_123',
        intent: { action: 'browse', resource: 'products' },
      }),
    });

    const beforeMs = Date.now();
    const response = await createTAPSessionRoute(mockContext);
    const data = await response.json();

    expect(response.status).toBe(201);
    expect(data.success).toBe(true);

    // Give the fire-and-forget updateAgentVerification a tick to resolve
    await new Promise(r => setTimeout(r, 10));

    // Verify last_verified_at was written to KV
    const updatedRaw = agentsKV.getRaw(`agent:${TEST_AGENT_ID}`);
    expect(updatedRaw).toBeDefined();
    const updatedAgent = JSON.parse(updatedRaw!) as TAPAgent;
    expect(updatedAgent.last_verified_at).toBeDefined();
    expect(updatedAgent.last_verified_at).toBeGreaterThanOrEqual(beforeMs);
  });
});

describe('TAP Routes - getTAPSessionRoute', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  test('should return session successfully', async () => {
    const sessionsKV = new MockKV();
    const now = Date.now();
    const testSession = {
      session_id: TEST_SESSION_ID,
      agent_id: TEST_AGENT_ID,
      app_id: TEST_APP_ID,
      user_context: 'user_hash_123',
      capabilities: [{ action: 'browse', scope: ['products'] }],
      intent: { action: 'browse', resource: 'products' },
      created_at: now,
      expires_at: now + 3600000, // 1 hour
    };
    sessionsKV.seed(`session:${TEST_SESSION_ID}`, testSession);

    const mockContext = createMockContext({
      sessionsKV,
      param: vi.fn((key: string) => key === 'id' ? TEST_SESSION_ID : undefined),
    });

    const response = await getTAPSessionRoute(mockContext);
    const data = await response.json();

    expect(response.status).toBe(200);
    expect(data.success).toBe(true);
    expect(data.session_id).toBe(TEST_SESSION_ID);
    expect(data.agent_id).toBe(TEST_AGENT_ID);
    expect(data.app_id).toBe(TEST_APP_ID);
    expect(data.capabilities).toHaveLength(1);
    expect(data.intent.action).toBe('browse');
    expect(data.time_remaining).toBeGreaterThan(0);
  });

  test('should return 404 when session not found', async () => {
    const mockContext = createMockContext({
      param: vi.fn((key: string) => key === 'id' ? 'nonexistent' : undefined),
    });

    const response = await getTAPSessionRoute(mockContext);
    const data = await response.json();

    expect(response.status).toBe(404);
    expect(data.success).toBe(false);
    expect(data.error).toBe('SESSION_NOT_FOUND');
  });

  test('should return 400 when session ID is missing', async () => {
    const mockContext = createMockContext({
      param: vi.fn(() => undefined),
    });

    const response = await getTAPSessionRoute(mockContext);
    const data = await response.json();

    expect(response.status).toBe(400);
    expect(data.success).toBe(false);
    expect(data.error).toBe('MISSING_SESSION_ID');
  });

  test('should return 404 for expired session', async () => {
    const sessionsKV = new MockKV();
    const now = Date.now();
    const testSession = {
      session_id: TEST_SESSION_ID,
      agent_id: TEST_AGENT_ID,
      app_id: TEST_APP_ID,
      user_context: 'user_hash_123',
      capabilities: [],
      intent: { action: 'browse' },
      created_at: now - 7200000, // 2 hours ago
      expires_at: now - 3600000, // Expired 1 hour ago
    };
    sessionsKV.seed(`session:${TEST_SESSION_ID}`, testSession);

    const mockContext = createMockContext({
      sessionsKV,
      param: vi.fn((key: string) => key === 'id' ? TEST_SESSION_ID : undefined),
    });

    const response = await getTAPSessionRoute(mockContext);
    const data = await response.json();

    // getTAPSession checks expiration and returns error if expired
    expect(response.status).toBe(404);
    expect(data.success).toBe(false);
    expect(data.error).toBe('SESSION_NOT_FOUND');
  });

  test('should return 404 when KV throws error', async () => {
    const sessionsKV = new MockKV();
    vi.spyOn(sessionsKV, 'get').mockRejectedValue(new Error('KV error'));

    const mockContext = createMockContext({
      sessionsKV,
      param: vi.fn((key: string) => key === 'id' ? TEST_SESSION_ID : undefined),
    });

    const response = await getTAPSessionRoute(mockContext);
    const data = await response.json();

    // getTAPSession catches error and returns not found
    expect(response.status).toBe(404);
    expect(data.success).toBe(false);
    expect(data.error).toBe('SESSION_NOT_FOUND');
  });
});

describe('TAP Routes - rotateKeyRoute (JWK support)', () => {
  const TEST_AGENT_ID = 'agent_rotatejwktest';

  function seedAgent(agentsKV: MockKV, overrides: Partial<TAPAgent> = {}) {
    const agent: TAPAgent = {
      agent_id: TEST_AGENT_ID,
      app_id: TEST_APP_ID,
      name: 'Rotate Test Agent',
      tap_enabled: true,
      trust_level: 'basic',
      capabilities: [],
      public_key: '-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEold\n-----END PUBLIC KEY-----',
      signature_algorithm: 'ecdsa-p256-sha256',
      created_at: Date.now(),
      updated_at: Date.now(),
      key_created_at: Date.now(),
      ...overrides,
    };
    agentsKV.seed(`agent:${TEST_AGENT_ID}`, agent);
    return agent;
  }

  test('should accept JWK object as new_public_key during rotation', async () => {
    const agentsKV = new MockKV();
    seedAgent(agentsKV);

    const jwkPublic = {
      kty: 'EC',
      crv: 'P-256',
      x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
      y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
    };

    const mockContext = createMockContext({
      agentsKV,
      param: vi.fn((key: string) => key === 'id' ? TEST_AGENT_ID : undefined),
      json: vi.fn().mockResolvedValue({
        public_key: jwkPublic,
        signature_algorithm: 'ecdsa-p256-sha256',
      }),
    });

    const response = await rotateKeyRoute(mockContext);
    const data = await response.json();

    expect(response.status).toBe(200);
    expect(data.success).toBe(true);
    expect(data.has_public_key).toBe(true);

    // Verify JWK object was stored as JSON string
    const storedRaw = agentsKV.getRaw(`agent:${TEST_AGENT_ID}`);
    const storedAgent = JSON.parse(storedRaw!);
    expect(typeof storedAgent.public_key).toBe('string');
    const storedJwk = JSON.parse(storedAgent.public_key);
    expect(storedJwk.kty).toBe('EC');
  });

  test('should accept JWK JSON string as new_public_key during rotation', async () => {
    const agentsKV = new MockKV();
    seedAgent(agentsKV);

    const jwkJson = JSON.stringify({
      kty: 'EC',
      crv: 'P-256',
      x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
      y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
    });

    const mockContext = createMockContext({
      agentsKV,
      param: vi.fn((key: string) => key === 'id' ? TEST_AGENT_ID : undefined),
      json: vi.fn().mockResolvedValue({
        public_key: jwkJson,
        signature_algorithm: 'ecdsa-p256-sha256',
      }),
    });

    const response = await rotateKeyRoute(mockContext);
    const data = await response.json();

    expect(response.status).toBe(200);
    expect(data.success).toBe(true);
    expect(data.has_public_key).toBe(true);
  });

  test('should return 400 for invalid key format during rotation', async () => {
    const agentsKV = new MockKV();
    seedAgent(agentsKV);

    const mockContext = createMockContext({
      agentsKV,
      param: vi.fn((key: string) => key === 'id' ? TEST_AGENT_ID : undefined),
      json: vi.fn().mockResolvedValue({
        public_key: 'not-a-valid-key',
        signature_algorithm: 'ecdsa-p256-sha256',
      }),
    });

    const response = await rotateKeyRoute(mockContext);
    const data = await response.json();

    expect(response.status).toBe(400);
    expect(data.error).toBe('INVALID_KEY_FORMAT');
  });
});

// ============================================================================
// RFC 9421 HTTP Message Signature Enforcement on createTAPSessionRoute
// These tests verify that the signature gate in createTAPSessionRoute works
// correctly.  Crypto correctness is covered in tap-verify.test.ts; here we
// test the route's response to various signature states.
// ============================================================================

describe('TAP Routes - createTAPSessionRoute RFC 9421 enforcement', () => {
  const MOCK_PUBLIC_KEY = '-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEtestkeytestkeytestkeytestkeytestkeytestkeytestkey==\n-----END PUBLIC KEY-----';
  const MOCK_ALGORITHM = 'ecdsa-p256-sha256';
  const MOCK_SIG = 'sig1=:YWJjZGVm:'; // fake base64 payload — crypto checked in tap-verify.test.ts
  const MOCK_SIG_INPUT = `sig1=("@method" "@path");created=${Math.floor(Date.now() / 1000)};keyid="k1";alg="${MOCK_ALGORITHM}"`;

  // Helper: agent with tap_enabled + public key (requires signature verification)
  function buildTAPAgent(extra: Partial<TAPAgent> = {}): TAPAgent {
    return {
      agent_id: TEST_AGENT_ID,
      app_id: TEST_APP_ID,
      name: 'SignedAgent',
      created_at: Date.now(),
      tap_enabled: true,
      public_key: MOCK_PUBLIC_KEY,
      signature_algorithm: MOCK_ALGORITHM,
      capabilities: [{ action: 'browse', scope: ['*'] }],
      ...extra,
    };
  }

  // Helper: base mock context for session requests
  function buildSessionContext(agentsKV: MockKV, rawHeaders: Record<string, string> = {}) {
    const sessionsKV = new MockKV();
    const noncesKV = new MockKV();
    return createMockContext({
      agentsKV,
      sessionsKV,
      noncesKV,
      rawHeaders,
      json: vi.fn().mockResolvedValue({
        agent_id: TEST_AGENT_ID,
        user_context: 'user_ctx_test',
        intent: { action: 'browse', resource: 'products' },
      }),
    });
  }

  beforeEach(() => {
    vi.clearAllMocks();
    // Default: signature verification passes — specific tests override this
    vi.mocked(verifyHTTPMessageSignature).mockResolvedValue({ valid: true });
  });

  // ── Test 1: both sig headers missing → SIGNATURE_REQUIRED ─────────────────
  test('returns 401 SIGNATURE_REQUIRED when both Signature and Signature-Input headers are absent', async () => {
    const agentsKV = new MockKV();
    agentsKV.seed(`agent:${TEST_AGENT_ID}`, buildTAPAgent());

    // No rawHeaders provided — no signature headers
    const ctx = buildSessionContext(agentsKV, {});

    const response = await createTAPSessionRoute(ctx);
    const data = await response.json();

    expect(response.status).toBe(401);
    expect(data.success).toBe(false);
    expect(data.error).toBe('SIGNATURE_REQUIRED');
    // verifyHTTPMessageSignature should NOT be called (we reject before reaching it)
    expect(verifyHTTPMessageSignature).not.toHaveBeenCalled();
  });

  // ── Test 2: Signature-Input present but Signature missing ─────────────────
  test('returns 401 SIGNATURE_REQUIRED when Signature-Input present but Signature header missing', async () => {
    const agentsKV = new MockKV();
    agentsKV.seed(`agent:${TEST_AGENT_ID}`, buildTAPAgent());

    const ctx = buildSessionContext(agentsKV, {
      'signature-input': MOCK_SIG_INPUT,
      // 'signature' intentionally omitted
    });

    const response = await createTAPSessionRoute(ctx);
    const data = await response.json();

    expect(response.status).toBe(401);
    expect(data.error).toBe('SIGNATURE_REQUIRED');
  });

  // ── Test 3: Signature present but Signature-Input missing ─────────────────
  test('returns 401 SIGNATURE_REQUIRED when Signature present but Signature-Input header missing', async () => {
    const agentsKV = new MockKV();
    agentsKV.seed(`agent:${TEST_AGENT_ID}`, buildTAPAgent());

    const ctx = buildSessionContext(agentsKV, {
      'signature': MOCK_SIG,
      // 'signature-input' intentionally omitted
    });

    const response = await createTAPSessionRoute(ctx);
    const data = await response.json();

    expect(response.status).toBe(401);
    expect(data.error).toBe('SIGNATURE_REQUIRED');
  });

  // ── Test 4: Valid signature → session created successfully ────────────────
  test('creates session (201) when valid RFC 9421 signature is provided', async () => {
    const agentsKV = new MockKV();
    const sessionsKV = new MockKV();
    const noncesKV = new MockKV();
    agentsKV.seed(`agent:${TEST_AGENT_ID}`, buildTAPAgent());

    vi.mocked(verifyHTTPMessageSignature).mockResolvedValue({ valid: true });

    const ctx = createMockContext({
      agentsKV,
      sessionsKV,
      noncesKV,
      rawHeaders: { 'signature': MOCK_SIG, 'signature-input': MOCK_SIG_INPUT },
      json: vi.fn().mockResolvedValue({
        agent_id: TEST_AGENT_ID,
        user_context: 'user_ctx_test',
        intent: { action: 'browse', resource: 'products' },
      }),
    });

    const response = await createTAPSessionRoute(ctx);
    const data = await response.json();

    expect(response.status).toBe(201);
    expect(data.success).toBe(true);
    expect(data.session_id).toBeDefined();
    // Verify that verifyHTTPMessageSignature was called with agent's key + algorithm
    expect(verifyHTTPMessageSignature).toHaveBeenCalledWith(
      expect.objectContaining({ method: 'POST', path: '/v1/sessions/tap' }),
      MOCK_PUBLIC_KEY,
      MOCK_ALGORITHM,
      expect.anything() // NONCES KV
    );
  });

  // ── Test 5: Signature crypto invalid → SIGNATURE_INVALID ─────────────────
  test('returns 401 SIGNATURE_INVALID when signature fails cryptographic verification', async () => {
    const agentsKV = new MockKV();
    agentsKV.seed(`agent:${TEST_AGENT_ID}`, buildTAPAgent());

    vi.mocked(verifyHTTPMessageSignature).mockResolvedValue({
      valid: false,
      error: 'Signature verification failed',
    });

    const ctx = buildSessionContext(agentsKV, {
      'signature': MOCK_SIG,
      'signature-input': MOCK_SIG_INPUT,
    });

    const response = await createTAPSessionRoute(ctx);
    const data = await response.json();

    expect(response.status).toBe(401);
    expect(data.error).toBe('SIGNATURE_INVALID');
    expect(data.message).toContain('RFC 9421 signature verification failed');
  });

  // ── Test 6: Signature expired → SIGNATURE_EXPIRED ────────────────────────
  test('returns 401 SIGNATURE_EXPIRED when expires param is in the past', async () => {
    const agentsKV = new MockKV();
    agentsKV.seed(`agent:${TEST_AGENT_ID}`, buildTAPAgent());

    vi.mocked(verifyHTTPMessageSignature).mockResolvedValue({
      valid: false,
      error: 'Signature has expired',
    });

    const ctx = buildSessionContext(agentsKV, {
      'signature': MOCK_SIG,
      'signature-input': MOCK_SIG_INPUT,
    });

    const response = await createTAPSessionRoute(ctx);
    const data = await response.json();

    expect(response.status).toBe(401);
    expect(data.error).toBe('SIGNATURE_EXPIRED');
    expect(data.message).toContain('expired');
  });

  // ── Test 7: Nonce replayed → NONCE_REPLAYED ───────────────────────────────
  test('returns 401 NONCE_REPLAYED when nonce was already consumed', async () => {
    const agentsKV = new MockKV();
    agentsKV.seed(`agent:${TEST_AGENT_ID}`, buildTAPAgent());

    vi.mocked(verifyHTTPMessageSignature).mockResolvedValue({
      valid: false,
      error: 'Nonce replay detected',
    });

    const ctx = buildSessionContext(agentsKV, {
      'signature': MOCK_SIG,
      'signature-input': MOCK_SIG_INPUT,
    });

    const response = await createTAPSessionRoute(ctx);
    const data = await response.json();

    expect(response.status).toBe(401);
    expect(data.error).toBe('NONCE_REPLAYED');
    expect(data.message).toContain('nonce');
  });

  // ── Test 8: Non-TAP agent short-circuits before sig check ────────────────
  test('returns 403 TAP_NOT_ENABLED (no sig check) for agent without a public key', async () => {
    const agentsKV = new MockKV();
    agentsKV.seed(`agent:${TEST_AGENT_ID}`, buildTAPAgent({ tap_enabled: false, public_key: undefined }));

    // Provide sig headers — they should NOT be consulted for non-TAP agents
    const ctx = buildSessionContext(agentsKV, {
      'signature': MOCK_SIG,
      'signature-input': MOCK_SIG_INPUT,
    });

    const response = await createTAPSessionRoute(ctx);
    const data = await response.json();

    expect(response.status).toBe(403);
    expect(data.error).toBe('TAP_NOT_ENABLED');
    // Crypto check should never be reached for non-TAP agents
    expect(verifyHTTPMessageSignature).not.toHaveBeenCalled();
  });

  // ── Test 9: NONCES KV passed for replay protection ────────────────────────
  test('passes NONCES KV namespace into verifyHTTPMessageSignature for replay protection', async () => {
    const agentsKV = new MockKV();
    const sessionsKV = new MockKV();
    const noncesKV = new MockKV();
    agentsKV.seed(`agent:${TEST_AGENT_ID}`, buildTAPAgent());

    vi.mocked(verifyHTTPMessageSignature).mockResolvedValue({ valid: true });

    const ctx = createMockContext({
      agentsKV,
      sessionsKV,
      noncesKV,
      rawHeaders: { 'signature': MOCK_SIG, 'signature-input': MOCK_SIG_INPUT },
      json: vi.fn().mockResolvedValue({
        agent_id: TEST_AGENT_ID,
        user_context: 'user_ctx_nonces',
        intent: { action: 'browse' },
      }),
    });

    await createTAPSessionRoute(ctx);

    // The 4th argument to verifyHTTPMessageSignature must be the NONCES KV
    const callArgs = vi.mocked(verifyHTTPMessageSignature).mock.calls[0];
    expect(callArgs[3]).toBe(noncesKV); // nonces KV namespace
  });
});
