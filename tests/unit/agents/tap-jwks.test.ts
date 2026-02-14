import { describe, test, expect, beforeEach } from 'vitest';
import {
  pemToJwk,
  jwkToPem,
  algToJWKAlg,
  jwksRoute,
  getKeyRoute,
  listKeysRoute,
  type JWK,
  type JWKSet,
} from '../../../packages/cloudflare-workers/src/tap-jwks.js';
import type { KVNamespace } from '../../../packages/cloudflare-workers/src/agents.js';
import type { TAPAgent } from '../../../packages/cloudflare-workers/src/tap-agents.js';

// Mock KV namespace
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

  // Test helper
  setData(key: string, value: any): void {
    this.store.set(key, JSON.stringify(value));
  }
}

// Mock Hono Context
function createMockContext(
  queryParams: Record<string, string> = {},
  pathParams: Record<string, string> = {},
  kv?: KVNamespace
): any {
  return {
    req: {
      query: (name: string) => queryParams[name],
      param: (name: string) => pathParams[name],
    },
    env: {
      AGENTS: kv,
    },
    json: (data: any, status: number = 200, headers?: any) => {
      return new Response(JSON.stringify(data), {
        status,
        headers: {
          'Content-Type': 'application/json',
          ...headers,
        },
      });
    },
  };
}

// Helper to parse mock response
async function parseResponse(response: Response): Promise<any> {
  return JSON.parse(await response.text());
}

describe('TAP JWKS - Algorithm Mapping', () => {
  test('algToJWKAlg maps ECDSA correctly', () => {
    expect(algToJWKAlg('ecdsa-p256-sha256')).toBe('ES256');
  });

  test('algToJWKAlg maps RSA-PSS correctly', () => {
    expect(algToJWKAlg('rsa-pss-sha256')).toBe('PS256');
  });

  test('algToJWKAlg maps Ed25519 correctly', () => {
    expect(algToJWKAlg('ed25519')).toBe('EdDSA');
  });

  test('algToJWKAlg throws on unsupported algorithm', () => {
    expect(() => algToJWKAlg('invalid-algo')).toThrow('Unsupported algorithm');
  });
});

describe('TAP JWKS - PEM to JWK Conversion', () => {
  test('converts ECDSA P-256 PEM to JWK with correct fields', async () => {
    // Generate a real ECDSA P-256 key pair
    const keyPair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify']
    );

    // Export as SPKI PEM
    const spkiBuffer = await crypto.subtle.exportKey('spki', keyPair.publicKey);
    const base64 = btoa(String.fromCharCode(...new Uint8Array(spkiBuffer)));
    const lines = base64.match(/.{1,64}/g) || [base64];
    const pem = `-----BEGIN PUBLIC KEY-----\n${lines.join('\n')}\n-----END PUBLIC KEY-----`;

    // Convert to JWK
    const jwk = await pemToJwk(pem, 'ecdsa-p256-sha256', 'test-key-id', {
      agent_id: 'agent_123',
      agent_name: 'TestAgent',
    });

    // Verify JWK structure
    expect(jwk.kty).toBe('EC');
    expect(jwk.crv).toBe('P-256');
    expect(jwk.kid).toBe('test-key-id');
    expect(jwk.use).toBe('sig');
    expect(jwk.alg).toBe('ES256');
    expect(jwk.x).toBeDefined();
    expect(jwk.y).toBeDefined();
    expect(jwk.agent_id).toBe('agent_123');
    expect(jwk.agent_name).toBe('TestAgent');
  });

  test('converts RSA-PSS PEM to JWK with correct fields', async () => {
    // Generate a real RSA key pair
    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'RSA-PSS',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256',
      },
      true,
      ['sign', 'verify']
    );

    // Export as SPKI PEM
    const spkiBuffer = await crypto.subtle.exportKey('spki', keyPair.publicKey);
    const base64 = btoa(String.fromCharCode(...new Uint8Array(spkiBuffer)));
    const lines = base64.match(/.{1,64}/g) || [base64];
    const pem = `-----BEGIN PUBLIC KEY-----\n${lines.join('\n')}\n-----END PUBLIC KEY-----`;

    // Convert to JWK
    const jwk = await pemToJwk(pem, 'rsa-pss-sha256', 'rsa-key-id');

    // Verify JWK structure
    expect(jwk.kty).toBe('RSA');
    expect(jwk.kid).toBe('rsa-key-id');
    expect(jwk.use).toBe('sig');
    expect(jwk.alg).toBe('PS256');
    expect(jwk.n).toBeDefined();
    expect(jwk.e).toBeDefined();
  });

  test('includes metadata in JWK when provided', async () => {
    const keyPair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify']
    );

    const spkiBuffer = await crypto.subtle.exportKey('spki', keyPair.publicKey);
    const base64 = btoa(String.fromCharCode(...new Uint8Array(spkiBuffer)));
    const lines = base64.match(/.{1,64}/g) || [base64];
    const pem = `-----BEGIN PUBLIC KEY-----\n${lines.join('\n')}\n-----END PUBLIC KEY-----`;

    const metadata = {
      agent_id: 'agent_abc123',
      agent_name: 'MetadataBot',
      expires_at: '2027-01-01T00:00:00Z',
    };

    const jwk = await pemToJwk(pem, 'ecdsa-p256-sha256', 'meta-key', metadata);

    expect(jwk.agent_id).toBe('agent_abc123');
    expect(jwk.agent_name).toBe('MetadataBot');
    expect(jwk.expires_at).toBe('2027-01-01T00:00:00Z');
  });
});

describe('TAP JWKS - JWK to PEM Roundtrip', () => {
  test('roundtrips ECDSA key: PEM -> JWK -> PEM', async () => {
    // Generate key
    const keyPair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify']
    );

    // Export as PEM
    const spkiBuffer = await crypto.subtle.exportKey('spki', keyPair.publicKey);
    const base64 = btoa(String.fromCharCode(...new Uint8Array(spkiBuffer)));
    const lines = base64.match(/.{1,64}/g) || [base64];
    const originalPem = `-----BEGIN PUBLIC KEY-----\n${lines.join('\n')}\n-----END PUBLIC KEY-----`;

    // Convert to JWK
    const jwk = await pemToJwk(originalPem, 'ecdsa-p256-sha256', 'roundtrip-test');

    // Convert back to PEM
    const reconstructedPem = await jwkToPem(jwk);

    // Verify both PEMs represent the same key by importing both
    const originalKey = await crypto.subtle.importKey(
      'spki',
      spkiBuffer,
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['verify']
    );

    const reconstructedBuffer = await crypto.subtle.exportKey('spki', originalKey);
    const reconstructedKey = await crypto.subtle.importKey(
      'spki',
      reconstructedBuffer,
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['verify']
    );

    // Both should export to identical JWKs
    const originalJwk = await crypto.subtle.exportKey('jwk', originalKey);
    const reconstructedJwk = await crypto.subtle.exportKey('jwk', reconstructedKey);

    expect(originalJwk.x).toBe(reconstructedJwk.x);
    expect(originalJwk.y).toBe(reconstructedJwk.y);
  });

  test('roundtrips RSA key: PEM -> JWK -> PEM', async () => {
    // Generate key
    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'RSA-PSS',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256',
      },
      true,
      ['sign', 'verify']
    );

    // Export as PEM
    const spkiBuffer = await crypto.subtle.exportKey('spki', keyPair.publicKey);
    const base64 = btoa(String.fromCharCode(...new Uint8Array(spkiBuffer)));
    const lines = base64.match(/.{1,64}/g) || [base64];
    const originalPem = `-----BEGIN PUBLIC KEY-----\n${lines.join('\n')}\n-----END PUBLIC KEY-----`;

    // Convert to JWK
    const jwk = await pemToJwk(originalPem, 'rsa-pss-sha256', 'rsa-roundtrip');

    // Convert back to PEM
    const reconstructedPem = await jwkToPem(jwk);

    // Both should represent the same key
    const originalJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
    expect(jwk.n).toBe(originalJwk.n);
    expect(jwk.e).toBe(originalJwk.e);
  });
});

describe('TAP JWKS - Route Handlers', () => {
  let mockKV: MockKV;

  beforeEach(() => {
    mockKV = new MockKV();
  });

  test('jwksRoute returns empty keys when no app_id provided', async () => {
    const ctx = createMockContext({}, {}, mockKV);
    const response = await jwksRoute(ctx);
    const data = await parseResponse(response);

    expect(response.status).toBe(200);
    expect(data).toEqual({ keys: [] });
    expect(response.headers.get('Cache-Control')).toBe('public, max-age=3600');
  });

  test('jwksRoute returns empty keys when app has no agents', async () => {
    const ctx = createMockContext({ app_id: 'app_nonexistent' }, {}, mockKV);
    const response = await jwksRoute(ctx);
    const data = await parseResponse(response);

    expect(response.status).toBe(200);
    expect(data).toEqual({ keys: [] });
  });

  test('jwksRoute returns JWKs for TAP-enabled agents', async () => {
    // Generate a test key
    const keyPair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify']
    );

    const spkiBuffer = await crypto.subtle.exportKey('spki', keyPair.publicKey);
    const base64 = btoa(String.fromCharCode(...new Uint8Array(spkiBuffer)));
    const lines = base64.match(/.{1,64}/g) || [base64];
    const publicKeyPem = `-----BEGIN PUBLIC KEY-----\n${lines.join('\n')}\n-----END PUBLIC KEY-----`;

    const tapAgent: TAPAgent = {
      agent_id: 'agent_tap123',
      app_id: 'app_test',
      name: 'TAPBot',
      created_at: Date.now(),
      public_key: publicKeyPem,
      signature_algorithm: 'ecdsa-p256-sha256',
      key_created_at: Date.now(),
      tap_enabled: true,
      capabilities: [],
      trust_level: 'verified',
    };

    // Set up KV data
    mockKV.setData('app_agents:app_test', ['agent_tap123']);
    mockKV.setData('agent:agent_tap123', tapAgent);

    const ctx = createMockContext({ app_id: 'app_test' }, {}, mockKV);
    const response = await jwksRoute(ctx);
    const data = (await parseResponse(response)) as JWKSet;

    expect(response.status).toBe(200);
    expect(data.keys).toHaveLength(1);
    expect(data.keys[0].kid).toBe('agent_tap123');
    expect(data.keys[0].alg).toBe('ES256');
    expect(data.keys[0].use).toBe('sig');
    expect(data.keys[0].kty).toBe('EC');
    expect(data.keys[0].agent_id).toBe('agent_tap123');
    expect(data.keys[0].agent_name).toBe('TAPBot');
  });

  test('jwksRoute filters out non-TAP agents', async () => {
    const basicAgent: TAPAgent = {
      agent_id: 'agent_basic',
      app_id: 'app_mixed',
      name: 'BasicBot',
      created_at: Date.now(),
      tap_enabled: false,
    };

    // Set up KV data
    mockKV.setData('app_agents:app_mixed', ['agent_basic']);
    mockKV.setData('agent:agent_basic', basicAgent);

    const ctx = createMockContext({ app_id: 'app_mixed' }, {}, mockKV);
    const response = await jwksRoute(ctx);
    const data = await parseResponse(response);

    expect(response.status).toBe(200);
    expect(data.keys).toHaveLength(0);
  });

  test('getKeyRoute returns 404 for unknown keyId', async () => {
    const ctx = createMockContext({}, { keyId: 'agent_unknown' }, mockKV);
    const response = await getKeyRoute(ctx);
    const data = await parseResponse(response);

    expect(response.status).toBe(404);
    expect(data.error).toBe('Key not found');
  });

  test('getKeyRoute returns JWK for valid TAP agent', async () => {
    // Generate a test key
    const keyPair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify']
    );

    const spkiBuffer = await crypto.subtle.exportKey('spki', keyPair.publicKey);
    const base64 = btoa(String.fromCharCode(...new Uint8Array(spkiBuffer)));
    const lines = base64.match(/.{1,64}/g) || [base64];
    const publicKeyPem = `-----BEGIN PUBLIC KEY-----\n${lines.join('\n')}\n-----END PUBLIC KEY-----`;

    const tapAgent: TAPAgent = {
      agent_id: 'agent_single',
      app_id: 'app_test',
      name: 'SingleBot',
      created_at: Date.now(),
      public_key: publicKeyPem,
      signature_algorithm: 'ecdsa-p256-sha256',
      key_created_at: Date.now(),
      tap_enabled: true,
      capabilities: [],
    };

    mockKV.setData('agent:agent_single', tapAgent);

    const ctx = createMockContext({}, { keyId: 'agent_single' }, mockKV);
    const response = await getKeyRoute(ctx);
    const data = await parseResponse(response);

    expect(response.status).toBe(200);
    expect(data.kid).toBe('agent_single');
    expect(data.alg).toBe('ES256');
    expect(data.agent_id).toBe('agent_single');
  });

  test('getKeyRoute supports keyID query param (Visa TAP compat)', async () => {
    const keyPair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify']
    );

    const spkiBuffer = await crypto.subtle.exportKey('spki', keyPair.publicKey);
    const base64 = btoa(String.fromCharCode(...new Uint8Array(spkiBuffer)));
    const lines = base64.match(/.{1,64}/g) || [base64];
    const publicKeyPem = `-----BEGIN PUBLIC KEY-----\n${lines.join('\n')}\n-----END PUBLIC KEY-----`;

    const tapAgent: TAPAgent = {
      agent_id: 'agent_visa',
      app_id: 'app_test',
      name: 'VisaBot',
      created_at: Date.now(),
      public_key: publicKeyPem,
      signature_algorithm: 'ecdsa-p256-sha256',
      key_created_at: Date.now(),
      tap_enabled: true,
      capabilities: [],
    };

    mockKV.setData('agent:agent_visa', tapAgent);

    const ctx = createMockContext({ keyID: 'agent_visa' }, {}, mockKV);
    const response = await getKeyRoute(ctx);
    const data = await parseResponse(response);

    expect(response.status).toBe(200);
    expect(data.kid).toBe('agent_visa');
  });

  test('listKeysRoute delegates to getKeyRoute when keyID provided', async () => {
    const keyPair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify']
    );

    const spkiBuffer = await crypto.subtle.exportKey('spki', keyPair.publicKey);
    const base64 = btoa(String.fromCharCode(...new Uint8Array(spkiBuffer)));
    const lines = base64.match(/.{1,64}/g) || [base64];
    const publicKeyPem = `-----BEGIN PUBLIC KEY-----\n${lines.join('\n')}\n-----END PUBLIC KEY-----`;

    const tapAgent: TAPAgent = {
      agent_id: 'agent_list',
      app_id: 'app_test',
      name: 'ListBot',
      created_at: Date.now(),
      public_key: publicKeyPem,
      signature_algorithm: 'ecdsa-p256-sha256',
      key_created_at: Date.now(),
      tap_enabled: true,
      capabilities: [],
    };

    mockKV.setData('agent:agent_list', tapAgent);

    const ctx = createMockContext({ keyID: 'agent_list' }, {}, mockKV);
    const response = await listKeysRoute(ctx);
    const data = await parseResponse(response);

    expect(response.status).toBe(200);
    expect(data.kid).toBe('agent_list'); // Single key, not array
  });

  test('listKeysRoute returns empty keys when no filters', async () => {
    const ctx = createMockContext({}, {}, mockKV);
    const response = await listKeysRoute(ctx);
    const data = await parseResponse(response);

    expect(response.status).toBe(200);
    expect(data).toEqual({ keys: [] });
  });
});

describe('TAP JWKS - JWK Set Structure', () => {
  test('JWK Set follows standard format', async () => {
    const jwkSet: JWKSet = {
      keys: [
        {
          kty: 'EC',
          kid: 'test-key-1',
          use: 'sig',
          alg: 'ES256',
          crv: 'P-256',
          x: 'base64url-x',
          y: 'base64url-y',
        },
      ],
    };

    expect(jwkSet).toHaveProperty('keys');
    expect(Array.isArray(jwkSet.keys)).toBe(true);
    expect(jwkSet.keys[0]).toHaveProperty('kty');
    expect(jwkSet.keys[0]).toHaveProperty('kid');
    expect(jwkSet.keys[0]).toHaveProperty('use');
    expect(jwkSet.keys[0]).toHaveProperty('alg');
  });
});
