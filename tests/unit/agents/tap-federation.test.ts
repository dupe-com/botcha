import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  fetchJWKS,
  jwkToFederatedKey,
  createFederationResolver,
  createVisaFederationResolver,
  resolveImportParams,
  inferAlgorithm,
  WELL_KNOWN_SOURCES,
  type FederatedKey,
  type FederatedKeySource,
  type FederationResolver,
} from '../../../packages/cloudflare-workers/src/tap-federation.js';

// ============ MOCKS ============

// Mock KV namespace
class MockKV {
  private store = new Map<string, string>();

  async get(key: string, type?: string): Promise<string | null> {
    return this.store.get(key) || null;
  }

  async put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void> {
    this.store.set(key, value);
  }

  // Test helper
  setData(key: string, value: any): void {
    this.store.set(key, JSON.stringify(value));
  }

  clear(): void {
    this.store.clear();
  }
}

// Mock fetch
const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

// ============ TEST DATA ============

// Generate real test keys for accurate testing
async function generateTestRSAKey() {
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
  const jwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
  return { ...jwk, kid: 'test-rsa-key-1', alg: 'PS256', use: 'sig' };
}

async function generateTestECKey() {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: 'ECDSA',
      namedCurve: 'P-256',
    },
    true,
    ['sign', 'verify']
  );
  const jwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
  return { ...jwk, kid: 'test-ec-key-1', alg: 'ES256', use: 'sig' };
}

// Mock JWKS response
const createMockJWKSResponse = (keys: any[]) => ({
  keys,
});

// Test source
const testSource: FederatedKeySource = {
  url: 'https://test.example.com/.well-known/jwks',
  name: 'test-provider',
  trustLevel: 'medium',
  refreshInterval: 3600,
  enabled: true,
};

// ============ TESTS ============

describe('TAP Federation - fetchJWKS', () => {
  beforeEach(() => {
    mockFetch.mockClear();
  });

  test('parses valid JWKS response', async () => {
    const testJwk = await generateTestRSAKey();
    const mockResponse = createMockJWKSResponse([testJwk]);

    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => mockResponse,
    });

    const result = await fetchJWKS('https://test.example.com/.well-known/jwks');

    expect(result.keys).toHaveLength(1);
    expect(result.keys[0].kid).toBe('test-rsa-key-1');
    expect(mockFetch).toHaveBeenCalledWith(
      'https://test.example.com/.well-known/jwks',
      expect.objectContaining({
        headers: { Accept: 'application/json' },
      })
    );
  });

  test('throws on non-200 response', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 404,
      statusText: 'Not Found',
    });

    await expect(fetchJWKS('https://test.example.com/.well-known/jwks')).rejects.toThrow(
      'JWKS fetch failed: 404 Not Found'
    );
  });

  test('throws on invalid JSON (missing keys array)', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({ invalid: 'response' }),
    });

    await expect(fetchJWKS('https://test.example.com/.well-known/jwks')).rejects.toThrow(
      'Invalid JWKS: missing keys array'
    );
  });

  test('throws on keys not being an array', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({ keys: 'not-an-array' }),
    });

    await expect(fetchJWKS('https://test.example.com/.well-known/jwks')).rejects.toThrow(
      'Invalid JWKS: missing keys array'
    );
  });
});

describe('TAP Federation - jwkToFederatedKey', () => {
  test('converts RSA JWK correctly', async () => {
    const testJwk = await generateTestRSAKey();
    const federatedKey = await jwkToFederatedKey(testJwk, testSource);

    expect(federatedKey.kid).toBe('test-rsa-key-1');
    expect(federatedKey.kty).toBe('RSA');
    expect(federatedKey.alg).toBe('PS256');
    expect(federatedKey.source).toBe('test-provider');
    expect(federatedKey.sourceUrl).toBe('https://test.example.com/.well-known/jwks');
    expect(federatedKey.trustLevel).toBe('medium');
    expect(federatedKey.publicKeyPem).toContain('-----BEGIN PUBLIC KEY-----');
    expect(federatedKey.publicKeyPem).toContain('-----END PUBLIC KEY-----');
    expect(federatedKey.fetchedAt).toBeLessThanOrEqual(Date.now());
    expect(federatedKey.expiresAt).toBeGreaterThan(Date.now());
  });

  test('converts EC JWK correctly', async () => {
    const testJwk = await generateTestECKey();
    const federatedKey = await jwkToFederatedKey(testJwk, testSource);

    expect(federatedKey.kid).toBe('test-ec-key-1');
    expect(federatedKey.kty).toBe('EC');
    expect(federatedKey.alg).toBe('ES256');
    expect(federatedKey.source).toBe('test-provider');
    expect(federatedKey.publicKeyPem).toContain('-----BEGIN PUBLIC KEY-----');
  });

  test('includes x5c if present in JWK', async () => {
    const testJwk = await generateTestRSAKey();
    const jwkWithX5c = { ...testJwk, x5c: ['cert1', 'cert2'] };

    const federatedKey = await jwkToFederatedKey(jwkWithX5c, testSource);

    expect(federatedKey.x5c).toEqual(['cert1', 'cert2']);
  });

  test('infers algorithm if not specified', async () => {
    const testJwk = await generateTestRSAKey();
    const jwkWithoutAlg = { ...testJwk };
    delete (jwkWithoutAlg as any).alg;

    const federatedKey = await jwkToFederatedKey(jwkWithoutAlg, testSource);

    expect(federatedKey.alg).toBe('PS256');
  });

  test('respects source refresh interval for expiration', async () => {
    const testJwk = await generateTestRSAKey();
    const shortRefreshSource: FederatedKeySource = {
      ...testSource,
      refreshInterval: 60, // 1 minute
    };

    const federatedKey = await jwkToFederatedKey(testJwk, shortRefreshSource);

    const expectedExpiry = Date.now() + 60 * 1000;
    expect(federatedKey.expiresAt).toBeGreaterThanOrEqual(expectedExpiry - 100);
    expect(federatedKey.expiresAt).toBeLessThanOrEqual(expectedExpiry + 100);
  });
});

describe('TAP Federation - resolveImportParams', () => {
  test('returns correct params for RSA key', () => {
    const params = resolveImportParams({ kty: 'RSA' });
    expect(params).toEqual({ name: 'RSA-PSS', hash: 'SHA-256' });
  });

  test('returns correct params for EC key with P-256', () => {
    const params = resolveImportParams({ kty: 'EC', crv: 'P-256' });
    expect(params).toEqual({ name: 'ECDSA', namedCurve: 'P-256' });
  });

  test('returns correct params for EC key without crv (defaults to P-256)', () => {
    const params = resolveImportParams({ kty: 'EC' });
    expect(params).toEqual({ name: 'ECDSA', namedCurve: 'P-256' });
  });

  test('returns correct params for OKP Ed25519 key', () => {
    const params = resolveImportParams({ kty: 'OKP', crv: 'Ed25519' });
    expect(params).toEqual({ name: 'Ed25519' });
  });

  test('returns correct params for OKP with EdDSA alg', () => {
    const params = resolveImportParams({ kty: 'OKP', alg: 'EdDSA' });
    expect(params).toEqual({ name: 'Ed25519' });
  });

  test('throws on unsupported key type', () => {
    expect(() => resolveImportParams({ kty: 'UNKNOWN' })).toThrow('Unsupported key type: UNKNOWN');
  });
});

describe('TAP Federation - inferAlgorithm', () => {
  test('infers PS256 for RSA', () => {
    expect(inferAlgorithm({ kty: 'RSA' })).toBe('PS256');
  });

  test('infers ES256 for EC P-256', () => {
    expect(inferAlgorithm({ kty: 'EC', crv: 'P-256' })).toBe('ES256');
  });

  test('infers EdDSA for OKP Ed25519', () => {
    expect(inferAlgorithm({ kty: 'OKP', crv: 'Ed25519' })).toBe('EdDSA');
  });

  test('returns unknown for unsupported types', () => {
    expect(inferAlgorithm({ kty: 'UNKNOWN' })).toBe('unknown');
  });
});

describe('TAP Federation - createFederationResolver', () => {
  let mockKV: MockKV;
  let resolver: FederationResolver;

  beforeEach(() => {
    mockKV = new MockKV();
    mockFetch.mockClear();
  });

  test('resolveKey returns from memory cache', async () => {
    const testJwk = await generateTestRSAKey();
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => createMockJWKSResponse([testJwk]),
    });

    resolver = createFederationResolver({
      sources: [testSource],
      kvNamespace: mockKV as any,
    });

    // First call: fetches from source
    const result1 = await resolver.resolveKey('test-rsa-key-1');
    expect(result1.found).toBe(true);
    expect(result1.key?.kid).toBe('test-rsa-key-1');
    expect(mockFetch).toHaveBeenCalledTimes(1);

    // Second call: returns from memory cache
    const result2 = await resolver.resolveKey('test-rsa-key-1');
    expect(result2.found).toBe(true);
    expect(result2.key?.kid).toBe('test-rsa-key-1');
    expect(mockFetch).toHaveBeenCalledTimes(1); // No additional fetch
  });

  test('resolveKey returns from KV cache when memory cache is cold', async () => {
    const testJwk = await generateTestRSAKey();
    const federatedKey: FederatedKey = {
      kid: 'test-rsa-key-1',
      kty: 'RSA',
      alg: 'PS256',
      publicKeyPem: '-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----',
      source: 'test-provider',
      sourceUrl: 'https://test.example.com/.well-known/jwks',
      trustLevel: 'medium',
      fetchedAt: Date.now(),
      expiresAt: Date.now() + 3600 * 1000,
    };

    mockKV.setData('federated_key:test-rsa-key-1', federatedKey);

    resolver = createFederationResolver({
      sources: [testSource],
      kvNamespace: mockKV as any,
    });

    const result = await resolver.resolveKey('test-rsa-key-1');
    expect(result.found).toBe(true);
    expect(result.key?.kid).toBe('test-rsa-key-1');
    expect(mockFetch).not.toHaveBeenCalled(); // No fetch needed
  });

  test('resolveKey fetches from source when not cached', async () => {
    const testJwk = await generateTestRSAKey();
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => createMockJWKSResponse([testJwk]),
    });

    resolver = createFederationResolver({
      sources: [testSource],
      kvNamespace: mockKV as any,
    });

    const result = await resolver.resolveKey('test-rsa-key-1');
    expect(result.found).toBe(true);
    expect(result.key?.kid).toBe('test-rsa-key-1');
    expect(result.key?.source).toBe('test-provider');
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });

  test('resolveKey opportunistically caches all keys from fetch', async () => {
    const testJwk1 = await generateTestRSAKey();
    const testJwk2 = await generateTestECKey();

    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => createMockJWKSResponse([testJwk1, testJwk2]),
    });

    resolver = createFederationResolver({
      sources: [testSource],
      kvNamespace: mockKV as any,
    });

    // Request first key
    const result1 = await resolver.resolveKey('test-rsa-key-1');
    expect(result1.found).toBe(true);
    expect(mockFetch).toHaveBeenCalledTimes(1);

    // Request second key (should be in cache from opportunistic caching)
    const result2 = await resolver.resolveKey('test-ec-key-1');
    expect(result2.found).toBe(true);
    expect(result2.key?.kid).toBe('test-ec-key-1');
    expect(mockFetch).toHaveBeenCalledTimes(1); // No additional fetch
  });

  test('resolveKey returns not found for unknown key', async () => {
    const testJwk = await generateTestRSAKey();
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => createMockJWKSResponse([testJwk]),
    });

    resolver = createFederationResolver({
      sources: [testSource],
      kvNamespace: mockKV as any,
    });

    const result = await resolver.resolveKey('unknown-key-id');
    expect(result.found).toBe(false);
    expect(result.error).toContain('Key unknown-key-id not found');
  });

  test('resolveKey continues to next source on fetch error (fail-open)', async () => {
    const testJwk = await generateTestRSAKey();
    const source1: FederatedKeySource = {
      url: 'https://failing.example.com/.well-known/jwks',
      name: 'failing-provider',
      trustLevel: 'low',
      refreshInterval: 3600,
      enabled: true,
    };
    const source2: FederatedKeySource = {
      url: 'https://working.example.com/.well-known/jwks',
      name: 'working-provider',
      trustLevel: 'high',
      refreshInterval: 3600,
      enabled: true,
    };

    // First source fails
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 500,
      statusText: 'Internal Server Error',
    });

    // Second source succeeds
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => createMockJWKSResponse([testJwk]),
    });

    resolver = createFederationResolver({
      sources: [source1, source2],
      kvNamespace: mockKV as any,
    });

    const result = await resolver.resolveKey('test-rsa-key-1');
    expect(result.found).toBe(true);
    expect(result.key?.source).toBe('working-provider');
    expect(mockFetch).toHaveBeenCalledTimes(2);
  });

  test('resolveKey skips disabled sources', async () => {
    const disabledSource: FederatedKeySource = {
      ...testSource,
      enabled: false,
    };

    resolver = createFederationResolver({
      sources: [disabledSource],
      kvNamespace: mockKV as any,
    });

    const result = await resolver.resolveKey('test-rsa-key-1');
    expect(result.found).toBe(false);
    expect(mockFetch).not.toHaveBeenCalled();
  });

  test('resolveKey handles KV cache read errors gracefully', async () => {
    const testJwk = await generateTestRSAKey();
    const faultyKV = {
      get: vi.fn().mockRejectedValue(new Error('KV read error')),
      put: vi.fn(),
    };

    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => createMockJWKSResponse([testJwk]),
    });

    resolver = createFederationResolver({
      sources: [testSource],
      kvNamespace: faultyKV as any,
    });

    // Should fall back to fetch despite KV error
    const result = await resolver.resolveKey('test-rsa-key-1');
    expect(result.found).toBe(true);
    expect(result.key?.kid).toBe('test-rsa-key-1');
  });

  test('resolveKey handles expired cache entries', async () => {
    const testJwk = await generateTestRSAKey();
    const expiredKey: FederatedKey = {
      kid: 'test-rsa-key-1',
      kty: 'RSA',
      alg: 'PS256',
      publicKeyPem: '-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----',
      source: 'test-provider',
      sourceUrl: 'https://test.example.com/.well-known/jwks',
      trustLevel: 'medium',
      fetchedAt: Date.now() - 7200 * 1000,
      expiresAt: Date.now() - 3600 * 1000, // Expired 1 hour ago
    };

    mockKV.setData('federated_key:test-rsa-key-1', expiredKey);

    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => createMockJWKSResponse([testJwk]),
    });

    resolver = createFederationResolver({
      sources: [testSource],
      kvNamespace: mockKV as any,
    });

    const result = await resolver.resolveKey('test-rsa-key-1');
    expect(result.found).toBe(true);
    expect(mockFetch).toHaveBeenCalledTimes(1); // Refetched
  });
});

describe('TAP Federation - refreshAll', () => {
  let mockKV: MockKV;
  let resolver: FederationResolver;

  beforeEach(() => {
    mockKV = new MockKV();
    mockFetch.mockClear();
  });

  test('refreshes all keys from all sources', async () => {
    const testJwk1 = await generateTestRSAKey();
    const testJwk2 = await generateTestECKey();

    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => createMockJWKSResponse([testJwk1, testJwk2]),
    });

    resolver = createFederationResolver({
      sources: [testSource],
      kvNamespace: mockKV as any,
    });

    const result = await resolver.refreshAll();
    expect(result.refreshed).toBe(2);
    expect(result.errors).toHaveLength(0);
    expect(mockFetch).toHaveBeenCalledTimes(1);

    // Verify keys are cached
    const cachedKeys = resolver.getCachedKeys();
    expect(cachedKeys).toHaveLength(2);
  });

  test('refreshAll handles fetch errors gracefully', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 500,
      statusText: 'Internal Server Error',
    });

    resolver = createFederationResolver({
      sources: [testSource],
      kvNamespace: mockKV as any,
    });

    const result = await resolver.refreshAll();
    expect(result.refreshed).toBe(0);
    expect(result.errors.length).toBeGreaterThan(0);
    expect(result.errors[0]).toContain('Failed to fetch test-provider');
  });

  test('refreshAll handles invalid key processing', async () => {
    const invalidJwk = { kid: 'invalid', kty: 'UNKNOWN' };

    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => createMockJWKSResponse([invalidJwk]),
    });

    resolver = createFederationResolver({
      sources: [testSource],
      kvNamespace: mockKV as any,
    });

    const result = await resolver.refreshAll();
    expect(result.refreshed).toBe(0);
    expect(result.errors.length).toBeGreaterThan(0);
    expect(result.errors[0]).toContain('Failed to process key invalid');
  });

  test('refreshAll processes multiple sources', async () => {
    const testJwk1 = await generateTestRSAKey();
    const testJwk2 = await generateTestECKey();

    const source1: FederatedKeySource = {
      url: 'https://provider1.example.com/.well-known/jwks',
      name: 'provider1',
      trustLevel: 'high',
      refreshInterval: 3600,
      enabled: true,
    };

    const source2: FederatedKeySource = {
      url: 'https://provider2.example.com/.well-known/jwks',
      name: 'provider2',
      trustLevel: 'medium',
      refreshInterval: 3600,
      enabled: true,
    };

    mockFetch
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => createMockJWKSResponse([testJwk1]),
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => createMockJWKSResponse([testJwk2]),
      });

    resolver = createFederationResolver({
      sources: [source1, source2],
      kvNamespace: mockKV as any,
    });

    const result = await resolver.refreshAll();
    expect(result.refreshed).toBe(2);
    expect(result.errors).toHaveLength(0);
    expect(mockFetch).toHaveBeenCalledTimes(2);
  });
});

describe('TAP Federation - getCachedKeys', () => {
  test('returns all cached keys', async () => {
    const testJwk1 = await generateTestRSAKey();
    const testJwk2 = await generateTestECKey();

    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => createMockJWKSResponse([testJwk1, testJwk2]),
    });

    const resolver = createFederationResolver({
      sources: [testSource],
    });

    await resolver.resolveKey('test-rsa-key-1');

    const cachedKeys = resolver.getCachedKeys();
    expect(cachedKeys).toHaveLength(2);
    expect(cachedKeys.find(k => k.kid === 'test-rsa-key-1')).toBeDefined();
    expect(cachedKeys.find(k => k.kid === 'test-ec-key-1')).toBeDefined();
  });

  test('returns empty array when no keys cached', () => {
    const resolver = createFederationResolver({
      sources: [testSource],
    });

    const cachedKeys = resolver.getCachedKeys();
    expect(cachedKeys).toHaveLength(0);
  });
});

describe('TAP Federation - clearCache', () => {
  beforeEach(() => {
    mockFetch.mockClear();
  });

  test('clears memory cache', async () => {
    const testJwk = await generateTestRSAKey();

    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => createMockJWKSResponse([testJwk]),
    });

    const resolver = createFederationResolver({
      sources: [testSource],
    });

    await resolver.resolveKey('test-rsa-key-1');
    expect(resolver.getCachedKeys()).toHaveLength(1);

    resolver.clearCache();
    expect(resolver.getCachedKeys()).toHaveLength(0);

    // Next resolve should fetch again
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => createMockJWKSResponse([testJwk]),
    });

    await resolver.resolveKey('test-rsa-key-1');
    expect(mockFetch).toHaveBeenCalledTimes(2);
  });
});

describe('TAP Federation - WELL_KNOWN_SOURCES', () => {
  test('includes Visa with correct URL', () => {
    const visaSource = WELL_KNOWN_SOURCES.find(s => s.name === 'visa');
    expect(visaSource).toBeDefined();
    expect(visaSource?.url).toBe('https://mcp.visa.com/.well-known/jwks');
    expect(visaSource?.trustLevel).toBe('high');
    expect(visaSource?.enabled).toBe(true);
  });

  test('Visa source has reasonable refresh interval', () => {
    const visaSource = WELL_KNOWN_SOURCES.find(s => s.name === 'visa');
    expect(visaSource?.refreshInterval).toBeGreaterThan(0);
    expect(visaSource?.refreshInterval).toBeLessThanOrEqual(86400); // Max 24 hours
  });
});

describe('TAP Federation - createVisaFederationResolver', () => {
  test('creates resolver with Visa sources', () => {
    const resolver = createVisaFederationResolver();
    expect(resolver).toBeDefined();
    expect(resolver.resolveKey).toBeDefined();
    expect(resolver.refreshAll).toBeDefined();
  });

  test('uses provided KV namespace', async () => {
    const mockKV = new MockKV();
    const testJwk = await generateTestRSAKey();

    const federatedKey: FederatedKey = {
      kid: 'test-rsa-key-1',
      kty: 'RSA',
      alg: 'PS256',
      publicKeyPem: '-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----',
      source: 'visa',
      sourceUrl: 'https://mcp.visa.com/.well-known/jwks',
      trustLevel: 'high',
      fetchedAt: Date.now(),
      expiresAt: Date.now() + 3600 * 1000,
    };

    mockKV.setData('federated_key:test-rsa-key-1', federatedKey);

    const resolver = createVisaFederationResolver(mockKV as any);
    const result = await resolver.resolveKey('test-rsa-key-1');

    expect(result.found).toBe(true);
    expect(result.key?.source).toBe('visa');
  });
});
