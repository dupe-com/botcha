/**
 * Tests for tap-did.ts — W3C DID Document generation + did:web resolution
 */

import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  generateBotchaDIDDocument,
  parseDID,
  didWebToUrl,
  resolveDIDWeb,
  buildAgentDID,
  parseAgentDID,
  isValidDIDWeb,
  type DIDDocument,
  type DIDResolutionResult,
} from '../../../packages/cloudflare-workers/src/tap-did.js';

// ============ generateBotchaDIDDocument ============

describe('generateBotchaDIDDocument', () => {
  const BASE_URL = 'https://botcha.ai';

  test('generates valid DID Document for did:web:botcha.ai', () => {
    const doc = generateBotchaDIDDocument(BASE_URL);
    expect(doc.id).toBe('did:web:botcha.ai');
    expect(doc.controller).toBe('did:web:botcha.ai');
    expect(doc['@context']).toContain('https://www.w3.org/ns/did/v1');
  });

  test('includes JsonWebKey2020 verification method when public key provided', () => {
    const mockPublicKey = {
      kty: 'EC',
      crv: 'P-256',
      x: 'abc123',
      y: 'def456',
      kid: 'botcha-signing-1',
    };
    const doc = generateBotchaDIDDocument(BASE_URL, mockPublicKey);

    expect(doc.verificationMethod).toHaveLength(1);
    const vm = doc.verificationMethod![0];
    expect(vm.type).toBe('JsonWebKey2020');
    expect(vm.id).toBe('did:web:botcha.ai#key-1');
    expect(vm.controller).toBe('did:web:botcha.ai');
    expect(vm.publicKeyJwk?.kty).toBe('EC');
    expect(vm.publicKeyJwk?.crv).toBe('P-256');
    expect(vm.publicKeyJwk?.x).toBe('abc123');
  });

  test('assertionMethod and authentication reference key when present', () => {
    const mockPublicKey = { kty: 'EC', crv: 'P-256', x: 'a', y: 'b', kid: 'k1' };
    const doc = generateBotchaDIDDocument(BASE_URL, mockPublicKey);

    expect(doc.assertionMethod).toContain('did:web:botcha.ai#key-1');
    expect(doc.authentication).toContain('did:web:botcha.ai#key-1');
  });

  test('verificationMethod is empty and auth arrays are empty when no key provided', () => {
    const doc = generateBotchaDIDDocument(BASE_URL);
    expect(doc.verificationMethod).toHaveLength(0);
    expect(doc.assertionMethod).toHaveLength(0);
    expect(doc.authentication).toHaveLength(0);
  });

  test('includes service endpoints', () => {
    const doc = generateBotchaDIDDocument(BASE_URL);
    expect(doc.service).toBeDefined();
    expect(doc.service!.length).toBeGreaterThanOrEqual(3);

    const types = doc.service!.map((s) => s.type);
    expect(types).toContain('LinkedDomains');
    expect(types).toContain('JwkSet');
    expect(types).toContain('CredentialIssuanceService');
  });

  test('JWKS service endpoint points to /.well-known/jwks', () => {
    const doc = generateBotchaDIDDocument('https://botcha.ai');
    const jwks = doc.service!.find((s) => s.type === 'JwkSet');
    expect(jwks).toBeDefined();
    expect(jwks!.serviceEndpoint).toBe('https://botcha.ai/.well-known/jwks');
  });

  test('VC issuance service endpoint points to /v1/credentials/issue', () => {
    const doc = generateBotchaDIDDocument('https://botcha.ai');
    const issuer = doc.service!.find((s) => s.type === 'CredentialIssuanceService');
    expect(issuer).toBeDefined();
    expect(issuer!.serviceEndpoint).toBe('https://botcha.ai/v1/credentials/issue');
  });
});

// ============ parseDID ============

describe('parseDID', () => {
  test('parses valid did:web DID', () => {
    const result = parseDID('did:web:example.com');
    expect(result.valid).toBe(true);
    expect(result.method).toBe('web');
    expect(result.methodSpecificId).toBe('example.com');
  });

  test('parses valid did:web DID with path', () => {
    const result = parseDID('did:web:example.com:user:alice');
    expect(result.valid).toBe(true);
    expect(result.method).toBe('web');
    expect(result.methodSpecificId).toBe('example.com:user:alice');
  });

  test('parses did:key DID', () => {
    const result = parseDID('did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK');
    expect(result.valid).toBe(true);
    expect(result.method).toBe('key');
  });

  test('rejects non-DID string', () => {
    expect(parseDID('https://example.com').valid).toBe(false);
    expect(parseDID('not-a-did').valid).toBe(false);
  });

  test('rejects DID with uppercase method', () => {
    expect(parseDID('did:WEB:example.com').valid).toBe(false);
  });

  test('rejects DID with missing method-specific-id', () => {
    expect(parseDID('did:web:').valid).toBe(false);
  });

  test('rejects DID with only two parts', () => {
    expect(parseDID('did:web').valid).toBe(false);
  });

  test('rejects empty string', () => {
    expect(parseDID('').valid).toBe(false);
  });

  test('rejects null/undefined', () => {
    expect(parseDID(null as any).valid).toBe(false);
    expect(parseDID(undefined as any).valid).toBe(false);
  });
});

// ============ didWebToUrl ============

describe('didWebToUrl', () => {
  test('simple domain → /.well-known/did.json', () => {
    expect(didWebToUrl('did:web:example.com')).toBe(
      'https://example.com/.well-known/did.json'
    );
  });

  test('domain with path → /path/resource/did.json', () => {
    expect(didWebToUrl('did:web:example.com:user:alice')).toBe(
      'https://example.com/user/alice/did.json'
    );
  });

  test('botcha.ai DID resolves correctly', () => {
    expect(didWebToUrl('did:web:botcha.ai')).toBe(
      'https://botcha.ai/.well-known/did.json'
    );
  });

  test('BOTCHA agent DID resolves correctly', () => {
    expect(didWebToUrl('did:web:botcha.ai:agents:agent_abc')).toBe(
      'https://botcha.ai/agents/agent_abc/did.json'
    );
  });

  test('returns null for non-did:web DID', () => {
    expect(didWebToUrl('did:key:z6Mk')).toBeNull();
    expect(didWebToUrl('did:ethr:0x123')).toBeNull();
  });

  test('returns null for empty string', () => {
    expect(didWebToUrl('')).toBeNull();
  });

  test('handles percent-encoded colon in domain (port)', () => {
    const url = didWebToUrl('did:web:example.com%3A8080');
    // After decoding %3A → : the domain is example.com:8080
    expect(url).toBe('https://example.com:8080/.well-known/did.json');
  });
});

// ============ buildAgentDID / parseAgentDID ============

describe('buildAgentDID', () => {
  test('builds correct BOTCHA agent DID', () => {
    expect(buildAgentDID('agent_abc123')).toBe(
      'did:web:botcha.ai:agents:agent_abc123'
    );
  });
});

describe('parseAgentDID', () => {
  test('extracts agent_id from BOTCHA agent DID', () => {
    expect(parseAgentDID('did:web:botcha.ai:agents:agent_abc123')).toBe('agent_abc123');
  });

  test('returns null for non-BOTCHA DID', () => {
    expect(parseAgentDID('did:web:example.com')).toBeNull();
    expect(parseAgentDID('did:key:z6Mk')).toBeNull();
    expect(parseAgentDID('did:web:botcha.ai')).toBeNull(); // no :agents: segment
  });

  test('returns null for empty string', () => {
    expect(parseAgentDID('')).toBeNull();
  });
});

// ============ isValidDIDWeb ============

describe('isValidDIDWeb', () => {
  test('valid did:web DIDs', () => {
    expect(isValidDIDWeb('did:web:example.com')).toBe(true);
    expect(isValidDIDWeb('did:web:botcha.ai')).toBe(true);
    expect(isValidDIDWeb('did:web:example.com:user:alice')).toBe(true);
  });

  test('invalid DIDs', () => {
    expect(isValidDIDWeb('did:key:z6Mk')).toBe(false);
    expect(isValidDIDWeb('not-a-did')).toBe(false);
    expect(isValidDIDWeb('')).toBe(false);
    expect(isValidDIDWeb('did:web:')).toBe(false);
  });
});

// ============ resolveDIDWeb ============

describe('resolveDIDWeb', () => {
  let originalFetch: typeof globalThis.fetch;
  const mockFetch = vi.fn();

  beforeEach(() => {
    originalFetch = globalThis.fetch;
    globalThis.fetch = mockFetch as any;
    mockFetch.mockReset();
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  test('resolves a valid did:web DID', async () => {
    const mockDoc: DIDDocument = {
      '@context': 'https://www.w3.org/ns/did/v1',
      id: 'did:web:example.com',
      controller: 'did:web:example.com',
    };
    mockFetch.mockResolvedValueOnce({
      ok: true,
      headers: { get: () => 'application/did+ld+json' },
      json: async () => mockDoc,
    });

    const result = await resolveDIDWeb('did:web:example.com');
    expect(result.didDocument).not.toBeNull();
    expect(result.didDocument!.id).toBe('did:web:example.com');
    expect(result.didResolutionMetadata.error).toBeUndefined();
    expect(mockFetch).toHaveBeenCalledWith(
      'https://example.com/.well-known/did.json',
      expect.any(Object)
    );
  });

  test('returns invalidDid for non-DID input', async () => {
    const result = await resolveDIDWeb('not-a-did');
    expect(result.didDocument).toBeNull();
    expect(result.didResolutionMetadata.error).toContain('invalidDid');
  });

  test('returns methodNotSupported for non-web DID', async () => {
    const result = await resolveDIDWeb('did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK');
    expect(result.didDocument).toBeNull();
    expect(result.didResolutionMetadata.error).toContain('methodNotSupported');
  });

  test('returns notFound when HTTP 404', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 404,
      headers: { get: () => null },
    });

    const result = await resolveDIDWeb('did:web:notfound.example.com');
    expect(result.didDocument).toBeNull();
    expect(result.didResolutionMetadata.error).toContain('notFound');
    expect(result.didResolutionMetadata.error).toContain('404');
  });

  test('returns internalError when fetch throws', async () => {
    mockFetch.mockRejectedValueOnce(new Error('Network unreachable'));

    const result = await resolveDIDWeb('did:web:unreachable.example.com');
    expect(result.didDocument).toBeNull();
    expect(result.didResolutionMetadata.error).toContain('internalError');
    expect(result.didResolutionMetadata.error).toContain('Network unreachable');
  });

  test('includes resolution duration', async () => {
    const mockDoc: DIDDocument = {
      '@context': 'https://www.w3.org/ns/did/v1',
      id: 'did:web:example.com',
    };
    mockFetch.mockResolvedValueOnce({
      ok: true,
      headers: { get: () => 'application/json' },
      json: async () => mockDoc,
    });

    const result = await resolveDIDWeb('did:web:example.com');
    expect(result.didResolutionMetadata.duration).toBeGreaterThanOrEqual(0);
  });

  test('returns invalidDid when document id does not match requested DID', async () => {
    const mockDoc: DIDDocument = {
      '@context': 'https://www.w3.org/ns/did/v1',
      id: 'did:web:different.com', // Mismatch!
    };
    mockFetch.mockResolvedValueOnce({
      ok: true,
      headers: { get: () => 'application/json' },
      json: async () => mockDoc,
    });

    const result = await resolveDIDWeb('did:web:example.com');
    expect(result.didDocument).toBeNull();
    expect(result.didResolutionMetadata.error).toContain('invalidDid');
    expect(result.didResolutionMetadata.error).toContain('mismatch');
  });

  test('resolves path-based did:web', async () => {
    const mockDoc: DIDDocument = {
      '@context': 'https://www.w3.org/ns/did/v1',
      id: 'did:web:example.com:user:alice',
    };
    mockFetch.mockResolvedValueOnce({
      ok: true,
      headers: { get: () => 'application/json' },
      json: async () => mockDoc,
    });

    const result = await resolveDIDWeb('did:web:example.com:user:alice');
    expect(result.didDocument).not.toBeNull();
    expect(mockFetch).toHaveBeenCalledWith(
      'https://example.com/user/alice/did.json',
      expect.any(Object)
    );
  });

  test('@context in resolution result is correct', async () => {
    const mockDoc: DIDDocument = {
      '@context': 'https://www.w3.org/ns/did/v1',
      id: 'did:web:example.com',
    };
    mockFetch.mockResolvedValueOnce({
      ok: true,
      headers: { get: () => 'application/json' },
      json: async () => mockDoc,
    });

    const result = await resolveDIDWeb('did:web:example.com');
    expect(result['@context']).toBe('https://w3id.org/did-resolution/v1');
  });
});
