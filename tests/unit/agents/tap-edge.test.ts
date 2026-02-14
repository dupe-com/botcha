import { describe, test, expect, beforeAll, vi } from 'vitest';
import { Hono } from 'hono';
import {
  createTAPEdgeMiddleware,
  parseEdgeSignatureInput,
  buildEdgeSignatureBase,
  verifyEdgeSignature,
  jwkToPublicKeyPem,
  tapEdgeStrict,
  tapEdgeFlexible,
  tapEdgeDev,
  TAP_EDGE_HEADERS,
  type TAPEdgeOptions,
  type EdgeVerificationResult,
  type ParsedEdgeSignatureInput,
} from '../../../packages/cloudflare-workers/src/tap-edge.js';

// ============ CRYPTO TEST HELPERS ============

/**
 * Generate ECDSA P-256 key pair for testing
 */
async function generateTestKeyPair(): Promise<{
  publicKeyPem: string;
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  keyId: string;
}> {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  );

  // Export public key to SPKI format
  const publicKeyBuffer = await crypto.subtle.exportKey('spki', keyPair.publicKey);
  const publicKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(publicKeyBuffer)));
  
  // Format as PEM
  const publicKeyPem = [
    '-----BEGIN PUBLIC KEY-----',
    publicKeyBase64.match(/.{1,64}/g)?.join('\n') || publicKeyBase64,
    '-----END PUBLIC KEY-----',
  ].join('\n');

  return {
    publicKeyPem,
    privateKey: keyPair.privateKey,
    publicKey: keyPair.publicKey,
    keyId: 'test-key-' + Math.random().toString(36).substring(7),
  };
}

/**
 * Sign a message using ECDSA P-256
 */
async function signMessage(
  signatureBase: string,
  privateKey: CryptoKey,
  label: string = 'sig1'
): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(signatureBase);
  
  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    privateKey,
    data
  );

  const signatureBase64 = btoa(String.fromCharCode(...new Uint8Array(signature)));
  return `${label}=:${signatureBase64}:`;
}

// ============ PARSING TESTS ============

describe('parseEdgeSignatureInput', () => {
  test('parses sig2 format correctly', () => {
    const input = 'sig2=("@authority" "@path");created=1735689600;keyid="agent123";alg="ecdsa-p256-sha256";expires=1735693200;nonce="abc123";tag="agent-browser-auth"';
    
    const parsed = parseEdgeSignatureInput(input);
    
    expect(parsed).not.toBeNull();
    expect(parsed!.label).toBe('sig2');
    expect(parsed!.components).toEqual(['@authority', '@path']);
    expect(parsed!.created).toBe(1735689600);
    expect(parsed!.keyId).toBe('agent123');
    expect(parsed!.algorithm).toBe('ecdsa-p256-sha256');
    expect(parsed!.expires).toBe(1735693200);
    expect(parsed!.nonce).toBe('abc123');
    expect(parsed!.tag).toBe('agent-browser-auth');
  });

  test('handles sig1 format (backward compat)', () => {
    const input = 'sig1=("@authority" "@path");created=1735689600;keyid="agent456";alg="Ed25519"';
    
    const parsed = parseEdgeSignatureInput(input);
    
    expect(parsed).not.toBeNull();
    expect(parsed!.label).toBe('sig1');
    expect(parsed!.keyId).toBe('agent456');
    expect(parsed!.algorithm).toBe('Ed25519');
  });

  test('returns null for invalid input', () => {
    expect(parseEdgeSignatureInput('')).toBeNull();
    expect(parseEdgeSignatureInput('invalid')).toBeNull();
    expect(parseEdgeSignatureInput('sig2=()')).toBeNull(); // missing required params
  });

  test('handles agent-payer-auth tag', () => {
    const input = 'sig2=("@authority" "@path");created=1735689600;keyid="agent789";alg="ecdsa-p256-sha256";tag="agent-payer-auth"';
    
    const parsed = parseEdgeSignatureInput(input);
    
    expect(parsed).not.toBeNull();
    expect(parsed!.tag).toBe('agent-payer-auth');
  });

  test('parses without optional params', () => {
    const input = 'sig2=("@authority" "@path");created=1735689600;keyid="agent123";alg="ecdsa-p256-sha256"';
    
    const parsed = parseEdgeSignatureInput(input);
    
    expect(parsed).not.toBeNull();
    expect(parsed!.expires).toBeUndefined();
    expect(parsed!.nonce).toBeUndefined();
    expect(parsed!.tag).toBeUndefined();
  });

  test('case-insensitive keyid/keyId', () => {
    const input1 = 'sig2=("@authority" "@path");created=1735689600;keyId="agent123";alg="ecdsa-p256-sha256"';
    const input2 = 'sig2=("@authority" "@path");created=1735689600;keyid="agent123";alg="ecdsa-p256-sha256"';
    
    const parsed1 = parseEdgeSignatureInput(input1);
    const parsed2 = parseEdgeSignatureInput(input2);
    
    expect(parsed1!.keyId).toBe('agent123');
    expect(parsed2!.keyId).toBe('agent123');
  });
});

// ============ SIGNATURE BASE TESTS ============

describe('buildEdgeSignatureBase', () => {
  test('produces correct canonical format', () => {
    const parsed: ParsedEdgeSignatureInput = {
      label: 'sig2',
      components: ['@authority', '@path'],
      created: 1735689600,
      keyId: 'agent123',
      algorithm: 'ecdsa-p256-sha256',
      expires: 1735693200,
      nonce: 'abc123',
      tag: 'agent-browser-auth',
    };

    const base = buildEdgeSignatureBase('example.com', '/product/123', parsed);

    const expected = [
      '"@authority": example.com',
      '"@path": /product/123',
      '"@signature-params": sig2=("@authority" "@path");created=1735689600;keyid="agent123";alg="ecdsa-p256-sha256";expires=1735693200;nonce="abc123";tag="agent-browser-auth"',
    ].join('\n');

    expect(base).toBe(expected);
  });

  test('handles missing optional params', () => {
    const parsed: ParsedEdgeSignatureInput = {
      label: 'sig1',
      components: ['@authority', '@path'],
      created: 1735689600,
      keyId: 'agent123',
      algorithm: 'Ed25519',
    };

    const base = buildEdgeSignatureBase('api.example.com', '/test', parsed);

    expect(base).toContain('"@authority": api.example.com');
    expect(base).toContain('"@path": /test');
    expect(base).not.toContain('expires=');
    expect(base).not.toContain('nonce=');
    expect(base).not.toContain('tag=');
  });
});

// ============ JWK CONVERSION TESTS ============

describe('jwkToPublicKeyPem', () => {
  test('converts ES256 JWK to PEM', async () => {
    // Generate a test key
    const keyPair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify']
    );

    const jwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
    jwk.alg = 'ES256';

    const pem = await jwkToPublicKeyPem(jwk);

    expect(pem).toContain('-----BEGIN PUBLIC KEY-----');
    expect(pem).toContain('-----END PUBLIC KEY-----');
    expect(pem.length).toBeGreaterThan(100);
  });
});

// ============ SIGNATURE VERIFICATION TESTS ============

describe('verifyEdgeSignature', () => {
  let testKey: Awaited<ReturnType<typeof generateTestKeyPair>>;
  
  beforeAll(async () => {
    testKey = await generateTestKeyPair();
  });

  test('verifies valid ECDSA signature', async () => {
    const now = Math.floor(Date.now() / 1000);
    const parsed: ParsedEdgeSignatureInput = {
      label: 'sig1',
      components: ['@authority', '@path'],
      created: now,
      keyId: testKey.keyId,
      algorithm: 'ecdsa-p256-sha256',
    };

    const authority = 'example.com';
    const path = '/test';
    const signatureBase = buildEdgeSignatureBase(authority, path, parsed);
    const signature = await signMessage(signatureBase, testKey.privateKey, 'sig1');

    // Mock request object
    const mockReq = {
      header: (name: string) => {
        if (name === 'host') return authority;
        return '';
      },
      path,
    };

    const result = await verifyEdgeSignature(
      mockReq,
      parsed,
      signature,
      testKey.publicKeyPem,
      'ecdsa-p256-sha256'
    );

    expect(result.verified).toBe(true);
    expect(result.error).toBeUndefined();
    expect(result.agentKeyId).toBe(testKey.keyId);
  });

  test('rejects expired signature', async () => {
    const now = Math.floor(Date.now() / 1000);
    const parsed: ParsedEdgeSignatureInput = {
      label: 'sig1',
      components: ['@authority', '@path'],
      created: now,
      expires: now - 10, // Expired 10 seconds ago
      keyId: testKey.keyId,
      algorithm: 'ecdsa-p256-sha256',
    };

    const mockReq = {
      header: (name: string) => name === 'host' ? 'example.com' : '',
      path: '/test',
    };

    const result = await verifyEdgeSignature(
      mockReq,
      parsed,
      'sig1=:dGVzdA==:',
      testKey.publicKeyPem,
      'ecdsa-p256-sha256'
    );

    expect(result.verified).toBe(false);
    expect(result.error).toContain('expired');
  });

  test('rejects tampered path', async () => {
    const now = Math.floor(Date.now() / 1000);
    const parsed: ParsedEdgeSignatureInput = {
      label: 'sig1',
      components: ['@authority', '@path'],
      created: now,
      keyId: testKey.keyId,
      algorithm: 'ecdsa-p256-sha256',
    };

    // Sign with one path
    const signatureBase = buildEdgeSignatureBase('example.com', '/original', parsed);
    const signature = await signMessage(signatureBase, testKey.privateKey, 'sig1');

    // Verify with different path
    const mockReq = {
      header: (name: string) => name === 'host' ? 'example.com' : '',
      path: '/tampered',
    };

    const result = await verifyEdgeSignature(
      mockReq,
      parsed,
      signature,
      testKey.publicKeyPem,
      'ecdsa-p256-sha256'
    );

    expect(result.verified).toBe(false);
    expect(result.error).toContain('verification failed');
  });

  test('validates timestamp window (8 minutes max)', async () => {
    const now = Math.floor(Date.now() / 1000);
    const parsed: ParsedEdgeSignatureInput = {
      label: 'sig2',
      components: ['@authority', '@path'],
      created: now,
      expires: now + 500, // 500 seconds = > 8 minutes
      keyId: testKey.keyId,
      algorithm: 'ecdsa-p256-sha256',
    };

    const mockReq = {
      header: (name: string) => name === 'host' ? 'example.com' : '',
      path: '/test',
    };

    const result = await verifyEdgeSignature(
      mockReq,
      parsed,
      'sig2=:dGVzdA==:',
      testKey.publicKeyPem,
      'ecdsa-p256-sha256'
    );

    expect(result.verified).toBe(false);
    expect(result.error).toContain('8 minutes');
  });

  test('includes metadata in successful verification', async () => {
    const now = Math.floor(Date.now() / 1000);
    const parsed: ParsedEdgeSignatureInput = {
      label: 'sig2',
      components: ['@authority', '@path'],
      created: now,
      keyId: testKey.keyId,
      algorithm: 'ecdsa-p256-sha256',
      nonce: 'test-nonce-123',
      tag: 'agent-browser-auth',
    };

    const authority = 'example.com';
    const path = '/test';
    const signatureBase = buildEdgeSignatureBase(authority, path, parsed);
    const signature = await signMessage(signatureBase, testKey.privateKey, 'sig2');

    const mockReq = {
      header: (name: string) => name === 'host' ? authority : '',
      path,
    };

    const result = await verifyEdgeSignature(
      mockReq,
      parsed,
      signature,
      testKey.publicKeyPem,
      'ecdsa-p256-sha256'
    );

    expect(result.verified).toBe(true);
    expect(result.tag).toBe('agent-browser-auth');
    expect(result.nonce).toBe('test-nonce-123');
    expect(result.agentKeyId).toBe(testKey.keyId);
    expect(result.timestamp).toBe(now);
  });
});

// ============ MIDDLEWARE TESTS ============

describe('createTAPEdgeMiddleware', () => {
  let testKey: Awaited<ReturnType<typeof generateTestKeyPair>>;
  
  beforeAll(async () => {
    testKey = await generateTestKeyPair();
  });

  test('middleware returns 403 when blockOnFailure + invalid sig', async () => {
    const staticKeys = new Map([[testKey.keyId, testKey.publicKeyPem]]);
    const middleware = createTAPEdgeMiddleware({
      staticKeys,
      blockOnFailure: true,
      allowUnverified: true,
    });

    const app = new Hono();
    app.use('*', middleware);
    app.get('/test', (c) => c.json({ ok: true }));

    const now = Math.floor(Date.now() / 1000);
    const input = `sig1=("@authority" "@path");created=${now};keyid="${testKey.keyId}";alg="ecdsa-p256-sha256"`;

    const res = await app.request('/test', {
      headers: {
        'signature-input': input,
        'signature': 'sig1=:invalid_signature:',
        'host': 'example.com',
      },
    });

    expect(res.status).toBe(403);
    const data = await res.json();
    expect(data.error).toBe('TAP_VERIFICATION_FAILED');
  });

  test('middleware passes through when allowUnverified + no headers', async () => {
    const middleware = createTAPEdgeMiddleware({
      allowUnverified: true,
    });

    const app = new Hono();
    app.use('*', middleware);
    app.get('/test', (c) => c.json({ ok: true }));

    const res = await app.request('/test');

    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.ok).toBe(true);
    expect(res.headers.get(TAP_EDGE_HEADERS.VERIFIED)).toBe('false');
  });

  test('middleware adds X-TAP-Verified header', async () => {
    const staticKeys = new Map([[testKey.keyId, testKey.publicKeyPem]]);
    const middleware = createTAPEdgeMiddleware({
      staticKeys,
      allowUnverified: true,
      blockOnFailure: false,
    });

    const app = new Hono();
    app.use('*', middleware);
    app.get('/test', (c) => c.json({ ok: true }));

    const res = await app.request('/test');

    expect(res.status).toBe(200);
    expect(res.headers.get(TAP_EDGE_HEADERS.VERIFIED)).toBe('false');
  });

  test('middleware requires TAP when allowUnverified=false', async () => {
    const middleware = createTAPEdgeMiddleware({
      allowUnverified: false,
    });

    const app = new Hono();
    app.use('*', middleware);
    app.get('/test', (c) => c.json({ ok: true }));

    const res = await app.request('/test');

    expect(res.status).toBe(403);
    const data = await res.json();
    expect(data.error).toBe('TAP_REQUIRED');
  });

  test('middleware requires tag when requireTag=true', async () => {
    const staticKeys = new Map([[testKey.keyId, testKey.publicKeyPem]]);
    const middleware = createTAPEdgeMiddleware({
      staticKeys,
      requireTag: true,
    });

    const app = new Hono();
    app.use('*', middleware);
    app.get('/test', (c) => c.json({ ok: true }));

    const now = Math.floor(Date.now() / 1000);
    // No tag in signature-input
    const input = `sig1=("@authority" "@path");created=${now};keyid="${testKey.keyId}";alg="ecdsa-p256-sha256"`;

    const res = await app.request('/test', {
      headers: {
        'signature-input': input,
        'signature': 'sig1=:test:',
        'host': 'example.com',
      },
    });

    expect(res.status).toBe(403);
    const data = await res.json();
    expect(data.error).toBe('TAP_TAG_REQUIRED');
  });

  test('middleware adds verification headers on success', async () => {
    const staticKeys = new Map([[testKey.keyId, testKey.publicKeyPem]]);
    const middleware = createTAPEdgeMiddleware({
      staticKeys,
      blockOnFailure: false,
    });

    const app = new Hono();
    app.use('*', middleware);
    app.get('/test', (c) => c.json({ ok: true }));

    const now = Math.floor(Date.now() / 1000);
    const parsed: ParsedEdgeSignatureInput = {
      label: 'sig2',
      components: ['@authority', '@path'],
      created: now,
      keyId: testKey.keyId,
      algorithm: 'ecdsa-p256-sha256',
      nonce: 'test-nonce',
      tag: 'agent-browser-auth',
    };

    const authority = 'example.com';
    const path = '/test';
    const signatureBase = buildEdgeSignatureBase(authority, path, parsed);
    const signature = await signMessage(signatureBase, testKey.privateKey, 'sig2');

    const input = `sig2=("@authority" "@path");created=${now};keyid="${testKey.keyId}";alg="ecdsa-p256-sha256";nonce="test-nonce";tag="agent-browser-auth"`;

    const res = await app.request(`http://${authority}/test`, {
      headers: {
        'host': authority,
        'signature-input': input,
        'signature': signature,
      },
    });

    expect(res.status).toBe(200);
    expect(res.headers.get(TAP_EDGE_HEADERS.VERIFIED)).toBe('true');
    expect(res.headers.get(TAP_EDGE_HEADERS.TAG)).toBe('agent-browser-auth');
    expect(res.headers.get(TAP_EDGE_HEADERS.KEY_ID)).toBe(testKey.keyId);
    expect(res.headers.get(TAP_EDGE_HEADERS.AGENT_SOURCE)).toBe('static');
    expect(res.headers.get(TAP_EDGE_HEADERS.NONCE)).toBe('test-nonce');
    expect(res.headers.get(TAP_EDGE_HEADERS.TIMESTAMP)).toBe(String(now));
  });

  test('middleware calls onVerified callback', async () => {
    const onVerified = vi.fn();
    const staticKeys = new Map([[testKey.keyId, testKey.publicKeyPem]]);
    const middleware = createTAPEdgeMiddleware({
      staticKeys,
      onVerified,
    });

    const app = new Hono();
    app.use('*', middleware);
    app.get('/test', (c) => c.json({ ok: true }));

    const now = Math.floor(Date.now() / 1000);
    const parsed: ParsedEdgeSignatureInput = {
      label: 'sig1',
      components: ['@authority', '@path'],
      created: now,
      keyId: testKey.keyId,
      algorithm: 'ecdsa-p256-sha256',
    };

    const authority = 'example.com';
    const path = '/test';
    const signatureBase = buildEdgeSignatureBase(authority, path, parsed);
    const signature = await signMessage(signatureBase, testKey.privateKey, 'sig1');

    const input = `sig1=("@authority" "@path");created=${now};keyid="${testKey.keyId}";alg="ecdsa-p256-sha256"`;

    await app.request(`http://${authority}/test`, {
      headers: {
        'host': authority,
        'signature-input': input,
        'signature': signature,
      },
    });

    expect(onVerified).toHaveBeenCalledWith(
      expect.objectContaining({
        verified: true,
        agentKeyId: testKey.keyId,
        source: 'static',
      })
    );
  });

  test('middleware calls onFailed callback', async () => {
    const onFailed = vi.fn();
    const middleware = createTAPEdgeMiddleware({
      onFailed,
      blockOnFailure: false,
    });

    const app = new Hono();
    app.use('*', middleware);
    app.get('/test', (c) => c.json({ ok: true }));

    const now = Math.floor(Date.now() / 1000);
    const input = `sig1=("@authority" "@path");created=${now};keyid="unknown-key";alg="ecdsa-p256-sha256"`;

    await app.request('/test', {
      headers: {
        'signature-input': input,
        'signature': 'sig1=:test:',
        'host': 'example.com',
      },
    });

    expect(onFailed).toHaveBeenCalledWith(
      expect.objectContaining({
        verified: false,
        error: expect.stringContaining('not found'),
      })
    );
  });

  test('middleware returns 403 for unknown key when blockOnFailure', async () => {
    const middleware = createTAPEdgeMiddleware({
      staticKeys: new Map(),
      blockOnFailure: true,
    });

    const app = new Hono();
    app.use('*', middleware);
    app.get('/test', (c) => c.json({ ok: true }));

    const now = Math.floor(Date.now() / 1000);
    const input = `sig1=("@authority" "@path");created=${now};keyid="unknown";alg="ecdsa-p256-sha256"`;

    const res = await app.request('/test', {
      headers: {
        'signature-input': input,
        'signature': 'sig1=:test:',
        'host': 'example.com',
      },
    });

    expect(res.status).toBe(403);
    const data = await res.json();
    expect(data.error).toBe('TAP_KEY_NOT_FOUND');
  });
});

// ============ PRESET TESTS ============

describe('preset configurations', () => {
  test('tapEdgeStrict blocks unverified requests', async () => {
    const middleware = tapEdgeStrict([]);

    const app = new Hono();
    app.use('*', middleware);
    app.get('/test', (c) => c.json({ ok: true }));

    const res = await app.request('/test');

    expect(res.status).toBe(403);
  });

  test('tapEdgeFlexible allows unverified requests', async () => {
    const middleware = tapEdgeFlexible([]);

    const app = new Hono();
    app.use('*', middleware);
    app.get('/test', (c) => c.json({ ok: true }));

    const res = await app.request('/test');

    expect(res.status).toBe(200);
  });

  test('tapEdgeDev never blocks', async () => {
    const middleware = tapEdgeDev();

    const app = new Hono();
    app.use('*', middleware);
    app.get('/test', (c) => c.json({ ok: true }));

    // Request with invalid signature
    const now = Math.floor(Date.now() / 1000);
    const input = `sig1=("@authority" "@path");created=${now};keyid="unknown";alg="ecdsa-p256-sha256"`;

    const res = await app.request('/test', {
      headers: {
        'signature-input': input,
        'signature': 'sig1=:invalid:',
        'host': 'example.com',
      },
    });

    expect(res.status).toBe(200); // Never blocks
  });
});
