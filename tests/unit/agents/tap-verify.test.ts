import { describe, test, expect, beforeAll, vi } from 'vitest';
import {
  verifyHTTPMessageSignature,
  parseTAPIntent,
  extractTAPHeaders,
  getVerificationMode,
  buildTAPChallengeResponse,
  checkAndStoreNonce,
  actionToTag,
  type TAPVerificationRequest,
  type TAPVerificationResult,
  type TAPHeaders,
} from '../../../packages/cloudflare-workers/src/tap-verify.js';
import { TAP_VALID_ACTIONS } from '../../../packages/cloudflare-workers/src/tap-agents.js';

// ============ CRYPTO TEST HELPERS ============

/**
 * Generate ECDSA P-256 key pair for testing
 * Returns PEM-encoded public key and CryptoKey pair
 */
async function generateTestKeyPair(): Promise<{
  publicKeyPem: string;
  privateKey: CryptoKey;
  publicKey: CryptoKey;
}> {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: 'ECDSA',
      namedCurve: 'P-256',
    },
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
  };
}

/**
 * Generate Ed25519 key pair for testing
 */
async function generateEd25519KeyPair(): Promise<{
  publicKeyPem: string;
  publicKeyRaw: string;
  privateKey: CryptoKey;
  publicKey: CryptoKey;
}> {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'Ed25519' },
    true,
    ['sign', 'verify']
  );

  // Export public key to SPKI format (PEM)
  const publicKeyBuffer = await crypto.subtle.exportKey('spki', keyPair.publicKey);
  const publicKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(publicKeyBuffer)));
  
  const publicKeyPem = [
    '-----BEGIN PUBLIC KEY-----',
    publicKeyBase64.match(/.{1,64}/g)?.join('\n') || publicKeyBase64,
    '-----END PUBLIC KEY-----',
  ].join('\n');

  // Extract raw 32-byte key (skip 12-byte SPKI header)
  const spkiBytes = new Uint8Array(publicKeyBuffer);
  const rawKeyBytes = spkiBytes.slice(12);
  const publicKeyRaw = btoa(String.fromCharCode(...rawKeyBytes));

  return {
    publicKeyPem,
    publicKeyRaw,
    privateKey: keyPair.privateKey,
    publicKey: keyPair.publicKey,
  };
}

/**
 * Sign a message using ECDSA P-256
 */
async function signMessage(
  signatureBase: string,
  privateKey: CryptoKey
): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(signatureBase);
  
  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    privateKey,
    data
  );

  const signatureBase64 = btoa(String.fromCharCode(...new Uint8Array(signature)));
  return `sig1=:${signatureBase64}:`;
}

/**
 * Sign a message using Ed25519
 */
async function signMessageEd25519(
  signatureBase: string,
  privateKey: CryptoKey,
  label: string = 'sig2'
): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(signatureBase);
  
  const signature = await crypto.subtle.sign(
    { name: 'Ed25519' },
    privateKey,
    data
  );

  const signatureBase64 = btoa(String.fromCharCode(...new Uint8Array(signature)));
  return `${label}=:${signatureBase64}:`;
}

/**
 * Build RFC 9421 signature base for testing (sig1 format)
 */
function buildTestSignatureBase(
  method: string,
  path: string,
  headers: Record<string, string>,
  components: string[],
  created: number,
  keyId: string,
  algorithm: string
): string {
  const lines: string[] = [];
  
  for (const component of components) {
    if (component === '@method') {
      lines.push(`"@method": ${method.toUpperCase()}`);
    } else if (component === '@path') {
      lines.push(`"@path": ${path}`);
    } else if (component === '@authority') {
      lines.push(`"@authority": ${headers['host'] || ''}`);
    } else {
      const value = headers[component];
      if (value !== undefined) {
        lines.push(`"${component}": ${value}`);
      }
    }
  }
  
  const componentsList = components.map(c => `"${c}"`).join(' ');
  lines.push(`"@signature-params": sig1=(${componentsList});created=${created};keyid="${keyId}";alg="${algorithm}"`);
  
  return lines.join('\n');
}

/**
 * Build RFC 9421 signature base for TAP (sig2 format with all params)
 */
function buildTAPSignatureBase(
  method: string,
  path: string,
  headers: Record<string, string>,
  components: string[],
  created: number,
  keyId: string,
  algorithm: string,
  expires?: number,
  nonce?: string,
  tag?: string
): string {
  const lines: string[] = [];
  
  for (const component of components) {
    if (component === '@method') {
      lines.push(`"@method": ${method.toUpperCase()}`);
    } else if (component === '@path') {
      lines.push(`"@path": ${path}`);
    } else if (component === '@authority') {
      const authority = headers['host'] || headers[':authority'] || '';
      lines.push(`"@authority": ${authority}`);
    } else {
      const value = headers[component];
      if (value !== undefined) {
        lines.push(`"${component}": ${value}`);
      }
    }
  }
  
  const componentsList = components.map(c => `"${c}"`).join(' ');
  let paramsLine = `"@signature-params": sig2=(${componentsList});created=${created};keyid="${keyId}";alg="${algorithm}"`;
  
  if (expires !== undefined) {
    paramsLine += `;expires=${expires}`;
  }
  if (nonce) {
    paramsLine += `;nonce="${nonce}"`;
  }
  if (tag) {
    paramsLine += `;tag="${tag}"`;
  }
  
  lines.push(paramsLine);
  
  return lines.join('\n');
}

/**
 * Mock KV namespace for testing
 */
function createMockKV(): any {
  const storage = new Map<string, { value: string; expiration?: number }>();
  
  return {
    get: vi.fn(async (key: string) => {
      const item = storage.get(key);
      if (!item) return null;
      if (item.expiration && Date.now() > item.expiration) {
        storage.delete(key);
        return null;
      }
      return item.value;
    }),
    put: vi.fn(async (key: string, value: string, options?: { expirationTtl?: number }) => {
      const expiration = options?.expirationTtl 
        ? Date.now() + options.expirationTtl * 1000 
        : undefined;
      storage.set(key, { value, expiration });
    }),
    delete: vi.fn(async (key: string) => {
      storage.delete(key);
    }),
    _storage: storage, // For test inspection
  };
}

// ============ parseTAPIntent() TESTS ============

describe('TAP Verify - parseTAPIntent()', () => {
  test('parses valid intent with all TAP_VALID_ACTIONS', () => {
    for (const action of TAP_VALID_ACTIONS) {
      const intentString = JSON.stringify({ action });
      const result = parseTAPIntent(intentString);
      
      expect(result.valid).toBe(true);
      expect(result.intent?.action).toBe(action);
      expect(result.error).toBeUndefined();
    }
  });

  test('parses intent with optional fields', () => {
    const intentString = JSON.stringify({
      action: 'purchase',
      resource: '/products/123',
      scope: ['products', 'orders'],
      duration: 3600,
    });
    
    const result = parseTAPIntent(intentString);
    
    expect(result.valid).toBe(true);
    expect(result.intent).toEqual({
      action: 'purchase',
      resource: '/products/123',
      scope: ['products', 'orders'],
      duration: 3600,
    });
  });

  test('rejects invalid action', () => {
    const intentString = JSON.stringify({ action: 'delete' });
    const result = parseTAPIntent(intentString);
    
    expect(result.valid).toBe(false);
    expect(result.error).toBe('Invalid action: delete');
  });

  test('rejects missing action', () => {
    const intentString = JSON.stringify({ resource: '/products' });
    const result = parseTAPIntent(intentString);
    
    expect(result.valid).toBe(false);
    expect(result.error).toBe('Intent must specify action');
  });

  test('rejects non-string action', () => {
    const intentString = JSON.stringify({ action: 123 });
    const result = parseTAPIntent(intentString);
    
    expect(result.valid).toBe(false);
    expect(result.error).toBe('Intent must specify action');
  });

  test('rejects invalid JSON', () => {
    const result = parseTAPIntent('not-json');
    
    expect(result.valid).toBe(false);
    expect(result.error).toBe('Invalid JSON in intent');
  });

  test('filters out non-array scope', () => {
    const intentString = JSON.stringify({
      action: 'browse',
      scope: 'invalid',
    });
    
    const result = parseTAPIntent(intentString);
    
    expect(result.valid).toBe(true);
    expect(result.intent?.scope).toBeUndefined();
  });

  test('filters out non-number duration', () => {
    const intentString = JSON.stringify({
      action: 'browse',
      duration: 'forever',
    });
    
    const result = parseTAPIntent(intentString);
    
    expect(result.valid).toBe(true);
    expect(result.intent?.duration).toBeUndefined();
  });
});

// ============ extractTAPHeaders() TESTS ============

describe('TAP Verify - extractTAPHeaders()', () => {
  test('extracts all TAP headers when present (BOTCHA extended)', () => {
    const headers: Record<string, string> = {
      'x-tap-agent-id': 'agent_123',
      'x-tap-user-context': '{"user_id":"user_456"}',
      'x-tap-intent': '{"action":"browse"}',
      'x-tap-timestamp': '1234567890',
      'signature': 'sig1=:abc123:',
      'signature-input': 'sig1=("@method" "@path");keyid="key1";alg="ecdsa-p256-sha256";created=1234567890',
    };

    const result = extractTAPHeaders(headers);

    expect(result.hasTAPHeaders).toBe(true);
    expect(result.isTAPStandard).toBe(false);
    expect(result.tapHeaders).toEqual({
      'x-tap-agent-id': 'agent_123',
      'x-tap-user-context': '{"user_id":"user_456"}',
      'x-tap-intent': '{"action":"browse"}',
      'x-tap-timestamp': '1234567890',
      'signature': 'sig1=:abc123:',
      'signature-input': 'sig1=("@method" "@path");keyid="key1";alg="ecdsa-p256-sha256";created=1234567890',
    });
  });

  test('detects standard TAP with sig2 and agent tag', () => {
    const headers: Record<string, string> = {
      'signature': 'sig2=:xyz:',
      'signature-input': 'sig2=("@authority" "@path");created=123;keyid="k1";alg="Ed25519";tag="agent-browser-auth"',
    };

    const result = extractTAPHeaders(headers);

    expect(result.hasTAPHeaders).toBe(true);
    expect(result.isTAPStandard).toBe(true);
  });

  test('returns hasTAPHeaders=false when missing required headers', () => {
    // Test missing agent-id (no tag either)
    let result = extractTAPHeaders({
      'x-tap-intent': '{"action":"browse"}',
      'signature': 'sig1=:abc:',
      'signature-input': 'sig1=();created=123',
    });
    expect(result.hasTAPHeaders).toBe(false);

    // Test missing intent (no tag either)
    result = extractTAPHeaders({
      'x-tap-agent-id': 'agent_123',
      'signature': 'sig1=:abc:',
      'signature-input': 'sig1=();created=123',
    });
    expect(result.hasTAPHeaders).toBe(false);

    // Test missing signature
    result = extractTAPHeaders({
      'x-tap-agent-id': 'agent_123',
      'x-tap-intent': '{"action":"browse"}',
      'signature-input': 'sig1=();created=123',
    });
    expect(result.hasTAPHeaders).toBe(false);

    // Test missing signature-input
    result = extractTAPHeaders({
      'x-tap-agent-id': 'agent_123',
      'x-tap-intent': '{"action":"browse"}',
      'signature': 'sig1=:abc:',
    });
    expect(result.hasTAPHeaders).toBe(false);
  });

  test('extracts optional headers even when hasTAPHeaders=false', () => {
    const headers: Record<string, string> = {
      'x-tap-user-context': '{"user_id":"user_456"}',
      'x-tap-timestamp': '1234567890',
    };

    const result = extractTAPHeaders(headers);

    expect(result.hasTAPHeaders).toBe(false);
    expect(result.tapHeaders['x-tap-user-context']).toBe('{"user_id":"user_456"}');
    expect(result.tapHeaders['x-tap-timestamp']).toBe('1234567890');
  });

  test('handles empty headers', () => {
    const result = extractTAPHeaders({});

    expect(result.hasTAPHeaders).toBe(false);
    expect(result.tapHeaders).toEqual({
      'x-tap-agent-id': undefined,
      'x-tap-user-context': undefined,
      'x-tap-intent': undefined,
      'x-tap-timestamp': undefined,
      'signature': undefined,
      'signature-input': undefined,
    });
  });
});

// ============ getVerificationMode() TESTS ============

describe('TAP Verify - getVerificationMode()', () => {
  test('returns "tap" mode when both TAP and challenge headers present', () => {
    const headers: Record<string, string> = {
      // TAP headers
      'x-tap-agent-id': 'agent_123',
      'x-tap-intent': '{"action":"browse"}',
      'signature': 'sig1=:abc:',
      'signature-input': 'sig1=();created=123',
      // Challenge headers
      'x-botcha-challenge-id': 'ch_123',
      'x-botcha-answers': '[1,2,3]',
    };

    const result = getVerificationMode(headers);

    expect(result.mode).toBe('tap');
    expect(result.hasTAPHeaders).toBe(true);
    expect(result.hasChallenge).toBe(true);
  });

  test('returns "signature-only" mode when only TAP headers present', () => {
    const headers: Record<string, string> = {
      'x-tap-agent-id': 'agent_123',
      'x-tap-intent': '{"action":"browse"}',
      'signature': 'sig1=:abc:',
      'signature-input': 'sig1=();created=123',
    };

    const result = getVerificationMode(headers);

    expect(result.mode).toBe('signature-only');
    expect(result.hasTAPHeaders).toBe(true);
    expect(result.hasChallenge).toBe(false);
  });

  test('returns "challenge-only" mode when only challenge headers present', () => {
    const headers: Record<string, string> = {
      'x-botcha-challenge-id': 'ch_123',
      'x-botcha-solution': 'solution123',
    };

    const result = getVerificationMode(headers);

    expect(result.mode).toBe('challenge-only');
    expect(result.hasTAPHeaders).toBe(false);
    expect(result.hasChallenge).toBe(true);
  });

  test('returns "challenge-only" when neither TAP nor challenge headers present', () => {
    const headers: Record<string, string> = {
      'content-type': 'application/json',
    };

    const result = getVerificationMode(headers);

    expect(result.mode).toBe('challenge-only');
    expect(result.hasTAPHeaders).toBe(false);
    expect(result.hasChallenge).toBe(false);
  });

  test('detects challenge with x-botcha-answers', () => {
    const headers: Record<string, string> = {
      'x-botcha-challenge-id': 'ch_123',
      'x-botcha-answers': '[1,2,3]',
    };

    const result = getVerificationMode(headers);
    expect(result.hasChallenge).toBe(true);
  });

  test('detects challenge with x-botcha-solution', () => {
    const headers: Record<string, string> = {
      'x-botcha-challenge-id': 'ch_123',
      'x-botcha-solution': 'nonce123',
    };

    const result = getVerificationMode(headers);
    expect(result.hasChallenge).toBe(true);
  });
});

// ============ actionToTag() TESTS ============

describe('TAP Verify - actionToTag()', () => {
  test('maps purchase to agent-payer-auth', () => {
    expect(actionToTag('purchase')).toBe('agent-payer-auth');
  });

  test('maps browse to agent-browser-auth', () => {
    expect(actionToTag('browse')).toBe('agent-browser-auth');
  });

  test('maps compare to agent-browser-auth', () => {
    expect(actionToTag('compare')).toBe('agent-browser-auth');
  });

  test('maps search to agent-browser-auth', () => {
    expect(actionToTag('search')).toBe('agent-browser-auth');
  });

  test('maps audit to agent-browser-auth', () => {
    expect(actionToTag('audit')).toBe('agent-browser-auth');
  });
});

// ============ checkAndStoreNonce() TESTS ============

describe('TAP Verify - checkAndStoreNonce()', () => {
  test('returns replay=false for new nonce', async () => {
    const mockKV = createMockKV();
    const nonce = 'nonce_abc123';

    const result = await checkAndStoreNonce(mockKV, nonce);

    expect(result.replay).toBe(false);
    expect(mockKV.put).toHaveBeenCalled();
  });

  test('returns replay=true for duplicate nonce', async () => {
    const mockKV = createMockKV();
    const nonce = 'nonce_duplicate';

    // First use
    await checkAndStoreNonce(mockKV, nonce);
    
    // Second use (replay)
    const result = await checkAndStoreNonce(mockKV, nonce);

    expect(result.replay).toBe(true);
  });

  test('stores nonce with 480 second TTL', async () => {
    const mockKV = createMockKV();
    const nonce = 'nonce_ttl_test';

    await checkAndStoreNonce(mockKV, nonce);

    expect(mockKV.put).toHaveBeenCalledWith(
      expect.stringContaining('nonce:'),
      '1',
      { expirationTtl: 480 }
    );
  });

  test('returns replay=false when KV is null', async () => {
    const result = await checkAndStoreNonce(null, 'nonce_test');
    expect(result.replay).toBe(false);
  });

  test('returns replay=false when nonce is empty', async () => {
    const mockKV = createMockKV();
    const result = await checkAndStoreNonce(mockKV, '');
    expect(result.replay).toBe(false);
  });

  test('hashes nonce for consistent key length', async () => {
    const mockKV = createMockKV();
    const longNonce = 'a'.repeat(1000);

    await checkAndStoreNonce(mockKV, longNonce);

    // Check that the key is a fixed-length hash
    const callArgs = mockKV.put.mock.calls[0];
    const key = callArgs[0];
    expect(key).toMatch(/^nonce:[a-f0-9]{64}$/);
  });
});

// ============ buildTAPChallengeResponse() TESTS ============

describe('TAP Verify - buildTAPChallengeResponse()', () => {
  test('builds response with computational challenge when needed', () => {
    const verificationResult: TAPVerificationResult = {
      verified: false,
      verification_method: 'tap',
      challenges_passed: {
        computational: false,
        cryptographic: true,
      },
      error: 'Computational challenge not solved',
    };

    const challengeData = {
      id: 'ch_test123',
      type: 'speed',
      problems: [{ num: 5, operation: 'factorial' }],
      timeLimit: 2000,
      instructions: 'Solve math problems',
    };

    const response = buildTAPChallengeResponse(verificationResult, challengeData);

    expect(response.success).toBe(false);
    expect(response.error).toBe('TAP_VERIFICATION_FAILED');
    expect(response.code).toBe('TAP_CHALLENGE');
    expect(response.message).toBe('🔐 Enterprise agent authentication required');
    expect(response.verification_method).toBe('tap');
    expect(response.challenges_passed).toEqual({
      computational: false,
      cryptographic: true,
    });
    expect(response.details).toBe('Computational challenge not solved');
    expect(response.challenge).toEqual({
      id: 'ch_test123',
      type: 'speed',
      problems: [{ num: 5, operation: 'factorial' }],
      timeLimit: '2000ms',
      instructions: 'Solve math problems',
    });
  });

  test('omits challenge data when computational challenge passed', () => {
    const verificationResult: TAPVerificationResult = {
      verified: false,
      verification_method: 'signature-only',
      challenges_passed: {
        computational: true,
        cryptographic: false,
      },
      error: 'Signature verification failed',
    };

    const challengeData = {
      id: 'ch_test123',
      type: 'speed',
      problems: [],
      timeLimit: 2000,
    };

    const response = buildTAPChallengeResponse(verificationResult, challengeData);

    expect(response.challenge).toBeUndefined();
  });

  test('includes Ed25519 in supported_algorithms', () => {
    const verificationResult: TAPVerificationResult = {
      verified: false,
      verification_method: 'tap',
      challenges_passed: {
        computational: false,
        cryptographic: false,
      },
      error: 'Both challenges failed',
    };

    const response = buildTAPChallengeResponse(verificationResult);

    expect(response.tap_requirements.supported_algorithms).toContain('ed25519');
    expect(response.tap_requirements.supported_algorithms).toContain('Ed25519');
    expect(response.tap_requirements.supported_algorithms).toContain('ecdsa-p256-sha256');
  });

  test('includes JWKS URL', () => {
    const verificationResult: TAPVerificationResult = {
      verified: false,
      verification_method: 'tap',
      challenges_passed: {
        computational: false,
        cryptographic: false,
      },
    };

    const response = buildTAPChallengeResponse(verificationResult);

    expect(response.tap_requirements.jwks_url).toBe('https://botcha.ai/.well-known/jwks');
  });

  test('includes TAP requirements with correct flags', () => {
    const verificationResult: TAPVerificationResult = {
      verified: false,
      verification_method: 'tap',
      challenges_passed: {
        computational: false,
        cryptographic: false,
      },
      error: 'Both challenges failed',
    };

    const response = buildTAPChallengeResponse(verificationResult);

    expect(response.tap_requirements).toEqual({
      cryptographic_signature: true,
      computational_challenge: true,
      required_headers: [
        'x-tap-agent-id',
        'x-tap-user-context',
        'x-tap-intent',
        'x-tap-timestamp',
        'signature',
        'signature-input',
      ],
      supported_algorithms: ['ed25519', 'Ed25519', 'ecdsa-p256-sha256', 'rsa-pss-sha256'],
      jwks_url: 'https://botcha.ai/.well-known/jwks',
    });
  });

  test('works without challengeData parameter', () => {
    const verificationResult: TAPVerificationResult = {
      verified: false,
      verification_method: 'signature-only',
      challenges_passed: {
        computational: true,
        cryptographic: false,
      },
      error: 'Invalid signature',
    };

    const response = buildTAPChallengeResponse(verificationResult);

    expect(response.success).toBe(false);
    expect(response.challenge).toBeUndefined();
    expect(response.tap_requirements).toBeDefined();
  });

  test('handles challengeData with "challenges" field (legacy)', () => {
    const verificationResult: TAPVerificationResult = {
      verified: false,
      verification_method: 'tap',
      challenges_passed: {
        computational: false,
        cryptographic: true,
      },
    };

    const challengeData = {
      id: 'ch_legacy',
      challenges: [{ num: 10, operation: 'prime' }], // Legacy field name
      timeLimit: 3000,
    };

    const response = buildTAPChallengeResponse(verificationResult, challengeData);

    expect(response.challenge.problems).toEqual([{ num: 10, operation: 'prime' }]);
  });
});

// ============ verifyHTTPMessageSignature() TESTS ============

describe('TAP Verify - verifyHTTPMessageSignature()', () => {
  test('rejects request missing signature header', async () => {
    const request: TAPVerificationRequest = {
      method: 'POST',
      path: '/api/products',
      headers: {
        'signature-input': 'sig1=();created=123',
      },
    };

    const result = await verifyHTTPMessageSignature(request, 'fake-key', 'ecdsa-p256-sha256');

    expect(result.valid).toBe(false);
    expect(result.error).toBe('Missing signature headers');
  });

  test('rejects request missing signature-input header', async () => {
    const request: TAPVerificationRequest = {
      method: 'POST',
      path: '/api/products',
      headers: {
        'signature': 'sig1=:abc123:',
      },
    };

    const result = await verifyHTTPMessageSignature(request, 'fake-key', 'ecdsa-p256-sha256');

    expect(result.valid).toBe(false);
    expect(result.error).toBe('Missing signature headers');
  });

  test('rejects malformed signature-input', async () => {
    const request: TAPVerificationRequest = {
      method: 'POST',
      path: '/api/products',
      headers: {
        'signature': 'sig1=:abc123:',
        'signature-input': 'invalid-format',
      },
    };

    const result = await verifyHTTPMessageSignature(request, 'fake-key', 'ecdsa-p256-sha256');

    expect(result.valid).toBe(false);
    expect(result.error).toBe('Invalid signature-input format');
  });

  test('rejects expired signature (expires in past)', async () => {
    const now = Math.floor(Date.now() / 1000);
    const created = now - 100;
    const expires = now - 10; // Already expired

    const request: TAPVerificationRequest = {
      method: 'POST',
      path: '/api/products',
      headers: {
        'signature': 'sig2=:abc123:',
        'signature-input': `sig2=("@authority" "@path");created=${created};keyid="key1";alg="Ed25519";expires=${expires}`,
      },
    };

    const result = await verifyHTTPMessageSignature(request, 'fake-key', 'Ed25519');

    expect(result.valid).toBe(false);
    expect(result.error).toBe('Signature has expired');
  });

  test('rejects signature with window > 480 seconds', async () => {
    const now = Math.floor(Date.now() / 1000);
    const created = now - 100;
    const expires = created + 500; // 500 seconds window (exceeds 480)

    const request: TAPVerificationRequest = {
      method: 'POST',
      path: '/api/products',
      headers: {
        'signature': 'sig2=:abc123:',
        'signature-input': `sig2=("@authority" "@path");created=${created};keyid="key1";alg="Ed25519";expires=${expires}`,
      },
    };

    const result = await verifyHTTPMessageSignature(request, 'fake-key', 'Ed25519');

    expect(result.valid).toBe(false);
    expect(result.error).toBe('Signature validity window exceeds 8 minutes');
  });

  test('rejects future created timestamp', async () => {
    const now = Math.floor(Date.now() / 1000);
    const futureCreated = now + 100; // 100 seconds in future

    const request: TAPVerificationRequest = {
      method: 'POST',
      path: '/api/products',
      headers: {
        'signature': 'sig1=:abc123:',
        'signature-input': `sig1=("@method" "@path");created=${futureCreated};keyid="key1";alg="ecdsa-p256-sha256"`,
      },
    };

    const result = await verifyHTTPMessageSignature(request, 'fake-key', 'ecdsa-p256-sha256');

    expect(result.valid).toBe(false);
    expect(result.error).toBe('Signature timestamp is in the future');
  });

  test('rejects old timestamp without expires (backward compat mode)', async () => {
    const now = Math.floor(Date.now() / 1000);
    const oldTimestamp = now - 400; // 400 seconds ago (exceeds 5min window)

    const request: TAPVerificationRequest = {
      method: 'POST',
      path: '/api/products',
      headers: {
        'signature': 'sig1=:abc123:',
        'signature-input': `sig1=("@method" "@path");keyid="key1";alg="ecdsa-p256-sha256";created=${oldTimestamp}`,
      },
    };

    const result = await verifyHTTPMessageSignature(request, 'fake-key', 'ecdsa-p256-sha256');

    expect(result.valid).toBe(false);
    expect(result.error).toBe('Signature timestamp too old or too new');
  });

  test('accepts timestamp within 5-minute window (backward compat)', async () => {
    const now = Math.floor(Date.now() / 1000);
    const recentTimestamp = now - 200; // 200 seconds ago (within 5min)

    const request: TAPVerificationRequest = {
      method: 'POST',
      path: '/api/products',
      headers: {
        'signature': 'sig1=:invalid:',
        'signature-input': `sig1=("@method" "@path");keyid="key1";alg="ecdsa-p256-sha256";created=${recentTimestamp}`,
      },
    };

    const result = await verifyHTTPMessageSignature(request, 'fake-key', 'ecdsa-p256-sha256');

    // Will fail on signature verification, not timestamp
    expect(result.error).not.toBe('Signature timestamp too old or too new');
  });

  test('rejects nonce replay', async () => {
    const mockKV = createMockKV();
    const now = Math.floor(Date.now() / 1000);
    const nonce = 'nonce_replay_test';

    const request: TAPVerificationRequest = {
      method: 'POST',
      path: '/api/products',
      headers: {
        'signature': 'sig2=:abc:',
        'signature-input': `sig2=("@authority" "@path");created=${now};keyid="k1";alg="Ed25519";nonce="${nonce}"`,
      },
    };

    // First request (should store nonce)
    await verifyHTTPMessageSignature(request, 'fake-key', 'Ed25519', mockKV);

    // Second request with same nonce (should reject)
    const result = await verifyHTTPMessageSignature(request, 'fake-key', 'Ed25519', mockKV);

    expect(result.valid).toBe(false);
    expect(result.error).toBe('Nonce replay detected');
  });

  test('extracts nonce and tag from signature-input', async () => {
    const now = Math.floor(Date.now() / 1000);
    const nonce = 'test_nonce_123';
    const tag = 'agent-browser-auth';

    const request: TAPVerificationRequest = {
      method: 'GET',
      path: '/api/browse',
      headers: {
        'host': 'botcha.ai',
        'signature': 'sig2=:invalid:',
        'signature-input': `sig2=("@authority" "@path");created=${now};keyid="k1";alg="Ed25519";nonce="${nonce}";tag="${tag}"`,
      },
    };

    const result = await verifyHTTPMessageSignature(request, 'fake-key', 'Ed25519');

    expect(result.metadata?.nonce).toBe(nonce);
    expect(result.metadata?.tag).toBe(tag);
    expect(result.metadata?.key_id).toBe('k1');
  });

  test('verifies valid ECDSA P-256 signature (sig1, backward compat)', async () => {
    const now = Math.floor(Date.now() / 1000);
    const keyId = 'test-key-1';
    const algorithm = 'ecdsa-p256-sha256';
    
    // Generate key pair
    const { publicKeyPem, privateKey } = await generateTestKeyPair();

    // Build request
    const method = 'POST';
    const path = '/api/products';
    const headers: Record<string, string> = {
      'x-tap-agent-id': 'agent_test123',
      'x-tap-intent': '{"action":"browse"}',
      'host': 'botcha.ai',
    };

    // Components to sign
    const components = ['@method', '@path', 'x-tap-agent-id', 'x-tap-intent'];

    // Build signature base
    const signatureBase = buildTestSignatureBase(
      method,
      path,
      headers,
      components,
      now,
      keyId,
      algorithm
    );

    // Sign it
    const signature = await signMessage(signatureBase, privateKey);

    // Build signature-input header
    const componentsList = components.map(c => `"${c}"`).join(' ');
    const signatureInput = `sig1=(${componentsList});keyid="${keyId}";alg="${algorithm}";created=${now}`;

    // Create request
    const request: TAPVerificationRequest = {
      method,
      path,
      headers: {
        ...headers,
        'signature': signature,
        'signature-input': signatureInput,
      },
    };

    // Verify
    const result = await verifyHTTPMessageSignature(request, publicKeyPem, algorithm);

    expect(result.valid).toBe(true);
    expect(result.error).toBeUndefined();
  });

  test('verifies valid Ed25519 signature with PEM key (sig2, TAP standard)', async () => {
    const now = Math.floor(Date.now() / 1000);
    const expires = now + 300; // 5 minutes
    const keyId = 'ed-key-1';
    const algorithm = 'Ed25519';
    const nonce = 'nonce_ed25519_test';
    const tag = 'agent-browser-auth';
    
    // Generate Ed25519 key pair
    const { publicKeyPem, privateKey } = await generateEd25519KeyPair();

    // Build request
    const method = 'GET';
    const path = '/api/browse';
    const headers: Record<string, string> = {
      'host': 'example.com',
    };

    const components = ['@authority', '@path'];

    // Build TAP signature base
    const signatureBase = buildTAPSignatureBase(
      method,
      path,
      headers,
      components,
      now,
      keyId,
      algorithm,
      expires,
      nonce,
      tag
    );

    // Sign it
    const signature = await signMessageEd25519(signatureBase, privateKey, 'sig2');

    // Build signature-input header
    const componentsList = components.map(c => `"${c}"`).join(' ');
    const signatureInput = `sig2=(${componentsList});created=${now};keyid="${keyId}";alg="${algorithm}";expires=${expires};nonce="${nonce}";tag="${tag}"`;

    // Create request
    const request: TAPVerificationRequest = {
      method,
      path,
      headers: {
        ...headers,
        'signature': signature,
        'signature-input': signatureInput,
      },
    };

    // Verify
    const result = await verifyHTTPMessageSignature(request, publicKeyPem, algorithm);

    expect(result.valid).toBe(true);
    expect(result.error).toBeUndefined();
    expect(result.metadata?.nonce).toBe(nonce);
    expect(result.metadata?.tag).toBe(tag);
  });

  test('verifies Ed25519 signature with raw 32-byte key', async () => {
    const now = Math.floor(Date.now() / 1000);
    const expires = now + 300;
    const keyId = 'ed-key-raw';
    const algorithm = 'Ed25519';
    
    // Generate Ed25519 key pair
    const { publicKeyRaw, privateKey } = await generateEd25519KeyPair();

    // Build request
    const method = 'POST';
    const path = '/api/purchase';
    const headers: Record<string, string> = {
      'host': 'botcha.ai',
    };

    const components = ['@authority', '@path'];
    const tag = 'agent-payer-auth';

    // Build TAP signature base
    const signatureBase = buildTAPSignatureBase(
      method,
      path,
      headers,
      components,
      now,
      keyId,
      algorithm,
      expires,
      undefined,
      tag
    );

    // Sign it
    const signature = await signMessageEd25519(signatureBase, privateKey, 'sig2');

    // Build signature-input header
    const componentsList = components.map(c => `"${c}"`).join(' ');
    const signatureInput = `sig2=(${componentsList});created=${now};keyid="${keyId}";alg="${algorithm}";expires=${expires};tag="${tag}"`;

    // Create request
    const request: TAPVerificationRequest = {
      method,
      path,
      headers: {
        ...headers,
        'signature': signature,
        'signature-input': signatureInput,
      },
    };

    // Verify with RAW key instead of PEM
    const result = await verifyHTTPMessageSignature(request, publicKeyRaw, algorithm);

    expect(result.valid).toBe(true);
    expect(result.error).toBeUndefined();
  });

  test('rejects signature with wrong private key', async () => {
    const now = Math.floor(Date.now() / 1000);
    const keyId = 'test-key-1';
    const algorithm = 'ecdsa-p256-sha256';
    
    // Generate TWO different key pairs
    const { publicKeyPem } = await generateTestKeyPair();
    const { privateKey: wrongPrivateKey } = await generateTestKeyPair();

    // Build request
    const method = 'POST';
    const path = '/api/products';
    const headers: Record<string, string> = {
      'x-tap-agent-id': 'agent_test123',
    };

    const components = ['@method', '@path'];
    const signatureBase = buildTestSignatureBase(
      method,
      path,
      headers,
      components,
      now,
      keyId,
      algorithm
    );

    // Sign with WRONG key
    const signature = await signMessage(signatureBase, wrongPrivateKey);

    const componentsList = components.map(c => `"${c}"`).join(' ');
    const signatureInput = `sig1=(${componentsList});keyid="${keyId}";alg="${algorithm}";created=${now}`;

    const request: TAPVerificationRequest = {
      method,
      path,
      headers: {
        ...headers,
        'signature': signature,
        'signature-input': signatureInput,
      },
    };

    // Verify with correct public key (should fail)
    const result = await verifyHTTPMessageSignature(request, publicKeyPem, algorithm);

    expect(result.valid).toBe(false);
    expect(result.error).toBe('Signature verification failed');
  });

  test('rejects signature with tampered data', async () => {
    const now = Math.floor(Date.now() / 1000);
    const keyId = 'test-key-1';
    const algorithm = 'ecdsa-p256-sha256';
    
    const { publicKeyPem, privateKey } = await generateTestKeyPair();

    const method = 'POST';
    const path = '/api/products';
    const headers: Record<string, string> = {
      'x-tap-agent-id': 'agent_original',
    };

    const components = ['@method', '@path', 'x-tap-agent-id'];
    const signatureBase = buildTestSignatureBase(
      method,
      path,
      headers,
      components,
      now,
      keyId,
      algorithm
    );

    const signature = await signMessage(signatureBase, privateKey);

    const componentsList = components.map(c => `"${c}"`).join(' ');
    const signatureInput = `sig1=(${componentsList});keyid="${keyId}";alg="${algorithm}";created=${now}`;

    // Tamper with agent ID after signing
    const request: TAPVerificationRequest = {
      method,
      path,
      headers: {
        'x-tap-agent-id': 'agent_tampered', // Changed!
        'signature': signature,
        'signature-input': signatureInput,
      },
    };

    const result = await verifyHTTPMessageSignature(request, publicKeyPem, algorithm);

    expect(result.valid).toBe(false);
  });

  test('handles invalid PEM format gracefully', async () => {
    const now = Math.floor(Date.now() / 1000);

    const request: TAPVerificationRequest = {
      method: 'POST',
      path: '/api/products',
      headers: {
        'signature': 'sig1=:YWJj:',
        'signature-input': `sig1=("@method");keyid="key1";alg="ecdsa-p256-sha256";created=${now}`,
      },
    };

    const result = await verifyHTTPMessageSignature(request, 'not-a-valid-pem', 'ecdsa-p256-sha256');

    expect(result.valid).toBe(false);
    // Invalid PEM is caught and returns generic failure message
    expect(result.error).toBe('Signature verification failed');
  });

  test('verifies signature with @authority component', async () => {
    const now = Math.floor(Date.now() / 1000);
    const keyId = 'test-key-1';
    const algorithm = 'ecdsa-p256-sha256';
    
    const { publicKeyPem, privateKey } = await generateTestKeyPair();

    const method = 'GET';
    const path = '/api/search';
    const headers: Record<string, string> = {
      'host': 'api.botcha.ai',
    };

    const components = ['@method', '@path', '@authority'];
    const signatureBase = buildTestSignatureBase(
      method,
      path,
      headers,
      components,
      now,
      keyId,
      algorithm
    );

    const signature = await signMessage(signatureBase, privateKey);

    const componentsList = components.map(c => `"${c}"`).join(' ');
    const signatureInput = `sig1=(${componentsList});keyid="${keyId}";alg="${algorithm}";created=${now}`;

    const request: TAPVerificationRequest = {
      method,
      path,
      headers: {
        ...headers,
        'signature': signature,
        'signature-input': signatureInput,
      },
    };

    const result = await verifyHTTPMessageSignature(request, publicKeyPem, algorithm);

    expect(result.valid).toBe(true);
  });

  test('supports :authority pseudo-header', async () => {
    const now = Math.floor(Date.now() / 1000);
    const expires = now + 300;
    const keyId = 'test-key-1';
    const algorithm = 'Ed25519';
    
    const { publicKeyPem, privateKey } = await generateEd25519KeyPair();

    const method = 'GET';
    const path = '/api/test';
    const headers: Record<string, string> = {
      ':authority': 'h2.botcha.ai', // HTTP/2 pseudo-header
    };

    const components = ['@authority', '@path'];
    const signatureBase = buildTAPSignatureBase(
      method,
      path,
      headers,
      components,
      now,
      keyId,
      algorithm,
      expires
    );

    const signature = await signMessageEd25519(signatureBase, privateKey, 'sig2');

    const componentsList = components.map(c => `"${c}"`).join(' ');
    const signatureInput = `sig2=(${componentsList});created=${now};keyid="${keyId}";alg="${algorithm}";expires=${expires}`;

    const request: TAPVerificationRequest = {
      method,
      path,
      headers: {
        ...headers,
        'signature': signature,
        'signature-input': signatureInput,
      },
    };

    const result = await verifyHTTPMessageSignature(request, publicKeyPem, algorithm);

    expect(result.valid).toBe(true);
  });
});
