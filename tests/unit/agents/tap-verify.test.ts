import { describe, test, expect, beforeAll, vi } from 'vitest';
import {
  verifyHTTPMessageSignature,
  parseTAPIntent,
  extractTAPHeaders,
  getVerificationMode,
  buildTAPChallengeResponse,
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
 * Build RFC 9421 signature base for testing
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
  lines.push(`"@signature-params": (${componentsList});keyid="${keyId}";alg="${algorithm}";created=${created}`);
  
  return lines.join('\n');
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
  test('extracts all TAP headers when present', () => {
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
    expect(result.tapHeaders).toEqual({
      'x-tap-agent-id': 'agent_123',
      'x-tap-user-context': '{"user_id":"user_456"}',
      'x-tap-intent': '{"action":"browse"}',
      'x-tap-timestamp': '1234567890',
      'signature': 'sig1=:abc123:',
      'signature-input': 'sig1=("@method" "@path");keyid="key1";alg="ecdsa-p256-sha256";created=1234567890',
    });
  });

  test('returns hasTAPHeaders=false when missing required headers', () => {
    // Test missing agent-id
    let result = extractTAPHeaders({
      'x-tap-intent': '{"action":"browse"}',
      'signature': 'sig1=:abc:',
      'signature-input': 'sig1=();created=123',
    });
    expect(result.hasTAPHeaders).toBe(false);

    // Test missing intent
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
      supported_algorithms: ['ecdsa-p256-sha256', 'rsa-pss-sha256'],
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

  test('rejects expired timestamp (too old)', async () => {
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

  test('rejects future timestamp (too new)', async () => {
    const now = Math.floor(Date.now() / 1000);
    const futureTimestamp = now + 400; // 400 seconds in future

    const request: TAPVerificationRequest = {
      method: 'POST',
      path: '/api/products',
      headers: {
        'signature': 'sig1=:abc123:',
        'signature-input': `sig1=("@method" "@path");keyid="key1";alg="ecdsa-p256-sha256";created=${futureTimestamp}`,
      },
    };

    const result = await verifyHTTPMessageSignature(request, 'fake-key', 'ecdsa-p256-sha256');

    expect(result.valid).toBe(false);
    expect(result.error).toBe('Signature timestamp too old or too new');
  });

  test('accepts timestamp within 5-minute window', async () => {
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

  test('rejects invalid signature format', async () => {
    const now = Math.floor(Date.now() / 1000);

    const request: TAPVerificationRequest = {
      method: 'POST',
      path: '/api/products',
      headers: {
        'signature': 'invalid-signature-format', // Missing sig1=:...:
        'signature-input': `sig1=("@method" "@path");keyid="key1";alg="ecdsa-p256-sha256";created=${now}`,
      },
    };

    const result = await verifyHTTPMessageSignature(request, 'fake-key', 'ecdsa-p256-sha256');

    expect(result.valid).toBe(false);
  });

  test('verifies valid ECDSA P-256 signature', async () => {
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
});
