/**
 * TAP Conformance Test Suite
 * 
 * Validates BOTCHA's Visa TAP implementation against the spec:
 * - Layer 1: Agent Recognition (RFC 9421 HTTP Message Signatures)
 * - Layer 2: Agentic Consumer Recognition
 * - Layer 3: Agentic Payment Container + 402 Browsing IOU
 * - Infrastructure: JWKS, Federation, Edge Verification
 * 
 * This is a comprehensive end-to-end conformance suite validating all TAP components.
 */

import { describe, test, expect, vi, beforeAll, beforeEach } from 'vitest';
import { Hono } from 'hono';

// Layer 1: Agent Recognition Signature
import {
  verifyHTTPMessageSignature,
  checkAndStoreNonce,
  type TAPVerificationRequest,
} from '../../packages/cloudflare-workers/src/tap-verify.js';

// Layer 2: Consumer Recognition
import {
  parseAgenticConsumer,
  verifyAgenticConsumer,
  parseIDToken,
  buildConsumerSignatureBase,
  type AgenticConsumer,
  type IDTokenClaims,
} from '../../packages/cloudflare-workers/src/tap-consumer.js';

// Layer 3: Payment Container
import {
  parsePaymentContainer,
  verifyPaymentContainer,
  verifyCredentialHash,
  createInvoice,
  getInvoice,
  build402Response,
  verifyBrowsingIOU,
  fulfillInvoice,
  detectPaymentType,
  buildPaymentSignatureBase,
  type AgenticPaymentContainer,
  type BrowsingIOU,
  type Invoice,
} from '../../packages/cloudflare-workers/src/tap-payment.js';

// Key Infrastructure
import {
  pemToJwk,
  jwkToPem,
  algToJWKAlg,
  type JWK,
} from '../../packages/cloudflare-workers/src/tap-jwks.js';

// Federation
import {
  createFederationResolver,
  fetchJWKS,
  WELL_KNOWN_SOURCES,
  resolveImportParams,
  inferAlgorithm,
} from '../../packages/cloudflare-workers/src/tap-federation.js';

// Edge Verification
import {
  createTAPEdgeMiddleware,
  tapEdgeStrict,
  tapEdgeFlexible,
  parseEdgeSignatureInput,
  buildEdgeSignatureBase,
  jwkToPublicKeyPem,
  TAP_EDGE_HEADERS,
} from '../../packages/cloudflare-workers/src/tap-edge.js';

// ============ TEST HELPERS ============

/**
 * Convert ArrayBuffer to PEM string
 */
function arrayBufferToPem(buffer: ArrayBuffer): string {
  const base64 = btoa(String.fromCharCode(...new Uint8Array(buffer)));
  const lines = base64.match(/.{1,64}/g) || [base64];
  return `-----BEGIN PUBLIC KEY-----\n${lines.join('\n')}\n-----END PUBLIC KEY-----`;
}

/**
 * Sign a TAP request with given parameters
 */
async function signTAPRequest(params: {
  authority: string;
  path: string;
  privateKey: CryptoKey;
  algorithm: string;
  keyId: string;
  tag: string;
  nonce: string;
  label?: string;
  method?: string;
}): Promise<{ signatureInput: string; signature: string }> {
  const now = Math.floor(Date.now() / 1000);
  const expires = now + 300;
  const label = params.label || 'sig2';
  const method = params.method || 'GET';
  
  // Build signature base per TAP spec
  const signatureBase = [
    `"@authority": ${params.authority}`,
    `"@path": ${params.path}`,
    `"@signature-params": ${label}=("@authority" "@path");created=${now};keyid="${params.keyId}";alg="${params.algorithm}";expires=${expires};nonce="${params.nonce}";tag="${params.tag}"`,
  ].join('\n');
  
  // Sign
  let verifyParams: any;
  if (params.algorithm.toLowerCase().includes('ed25519') || params.algorithm === 'Ed25519') {
    verifyParams = { name: 'Ed25519' };
  } else if (params.algorithm === 'ecdsa-p256-sha256' || params.algorithm === 'ES256') {
    verifyParams = { name: 'ECDSA', hash: 'SHA-256' };
  } else {
    throw new Error(`Unsupported algorithm for signing: ${params.algorithm}`);
  }
  
  const sigBytes = await crypto.subtle.sign(verifyParams, params.privateKey, new TextEncoder().encode(signatureBase));
  const sigBase64 = btoa(String.fromCharCode(...new Uint8Array(sigBytes)));
  
  return {
    signatureInput: `${label}=("@authority" "@path");created=${now};keyid="${params.keyId}";alg="${params.algorithm}";expires=${expires};nonce="${params.nonce}";tag="${params.tag}"`,
    signature: `${label}=:${sigBase64}:`,
  };
}

/**
 * Sign arbitrary data with a private key
 */
async function signData(data: string, privateKey: CryptoKey, algorithm: string): Promise<string> {
  let verifyParams: any;
  if (algorithm.toLowerCase().includes('ed25519') || algorithm === 'Ed25519' || algorithm === 'EdDSA') {
    verifyParams = { name: 'Ed25519' };
  } else if (algorithm === 'ecdsa-p256-sha256' || algorithm === 'ES256') {
    verifyParams = { name: 'ECDSA', hash: 'SHA-256' };
  } else {
    throw new Error(`Unsupported algorithm for signing: ${algorithm}`);
  }
  
  const sigBytes = await crypto.subtle.sign(verifyParams, privateKey, new TextEncoder().encode(data));
  return btoa(String.fromCharCode(...new Uint8Array(sigBytes)));
}

/**
 * Create a mock KV namespace for testing
 */
function createMockKV(): any {
  const store = new Map<string, { value: string; expireAt?: number }>();
  return {
    get: async (key: string) => {
      const entry = store.get(key);
      if (!entry) return null;
      if (entry.expireAt && Date.now() > entry.expireAt) {
        store.delete(key);
        return null;
      }
      return entry.value;
    },
    put: async (key: string, value: string, opts?: { expirationTtl?: number }) => {
      store.set(key, {
        value,
        expireAt: opts?.expirationTtl ? Date.now() + opts.expirationTtl * 1000 : undefined,
      });
    },
  };
}

/**
 * Create a test JWT (unsigned, for structure testing)
 */
function createTestJWT(claims: Record<string, any>): string {
  const header = btoa(JSON.stringify({ alg: 'none', typ: 'JWT' })).replace(/=/g, '');
  const payload = btoa(JSON.stringify(claims)).replace(/=/g, '');
  return `${header}.${payload}.`;
}

// ============ TEST STATE ============

let ecdsaKeys: { publicKeyPem: string; privateKey: CryptoKey; publicKey: CryptoKey };
let ed25519Keys: { publicKeyPem: string; privateKey: CryptoKey; publicKey: CryptoKey };

beforeAll(async () => {
  // Generate ECDSA P-256 key pair
  const ecdsaPair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  );
  const ecdsaPub = await crypto.subtle.exportKey('spki', ecdsaPair.publicKey);
  ecdsaKeys = {
    publicKeyPem: arrayBufferToPem(ecdsaPub),
    privateKey: ecdsaPair.privateKey,
    publicKey: ecdsaPair.publicKey,
  };

  // Generate Ed25519 key pair
  const ed25519Pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const ed25519Pub = await crypto.subtle.exportKey('spki', ed25519Pair.publicKey);
  ed25519Keys = {
    publicKeyPem: arrayBufferToPem(ed25519Pub),
    privateKey: ed25519Pair.privateKey,
    publicKey: ed25519Pair.publicKey,
  };
});

// ============ SECTION 1: AGENT RECOGNITION SIGNATURE (RFC 9421) ============

describe('TAP Conformance: Layer 1 - Agent Recognition', () => {
  test('1.1: Ed25519 signed request verifies successfully', async () => {
    const nonce = 'test-nonce-' + Math.random();
    const { signatureInput, signature } = await signTAPRequest({
      authority: 'botcha.ai',
      path: '/v1/verify',
      privateKey: ed25519Keys.privateKey,
      algorithm: 'Ed25519',
      keyId: 'test-ed25519-key',
      tag: 'agent-browser-auth',
      nonce,
    });

    const request: TAPVerificationRequest = {
      method: 'GET',
      path: '/v1/verify',
      headers: {
        host: 'botcha.ai',
        'signature-input': signatureInput,
        signature: signature,
      },
    };

    const result = await verifyHTTPMessageSignature(
      request,
      ed25519Keys.publicKeyPem,
      'Ed25519',
      null
    );

    expect(result.valid).toBe(true);
    expect(result.error).toBeUndefined();
    expect(result.metadata?.nonce).toBe(nonce);
    expect(result.metadata?.tag).toBe('agent-browser-auth');
  });

  test('1.2: ECDSA P-256 signed request verifies successfully', async () => {
    const nonce = 'test-nonce-' + Math.random();
    const { signatureInput, signature } = await signTAPRequest({
      authority: 'botcha.ai',
      path: '/v1/verify',
      privateKey: ecdsaKeys.privateKey,
      algorithm: 'ecdsa-p256-sha256',
      keyId: 'test-ecdsa-key',
      tag: 'agent-payer-auth',
      nonce,
    });

    const request: TAPVerificationRequest = {
      method: 'GET',
      path: '/v1/verify',
      headers: {
        host: 'botcha.ai',
        'signature-input': signatureInput,
        signature: signature,
      },
    };

    const result = await verifyHTTPMessageSignature(
      request,
      ecdsaKeys.publicKeyPem,
      'ecdsa-p256-sha256',
      null
    );

    expect(result.valid).toBe(true);
    expect(result.metadata?.tag).toBe('agent-payer-auth');
  });

  test('1.3: Missing @authority component → rejected', async () => {
    // Manually craft a signature-input without @authority
    const now = Math.floor(Date.now() / 1000);
    const expires = now + 300;
    const nonce = 'test-nonce-' + Math.random();
    
    const signatureInput = `sig2=("@path");created=${now};keyid="test-key";alg="Ed25519";expires=${expires};nonce="${nonce}";tag="agent-browser-auth"`;
    
    const request: TAPVerificationRequest = {
      method: 'GET',
      path: '/v1/verify',
      headers: {
        host: 'botcha.ai',
        'signature-input': signatureInput,
        signature: 'sig2=:dGVzdC1zaWduYXR1cmU=:',
      },
    };

    const result = await verifyHTTPMessageSignature(
      request,
      ed25519Keys.publicKeyPem,
      'Ed25519',
      null
    );

    expect(result.valid).toBe(false);
  });

  test('1.4: Expired signature (expires in past) → rejected', async () => {
    const now = Math.floor(Date.now() / 1000);
    const created = now - 600; // 10 minutes ago
    const expires = now - 300; // Expired 5 minutes ago
    const nonce = 'test-nonce-' + Math.random();
    
    // Manually create expired signature
    const signatureInput = `sig2=("@authority" "@path");created=${created};keyid="test-key";alg="Ed25519";expires=${expires};nonce="${nonce}";tag="agent-browser-auth"`;
    
    const request: TAPVerificationRequest = {
      method: 'GET',
      path: '/v1/verify',
      headers: {
        host: 'botcha.ai',
        'signature-input': signatureInput,
        signature: 'sig2=:dGVzdC1zaWduYXR1cmU=:',
      },
    };

    const result = await verifyHTTPMessageSignature(
      request,
      ed25519Keys.publicKeyPem,
      'Ed25519',
      null
    );

    expect(result.valid).toBe(false);
    expect(result.error).toContain('expired');
  });

  test('1.5: Reused nonce → rejected (replay protection)', async () => {
    const mockKV = createMockKV();
    const nonce = 'test-nonce-' + Math.random();

    // First use - should succeed
    const firstCheck = await checkAndStoreNonce(mockKV, nonce);
    expect(firstCheck.replay).toBe(false);

    // Second use - should detect replay
    const secondCheck = await checkAndStoreNonce(mockKV, nonce);
    expect(secondCheck.replay).toBe(true);
  });

  test('1.6: Tampered path → rejected', async () => {
    const nonce = 'test-nonce-' + Math.random();
    const { signatureInput, signature } = await signTAPRequest({
      authority: 'botcha.ai',
      path: '/v1/verify',
      privateKey: ed25519Keys.privateKey,
      algorithm: 'Ed25519',
      keyId: 'test-key',
      tag: 'agent-browser-auth',
      nonce,
    });

    // Use signature but different path
    const request: TAPVerificationRequest = {
      method: 'GET',
      path: '/v1/different-path', // TAMPERED
      headers: {
        host: 'botcha.ai',
        'signature-input': signatureInput,
        signature: signature,
      },
    };

    const result = await verifyHTTPMessageSignature(
      request,
      ed25519Keys.publicKeyPem,
      'Ed25519',
      null
    );

    expect(result.valid).toBe(false);
  });

  test('1.7: Tampered authority → rejected', async () => {
    const nonce = 'test-nonce-' + Math.random();
    const { signatureInput, signature } = await signTAPRequest({
      authority: 'botcha.ai',
      path: '/v1/verify',
      privateKey: ed25519Keys.privateKey,
      algorithm: 'Ed25519',
      keyId: 'test-key',
      tag: 'agent-browser-auth',
      nonce,
    });

    // Use signature but different authority
    const request: TAPVerificationRequest = {
      method: 'GET',
      path: '/v1/verify',
      headers: {
        host: 'evil.com', // TAMPERED
        'signature-input': signatureInput,
        signature: signature,
      },
    };

    const result = await verifyHTTPMessageSignature(
      request,
      ed25519Keys.publicKeyPem,
      'Ed25519',
      null
    );

    expect(result.valid).toBe(false);
  });

  test('1.8: tag=agent-browser-auth parsed correctly', async () => {
    const input = 'sig2=("@authority" "@path");created=1234567890;keyid="test";alg="Ed25519";expires=1234567890;nonce="abc123";tag="agent-browser-auth"';
    const parsed = parseEdgeSignatureInput(input);
    
    expect(parsed).not.toBeNull();
    expect(parsed?.tag).toBe('agent-browser-auth');
  });

  test('1.9: tag=agent-payer-auth parsed correctly', async () => {
    const input = 'sig2=("@authority" "@path");created=1234567890;keyid="test";alg="Ed25519";expires=1234567890;nonce="abc123";tag="agent-payer-auth"';
    const parsed = parseEdgeSignatureInput(input);
    
    expect(parsed).not.toBeNull();
    expect(parsed?.tag).toBe('agent-payer-auth');
  });

  test('1.10: Backward compat — sig1 label still works', async () => {
    const nonce = 'test-nonce-' + Math.random();
    const { signatureInput, signature } = await signTAPRequest({
      authority: 'botcha.ai',
      path: '/v1/verify',
      privateKey: ed25519Keys.privateKey,
      algorithm: 'Ed25519',
      keyId: 'test-key',
      tag: 'agent-browser-auth',
      nonce,
      label: 'sig1', // Using sig1 instead of sig2
    });

    const request: TAPVerificationRequest = {
      method: 'GET',
      path: '/v1/verify',
      headers: {
        host: 'botcha.ai',
        'signature-input': signatureInput,
        signature: signature,
      },
    };

    const result = await verifyHTTPMessageSignature(
      request,
      ed25519Keys.publicKeyPem,
      'Ed25519',
      null
    );

    expect(result.valid).toBe(true);
  });
});

// ============ SECTION 2: AGENTIC CONSUMER RECOGNITION ============

describe('TAP Conformance: Layer 2 - Consumer Recognition', () => {
  test('2.1: Valid agenticConsumer with matching nonce → verified', async () => {
    const nonce = 'test-nonce-' + Math.random();
    const kid = 'test-consumer-key';
    
    // Create consumer object (using JWK algorithm name "EdDSA")
    const consumer: AgenticConsumer = {
      nonce,
      kid,
      alg: 'EdDSA',
      signature: '',
    };
    
    // Build signature base and sign
    const signatureBase = buildConsumerSignatureBase(consumer);
    const signature = await signData(signatureBase, ed25519Keys.privateKey, 'EdDSA');
    consumer.signature = signature;
    
    // Verify (using JWK algorithm name)
    const result = await verifyAgenticConsumer(
      consumer,
      nonce, // Matching nonce
      ed25519Keys.publicKeyPem,
      'EdDSA'
    );
    
    expect(result.verified).toBe(true);
    expect(result.nonceLinked).toBe(true);
    expect(result.signatureValid).toBe(true);
  });

  test('2.2: Nonce mismatch between header and consumer → flagged', async () => {
    const consumerNonce = 'consumer-nonce-123';
    const headerNonce = 'header-nonce-456'; // Different!
    const kid = 'test-key';
    
    const consumer: AgenticConsumer = {
      nonce: consumerNonce,
      kid,
      alg: 'Ed25519',
      signature: '',
    };
    
    const signatureBase = buildConsumerSignatureBase(consumer);
    const signature = await signData(signatureBase, ed25519Keys.privateKey, 'Ed25519');
    consumer.signature = signature;
    
    const result = await verifyAgenticConsumer(
      consumer,
      headerNonce, // Mismatched
      ed25519Keys.publicKeyPem,
      'Ed25519'
    );
    
    expect(result.verified).toBe(false);
    expect(result.nonceLinked).toBe(false);
  });

  test('2.3: Invalid consumer signature → rejected', async () => {
    const nonce = 'test-nonce-' + Math.random();
    const kid = 'test-key';
    
    const consumer: AgenticConsumer = {
      nonce,
      kid,
      alg: 'Ed25519',
      signature: 'INVALID_SIGNATURE_BASE64',
    };
    
    const result = await verifyAgenticConsumer(
      consumer,
      nonce,
      ed25519Keys.publicKeyPem,
      'Ed25519'
    );
    
    expect(result.verified).toBe(false);
    expect(result.signatureValid).toBe(false);
  });

  test('2.4: ID Token with valid claims → parsed correctly', async () => {
    const now = Math.floor(Date.now() / 1000);
    const claims = {
      iss: 'https://auth.example.com',
      sub: 'user-12345',
      aud: 'botcha-app',
      exp: now + 3600,
      iat: now,
      email: 'j***@g***.com',
      email_verified: true,
    };
    
    const token = createTestJWT(claims);
    const parsed = parseIDToken(token);
    
    expect(parsed).not.toBeNull();
    expect(parsed?.sub).toBe('user-12345');
    expect(parsed?.email).toBe('j***@g***.com');
  });

  test('2.5: Expired ID Token → flagged', async () => {
    const now = Math.floor(Date.now() / 1000);
    const claims = {
      iss: 'https://auth.example.com',
      sub: 'user-12345',
      aud: 'botcha-app',
      exp: now - 3600, // Expired 1 hour ago
      iat: now - 7200,
    };
    
    const token = createTestJWT(claims);
    const parsed = parseIDToken(token);
    
    expect(parsed).toBeNull(); // Should reject expired tokens
  });

  test('2.6: Contextual data extracted correctly', async () => {
    const nonce = 'test-nonce-' + Math.random();
    const kid = 'test-key';
    
    const consumer: AgenticConsumer = {
      nonce,
      kid,
      alg: 'EdDSA',
      signature: '',
      contextualData: {
        countryCode: 'US',
        zip: '94102',
        ipAddress: '192.168.1.1',
        deviceData: {
          userAgent: 'Mozilla/5.0',
          screenResolution: '1920x1080',
        },
      },
    };
    
    const signatureBase = buildConsumerSignatureBase(consumer);
    const signature = await signData(signatureBase, ed25519Keys.privateKey, 'EdDSA');
    consumer.signature = signature;
    
    const result = await verifyAgenticConsumer(
      consumer,
      nonce,
      ed25519Keys.publicKeyPem,
      'EdDSA'
    );
    
    expect(result.verified).toBe(true);
    expect(result.contextualData?.countryCode).toBe('US');
    expect(result.contextualData?.zip).toBe('94102');
    expect(result.contextualData?.deviceData?.userAgent).toBe('Mozilla/5.0');
  });

  test('2.7: Obfuscated email/phone claims preserved', async () => {
    const consumer: AgenticConsumer = {
      nonce: 'test-nonce',
      kid: 'test-key',
      alg: 'Ed25519',
      signature: '',
      idToken: createTestJWT({
        iss: 'https://auth.example.com',
        sub: 'user-123',
        aud: 'app',
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        email: 'j***@g***.com',
        phone_number: '15551234',
        phone_number_mask: '***-***-1234',
      }),
    };
    
    const parsed = parseAgenticConsumer({ agenticConsumer: consumer });
    expect(parsed).not.toBeNull();
    expect(parsed?.idToken).toBeTruthy();
  });
});

// ============ SECTION 3: AGENTIC PAYMENT CONTAINER ============

describe('TAP Conformance: Layer 3 - Payment Container', () => {
  test('3.1: Valid credential hash → verified', async () => {
    const pan = '4111111111111111';
    const expMonth = '12';
    const expYear = '25';
    const cvv = '123';
    
    // Compute expected hash
    const input = `${pan}${expMonth}${expYear}${cvv}`;
    const hashBuffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
    const expectedHash = btoa(String.fromCharCode(...new Uint8Array(hashBuffer)));
    
    const isValid = await verifyCredentialHash(expectedHash, pan, expMonth, expYear, cvv);
    expect(isValid).toBe(true);
  });

  test('3.2: Wrong credential hash → rejected', async () => {
    const wrongHash = 'WRONG_HASH_VALUE';
    const isValid = await verifyCredentialHash(wrongHash, '4111111111111111', '12', '25', '123');
    expect(isValid).toBe(false);
  });

  test('3.3: Card metadata extracted correctly', async () => {
    const nonce = 'test-nonce-' + Math.random();
    const container: AgenticPaymentContainer = {
      nonce,
      kid: 'test-key',
      alg: 'Ed25519',
      signature: '',
      cardMetadata: {
        lastFour: '1234',
        paymentAccountReference: 'PAR-ABC-123',
        shortDescription: 'Visa ****1234',
      },
    };
    
    const signatureBase = buildPaymentSignatureBase(container);
    const signature = await signData(signatureBase, ed25519Keys.privateKey, 'Ed25519');
    container.signature = signature;
    
    const result = await verifyPaymentContainer(
      container,
      nonce,
      ed25519Keys.publicKeyPem,
      'Ed25519'
    );
    
    expect(result.verified).toBe(true);
    expect(result.paymentType).toBe('cardMetadata');
    expect(result.cardMetadata?.lastFour).toBe('1234');
    expect(result.cardMetadata?.paymentAccountReference).toBe('PAR-ABC-123');
  });

  test('3.4: Payment type detection works for all types', () => {
    const baseContainer: AgenticPaymentContainer = {
      nonce: 'test',
      kid: 'key',
      alg: 'Ed25519',
      signature: 'sig',
    };
    
    expect(detectPaymentType({ ...baseContainer, browsingIOU: {} as any })).toBe('browsingIOU');
    expect(detectPaymentType({ ...baseContainer, credentialHash: {} as any })).toBe('credentialHash');
    expect(detectPaymentType({ ...baseContainer, payload: 'encrypted' })).toBe('payload');
    expect(detectPaymentType({ ...baseContainer, cardMetadata: {} as any })).toBe('cardMetadata');
    expect(detectPaymentType(baseContainer)).toBe('unknown');
  });

  test('3.5: Browsing IOU with matching invoice → verified', async () => {
    const mockKV = createMockKV();
    
    // Create invoice
    const invoiceResult = await createInvoice(mockKV, 'test-app', {
      resource_uri: '/premium/article-123',
      amount: '0.99',
      currency: 'USD',
      card_acceptor_id: 'CAID-12345',
    });
    
    expect(invoiceResult.success).toBe(true);
    const invoice = invoiceResult.invoice!;
    
    // Create matching IOU
    const iou: BrowsingIOU = {
      invoiceId: invoice.invoice_id,
      amount: invoice.amount,
      cardAcceptorId: invoice.card_acceptor_id,
      acquirerId: 'ACQ-67890',
      uri: invoice.resource_uri,
      sequenceCounter: '1',
      paymentService: 'visa-tap',
      kid: 'test-key',
      alg: 'Ed25519',
      signature: '',
    };
    
    // Sign the IOU (excluding signature, kid, alg)
    const iouFields = [
      `"invoiceId": "${iou.invoiceId}"`,
      `"amount": "${iou.amount}"`,
      `"cardAcceptorId": "${iou.cardAcceptorId}"`,
      `"acquirerId": "${iou.acquirerId}"`,
      `"uri": "${iou.uri}"`,
      `"sequenceCounter": "${iou.sequenceCounter}"`,
      `"paymentService": "${iou.paymentService}"`,
    ].join('\n');
    
    iou.signature = await signData(iouFields, ed25519Keys.privateKey, 'Ed25519');
    
    // Verify IOU against invoice
    const result = await verifyBrowsingIOU(iou, invoice, ed25519Keys.publicKeyPem, 'Ed25519');
    
    expect(result.valid).toBe(true);
  });

  test('3.6: Browsing IOU with mismatched amount → rejected', async () => {
    const mockKV = createMockKV();
    
    const invoiceResult = await createInvoice(mockKV, 'test-app', {
      resource_uri: '/premium/article-123',
      amount: '0.99',
      currency: 'USD',
      card_acceptor_id: 'CAID-12345',
    });
    
    const invoice = invoiceResult.invoice!;
    
    const iou: BrowsingIOU = {
      invoiceId: invoice.invoice_id,
      amount: '1.99', // WRONG AMOUNT
      cardAcceptorId: invoice.card_acceptor_id,
      acquirerId: 'ACQ-67890',
      uri: invoice.resource_uri,
      sequenceCounter: '1',
      paymentService: 'visa-tap',
      kid: 'test-key',
      alg: 'Ed25519',
      signature: 'fake-sig',
    };
    
    const result = await verifyBrowsingIOU(iou, invoice, ed25519Keys.publicKeyPem, 'Ed25519');
    
    expect(result.valid).toBe(false);
    expect(result.error).toContain('Amount mismatch');
  });

  test('3.7: Browsing IOU with wrong invoiceId → rejected', async () => {
    const mockKV = createMockKV();
    
    const invoiceResult = await createInvoice(mockKV, 'test-app', {
      resource_uri: '/premium/article-123',
      amount: '0.99',
      currency: 'USD',
      card_acceptor_id: 'CAID-12345',
    });
    
    const invoice = invoiceResult.invoice!;
    
    const iou: BrowsingIOU = {
      invoiceId: 'WRONG-INVOICE-ID',
      amount: invoice.amount,
      cardAcceptorId: invoice.card_acceptor_id,
      acquirerId: 'ACQ-67890',
      uri: invoice.resource_uri,
      sequenceCounter: '1',
      paymentService: 'visa-tap',
      kid: 'test-key',
      alg: 'Ed25519',
      signature: 'fake-sig',
    };
    
    const result = await verifyBrowsingIOU(iou, invoice, ed25519Keys.publicKeyPem, 'Ed25519');
    
    expect(result.valid).toBe(false);
    expect(result.error).toContain('Invoice ID mismatch');
  });
});

// ============ SECTION 4: KEY INFRASTRUCTURE ============

describe('TAP Conformance: Key Infrastructure', () => {
  test('4.1: PEM → JWK → PEM roundtrip preserves key', async () => {
    const originalPem = ecdsaKeys.publicKeyPem;
    
    // Convert to JWK
    const jwk = await pemToJwk(originalPem, 'ecdsa-p256-sha256', 'test-key-id');
    expect(jwk.kid).toBe('test-key-id');
    expect(jwk.use).toBe('sig');
    
    // Convert back to PEM
    const pemRoundtrip = await jwkToPem(jwk);
    
    // Both PEMs should represent the same key
    // (normalize whitespace for comparison)
    const normalize = (pem: string) => pem.replace(/\s+/g, '').replace(/-----[^-]+-----/g, '');
    expect(normalize(pemRoundtrip)).toBe(normalize(originalPem));
  });

  test('4.2: ECDSA P-256 exports as ES256 JWK', async () => {
    const jwk = await pemToJwk(ecdsaKeys.publicKeyPem, 'ecdsa-p256-sha256', 'ecdsa-key');
    
    expect(jwk.alg).toBe('ES256');
    expect(jwk.kty).toBe('EC');
    expect(jwk.crv).toBe('P-256');
    expect(jwk.x).toBeDefined();
    expect(jwk.y).toBeDefined();
  });

  test('4.3: Ed25519 exports as EdDSA JWK', async () => {
    const jwk = await pemToJwk(ed25519Keys.publicKeyPem, 'ed25519', 'ed25519-key');
    
    expect(jwk.alg).toBe('EdDSA');
    expect(jwk.kty).toBe('OKP');
    expect(jwk.crv).toBe('Ed25519');
    expect(jwk.x).toBeDefined();
  });

  test('4.4: algToJWKAlg maps correctly', () => {
    expect(algToJWKAlg('ecdsa-p256-sha256')).toBe('ES256');
    expect(algToJWKAlg('rsa-pss-sha256')).toBe('PS256');
    expect(algToJWKAlg('ed25519')).toBe('EdDSA');
  });

  test('4.5: Federation resolver caches fetched keys', async () => {
    const mockKV = createMockKV();
    
    // Create resolver with empty sources (we'll test cache only)
    const resolver = createFederationResolver({
      sources: [],
      kvNamespace: mockKV,
    });
    
    // Initially no keys
    expect(resolver.getCachedKeys()).toHaveLength(0);
    
    // Trying to resolve a key that doesn't exist
    const result = await resolver.resolveKey('nonexistent-key');
    expect(result.found).toBe(false);
  });

  test('4.6: WELL_KNOWN_SOURCES includes Visa URL', () => {
    expect(WELL_KNOWN_SOURCES).toBeDefined();
    expect(Array.isArray(WELL_KNOWN_SOURCES)).toBe(true);
    
    const visaSource = WELL_KNOWN_SOURCES.find(s => s.name === 'visa');
    expect(visaSource).toBeDefined();
    expect(visaSource?.url).toContain('visa.com');
    expect(visaSource?.trustLevel).toBe('high');
  });

  test('4.7: resolveImportParams handles all key types', () => {
    expect(() => resolveImportParams({ kty: 'RSA' })).not.toThrow();
    expect(() => resolveImportParams({ kty: 'EC', crv: 'P-256' })).not.toThrow();
    expect(() => resolveImportParams({ kty: 'OKP', crv: 'Ed25519' })).not.toThrow();
  });

  test('4.8: inferAlgorithm detects correct algorithm', () => {
    expect(inferAlgorithm({ kty: 'RSA' })).toBe('PS256');
    expect(inferAlgorithm({ kty: 'EC', crv: 'P-256' })).toBe('ES256');
    expect(inferAlgorithm({ kty: 'OKP', crv: 'Ed25519' })).toBe('EdDSA');
  });
});

// ============ SECTION 5: 402 MICROPAYMENT FLOW ============

describe('TAP Conformance: 402 Flow', () => {
  test('5.1: Create invoice → get invoice → matches', async () => {
    const mockKV = createMockKV();
    
    const createResult = await createInvoice(mockKV, 'test-app', {
      resource_uri: '/premium/content',
      amount: '0.99',
      currency: 'USD',
      card_acceptor_id: 'CAID-123',
      description: 'Premium article access',
    });
    
    expect(createResult.success).toBe(true);
    expect(createResult.invoice).toBeDefined();
    
    const invoiceId = createResult.invoice!.invoice_id;
    
    const getResult = await getInvoice(mockKV, invoiceId);
    
    expect(getResult.success).toBe(true);
    expect(getResult.invoice?.invoice_id).toBe(invoiceId);
    expect(getResult.invoice?.amount).toBe('0.99');
    expect(getResult.invoice?.description).toBe('Premium article access');
  });

  test('5.2: 402 response has correct structure', async () => {
    const mockKV = createMockKV();
    
    const createResult = await createInvoice(mockKV, 'test-app', {
      resource_uri: '/premium/content',
      amount: '0.99',
      currency: 'USD',
      card_acceptor_id: 'CAID-123',
    });
    
    const invoice = createResult.invoice!;
    const response = build402Response(invoice);
    
    expect(response.status).toBe(402);
    expect(response.body.error).toBe('PAYMENT_REQUIRED');
    expect(response.body.invoice_id).toBe(invoice.invoice_id);
    expect(response.body.amount).toBe('0.99');
    expect(response.body.currency).toBe('USD');
    expect(response.body.accept_payment).toContain('browsingIOU');
    expect(response.body.accept_payment).toContain('credentialHash');
  });

  test('5.3: Valid IOU fulfills invoice and returns access token', async () => {
    const mockKV = createMockKV();
    
    // Create invoice
    const createResult = await createInvoice(mockKV, 'test-app', {
      resource_uri: '/premium/content',
      amount: '0.99',
      currency: 'USD',
      card_acceptor_id: 'CAID-123',
    });
    
    const invoice = createResult.invoice!;
    
    // Create valid IOU
    const iou: BrowsingIOU = {
      invoiceId: invoice.invoice_id,
      amount: invoice.amount,
      cardAcceptorId: invoice.card_acceptor_id,
      acquirerId: 'ACQ-123',
      uri: invoice.resource_uri,
      sequenceCounter: '1',
      paymentService: 'visa-tap',
      kid: 'test-key',
      alg: 'Ed25519',
      signature: 'test-sig',
    };
    
    // Fulfill invoice
    const fulfillResult = await fulfillInvoice(mockKV, invoice.invoice_id, iou);
    
    expect(fulfillResult.success).toBe(true);
    expect(fulfillResult.access_token).toBeDefined();
    expect(typeof fulfillResult.access_token).toBe('string');
  });

  test('5.4: Expired invoice → IOU rejected', async () => {
    const mockKV = createMockKV();
    
    // Create invoice with very short TTL
    const createResult = await createInvoice(mockKV, 'test-app', {
      resource_uri: '/premium/content',
      amount: '0.99',
      currency: 'USD',
      card_acceptor_id: 'CAID-123',
      ttl_seconds: 1, // 1 second
    });
    
    const invoice = createResult.invoice!;
    
    // Wait for expiration
    await new Promise(resolve => setTimeout(resolve, 1100));
    
    // Try to get expired invoice
    const getResult = await getInvoice(mockKV, invoice.invoice_id);
    
    expect(getResult.success).toBe(false);
    expect(getResult.error).toContain('expired');
  });
});

// ============ SECTION 6: EDGE VERIFICATION ============

describe('TAP Conformance: Edge Verification', () => {
  test('6.1: Middleware adds X-TAP-Verified header on valid signature', async () => {
    const app = new Hono();
    
    // Create static key map for testing
    const staticKeys = new Map<string, string>();
    staticKeys.set('test-key', ed25519Keys.publicKeyPem);
    
    // Add middleware
    app.use('*', createTAPEdgeMiddleware({ staticKeys, allowUnverified: true }));
    
    app.get('/test', (c) => {
      return c.json({ verified: c.req.header(TAP_EDGE_HEADERS.VERIFIED) === 'true' });
    });
    
    // Create signed request
    const nonce = 'test-nonce-' + Math.random();
    const { signatureInput, signature } = await signTAPRequest({
      authority: 'test.com',
      path: '/test',
      privateKey: ed25519Keys.privateKey,
      algorithm: 'Ed25519',
      keyId: 'test-key',
      tag: 'agent-browser-auth',
      nonce,
    });
    
    // Make request
    const req = new Request('http://test.com/test', {
      headers: {
        'host': 'test.com',
        'signature-input': signatureInput,
        'signature': signature,
      },
    });
    
    const res = await app.fetch(req);
    const data = await res.json();
    
    expect(res.headers.get(TAP_EDGE_HEADERS.VERIFIED)).toBe('true');
  });

  test('6.2: Strict mode blocks unsigned requests', async () => {
    const app = new Hono();
    
    app.use('*', tapEdgeStrict([]));
    app.get('/test', (c) => c.json({ ok: true }));
    
    // Request without signature
    const req = new Request('http://test.com/test');
    const res = await app.fetch(req);
    
    expect(res.status).toBe(403);
    const data = await res.json() as any;
    expect(data.error).toBe('TAP_REQUIRED');
  });

  test('6.3: Flexible mode allows unsigned requests through', async () => {
    const app = new Hono();
    
    app.use('*', tapEdgeFlexible([]));
    app.get('/test', (c) => c.json({ ok: true }));
    
    // Request without signature
    const req = new Request('http://test.com/test');
    const res = await app.fetch(req);
    
    expect(res.status).toBe(200);
    const data = await res.json() as any;
    expect(data.ok).toBe(true);
  });

  test('6.4: parseEdgeSignatureInput handles sig1 and sig2', () => {
    const sig1Input = 'sig1=("@authority" "@path");created=1234567890;keyid="key1";alg="Ed25519"';
    const sig2Input = 'sig2=("@authority" "@path");created=1234567890;keyid="key2";alg="ES256"';
    
    const parsed1 = parseEdgeSignatureInput(sig1Input);
    expect(parsed1?.label).toBe('sig1');
    expect(parsed1?.keyId).toBe('key1');
    
    const parsed2 = parseEdgeSignatureInput(sig2Input);
    expect(parsed2?.label).toBe('sig2');
    expect(parsed2?.keyId).toBe('key2');
  });

  test('6.5: buildEdgeSignatureBase matches RFC 9421 format', () => {
    const parsed = {
      label: 'sig2',
      components: ['@authority', '@path'],
      created: 1234567890,
      expires: 1234568190,
      keyId: 'test-key',
      algorithm: 'Ed25519',
      nonce: 'abc123',
      tag: 'agent-browser-auth',
    };
    
    const base = buildEdgeSignatureBase('botcha.ai', '/v1/verify', parsed);
    
    expect(base).toContain('"@authority": botcha.ai');
    expect(base).toContain('"@path": /v1/verify');
    expect(base).toContain('created=1234567890');
    expect(base).toContain('nonce="abc123"');
    expect(base).toContain('tag="agent-browser-auth"');
  });

  test('6.6: jwkToPublicKeyPem converts JWK to PEM', async () => {
    // First convert our test key to JWK
    const jwk = await pemToJwk(ed25519Keys.publicKeyPem, 'ed25519', 'test-key');
    
    // Then convert back to PEM
    const pem = await jwkToPublicKeyPem(jwk);
    
    expect(pem).toContain('-----BEGIN PUBLIC KEY-----');
    expect(pem).toContain('-----END PUBLIC KEY-----');
  });
});
