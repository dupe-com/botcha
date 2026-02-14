import { describe, test, expect } from 'vitest';
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
  type Invoice,
  type BrowsingIOU,
} from '../../../packages/cloudflare-workers/src/tap-payment.js';
import type { KVNamespace } from '../../../packages/cloudflare-workers/src/agents.js';

// ============ CRYPTO TEST HELPERS ============

/**
 * Generate ECDSA P-256 key pair for testing
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
  return signatureBase64;
}

// ============ MOCK KV NAMESPACE ============

function createMockKV(): KVNamespace {
  const store = new Map<string, { value: string; expires?: number }>();

  return {
    get: async (key: string, _type?: string) => {
      const entry = store.get(key);
      if (!entry) return null;
      
      // Check expiration
      if (entry.expires && entry.expires < Date.now()) {
        store.delete(key);
        return null;
      }
      
      return entry.value;
    },
    put: async (key: string, value: string, opts?: { expirationTtl?: number }) => {
      const entry: { value: string; expires?: number } = { value };
      if (opts?.expirationTtl) {
        entry.expires = Date.now() + opts.expirationTtl * 1000;
      }
      store.set(key, entry);
    },
    delete: async (key: string) => {
      store.delete(key);
    },
    list: async () => ({ keys: [], list_complete: true, cursor: '' }),
    getWithMetadata: async () => ({ value: null, metadata: null }),
    // Add missing methods for interface compliance
  } as any;
}

// ============ TESTS ============

describe('TAP Payment Container', () => {
  
  // ============ PARSING ============
  
  test('parsePaymentContainer extracts from body correctly', () => {
    const body = {
      agenticPaymentContainer: {
        nonce: 'e8N7S2MFd',
        kid: 'poqkLGiymh',
        alg: 'ES256',
        signature: 'jdq0SqOwHdyHr9',
        cardMetadata: {
          lastFour: '1234',
          paymentAccountReference: 'PAR123',
        },
      },
    };

    const container = parsePaymentContainer(body);
    
    expect(container).not.toBeNull();
    expect(container?.nonce).toBe('e8N7S2MFd');
    expect(container?.kid).toBe('poqkLGiymh');
    expect(container?.alg).toBe('ES256');
    expect(container?.signature).toBe('jdq0SqOwHdyHr9');
    expect(container?.cardMetadata?.lastFour).toBe('1234');
  });

  test('parsePaymentContainer returns null for missing required fields', () => {
    // Missing nonce
    expect(parsePaymentContainer({
      agenticPaymentContainer: {
        kid: 'poqk',
        alg: 'ES256',
        signature: 'jdq0',
      },
    })).toBeNull();

    // Missing kid
    expect(parsePaymentContainer({
      agenticPaymentContainer: {
        nonce: 'e8N7',
        alg: 'ES256',
        signature: 'jdq0',
      },
    })).toBeNull();

    // Missing container entirely
    expect(parsePaymentContainer({})).toBeNull();

    // Invalid body
    expect(parsePaymentContainer(null)).toBeNull();
  });

  // ============ PAYMENT TYPE DETECTION ============

  test('detectPaymentType identifies correct payment type', () => {
    const iouContainer: AgenticPaymentContainer = {
      nonce: 'n1',
      kid: 'k1',
      alg: 'ES256',
      signature: 's1',
      browsingIOU: {
        invoiceId: 'inv1',
        amount: '100',
        cardAcceptorId: 'CA123',
        acquirerId: 'ACQ123',
        uri: '/resource',
        sequenceCounter: '1',
        paymentService: 'stripe',
        kid: 'k1',
        alg: 'ES256',
        signature: 's2',
      },
    };

    const hashContainer: AgenticPaymentContainer = {
      nonce: 'n1',
      kid: 'k1',
      alg: 'ES256',
      signature: 's1',
      credentialHash: {
        hash: 'abc123',
        algorithm: 'sha256',
      },
    };

    const cardContainer: AgenticPaymentContainer = {
      nonce: 'n1',
      kid: 'k1',
      alg: 'ES256',
      signature: 's1',
      cardMetadata: {
        lastFour: '1234',
        paymentAccountReference: 'PAR123',
      },
    };

    const emptyContainer: AgenticPaymentContainer = {
      nonce: 'n1',
      kid: 'k1',
      alg: 'ES256',
      signature: 's1',
    };

    expect(detectPaymentType(iouContainer)).toBe('browsingIOU');
    expect(detectPaymentType(hashContainer)).toBe('credentialHash');
    expect(detectPaymentType(cardContainer)).toBe('cardMetadata');
    expect(detectPaymentType(emptyContainer)).toBe('unknown');
  });

  // ============ SIGNATURE VERIFICATION ============

  test('verifyPaymentContainer — nonce linkage check', async () => {
    const { publicKeyPem, privateKey } = await generateTestKeyPair();

    const container: AgenticPaymentContainer = {
      nonce: 'correct-nonce',
      kid: 'key-1',
      alg: 'ES256',
      signature: 'dummy-sig',
      cardMetadata: {
        lastFour: '1234',
        paymentAccountReference: 'PAR123',
      },
    };

    // Wrong header nonce should fail
    const result = await verifyPaymentContainer(
      container,
      'wrong-nonce',
      publicKeyPem,
      'ES256'
    );

    expect(result.verified).toBe(false);
    expect(result.nonceLinked).toBe(false);
    expect(result.error).toContain('Nonce mismatch');
  });

  test('verifyPaymentContainer — signature verification with ECDSA', async () => {
    const { publicKeyPem, privateKey } = await generateTestKeyPair();

    const container: AgenticPaymentContainer = {
      nonce: 'test-nonce',
      kid: 'key-1',
      alg: 'ES256',
      signature: '', // Will be filled below
      cardMetadata: {
        lastFour: '1234',
        paymentAccountReference: 'PAR123',
      },
    };

    // Build signature base
    const signatureBase = buildPaymentSignatureBase(container);

    // Sign it
    const signature = await signMessage(signatureBase, privateKey);
    container.signature = signature;

    // Verify
    const result = await verifyPaymentContainer(
      container,
      'test-nonce',
      publicKeyPem,
      'ES256'
    );

    expect(result.verified).toBe(true);
    expect(result.nonceLinked).toBe(true);
    expect(result.signatureValid).toBe(true);
    expect(result.paymentType).toBe('cardMetadata');
  });

  test('verifyPaymentContainer — rejects tampered data', async () => {
    const { publicKeyPem, privateKey } = await generateTestKeyPair();

    const container: AgenticPaymentContainer = {
      nonce: 'test-nonce',
      kid: 'key-1',
      alg: 'ES256',
      signature: '',
      cardMetadata: {
        lastFour: '1234',
        paymentAccountReference: 'PAR123',
      },
    };

    // Build signature base and sign
    const signatureBase = buildPaymentSignatureBase(container);
    const signature = await signMessage(signatureBase, privateKey);
    container.signature = signature;

    // Tamper with data AFTER signing
    container.cardMetadata!.lastFour = '9999';

    // Verify should fail
    const result = await verifyPaymentContainer(
      container,
      'test-nonce',
      publicKeyPem,
      'ES256'
    );

    expect(result.verified).toBe(false);
    expect(result.nonceLinked).toBe(true);
    expect(result.signatureValid).toBe(false);
  });

  // ============ CREDENTIAL HASH ============

  test('verifyCredentialHash — correct hash matches', async () => {
    const pan = '4532123456789012';
    const expMonth = '12';
    const expYear = '2025';
    const cvv = '123';

    // Compute expected hash
    const input = `${pan}${expMonth}${expYear}${cvv}`;
    const encoder = new TextEncoder();
    const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(input));
    const expectedHash = btoa(String.fromCharCode(...new Uint8Array(hashBuffer)));

    // Verify
    const result = await verifyCredentialHash(expectedHash, pan, expMonth, expYear, cvv);
    expect(result).toBe(true);
  });

  test('verifyCredentialHash — wrong data does not match', async () => {
    const pan = '4532123456789012';
    const expMonth = '12';
    const expYear = '2025';
    const cvv = '123';

    // Compute hash
    const input = `${pan}${expMonth}${expYear}${cvv}`;
    const encoder = new TextEncoder();
    const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(input));
    const correctHash = btoa(String.fromCharCode(...new Uint8Array(hashBuffer)));

    // Verify with wrong CVV
    const result = await verifyCredentialHash(correctHash, pan, expMonth, expYear, '999');
    expect(result).toBe(false);
  });

  // ============ INVOICE MANAGEMENT ============

  test('createInvoice creates with correct fields and TTL', async () => {
    const mockKV = createMockKV();

    const result = await createInvoice(mockKV, 'app-123', {
      resource_uri: '/premium/article',
      amount: '500',
      currency: 'USD',
      card_acceptor_id: 'CA-12345',
      description: 'Premium article access',
      ttl_seconds: 3600,
    });

    expect(result.success).toBe(true);
    expect(result.invoice).toBeDefined();
    expect(result.invoice?.app_id).toBe('app-123');
    expect(result.invoice?.amount).toBe('500');
    expect(result.invoice?.currency).toBe('USD');
    expect(result.invoice?.status).toBe('pending');
    expect(result.invoice?.invoice_id).toMatch(/^[0-9a-f]{32}$/);

    // Verify it was stored
    const getResult = await getInvoice(mockKV, result.invoice!.invoice_id);
    expect(getResult.success).toBe(true);
    expect(getResult.invoice?.invoice_id).toBe(result.invoice?.invoice_id);
  });

  test('build402Response returns correct structure', async () => {
    const invoice: Invoice = {
      invoice_id: 'inv-123',
      app_id: 'app-123',
      resource_uri: '/premium/content',
      amount: '1000',
      currency: 'USD',
      card_acceptor_id: 'CA-12345',
      description: 'Premium content',
      created_at: Math.floor(Date.now() / 1000),
      expires_at: Math.floor(Date.now() / 1000) + 3600,
      status: 'pending',
    };

    const response = build402Response(invoice);

    expect(response.status).toBe(402);
    expect(response.body.error).toBe('PAYMENT_REQUIRED');
    expect(response.body.invoice_id).toBe('inv-123');
    expect(response.body.amount).toBe('1000');
    expect(response.body.currency).toBe('USD');
    expect(response.body.card_acceptor_id).toBe('CA-12345');
    expect(response.body.resource_uri).toBe('/premium/content');
    expect(response.body.accept_payment).toEqual(['browsingIOU', 'credentialHash', 'payload']);
    expect(response.body.expires_at).toMatch(/^\d{4}-\d{2}-\d{2}T/); // ISO format
  });

  // ============ BROWSING IOU ============

  test('verifyBrowsingIOU — valid IOU matches invoice', async () => {
    const { publicKeyPem, privateKey } = await generateTestKeyPair();

    const invoice: Invoice = {
      invoice_id: 'inv-123',
      app_id: 'app-123',
      resource_uri: '/premium/content',
      amount: '500',
      currency: 'USD',
      card_acceptor_id: 'CA-12345',
      created_at: Math.floor(Date.now() / 1000),
      expires_at: Math.floor(Date.now() / 1000) + 3600,
      status: 'pending',
    };

    const iou: BrowsingIOU = {
      invoiceId: 'inv-123',
      amount: '500',
      cardAcceptorId: 'CA-12345',
      acquirerId: 'ACQ-999',
      uri: '/premium/content',
      sequenceCounter: '1',
      paymentService: 'stripe',
      kid: 'key-1',
      alg: 'ES256',
      signature: '', // Will be filled
    };

    // Build IOU signature base
    const encoder = new TextEncoder();
    const signatureBase = `"invoiceId": "${iou.invoiceId}"\n"amount": "${iou.amount}"\n"cardAcceptorId": "${iou.cardAcceptorId}"\n"acquirerId": "${iou.acquirerId}"\n"uri": "${iou.uri}"\n"sequenceCounter": "${iou.sequenceCounter}"\n"paymentService": "${iou.paymentService}"`;
    
    const data = encoder.encode(signatureBase);
    const signatureBytes = await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      privateKey,
      data
    );
    iou.signature = btoa(String.fromCharCode(...new Uint8Array(signatureBytes)));

    // Verify IOU
    const result = await verifyBrowsingIOU(iou, invoice, publicKeyPem, 'ES256');
    expect(result.valid).toBe(true);
  });

  test('verifyBrowsingIOU — rejects mismatched amount', async () => {
    const { publicKeyPem, privateKey } = await generateTestKeyPair();

    const invoice: Invoice = {
      invoice_id: 'inv-123',
      app_id: 'app-123',
      resource_uri: '/premium/content',
      amount: '500',
      currency: 'USD',
      card_acceptor_id: 'CA-12345',
      created_at: Math.floor(Date.now() / 1000),
      expires_at: Math.floor(Date.now() / 1000) + 3600,
      status: 'pending',
    };

    const iou: BrowsingIOU = {
      invoiceId: 'inv-123',
      amount: '999', // Wrong amount
      cardAcceptorId: 'CA-12345',
      acquirerId: 'ACQ-999',
      uri: '/premium/content',
      sequenceCounter: '1',
      paymentService: 'stripe',
      kid: 'key-1',
      alg: 'ES256',
      signature: 'dummy',
    };

    const result = await verifyBrowsingIOU(iou, invoice, publicKeyPem, 'ES256');
    expect(result.valid).toBe(false);
    expect(result.error).toContain('Amount mismatch');
  });

  test('verifyBrowsingIOU — rejects mismatched invoiceId', async () => {
    const { publicKeyPem } = await generateTestKeyPair();

    const invoice: Invoice = {
      invoice_id: 'inv-123',
      app_id: 'app-123',
      resource_uri: '/premium/content',
      amount: '500',
      currency: 'USD',
      card_acceptor_id: 'CA-12345',
      created_at: Math.floor(Date.now() / 1000),
      expires_at: Math.floor(Date.now() / 1000) + 3600,
      status: 'pending',
    };

    const iou: BrowsingIOU = {
      invoiceId: 'inv-999', // Wrong invoice ID
      amount: '500',
      cardAcceptorId: 'CA-12345',
      acquirerId: 'ACQ-999',
      uri: '/premium/content',
      sequenceCounter: '1',
      paymentService: 'stripe',
      kid: 'key-1',
      alg: 'ES256',
      signature: 'dummy',
    };

    const result = await verifyBrowsingIOU(iou, invoice, publicKeyPem, 'ES256');
    expect(result.valid).toBe(false);
    expect(result.error).toContain('Invoice ID mismatch');
  });

  test('fulfillInvoice marks invoice fulfilled', async () => {
    const mockKV = createMockKV();
    const { publicKeyPem, privateKey } = await generateTestKeyPair();

    // Create invoice
    const createResult = await createInvoice(mockKV, 'app-123', {
      resource_uri: '/premium/content',
      amount: '500',
      currency: 'USD',
      card_acceptor_id: 'CA-12345',
      ttl_seconds: 3600,
    });

    expect(createResult.success).toBe(true);
    const invoice = createResult.invoice!;

    // Create valid IOU
    const iou: BrowsingIOU = {
      invoiceId: invoice.invoice_id,
      amount: '500',
      cardAcceptorId: 'CA-12345',
      acquirerId: 'ACQ-999',
      uri: '/premium/content',
      sequenceCounter: '1',
      paymentService: 'stripe',
      kid: 'key-1',
      alg: 'ES256',
      signature: 'dummy',
    };

    // Fulfill invoice
    const fulfillResult = await fulfillInvoice(mockKV, invoice.invoice_id, iou);
    
    expect(fulfillResult.success).toBe(true);
    expect(fulfillResult.access_token).toBeDefined();
    expect(fulfillResult.access_token).toMatch(/^[0-9a-f]{64}$/);

    // Verify invoice status changed
    const getResult = await getInvoice(mockKV, invoice.invoice_id);
    expect(getResult.success).toBe(true);
    expect(getResult.invoice?.status).toBe('fulfilled');
  });

});
