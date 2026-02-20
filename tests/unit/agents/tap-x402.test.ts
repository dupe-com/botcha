/**
 * Unit tests for x402 Payment Gating
 * Tests: payment descriptor, header parsing, verification logic, token issuance, webhook processing
 */

import { describe, test, expect, beforeEach } from 'vitest';
import {
  buildPaymentRequiredDescriptor,
  parsePaymentHeader,
  verifyX402Payment,
  storePaymentRecord,
  getPaymentRecord,
  processWebhookEvent,
  buildPaymentResponseHeader,
  BOTCHA_WALLET,
  USDC_BASE_ADDRESS,
  BASE_CHAIN_ID,
  VERIFICATION_PRICE_USDC_UNITS,
  PAYMENT_DEADLINE_SECONDS,
  type X402PaymentProof,
  type X402PaymentRecord,
  type X402WebhookEvent,
} from '../../../packages/cloudflare-workers/src/tap-x402.js';
import type { KVNamespace } from '../../../packages/cloudflare-workers/src/agents.js';

// ============ MOCK KV ============

class MockKV implements KVNamespace {
  private store = new Map<string, string>();

  async get(key: string, type?: string): Promise<any> {
    const value = this.store.get(key);
    if (!value) return null;
    if (type === 'json') return JSON.parse(value);
    return value;
  }

  async put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void> {
    this.store.set(key, value);
  }

  async delete(key: string): Promise<void> {
    this.store.delete(key);
  }

  has(key: string): boolean {
    return this.store.has(key);
  }

  getRaw(key: string): string | undefined {
    return this.store.get(key);
  }

  clear(): void {
    this.store.clear();
  }
}

// ============ HELPERS ============

/** Build a valid x402 payment proof for testing */
function buildValidProof(overrides: Partial<X402PaymentProof['payload']> = {}): X402PaymentProof {
  const now = Math.floor(Date.now() / 1000);
  return {
    scheme: 'exact',
    network: `eip155:${BASE_CHAIN_ID}`,
    payload: {
      from: '0x1234567890123456789012345678901234567890',
      to: BOTCHA_WALLET,
      value: VERIFICATION_PRICE_USDC_UNITS,
      validAfter: String(now - 60),
      validBefore: String(now + PAYMENT_DEADLINE_SECONDS),
      nonce: '0x' + 'a'.repeat(64),
      signature: '0x' + 'b'.repeat(130),
      chainId: BASE_CHAIN_ID,
      ...overrides,
    },
  };
}

/** Encode proof as base64 (X-Payment header value) */
function encodeProof(proof: X402PaymentProof): string {
  return btoa(JSON.stringify(proof));
}

// ============ TESTS ============

describe('buildPaymentRequiredDescriptor', () => {
  test('returns valid x402 exact descriptor with defaults', () => {
    const descriptor = buildPaymentRequiredDescriptor('/v1/x402/challenge');

    expect(descriptor.scheme).toBe('exact');
    expect(descriptor.network).toBe(`eip155:${BASE_CHAIN_ID}`);
    expect(descriptor.maxAmountRequired).toBe(VERIFICATION_PRICE_USDC_UNITS);
    expect(descriptor.resource).toBe('/v1/x402/challenge');
    expect(descriptor.payTo).toBe(BOTCHA_WALLET);
    expect(descriptor.asset).toBe(USDC_BASE_ADDRESS);
    expect(descriptor.maxTimeoutSeconds).toBe(PAYMENT_DEADLINE_SECONDS);
    expect(descriptor.mimeType).toBe('application/json');
  });

  test('accepts custom options', () => {
    const descriptor = buildPaymentRequiredDescriptor('/v1/custom', {
      description: 'Custom resource',
      payTo: '0xCustomWallet',
      amount: '5000',
      appId: 'app_test123',
    });

    expect(descriptor.payTo).toBe('0xCustomWallet');
    expect(descriptor.maxAmountRequired).toBe('5000');
    expect(descriptor.description).toBe('Custom resource');
    expect(descriptor.extra?.botcha_app_id).toBe('app_test123');
  });

  test('extra field includes BOTCHA name and version', () => {
    const descriptor = buildPaymentRequiredDescriptor('/test');
    expect(descriptor.extra?.name).toBe('BOTCHA');
    expect(descriptor.extra?.version).toBe('1.0');
  });
});

describe('parsePaymentHeader', () => {
  test('parses valid base64-encoded proof', () => {
    const proof = buildValidProof();
    const encoded = encodeProof(proof);
    const parsed = parsePaymentHeader(encoded);

    expect(parsed).not.toBeNull();
    expect(parsed!.scheme).toBe('exact');
    expect(parsed!.network).toBe(`eip155:${BASE_CHAIN_ID}`);
    expect(parsed!.payload.from).toBe(proof.payload.from);
    expect(parsed!.payload.to).toBe(proof.payload.to);
    expect(parsed!.payload.value).toBe(proof.payload.value);
  });

  test('returns null for invalid base64', () => {
    expect(parsePaymentHeader('not-valid-base64!!!!')).toBeNull();
  });

  test('returns null for wrong scheme', () => {
    const proof = buildValidProof();
    const bad = { ...proof, scheme: 'x402-v2' } as any;
    expect(parsePaymentHeader(encodeProof(bad))).toBeNull();
  });

  test('returns null for missing payload', () => {
    const bad = { scheme: 'exact', network: 'eip155:8453' };
    expect(parsePaymentHeader(btoa(JSON.stringify(bad)))).toBeNull();
  });

  test('returns null for missing required payload fields', () => {
    const bad = {
      scheme: 'exact',
      network: 'eip155:8453',
      payload: { from: '0x123' }, // missing to, value, nonce, signature, validBefore
    };
    expect(parsePaymentHeader(btoa(JSON.stringify(bad)))).toBeNull();
  });

  test('handles leading/trailing whitespace in header value', () => {
    const proof = buildValidProof();
    const encoded = '  ' + encodeProof(proof) + '  ';
    const parsed = parsePaymentHeader(encoded);
    expect(parsed).not.toBeNull();
  });
});

describe('verifyX402Payment', () => {
  let nonces: MockKV;

  beforeEach(() => {
    nonces = new MockKV();
  });

  test('verifies valid payment proof', async () => {
    const proof = buildValidProof();
    const result = await verifyX402Payment(proof, nonces as any);

    expect(result.verified).toBe(true);
    expect(result.valid).toBe(true);
    expect(result.payer).toBe(proof.payload.from);
    expect(result.amount).toBe(proof.payload.value);
    expect(result.txHash).toMatch(/^0x[0-9a-f]+$/);
  });

  test('rejects unsupported network', async () => {
    const proof = { ...buildValidProof(), network: 'eip155:1' }; // Ethereum mainnet
    const result = await verifyX402Payment(proof, nonces as any);

    expect(result.verified).toBe(false);
    expect(result.errorCode).toBe('NETWORK_MISMATCH');
  });

  test('accepts "base" as network alias', async () => {
    const proof = { ...buildValidProof(), network: 'base' };
    const result = await verifyX402Payment(proof, nonces as any);
    expect(result.verified).toBe(true);
  });

  test('accepts "base-mainnet" as network alias', async () => {
    const proof = { ...buildValidProof(), network: 'base-mainnet' };
    const result = await verifyX402Payment(proof, nonces as any);
    expect(result.verified).toBe(true);
  });

  test('rejects wrong recipient', async () => {
    const proof = buildValidProof({ to: '0x0000000000000000000000000000000000000001' });
    const result = await verifyX402Payment(proof, nonces as any);

    expect(result.verified).toBe(false);
    expect(result.errorCode).toBe('RECIPIENT_MISMATCH');
  });

  test('rejects when custom required_recipient not matched', async () => {
    const proof = buildValidProof({ to: BOTCHA_WALLET });
    const result = await verifyX402Payment(proof, nonces as any, {
      requiredRecipient: '0x9999999999999999999999999999999999999999',
    });

    expect(result.verified).toBe(false);
    expect(result.errorCode).toBe('RECIPIENT_MISMATCH');
  });

  test('rejects insufficient payment amount', async () => {
    const proof = buildValidProof({ value: '500' }); // below 1000 threshold
    const result = await verifyX402Payment(proof, nonces as any);

    expect(result.verified).toBe(false);
    expect(result.errorCode).toBe('INSUFFICIENT_AMOUNT');
  });

  test('accepts payment above required amount', async () => {
    const proof = buildValidProof({ value: '9999' }); // more than enough
    const result = await verifyX402Payment(proof, nonces as any);
    expect(result.verified).toBe(true);
  });

  test('rejects expired payment (validBefore in the past)', async () => {
    const pastTime = String(Math.floor(Date.now() / 1000) - 1); // 1 second ago
    const proof = buildValidProof({ validBefore: pastTime });
    const result = await verifyX402Payment(proof, nonces as any);

    expect(result.verified).toBe(false);
    expect(result.errorCode).toBe('PAYMENT_EXPIRED');
  });

  test('rejects replayed nonce', async () => {
    const proof = buildValidProof();

    // First use — should succeed
    const first = await verifyX402Payment(proof, nonces as any);
    expect(first.verified).toBe(true);

    // Second use — same nonce, should fail
    const second = await verifyX402Payment(proof, nonces as any);
    expect(second.verified).toBe(false);
    expect(second.errorCode).toBe('NONCE_REPLAY');
  });

  test('stores nonce in KV after successful verification', async () => {
    const proof = buildValidProof();
    await verifyX402Payment(proof, nonces as any);

    const nonceKey = `x402_nonce:${proof.payload.nonce.toLowerCase()}`;
    expect(nonces.has(nonceKey)).toBe(true);
  });

  test('rejects invalid signature format (wrong length)', async () => {
    const proof = buildValidProof({
      signature: '0x' + 'c'.repeat(64), // too short (32 bytes, should be 65)
    });
    const result = await verifyX402Payment(proof, nonces as any);
    expect(result.verified).toBe(false);
    expect(result.errorCode).toBe('SIGNATURE_INVALID');
  });

  test('rejects signature without 0x prefix', async () => {
    const proof = buildValidProof({
      signature: 'b'.repeat(130), // no 0x prefix
    });
    const result = await verifyX402Payment(proof, nonces as any);
    expect(result.verified).toBe(false);
  });

  test('rejects invalid from address (wrong length)', async () => {
    const proof = buildValidProof({
      from: '0x12345', // too short
    });
    const result = await verifyX402Payment(proof, nonces as any);
    expect(result.verified).toBe(false);
    expect(result.errorCode).toBe('SIGNATURE_INVALID');
  });

  test('rejects invalid nonce format', async () => {
    const proof = buildValidProof({
      nonce: '0xshort', // not 32 bytes
    });
    const result = await verifyX402Payment(proof, nonces as any);
    expect(result.verified).toBe(false);
    expect(result.errorCode).toBe('SIGNATURE_INVALID');
  });
});

describe('buildPaymentResponseHeader', () => {
  test('returns valid X-Payment-Response JSON string', () => {
    const result = {
      verified: true,
      valid: true,
      txHash: '0xabc123',
      payer: '0x123',
      amount: '1000',
      network: `eip155:${BASE_CHAIN_ID}`,
    };
    const header = buildPaymentResponseHeader(result);
    const parsed = JSON.parse(header);

    expect(parsed.success).toBe(true);
    expect(parsed.txHash).toBe('0xabc123');
    expect(parsed.networkId).toBe(`eip155:${BASE_CHAIN_ID}`);
  });

  test('sets success=false for failed verification', () => {
    const result = {
      verified: false,
      valid: false,
      network: 'eip155:8453',
    };
    const header = buildPaymentResponseHeader(result);
    const parsed = JSON.parse(header);
    expect(parsed.success).toBe(false);
  });

  test('falls back to Base chain ID when network is undefined', () => {
    const result = { verified: true, valid: true };
    const header = buildPaymentResponseHeader(result);
    const parsed = JSON.parse(header);
    expect(parsed.networkId).toBe(`eip155:${BASE_CHAIN_ID}`);
  });
});

describe('storePaymentRecord / getPaymentRecord', () => {
  let nonces: MockKV;

  beforeEach(() => {
    nonces = new MockKV();
  });

  test('stores and retrieves a payment record', async () => {
    const record: X402PaymentRecord = {
      payment_id: 'test-payment-001',
      payer: '0x1234567890123456789012345678901234567890',
      amount: '1000',
      network: `eip155:${BASE_CHAIN_ID}`,
      tx_hash: '0xdeadbeef',
      resource: '/v1/x402/challenge',
      nonce: '0x' + 'a'.repeat(64),
      botcha_app_id: 'app_test',
      verified_at: Math.floor(Date.now() / 1000),
      status: 'verified',
    };

    await storePaymentRecord(nonces as any, record);
    const retrieved = await getPaymentRecord(nonces as any, 'test-payment-001');

    expect(retrieved).not.toBeNull();
    expect(retrieved!.payment_id).toBe('test-payment-001');
    expect(retrieved!.payer).toBe(record.payer);
    expect(retrieved!.amount).toBe('1000');
    expect(retrieved!.status).toBe('verified');
  });

  test('returns null for unknown payment ID', async () => {
    const result = await getPaymentRecord(nonces as any, 'nonexistent');
    expect(result).toBeNull();
  });

  test('stores payer index', async () => {
    const record: X402PaymentRecord = {
      payment_id: 'payer-index-test',
      payer: '0xABCDEF0123456789ABCDEF0123456789ABCDEF01',
      amount: '1000',
      network: `eip155:${BASE_CHAIN_ID}`,
      tx_hash: '0xfeedface',
      resource: '/v1/x402/challenge',
      nonce: '0x' + 'c'.repeat(64),
      verified_at: Math.floor(Date.now() / 1000),
      status: 'verified',
    };

    await storePaymentRecord(nonces as any, record);

    // Should index by payer (lowercase)
    const indexKey = `x402_payer_last:${record.payer.toLowerCase()}`;
    expect(nonces.has(indexKey)).toBe(true);
    expect(nonces.getRaw(indexKey)).toBe('payer-index-test');
  });
});

describe('processWebhookEvent', () => {
  let nonces: MockKV;
  let agents: MockKV;
  let sessions: MockKV;

  beforeEach(() => {
    nonces = new MockKV();
    agents = new MockKV();
    sessions = new MockKV();
  });

  test('handles payment.settled event', async () => {
    // Pre-store a payment record
    const record: X402PaymentRecord = {
      payment_id: 'webhook-test-001',
      payer: '0x1234567890123456789012345678901234567890',
      amount: '1000',
      network: `eip155:${BASE_CHAIN_ID}`,
      tx_hash: '0xsettled',
      resource: '/v1/x402/challenge',
      nonce: '0x' + 'd'.repeat(64),
      verified_at: Math.floor(Date.now() / 1000),
      status: 'pending',
    };
    await storePaymentRecord(nonces as any, record);

    const event: X402WebhookEvent = {
      event_type: 'payment.settled',
      payment_id: 'webhook-test-001',
      tx_hash: '0xsettledtx',
      from: '0x1234567890123456789012345678901234567890',
      to: BOTCHA_WALLET,
      amount: '1000',
      token: USDC_BASE_ADDRESS,
      network: `eip155:${BASE_CHAIN_ID}`,
      resource: '/v1/x402/challenge',
      timestamp: new Date().toISOString(),
    };

    const result = await processWebhookEvent(
      event,
      nonces as any,
      agents as any,
      sessions as any
    );

    expect(result.handled).toBe(true);
    expect(result.message).toContain('settled');
  });

  test('handles payment.failed event', async () => {
    const event: X402WebhookEvent = {
      event_type: 'payment.failed',
      payment_id: 'failed-payment-001',
      tx_hash: '0xfailed',
      from: '0x1234567890123456789012345678901234567890',
      to: BOTCHA_WALLET,
      amount: '1000',
      token: USDC_BASE_ADDRESS,
      network: `eip155:${BASE_CHAIN_ID}`,
      resource: '/v1/x402/challenge',
      timestamp: new Date().toISOString(),
    };

    const result = await processWebhookEvent(
      event,
      nonces as any,
      agents as any,
      sessions as any
    );

    expect(result.handled).toBe(true);
    expect(result.message).toContain('failed');
  });

  test('handles payment.refunded event', async () => {
    const event: X402WebhookEvent = {
      event_type: 'payment.refunded',
      payment_id: 'refund-001',
      tx_hash: '0xrefunded',
      from: '0x1234567890123456789012345678901234567890',
      to: BOTCHA_WALLET,
      amount: '1000',
      token: USDC_BASE_ADDRESS,
      network: `eip155:${BASE_CHAIN_ID}`,
      resource: '/v1/x402/challenge',
      timestamp: new Date().toISOString(),
    };

    const result = await processWebhookEvent(
      event,
      nonces as any,
      agents as any,
      sessions as any
    );

    expect(result.handled).toBe(true);
    expect(result.message).toContain('refunded');
  });

  test('handles unknown event type gracefully', async () => {
    const event = {
      event_type: 'payment.unknown_event',
      payment_id: 'unknown-001',
      tx_hash: '0xunknown',
      from: '0x123',
      to: BOTCHA_WALLET,
      amount: '1000',
      token: USDC_BASE_ADDRESS,
      network: `eip155:${BASE_CHAIN_ID}`,
      resource: '/test',
      timestamp: new Date().toISOString(),
    } as any;

    const result = await processWebhookEvent(
      event,
      nonces as any,
      agents as any,
      sessions as any
    );

    expect(result.handled).toBe(false);
  });

  test('updates reputation when agent_id is in metadata', async () => {
    const agentId = 'agent_x402_test';

    const event: X402WebhookEvent = {
      event_type: 'payment.settled',
      payment_id: 'rep-update-001',
      tx_hash: '0xrepupdate',
      from: '0x1234567890123456789012345678901234567890',
      to: BOTCHA_WALLET,
      amount: '1000',
      token: USDC_BASE_ADDRESS,
      network: `eip155:${BASE_CHAIN_ID}`,
      resource: '/v1/x402/challenge',
      timestamp: new Date().toISOString(),
      metadata: {
        agent_id: agentId,
        app_id: 'app_test123',
      },
    };

    await processWebhookEvent(event, nonces as any, agents as any, sessions as any);

    // Reputation should be updated in sessions KV
    const repKey = `reputation:${agentId}`;
    const rawScore = sessions.getRaw(repKey);
    expect(rawScore).not.toBeNull();

    const score = JSON.parse(rawScore!);
    expect(score.score).toBeGreaterThan(500); // positive delta applied
    expect(score.tier).toBeDefined();
  });
});

describe('constants', () => {
  test('BOTCHA_WALLET is a valid Ethereum address', () => {
    expect(BOTCHA_WALLET).toMatch(/^0x[0-9a-fA-F]{40}$/);
  });

  test('USDC_BASE_ADDRESS is a valid Ethereum address', () => {
    expect(USDC_BASE_ADDRESS).toMatch(/^0x[0-9a-fA-F]{40}$/);
  });

  test('BASE_CHAIN_ID is 8453', () => {
    expect(BASE_CHAIN_ID).toBe(8453);
  });

  test('VERIFICATION_PRICE is a numeric string', () => {
    expect(Number(VERIFICATION_PRICE_USDC_UNITS)).toBeGreaterThan(0);
    expect(typeof VERIFICATION_PRICE_USDC_UNITS).toBe('string');
  });

  test('PAYMENT_DEADLINE_SECONDS is reasonable (> 60)', () => {
    expect(PAYMENT_DEADLINE_SECONDS).toBeGreaterThan(60);
  });
});
