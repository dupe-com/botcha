/**
 * Tests for A2A Agent Card Attestation (tap-a2a.ts)
 *
 * Coverage:
 *   - getBotchaAgentCard: structure, required fields, skills
 *   - canonicalizeCard: deterministic, strips botcha_attestation extension
 *   - hashCard: consistent hash, different cards → different hashes
 *   - attestCard: issuance, KV storage, attested_card embedding
 *   - verifyCard: valid attestation, expired, hash mismatch, revoked, missing token
 *   - listVerifiedCards: global registry, agent_url filter
 *   - getCardAttestation: lookup by ID
 */

import { describe, test, expect, beforeEach } from 'vitest';
import {
  getBotchaAgentCard,
  canonicalizeCard,
  hashCard,
  attestCard,
  verifyCard,
  getCardAttestation,
  listVerifiedCards,
  type A2AAgentCard,
} from '../../../packages/cloudflare-workers/src/tap-a2a.js';
import type { KVNamespace } from '../../../packages/cloudflare-workers/src/agents.js';

// ============ Mock KV ============

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

  has(key: string): boolean { return this.store.has(key); }
  getRaw(key: string): string | undefined { return this.store.get(key); }
  clear(): void { this.store.clear(); }
}

// ============ Constants ============

const TEST_SECRET = 'test-jwt-secret-for-a2a-attestation-tests!!';
const TEST_APP_ID = 'app_a2a_test_01';

const SAMPLE_CARD: A2AAgentCard = {
  name: 'Commerce Agent',
  description: 'An A2A-compatible commerce agent',
  url: 'https://commerce-agent.example.com',
  version: '1.0.0',
  capabilities: { streaming: false },
  authentication: [{ schemes: ['Bearer'] }],
  skills: [
    { id: 'browse', name: 'Browse', description: 'Browse products' },
    { id: 'purchase', name: 'Purchase', description: 'Purchase items' },
  ],
};

// ============ BOTCHA Agent Card ============

describe('getBotchaAgentCard', () => {
  test('returns a valid A2A Agent Card', () => {
    const card = getBotchaAgentCard();
    expect(card.name).toBe('BOTCHA');
    expect(card.url).toBe('https://botcha.ai');
    expect(card.version).toBeDefined();
  });

  test('has all required A2A Agent Card fields', () => {
    const card = getBotchaAgentCard();
    expect(card.name).toBeTruthy();
    expect(card.url).toBeTruthy();
    expect(card.capabilities).toBeDefined();
    expect(card.authentication).toBeInstanceOf(Array);
    expect(card.skills).toBeInstanceOf(Array);
  });

  test('has the three required skills', () => {
    const card = getBotchaAgentCard();
    const skillIds = card.skills!.map(s => s.id);
    expect(skillIds).toContain('verify-agent');
    expect(skillIds).toContain('attest-card');
    expect(skillIds).toContain('check-reputation');
  });

  test('includes verify-card skill', () => {
    const card = getBotchaAgentCard();
    const skillIds = card.skills!.map(s => s.id);
    expect(skillIds).toContain('verify-card');
  });

  test('uses Bearer auth scheme', () => {
    const card = getBotchaAgentCard();
    const bearerAuth = card.authentication!.find(a => a.schemes.includes('Bearer'));
    expect(bearerAuth).toBeDefined();
  });

  test('respects custom version', () => {
    const card = getBotchaAgentCard('9.9.9');
    expect(card.version).toBe('9.9.9');
  });

  test('has botcha extensions with endpoints', () => {
    const card = getBotchaAgentCard();
    expect(card.extensions?.botcha).toBeDefined();
    const ext = card.extensions!.botcha as any;
    expect(ext.attest_endpoint).toContain('/v1/a2a/attest');
    expect(ext.verify_card_endpoint).toContain('/v1/a2a/verify-card');
    expect(ext.registry_endpoint).toContain('/v1/a2a/cards');
  });
});

// ============ Canonicalization & Hashing ============

describe('canonicalizeCard', () => {
  test('produces deterministic output', () => {
    const c1 = canonicalizeCard(SAMPLE_CARD);
    const c2 = canonicalizeCard(SAMPLE_CARD);
    expect(c1).toBe(c2);
  });

  test('strips botcha_attestation from extensions before hashing', () => {
    const cardWithAttestation: A2AAgentCard = {
      ...SAMPLE_CARD,
      extensions: {
        some_extension: 'hello',
        botcha_attestation: {
          token: 'some-jwt-token',
          verified_at: '2026-01-01T00:00:00Z',
          trust_level: 'verified',
          issuer: 'https://botcha.ai',
          card_hash: 'abc123',
          expires_at: '2027-01-01T00:00:00Z',
        },
      },
    };

    const cardWithoutAttestation: A2AAgentCard = {
      ...SAMPLE_CARD,
      extensions: {
        some_extension: 'hello',
      },
    };

    expect(canonicalizeCard(cardWithAttestation)).toBe(canonicalizeCard(cardWithoutAttestation));
  });

  test('strips extensions entirely if only botcha_attestation present', () => {
    const cardWithOnlyAttestation: A2AAgentCard = {
      ...SAMPLE_CARD,
      extensions: {
        botcha_attestation: { token: 'jwt', verified_at: 'now', trust_level: 'v', issuer: 'b', card_hash: 'h', expires_at: 'e' },
      },
    };

    const cardWithoutExtensions: A2AAgentCard = { ...SAMPLE_CARD };

    expect(canonicalizeCard(cardWithOnlyAttestation)).toBe(canonicalizeCard(cardWithoutExtensions));
  });

  test('is sensitive to card content changes', () => {
    const modified: A2AAgentCard = { ...SAMPLE_CARD, version: '2.0.0' };
    expect(canonicalizeCard(SAMPLE_CARD)).not.toBe(canonicalizeCard(modified));
  });

  test('keys are sorted (deterministic ordering)', () => {
    const card1: A2AAgentCard = { name: 'Agent', url: 'https://a.com', version: '1' };
    const card2: A2AAgentCard = { url: 'https://a.com', name: 'Agent', version: '1' };
    expect(canonicalizeCard(card1)).toBe(canonicalizeCard(card2));
  });
});

describe('hashCard', () => {
  test('returns a 64-char hex string (SHA-256)', async () => {
    const hash = await hashCard(SAMPLE_CARD);
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
  });

  test('is consistent across calls', async () => {
    const h1 = await hashCard(SAMPLE_CARD);
    const h2 = await hashCard(SAMPLE_CARD);
    expect(h1).toBe(h2);
  });

  test('different cards produce different hashes', async () => {
    const card2: A2AAgentCard = { ...SAMPLE_CARD, name: 'Different Agent' };
    const h1 = await hashCard(SAMPLE_CARD);
    const h2 = await hashCard(card2);
    expect(h1).not.toBe(h2);
  });

  test('botcha_attestation extension is excluded from hash', async () => {
    const plain = await hashCard(SAMPLE_CARD);
    const withAttestation = await hashCard({
      ...SAMPLE_CARD,
      extensions: {
        botcha_attestation: {
          token: 'some-jwt',
          verified_at: '2026-01-01T00:00:00Z',
          trust_level: 'verified',
          issuer: 'https://botcha.ai',
          card_hash: plain,
          expires_at: '2027-01-01T00:00:00Z',
        },
      },
    });
    expect(plain).toBe(withAttestation);
  });
});

// ============ Attestation Issuance ============

describe('attestCard', () => {
  let sessions: MockKV;

  beforeEach(() => {
    sessions = new MockKV();
  });

  test('successfully attests a valid card', async () => {
    const result = await attestCard(sessions, TEST_SECRET, {
      card: SAMPLE_CARD,
      app_id: TEST_APP_ID,
    });

    expect(result.success).toBe(true);
    expect(result.attestation).toBeDefined();
    expect(result.attested_card).toBeDefined();
  });

  test('attested card has extensions.botcha_attestation', async () => {
    const result = await attestCard(sessions, TEST_SECRET, {
      card: SAMPLE_CARD,
      app_id: TEST_APP_ID,
    });

    expect(result.attested_card?.extensions?.botcha_attestation).toBeDefined();
    const ext = result.attested_card!.extensions!.botcha_attestation as any;
    expect(ext.token).toBeTruthy();
    expect(ext.verified_at).toBeTruthy();
    expect(ext.trust_level).toBe('verified');
    expect(ext.issuer).toBe('https://botcha.ai');
    expect(ext.card_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(ext.expires_at).toBeTruthy();
  });

  test('attestation stored in KV', async () => {
    const result = await attestCard(sessions, TEST_SECRET, {
      card: SAMPLE_CARD,
      app_id: TEST_APP_ID,
    });

    expect(result.attestation!.attestation_id).toBeTruthy();
    const stored = sessions.getRaw(`a2a_attestation:${result.attestation!.attestation_id}`);
    expect(stored).toBeTruthy();
  });

  test('attestation record has correct fields', async () => {
    const result = await attestCard(sessions, TEST_SECRET, {
      card: SAMPLE_CARD,
      app_id: TEST_APP_ID,
    });

    const att = result.attestation!;
    expect(att.agent_url).toBe(SAMPLE_CARD.url);
    expect(att.agent_name).toBe(SAMPLE_CARD.name);
    expect(att.app_id).toBe(TEST_APP_ID);
    expect(att.card_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(att.trust_level).toBe('verified');
    expect(att.revoked).toBe(false);
    expect(att.created_at).toBeGreaterThan(0);
    expect(att.expires_at).toBeGreaterThan(att.created_at);
  });

  test('custom trust_level is respected', async () => {
    const result = await attestCard(sessions, TEST_SECRET, {
      card: SAMPLE_CARD,
      app_id: TEST_APP_ID,
      trust_level: 'enterprise',
    });

    expect(result.attestation!.trust_level).toBe('enterprise');
    const ext = result.attested_card!.extensions!.botcha_attestation as any;
    expect(ext.trust_level).toBe('enterprise');
  });

  test('custom duration_seconds respected', async () => {
    const result = await attestCard(sessions, TEST_SECRET, {
      card: SAMPLE_CARD,
      app_id: TEST_APP_ID,
      duration_seconds: 3600,
    });

    const att = result.attestation!;
    const diffMs = att.expires_at - att.created_at;
    // Should be approximately 3600s (within 5 seconds tolerance)
    expect(diffMs).toBeGreaterThanOrEqual(3595 * 1000);
    expect(diffMs).toBeLessThanOrEqual(3605 * 1000);
  });

  test('duration capped at MAX (30 days)', async () => {
    const result = await attestCard(sessions, TEST_SECRET, {
      card: SAMPLE_CARD,
      app_id: TEST_APP_ID,
      duration_seconds: 999999999, // way too long
    });

    const att = result.attestation!;
    const maxMs = 30 * 24 * 3600 * 1000;
    expect(att.expires_at - att.created_at).toBeLessThanOrEqual(maxMs + 5000);
  });

  test('fails if card has no name', async () => {
    const cardNoName = { ...SAMPLE_CARD } as any;
    delete cardNoName.name;

    const result = await attestCard(sessions, TEST_SECRET, {
      card: cardNoName,
      app_id: TEST_APP_ID,
    });

    expect(result.success).toBe(false);
    expect(result.error).toMatch(/name/i);
  });

  test('fails if card has no url', async () => {
    const cardNoUrl = { ...SAMPLE_CARD } as any;
    delete cardNoUrl.url;

    const result = await attestCard(sessions, TEST_SECRET, {
      card: cardNoUrl,
      app_id: TEST_APP_ID,
    });

    expect(result.success).toBe(false);
    expect(result.error).toMatch(/url/i);
  });

  test('fails if card has invalid url', async () => {
    const result = await attestCard(sessions, TEST_SECRET, {
      card: { ...SAMPLE_CARD, url: 'not-a-url' },
      app_id: TEST_APP_ID,
    });

    expect(result.success).toBe(false);
    expect(result.error).toMatch(/Invalid.*url/i);
  });

  test('adds attestation to registry index', async () => {
    const result = await attestCard(sessions, TEST_SECRET, {
      card: SAMPLE_CARD,
      app_id: TEST_APP_ID,
    });

    const registryKey = `a2a_registry:${encodeURIComponent(SAMPLE_CARD.url)}`;
    const index = sessions.getRaw(registryKey);
    expect(index).toBeTruthy();
    const ids = JSON.parse(index!);
    expect(ids).toContain(result.attestation!.attestation_id);
  });

  test('adds to global registry index', async () => {
    await attestCard(sessions, TEST_SECRET, {
      card: SAMPLE_CARD,
      app_id: TEST_APP_ID,
    });

    const globalIndex = sessions.getRaw('a2a_registry:global');
    expect(globalIndex).toBeTruthy();
    expect(JSON.parse(globalIndex!).length).toBeGreaterThan(0);
  });

  test('preserves existing extensions when embedding attestation', async () => {
    const cardWithExtensions: A2AAgentCard = {
      ...SAMPLE_CARD,
      extensions: { custom_ext: 'custom_value' },
    };

    const result = await attestCard(sessions, TEST_SECRET, {
      card: cardWithExtensions,
      app_id: TEST_APP_ID,
    });

    expect(result.attested_card!.extensions!.custom_ext).toBe('custom_value');
    expect(result.attested_card!.extensions!.botcha_attestation).toBeDefined();
  });
});

// ============ Attestation Verification ============

describe('verifyCard', () => {
  let sessions: MockKV;

  beforeEach(() => {
    sessions = new MockKV();
  });

  test('verifies a freshly attested card successfully', async () => {
    const attestResult = await attestCard(sessions, TEST_SECRET, {
      card: SAMPLE_CARD,
      app_id: TEST_APP_ID,
    });
    expect(attestResult.success).toBe(true);

    const verifyResult = await verifyCard(sessions, TEST_SECRET, attestResult.attested_card!);

    expect(verifyResult.success).toBe(true);
    expect(verifyResult.valid).toBe(true);
    expect(verifyResult.agent_url).toBe(SAMPLE_CARD.url);
    expect(verifyResult.agent_name).toBe(SAMPLE_CARD.name);
    expect(verifyResult.trust_level).toBe('verified');
    expect(verifyResult.app_id).toBe(TEST_APP_ID);
    expect(verifyResult.card_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(verifyResult.attestation_id).toBeTruthy();
  });

  test('fails if card has no botcha_attestation extension', async () => {
    const result = await verifyCard(sessions, TEST_SECRET, SAMPLE_CARD);

    expect(result.success).toBe(true);
    expect(result.valid).toBe(false);
    expect(result.error).toBe('NO_ATTESTATION');
  });

  test('fails if token is missing from extension', async () => {
    const cardNoToken: A2AAgentCard = {
      ...SAMPLE_CARD,
      extensions: {
        botcha_attestation: {
          // token is missing
          verified_at: '2026-01-01T00:00:00Z',
          trust_level: 'verified',
          issuer: 'https://botcha.ai',
          card_hash: 'abc',
          expires_at: '2027-01-01T00:00:00Z',
        } as any,
      },
    };

    const result = await verifyCard(sessions, TEST_SECRET, cardNoToken);

    expect(result.success).toBe(true);
    expect(result.valid).toBe(false);
    expect(result.error).toBe('MISSING_TOKEN');
  });

  test('detects tampered card (hash mismatch)', async () => {
    const attestResult = await attestCard(sessions, TEST_SECRET, {
      card: SAMPLE_CARD,
      app_id: TEST_APP_ID,
    });

    // Tamper with card content (change name)
    const tamperedCard: A2AAgentCard = {
      ...attestResult.attested_card!,
      name: 'EVIL IMPERSONATOR',
    };

    const verifyResult = await verifyCard(sessions, TEST_SECRET, tamperedCard);

    expect(verifyResult.success).toBe(true);
    expect(verifyResult.valid).toBe(false);
    expect(verifyResult.error).toBe('HASH_MISMATCH');
    expect(verifyResult.reason).toContain('modified');
  });

  test('detects tampered card (changed url)', async () => {
    const attestResult = await attestCard(sessions, TEST_SECRET, {
      card: SAMPLE_CARD,
      app_id: TEST_APP_ID,
    });

    const tamperedCard: A2AAgentCard = {
      ...attestResult.attested_card!,
      url: 'https://evil.example.com',
    };

    const verifyResult = await verifyCard(sessions, TEST_SECRET, tamperedCard);

    expect(verifyResult.valid).toBe(false);
    expect(verifyResult.error).toBe('HASH_MISMATCH');
  });

  test('detects tampered card (added skill)', async () => {
    const attestResult = await attestCard(sessions, TEST_SECRET, {
      card: SAMPLE_CARD,
      app_id: TEST_APP_ID,
    });

    const tamperedCard: A2AAgentCard = {
      ...attestResult.attested_card!,
      skills: [
        ...(SAMPLE_CARD.skills || []),
        { id: 'injected', name: 'Injected Skill', description: 'Evil' },
      ],
    };

    const verifyResult = await verifyCard(sessions, TEST_SECRET, tamperedCard);

    expect(verifyResult.valid).toBe(false);
    expect(verifyResult.error).toBe('HASH_MISMATCH');
  });

  test('fails with wrong JWT secret', async () => {
    const attestResult = await attestCard(sessions, TEST_SECRET, {
      card: SAMPLE_CARD,
      app_id: TEST_APP_ID,
    });

    const verifyResult = await verifyCard(sessions, 'wrong-secret', attestResult.attested_card!);

    expect(verifyResult.valid).toBe(false);
    expect(verifyResult.error).toBe('INVALID_TOKEN');
  });

  test('fails on revoked attestation', async () => {
    const attestResult = await attestCard(sessions, TEST_SECRET, {
      card: SAMPLE_CARD,
      app_id: TEST_APP_ID,
    });

    const attestationId = attestResult.attestation!.attestation_id;

    // Manually mark as revoked in KV
    await sessions.put(`a2a_attestation_revoked:${attestationId}`, JSON.stringify({
      revokedAt: Date.now(),
      reason: 'Test revocation',
    }));

    const verifyResult = await verifyCard(sessions, TEST_SECRET, attestResult.attested_card!);

    expect(verifyResult.valid).toBe(false);
    expect(verifyResult.error).toBe('REVOKED');
  });

  test('fails on invalid token type', async () => {
    // Create a token with wrong type (reuse a valid JWT but it won't have the right type claim)
    const cardWithWrongToken: A2AAgentCard = {
      ...SAMPLE_CARD,
      extensions: {
        botcha_attestation: {
          token: 'eyJhbGciOiJIUzI1NiJ9.eyJ0eXBlIjoibm90LWEyYSJ9.invalid',
          verified_at: '2026-01-01T00:00:00Z',
          trust_level: 'verified',
          issuer: 'https://botcha.ai',
          card_hash: 'abc',
          expires_at: '2027-01-01T00:00:00Z',
        } as any,
      },
    };

    const result = await verifyCard(sessions, TEST_SECRET, cardWithWrongToken);

    expect(result.valid).toBe(false);
    expect(result.error).toBe('INVALID_TOKEN');
  });

  test('roundtrip: attest → embed → verify → valid', async () => {
    // Full end-to-end roundtrip
    const attestResult = await attestCard(sessions, TEST_SECRET, {
      card: SAMPLE_CARD,
      app_id: TEST_APP_ID,
      trust_level: 'enterprise',
    });

    expect(attestResult.success).toBe(true);

    const attestedCard = attestResult.attested_card!;

    // The attested card should verify successfully
    const verifyResult = await verifyCard(sessions, TEST_SECRET, attestedCard);

    expect(verifyResult.valid).toBe(true);
    expect(verifyResult.trust_level).toBe('enterprise');
    expect(verifyResult.agent_url).toBe(SAMPLE_CARD.url);
  });
});

// ============ Card Registry ============

describe('getCardAttestation', () => {
  let sessions: MockKV;

  beforeEach(() => {
    sessions = new MockKV();
  });

  test('retrieves attestation by ID', async () => {
    const attestResult = await attestCard(sessions, TEST_SECRET, {
      card: SAMPLE_CARD,
      app_id: TEST_APP_ID,
    });

    const id = attestResult.attestation!.attestation_id;
    const getResult = await getCardAttestation(sessions, id);

    expect(getResult.success).toBe(true);
    expect(getResult.attestation!.attestation_id).toBe(id);
    expect(getResult.attestation!.agent_url).toBe(SAMPLE_CARD.url);
  });

  test('returns error for non-existent ID', async () => {
    const result = await getCardAttestation(sessions, 'nonexistent-id');
    expect(result.success).toBe(false);
    expect(result.error).toContain('not found');
  });
});

describe('listVerifiedCards', () => {
  let sessions: MockKV;

  beforeEach(() => {
    sessions = new MockKV();
  });

  test('returns empty list when no cards attested', async () => {
    const result = await listVerifiedCards(sessions);
    expect(result.success).toBe(true);
    expect(result.attestations).toHaveLength(0);
  });

  test('lists attested cards', async () => {
    await attestCard(sessions, TEST_SECRET, {
      card: SAMPLE_CARD,
      app_id: TEST_APP_ID,
    });

    const result = await listVerifiedCards(sessions);

    expect(result.success).toBe(true);
    expect(result.attestations!.length).toBeGreaterThanOrEqual(1);
  });

  test('multiple attestations appear in registry', async () => {
    const card2: A2AAgentCard = {
      ...SAMPLE_CARD,
      name: 'Agent 2',
      url: 'https://agent2.example.com',
    };

    await attestCard(sessions, TEST_SECRET, { card: SAMPLE_CARD, app_id: TEST_APP_ID });
    await attestCard(sessions, TEST_SECRET, { card: card2, app_id: TEST_APP_ID });

    const result = await listVerifiedCards(sessions);

    expect(result.attestations!.length).toBeGreaterThanOrEqual(2);
  });

  test('filters by agent_url', async () => {
    const card2: A2AAgentCard = {
      ...SAMPLE_CARD,
      name: 'Agent 2',
      url: 'https://agent2.example.com',
    };

    await attestCard(sessions, TEST_SECRET, { card: SAMPLE_CARD, app_id: TEST_APP_ID });
    await attestCard(sessions, TEST_SECRET, { card: card2, app_id: TEST_APP_ID });

    const result = await listVerifiedCards(sessions, {
      agent_url: SAMPLE_CARD.url,
    });

    expect(result.success).toBe(true);
    expect(result.attestations!.every(a => a.agent_url === SAMPLE_CARD.url)).toBe(true);
  });

  test('verified_only=false includes revoked', async () => {
    const attestResult = await attestCard(sessions, TEST_SECRET, {
      card: SAMPLE_CARD,
      app_id: TEST_APP_ID,
    });

    // Mark as revoked
    const attestation = JSON.parse(
      sessions.getRaw(`a2a_attestation:${attestResult.attestation!.attestation_id}`)!
    );
    attestation.revoked = true;
    await sessions.put(
      `a2a_attestation:${attestResult.attestation!.attestation_id}`,
      JSON.stringify(attestation)
    );

    const resultVerifiedOnly = await listVerifiedCards(sessions, { verified_only: true });
    const resultAll = await listVerifiedCards(sessions, { verified_only: false });

    expect(resultAll.attestations!.length).toBeGreaterThanOrEqual(resultVerifiedOnly.attestations!.length);
  });
});
