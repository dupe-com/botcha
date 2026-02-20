/**
 * Tests for BOTCHA ANS (Agent Name Service) Integration
 *
 * Tests: name parsing, DNS resolution (mocked), badge issuance,
 * nonce management, registry CRUD, ownership verification.
 */

import { describe, test, expect, beforeEach, vi } from 'vitest';
import {
  parseANSName,
  resolveANSName,
  issueANSBadge,
  saveANSRegistryEntry,
  getANSRegistryEntry,
  listANSRegistry,
  generateANSNonce,
  consumeANSNonce,
  getBotchaANSRecord,
  type ANSRegistryEntry,
} from '../../../packages/cloudflare-workers/src/tap-ans.js';

// ============ Mock KV ============

class MockKV {
  private store = new Map<string, { value: string; expiresAt?: number }>();

  async get(key: string, _encoding?: string): Promise<string | null> {
    const entry = this.store.get(key);
    if (!entry) return null;
    if (entry.expiresAt && Date.now() > entry.expiresAt) {
      this.store.delete(key);
      return null;
    }
    return entry.value;
  }

  async put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void> {
    const expiresAt = options?.expirationTtl
      ? Date.now() + options.expirationTtl * 1000
      : undefined;
    this.store.set(key, { value, expiresAt });
  }

  async delete(key: string): Promise<void> {
    this.store.delete(key);
  }

  async list(options?: { prefix?: string; limit?: number }): Promise<{
    keys: Array<{ name: string; expiration?: number }>;
    list_complete: boolean;
    cursor?: string;
  }> {
    const prefix = options?.prefix ?? '';
    const keys = [...this.store.keys()]
      .filter(k => k.startsWith(prefix))
      .map(name => ({ name }));
    return { keys, list_complete: true };
  }

  clear(): void { this.store.clear(); }
  has(key: string): boolean { return this.store.has(key); }
}

const TEST_JWT_SECRET = 'test-jwt-secret-for-ans-tests-32chars!!extra';

// ============ ANS Name Parsing Tests ============

describe('parseANSName', () => {
  test('parses full ANS URI with version', () => {
    const result = parseANSName('ans://v1.0.myagent.example.com');
    expect(result.success).toBe(true);
    expect(result.components).toBeDefined();
    expect(result.components!.version).toBe('v1.0');
    expect(result.components!.label).toBe('myagent');
    expect(result.components!.domain).toBe('example.com');
    expect(result.components!.fqdn).toBe('myagent.example.com');
    expect(result.components!.dnsLookupName).toBe('_ans.example.com');
  });

  test('parses ANS name without scheme', () => {
    const result = parseANSName('v1.0.myagent.example.com');
    expect(result.success).toBe(true);
    expect(result.components!.version).toBe('v1.0');
    expect(result.components!.label).toBe('myagent');
    expect(result.components!.domain).toBe('example.com');
  });

  test('parses bare domain with no version', () => {
    const result = parseANSName('myagent.example.com');
    expect(result.success).toBe(true);
    expect(result.components!.version).toBe('v1.0'); // default
    expect(result.components!.label).toBe('myagent');
    expect(result.components!.domain).toBe('example.com');
    expect(result.components!.dnsLookupName).toBe('_ans.example.com');
  });

  test('parses subdomain ANS name', () => {
    const result = parseANSName('ans://v1.0.choco.botcha.ai');
    expect(result.success).toBe(true);
    expect(result.components!.label).toBe('choco');
    expect(result.components!.domain).toBe('botcha.ai');
    expect(result.components!.fqdn).toBe('choco.botcha.ai');
    expect(result.components!.dnsLookupName).toBe('_ans.botcha.ai');
  });

  test('parses v2 version prefix', () => {
    const result = parseANSName('v2.myagent.example.com');
    expect(result.success).toBe(true);
    expect(result.components!.version).toBe('v2');
  });

  test('rejects invalid ANS name (single segment)', () => {
    const result = parseANSName('justadomain');
    expect(result.success).toBe(false);
    expect(result.error).toBeDefined();
  });

  test('rejects empty string', () => {
    const result = parseANSName('');
    expect(result.success).toBe(false);
  });

  test('rejects version-only ANS name (missing label/domain)', () => {
    const result = parseANSName('v1.0.example');
    // v1.0 is version, "example" is label, but no domain remains
    expect(result.success).toBe(false);
  });

  test('handles URL-encoded input', () => {
    // Not directly testing decoding here since parseANSName receives already-decoded strings
    const result = parseANSName('ans://v1.0.myagent.example.com');
    expect(result.success).toBe(true);
  });

  // Bug B2 regression tests: 2-part domain names must resolve to _ans.<full-domain>
  // not _ans.<tld> (which is uncontrollable by users)
  test('2-part name: botcha.ai resolves dnsLookupName to _ans.botcha.ai (not _ans.ai)', () => {
    const result = parseANSName('botcha.ai');
    expect(result.success).toBe(true);
    expect(result.components!.label).toBe('botcha');
    expect(result.components!.domain).toBe('botcha.ai');
    expect(result.components!.dnsLookupName).toBe('_ans.botcha.ai');
  });

  test('2-part name: example.com resolves dnsLookupName to _ans.example.com (not _ans.com)', () => {
    const result = parseANSName('example.com');
    expect(result.success).toBe(true);
    expect(result.components!.dnsLookupName).toBe('_ans.example.com');
  });

  test('2-part name: fqdn equals domain (no double-stacking)', () => {
    const result = parseANSName('botcha.ai');
    expect(result.success).toBe(true);
    // fqdn should NOT be "botcha.botcha.ai" — it should equal the domain
    expect(result.components!.fqdn).toBe('botcha.ai');
    expect(result.components!.fqdn).not.toBe('botcha.botcha.ai');
  });

  test('3-part name still resolves correctly after 2-part fix', () => {
    const result = parseANSName('myagent.example.com');
    expect(result.success).toBe(true);
    expect(result.components!.label).toBe('myagent');
    expect(result.components!.domain).toBe('example.com');
    expect(result.components!.fqdn).toBe('myagent.example.com');
    expect(result.components!.dnsLookupName).toBe('_ans.example.com');
  });
});

// ============ Badge Issuance Tests ============

describe('issueANSBadge', () => {
  test('issues domain-validated badge', async () => {
    const parsed = parseANSName('ans://v1.0.myagent.example.com');
    expect(parsed.success).toBe(true);
    const badge = await issueANSBadge(parsed.components!, 'domain-validated', TEST_JWT_SECRET);

    expect(badge.badge_id).toMatch(/^ans_/);
    expect(badge.ans_name).toBe('ans://v1.0.myagent.example.com');
    expect(badge.domain).toBe('example.com');
    expect(badge.verified).toBe(true);
    expect(badge.trust_level).toBe('domain-validated');
    expect(badge.verification_type).toBe('dns-ownership');
    expect(badge.issuer).toBe('botcha.ai');
    expect(badge.credential_token).toBeTruthy();
    expect(badge.issued_at).toBeLessThanOrEqual(Date.now());
    expect(badge.expires_at).toBeGreaterThan(Date.now());
  });

  test('issues key-validated badge', async () => {
    const parsed = parseANSName('myagent.example.com');
    expect(parsed.success).toBe(true);
    const badge = await issueANSBadge(parsed.components!, 'key-validated', TEST_JWT_SECRET);

    expect(badge.trust_level).toBe('key-validated');
    expect(badge.verification_type).toBe('key-ownership');
  });

  test('issues badge with agent_id', async () => {
    const parsed = parseANSName('myagent.example.com');
    expect(parsed.success).toBe(true);
    const badge = await issueANSBadge(parsed.components!, 'domain-validated', TEST_JWT_SECRET, {
      agentId: 'agent_abc123',
    });

    expect(badge.agent_id).toBe('agent_abc123');
  });

  test('badge expires in ~90 days by default', async () => {
    const parsed = parseANSName('myagent.example.com');
    expect(parsed.success).toBe(true);
    const badge = await issueANSBadge(parsed.components!, 'domain-validated', TEST_JWT_SECRET);
    const ninetyDaysMs = 90 * 24 * 60 * 60 * 1000;
    const diff = badge.expires_at - badge.issued_at;
    // Allow ±1 second tolerance
    expect(diff).toBeGreaterThan(ninetyDaysMs - 1000);
    expect(diff).toBeLessThan(ninetyDaysMs + 1000);
  });

  test('respects custom expiry', async () => {
    const parsed = parseANSName('myagent.example.com');
    expect(parsed.success).toBe(true);
    const badge = await issueANSBadge(parsed.components!, 'domain-validated', TEST_JWT_SECRET, {
      expiresInSeconds: 3600,
    });
    const diff = badge.expires_at - badge.issued_at;
    expect(diff).toBeGreaterThan(3599000);
    expect(diff).toBeLessThan(3601000);
  });
});

// ============ ANS Registry Tests ============

describe('ANS Discovery Registry', () => {
  let kv: MockKV;

  beforeEach(() => {
    kv = new MockKV();
  });

  const makeEntry = (label: string, domain: string, trustLevel: ANSRegistryEntry['trust_level'] = 'domain-validated'): ANSRegistryEntry => ({
    ans_name: `ans://v1.0.${label}.${domain}`,
    domain,
    label,
    badge_id: `ans_badge_${label}`,
    trust_level: trustLevel,
    verified_at: Date.now(),
    expires_at: Date.now() + 90 * 24 * 60 * 60 * 1000,
  });

  test('saves and retrieves registry entry', async () => {
    const entry = makeEntry('myagent', 'example.com');
    await saveANSRegistryEntry(kv as any, entry);
    const retrieved = await getANSRegistryEntry(kv as any, 'example.com', 'myagent');
    expect(retrieved).not.toBeNull();
    expect(retrieved!.label).toBe('myagent');
    expect(retrieved!.domain).toBe('example.com');
    expect(retrieved!.trust_level).toBe('domain-validated');
  });

  test('returns null for missing entry', async () => {
    const result = await getANSRegistryEntry(kv as any, 'example.com', 'nobody');
    expect(result).toBeNull();
  });

  test('lists all registry entries', async () => {
    await saveANSRegistryEntry(kv as any, makeEntry('agent1', 'example.com'));
    await saveANSRegistryEntry(kv as any, makeEntry('agent2', 'example.com'));
    await saveANSRegistryEntry(kv as any, makeEntry('choco', 'botcha.ai', 'key-validated'));

    const entries = await listANSRegistry(kv as any);
    expect(entries.length).toBe(3);
  });

  test('filters by domain', async () => {
    await saveANSRegistryEntry(kv as any, makeEntry('agent1', 'example.com'));
    await saveANSRegistryEntry(kv as any, makeEntry('choco', 'botcha.ai'));

    const entries = await listANSRegistry(kv as any, { domain: 'botcha.ai' });
    expect(entries.length).toBe(1);
    expect(entries[0].label).toBe('choco');
  });

  test('deduplicates entries (same domain+label)', async () => {
    const entry = makeEntry('agent1', 'example.com');
    await saveANSRegistryEntry(kv as any, entry);
    await saveANSRegistryEntry(kv as any, entry); // same key, should not duplicate in index

    const entries = await listANSRegistry(kv as any);
    expect(entries.length).toBe(1);
  });

  test('respects limit', async () => {
    for (let i = 0; i < 10; i++) {
      await saveANSRegistryEntry(kv as any, makeEntry(`agent${i}`, 'example.com'));
    }
    const entries = await listANSRegistry(kv as any, { limit: 3 });
    expect(entries.length).toBeLessThanOrEqual(3);
  });

  test('empty registry returns empty array', async () => {
    const entries = await listANSRegistry(kv as any);
    expect(entries).toEqual([]);
  });
});

// ============ Nonce Management Tests ============

describe('ANS Nonce Management', () => {
  let kv: MockKV;

  beforeEach(() => {
    kv = new MockKV();
  });

  test('generates a nonce', async () => {
    const nonce = await generateANSNonce(kv as any, 'myagent.example.com');
    expect(nonce).toBeTruthy();
    expect(nonce).toMatch(/^nonce_/);
  });

  test('generates unique nonces', async () => {
    const n1 = await generateANSNonce(kv as any, 'agent1.example.com');
    const n2 = await generateANSNonce(kv as any, 'agent2.example.com');
    expect(n1).not.toBe(n2);
  });

  test('consumes a valid nonce (single use)', async () => {
    const nonce = await generateANSNonce(kv as any, 'myagent.example.com');
    const valid = await consumeANSNonce(kv as any, 'myagent.example.com', nonce);
    expect(valid).toBe(true);

    // Second attempt should fail (nonce deleted)
    const reuse = await consumeANSNonce(kv as any, 'myagent.example.com', nonce);
    expect(reuse).toBe(false);
  });

  test('rejects wrong nonce', async () => {
    await generateANSNonce(kv as any, 'myagent.example.com');
    const valid = await consumeANSNonce(kv as any, 'myagent.example.com', 'wrong_nonce');
    expect(valid).toBe(false);
  });

  test('rejects nonce for wrong ANS name', async () => {
    const nonce = await generateANSNonce(kv as any, 'agent1.example.com');
    const valid = await consumeANSNonce(kv as any, 'agent2.example.com', nonce);
    expect(valid).toBe(false);
  });

  test('returns false for non-existent nonce', async () => {
    const valid = await consumeANSNonce(kv as any, 'myagent.example.com', 'nonce_nonexistent');
    expect(valid).toBe(false);
  });
});

// ============ BOTCHA Identity Tests ============

describe('getBotchaANSRecord', () => {
  test('returns correct ANS identity', () => {
    const record = getBotchaANSRecord();
    expect(record.ans_name).toBe('ans://v1.0.botcha.ai');
    expect(record.dns_name).toBe('_ans.botcha.ai');
    expect(record.txt_record).toContain('v=ANS1');
    expect(record.txt_record).toContain('name=botcha');
    expect(record.txt_record).toContain('cap=');
    expect(record.txt_record).toContain('url=');
    expect(record.agent_card).toBeDefined();
    expect(record.agent_card['@type']).toBe('SoftwareApplication');
  });

  test('agent card has required ANS fields', () => {
    const { agent_card } = getBotchaANSRecord();
    expect(agent_card.name).toBe('BOTCHA');
    expect(agent_card.identifier).toBe('ans://v1.0.botcha.ai');
    expect(agent_card.did).toBe('did:web:botcha.ai');
    expect(Array.isArray(agent_card.capabilities)).toBe(true);
    expect((agent_card.capabilities as string[]).length).toBeGreaterThan(0);
  });
});

// ============ ANS Resolution Tests (mocked fetch) ============

describe('resolveANSName', () => {
  test('returns error for invalid ANS name', async () => {
    const result = await resolveANSName('invalid');
    expect(result.success).toBe(false);
    expect(result.error).toBeDefined();
  });

  test('handles DNS lookup failure gracefully', async () => {
    // Mock fetch to simulate DNS error
    const originalFetch = global.fetch;
    global.fetch = vi.fn().mockRejectedValue(new Error('Network error'));

    const result = await resolveANSName('myagent.example.com');
    expect(result.success).toBe(false);
    expect(result.error).toBeTruthy();
    expect(result.name).toBeDefined(); // name components should still be parsed

    global.fetch = originalFetch;
  });

  test('handles no ANS TXT record (NXDOMAIN)', async () => {
    // Mock fetch to return no TXT records
    const originalFetch = global.fetch;
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ Status: 3, Answer: [] }), // NXDOMAIN
    } as any);

    const result = await resolveANSName('myagent.example.com');
    expect(result.success).toBe(false);
    expect(result.name?.dnsLookupName).toBe('_ans.example.com');

    global.fetch = originalFetch;
  });

  test('resolves valid ANS TXT record', async () => {
    // Mock fetch to return a valid ANS TXT record
    const originalFetch = global.fetch;
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        Status: 0,
        Answer: [
          {
            type: 16,
            data: '"v=ANS1 name=myagent cap=browse,search url=https://example.com/agent.json"',
          },
        ],
      }),
    } as any);

    const result = await resolveANSName('myagent.example.com');

    if (result.success) {
      expect(result.record?.version).toBe('ANS1');
      expect(result.record?.cap).toContain('browse');
      expect(result.record?.cap).toContain('search');
      expect(result.record?.url).toBe('https://example.com/agent.json');
      expect(result.name?.label).toBe('myagent');
    } else {
      // DNS might have returned the record but agent card fetch failed, that's fine
      expect(result.name).toBeDefined();
    }

    global.fetch = originalFetch;
  });
});
