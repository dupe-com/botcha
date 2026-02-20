/**
 * BOTCHA ANS Integration — tap-ans.ts
 *
 * Agent Name Service (ANS) is the emerging "DNS for AI agents" led by GoDaddy.
 * ANS names like `ans://v1.0.myagent.example.com` resolve via DNS TXT records
 * to structured agent metadata. This module makes BOTCHA the verification badge
 * on top of ANS's domain-level trust.
 *
 * ANS gives you DV-level trust (domain exists). BOTCHA adds:
 *   "this agent actually behaves like an AI."
 *
 * Together: ANS names the agent, BOTCHA verifies it.
 *
 * Key ANS spec: https://agentnameregistry.org
 * ANS format:   ans://v1.0.<label>.<domain>
 *               e.g. ans://v1.0.myagent.example.com
 * DNS lookup:   TXT record at _ans.<domain>
 *               e.g. _ans.example.com TXT "v=ANS1 ..."
 *
 * References:
 *   - https://agentnameregistry.org
 *   - GoDaddy ANS Marketplace (Dec 2025)
 *   - IETF ANS draft (Nov 2025)
 */

import { SignJWT } from 'jose';

export interface KVNamespace {
  get(key: string, encoding?: string): Promise<string | null>;
  put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void>;
  delete(key: string): Promise<void>;
  list(options?: { prefix?: string; limit?: number; cursor?: string }): Promise<{
    keys: Array<{ name: string; expiration?: number }>;
    list_complete: boolean;
    cursor?: string;
  }>;
}

// ============ ANS TYPES ============

/**
 * Parsed ANS name components
 * ans://v1.0.myagent.example.com
 *   version: "v1.0"
 *   label:   "myagent"
 *   domain:  "example.com"
 */
export interface ANSNameComponents {
  raw: string;           // full ANS name as provided
  version: string;       // "v1.0"
  label: string;         // "myagent"
  domain: string;        // "example.com"
  fqdn: string;          // "myagent.example.com" (fully qualified)
  dnsLookupName: string; // "_ans.example.com" (where TXT record lives)
}

/**
 * Raw ANS TXT record content (after parsing)
 * ANS spec v1: v=ANS1 name=<label> pub=<base64-pubkey> cap=<csv> url=<agentcard-url>
 */
export interface ANSTXTRecord {
  version: string;       // "ANS1"
  name?: string;         // agent label from record
  pub?: string;          // base64-encoded public key
  cap?: string[];        // capabilities list
  url?: string;          // agent card / metadata URL
  did?: string;          // optional DID for the agent
  raw: string;           // raw TXT record string
}

/**
 * Result of resolving an ANS name
 */
export interface ANSResolutionResult {
  success: boolean;
  name?: ANSNameComponents;
  record?: ANSTXTRecord;
  agentCard?: Record<string, unknown>;  // fetched from record.url if present
  error?: string;
  resolvedAt?: number;
}

/**
 * BOTCHA verification badge linked to an ANS name
 */
export interface ANSVerificationBadge {
  badge_id: string;
  ans_name: string;        // e.g. "ans://v1.0.choco.botcha.ai"
  domain: string;          // verified domain
  agent_id?: string;       // BOTCHA agent ID (if registered)
  verified: boolean;
  verification_type: 'dns-ownership' | 'key-ownership' | 'challenge-verified';
  trust_level: 'domain-validated' | 'key-validated' | 'behavior-validated';
  credential_token: string; // signed JWT credential
  issued_at: number;
  expires_at: number;
  issuer: 'botcha.ai';
}

/**
 * ANS-verified agent in the BOTCHA discovery registry
 */
export interface ANSRegistryEntry {
  ans_name: string;
  domain: string;
  label: string;
  agent_id?: string;
  app_id?: string;
  badge_id: string;
  trust_level: 'domain-validated' | 'key-validated' | 'behavior-validated';
  capabilities?: string[];
  agent_card_url?: string;
  verified_at: number;
  expires_at: number;
}

// ============ ANS NAME PARSING ============

/**
 * Parse an ANS name into its components.
 *
 * Accepts:
 *   - ans://v1.0.myagent.example.com
 *   - v1.0.myagent.example.com   (without scheme)
 *   - myagent.example.com        (bare domain, defaults to v1.0)
 *   - example.com                (root domain, label = domain apex)
 */
export function parseANSName(input: string): { success: boolean; components?: ANSNameComponents; error?: string } {
  let raw = input.trim();

  // Strip scheme
  const withoutScheme = raw.startsWith('ans://')
    ? raw.slice('ans://'.length)
    : raw;

  // Split by dots
  const parts = withoutScheme.split('.');

  if (parts.length < 2) {
    return { success: false, error: `Invalid ANS name: "${input}" — must have at least 2 parts` };
  }

  let version = 'v1.0';
  let label: string;
  let domainParts: string[];

  // Detect version prefix: v1.0, v1, v2.0, etc.
  if (/^v\d+(\.\d+)?$/.test(parts[0])) {
    version = parts[0];
    // After version: next part is label, rest is domain
    if (parts.length < 3) {
      return { success: false, error: `ANS name with version requires: v<ver>.<label>.<domain>` };
    }
    label = parts[1];
    domainParts = parts.slice(2);
  } else {
    // No version: first part is label, rest is domain
    // But if only 2 parts (e.g. "example.com"), treat as root domain, label = first part
    label = parts[0];
    domainParts = parts.slice(1);
  }

  const domain = domainParts.join('.');
  const fqdn = `${label}.${domain}`;

  // DNS TXT lookup lives at _ans.<domain>
  const dnsLookupName = `_ans.${domain}`;

  const components: ANSNameComponents = {
    raw: input,
    version,
    label,
    domain,
    fqdn,
    dnsLookupName,
  };

  return { success: true, components };
}

// ============ DNS RESOLUTION (Cloudflare DNS-over-HTTPS) ============

/**
 * Resolve DNS TXT records using Cloudflare's DNS-over-HTTPS API.
 * Works inside Cloudflare Workers (no Node.js dns module needed).
 */
async function resolveTXTRecords(name: string): Promise<{ records: string[]; error?: string }> {
  try {
    const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=TXT`;
    const response = await fetch(url, {
      headers: {
        'Accept': 'application/dns-json',
      },
    });

    if (!response.ok) {
      return { records: [], error: `DNS query failed: HTTP ${response.status}` };
    }

    const data = await response.json() as {
      Status: number;
      Answer?: Array<{ type: number; data: string }>;
    };

    // Status 0 = NOERROR, Status 3 = NXDOMAIN
    if (data.Status !== 0) {
      return { records: [], error: `DNS status ${data.Status} (NXDOMAIN or error)` };
    }

    if (!data.Answer || data.Answer.length === 0) {
      return { records: [] };
    }

    // Filter TXT records (type 16), strip surrounding quotes
    const txtRecords = data.Answer
      .filter(a => a.type === 16)
      .map(a => a.data.replace(/^"|"$/g, '').replace(/"\s*"/g, '')); // handle multi-string TXT

    return { records: txtRecords };
  } catch (err) {
    return { records: [], error: `DNS fetch error: ${err instanceof Error ? err.message : String(err)}` };
  }
}

/**
 * Parse a raw ANS TXT record string into structured fields.
 * Format: v=ANS1 name=myagent pub=<base64> cap=browse,search url=https://...
 */
function parseANSTXTRecord(raw: string): ANSTXTRecord | null {
  if (!raw.includes('v=ANS1') && !raw.includes('v=ANS')) {
    return null;
  }

  const record: ANSTXTRecord = { version: 'ANS1', raw };

  // Extract key=value pairs (values may be quoted)
  const kvPattern = /(\w+)=("(?:[^"\\]|\\.)*"|[^\s]+)/g;
  let match: RegExpExecArray | null;

  while ((match = kvPattern.exec(raw)) !== null) {
    const key = match[1];
    const value = match[2].replace(/^"|"$/g, '');

    switch (key) {
      case 'v':
        record.version = value.replace('v=', '').trim() || 'ANS1';
        break;
      case 'name':
        record.name = value;
        break;
      case 'pub':
        record.pub = value;
        break;
      case 'cap':
        record.cap = value.split(',').map(s => s.trim()).filter(Boolean);
        break;
      case 'url':
        record.url = value;
        break;
      case 'did':
        record.did = value;
        break;
    }
  }

  return record;
}

// ============ ANS RESOLUTION ============

/**
 * Resolve an ANS name to agent metadata.
 *
 * Steps:
 *  1. Parse the ANS name
 *  2. Look up DNS TXT at _ans.<domain>
 *  3. Parse ANS TXT record
 *  4. Optionally fetch Agent Card from record.url
 */
export async function resolveANSName(ansName: string): Promise<ANSResolutionResult> {
  const parsed = parseANSName(ansName);
  if (!parsed.success || !parsed.components) {
    return { success: false, error: parsed.error };
  }

  const { components } = parsed;

  // DNS TXT lookup
  const dnsResult = await resolveTXTRecords(components.dnsLookupName);
  if (dnsResult.error && dnsResult.records.length === 0) {
    return {
      success: false,
      name: components,
      error: `DNS lookup failed for ${components.dnsLookupName}: ${dnsResult.error}`,
    };
  }

  // Find ANS record among TXT records
  let ansRecord: ANSTXTRecord | null = null;
  for (const txt of dnsResult.records) {
    const parsed = parseANSTXTRecord(txt);
    if (parsed) {
      ansRecord = parsed;
      break;
    }
  }

  if (!ansRecord) {
    return {
      success: false,
      name: components,
      error: `No ANS TXT record found at ${components.dnsLookupName}. Found ${dnsResult.records.length} TXT record(s) but none matched ANS format (v=ANS1).`,
    };
  }

  // Optionally fetch Agent Card from URL
  let agentCard: Record<string, unknown> | undefined;
  if (ansRecord.url) {
    try {
      const cardResponse = await fetch(ansRecord.url, {
        headers: { 'Accept': 'application/json' },
        signal: AbortSignal.timeout(5000),
      });
      if (cardResponse.ok) {
        agentCard = await cardResponse.json() as Record<string, unknown>;
      }
    } catch {
      // Non-fatal: agent card fetch failed, continue without it
    }
  }

  return {
    success: true,
    name: components,
    record: ansRecord,
    agentCard,
    resolvedAt: Date.now(),
  };
}

// ============ ANS OWNERSHIP VERIFICATION ============

/**
 * Verify that the caller owns the ANS name.
 *
 * Ownership proof options (in order of strength):
 *
 * 1. Key ownership: caller provides a signature over a BOTCHA nonce using the
 *    public key embedded in the ANS TXT record. This proves the holder of the
 *    private key is the registrant.
 *
 * 2. DNS challenge: BOTCHA issues a nonce, caller must place it in a DNS TXT
 *    record at _botcha-verify.<domain>. This proves DNS control.
 *
 * For Phase 1 we implement key-ownership verification using SubtleCrypto.
 */
export interface ANSOwnershipProof {
  ans_name: string;
  nonce: string;          // provided by BOTCHA, must be signed
  signature: string;      // base64url signature of nonce using ANS key
  algorithm?: string;     // default: 'ECDSA-P256'
  public_key?: string;    // optional: provide key directly (must match ANS record)
}

export interface ANSOwnershipResult {
  verified: boolean;
  method: 'key-ownership' | 'dns-challenge';
  error?: string;
}

/**
 * Verify ANS name ownership via key signature.
 * The ANS TXT record must contain `pub=<base64-pubkey>`.
 */
export async function verifyANSOwnership(
  proof: ANSOwnershipProof,
  resolvedRecord: ANSTXTRecord,
): Promise<ANSOwnershipResult> {
  // Determine which public key to use
  const pubKeyB64 = proof.public_key || resolvedRecord.pub;

  if (!pubKeyB64) {
    return {
      verified: false,
      method: 'key-ownership',
      error: 'No public key available in ANS record or proof. Add pub=<base64-key> to your _ans TXT record.',
    };
  }

  try {
    // Decode base64url public key (SPKI format expected)
    const pubKeyBytes = base64urlDecode(pubKeyB64);

    // Determine algorithm (default: ECDSA P-256)
    const algorithm = proof.algorithm?.toUpperCase() || 'ECDSA-P256';
    const cryptoAlg = algorithm === 'ED25519'
      ? { name: 'Ed25519' }
      : { name: 'ECDSA', namedCurve: 'P-256' };
    const verifyAlg = algorithm === 'ED25519'
      ? { name: 'Ed25519' }
      : { name: 'ECDSA', hash: { name: 'SHA-256' } };

    // Import public key
    const cryptoKey = await crypto.subtle.importKey(
      'spki',
      pubKeyBytes,
      cryptoAlg,
      false,
      ['verify'],
    );

    // Decode and verify signature over nonce
    const sigBytes = base64urlDecode(proof.signature);
    const nonceBytes = new TextEncoder().encode(proof.nonce);
    const isValid = await crypto.subtle.verify(verifyAlg, cryptoKey, sigBytes, nonceBytes);

    return {
      verified: isValid,
      method: 'key-ownership',
      error: isValid ? undefined : 'Signature verification failed — nonce not signed by ANS key',
    };
  } catch (err) {
    return {
      verified: false,
      method: 'key-ownership',
      error: `Crypto error: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
}

// ============ BOTCHA CREDENTIAL ISSUANCE ============

/**
 * Issue a BOTCHA-ANS linked verification badge.
 *
 * The badge is a signed JWT (HS256) containing:
 *   - ans_name: canonical ANS identifier
 *   - domain: verified domain
 *   - trust_level: what was verified
 *   - botcha: "verified" — the stamp
 *
 * This badge can be embedded in ANS Marketplace listings and verified
 * by anyone who knows the BOTCHA JWT secret (or JWKS public key).
 */
export async function issueANSBadge(
  components: ANSNameComponents,
  trustLevel: ANSVerificationBadge['trust_level'],
  jwtSecret: string,
  options?: {
    agentId?: string;
    capabilities?: string[];
    agentCardUrl?: string;
    expiresInSeconds?: number;
  }
): Promise<ANSVerificationBadge> {
  const now = Date.now();
  const expiresInMs = (options?.expiresInSeconds ?? 86400 * 90) * 1000; // default 90 days
  const expiresAt = now + expiresInMs;
  const badgeId = generateId('ans');

  const payload: Record<string, unknown> = {
    type: 'botcha-ans-badge',
    jti: badgeId,
    ans_name: components.raw,
    domain: components.domain,
    label: components.label,
    trust_level: trustLevel,
    botcha: 'verified',
    issuer: 'botcha.ai',
  };

  if (options?.agentId) {
    payload.agent_id = options.agentId;
  }
  if (options?.capabilities) {
    payload.capabilities = options.capabilities;
  }

  const secretBytes = new TextEncoder().encode(jwtSecret);
  const token = await new SignJWT(payload)
    .setProtectedHeader({ alg: 'HS256' })
    .setSubject(components.fqdn)
    .setIssuer('botcha.ai')
    .setIssuedAt()
    .setExpirationTime(Math.floor(expiresAt / 1000))
    .sign(secretBytes);

  return {
    badge_id: badgeId,
    ans_name: components.raw,
    domain: components.domain,
    agent_id: options?.agentId,
    verified: true,
    verification_type: trustLevel === 'domain-validated' ? 'dns-ownership'
      : trustLevel === 'key-validated' ? 'key-ownership'
      : 'challenge-verified',
    trust_level: trustLevel,
    credential_token: token,
    issued_at: now,
    expires_at: expiresAt,
    issuer: 'botcha.ai',
  };
}

// ============ ANS DISCOVERY REGISTRY ============

/**
 * Save a verified ANS agent to the BOTCHA discovery registry.
 * Stored in KV under `ans_registry:<domain>:<label>`
 */
export async function saveANSRegistryEntry(
  kv: KVNamespace,
  entry: ANSRegistryEntry,
): Promise<void> {
  const key = `ans_registry:${entry.domain}:${entry.label}`;
  const ttlSeconds = Math.max(1, Math.floor((entry.expires_at - Date.now()) / 1000));
  await kv.put(key, JSON.stringify(entry), { expirationTtl: ttlSeconds });

  // Also maintain a global index for listing
  const indexKey = 'ans_registry_index';
  const existingRaw = await kv.get(indexKey);
  const index: string[] = existingRaw ? JSON.parse(existingRaw) : [];
  const entryKey = `${entry.domain}:${entry.label}`;
  if (!index.includes(entryKey)) {
    index.push(entryKey);
    await kv.put(indexKey, JSON.stringify(index));
  }
}

/**
 * Get a single ANS registry entry.
 */
export async function getANSRegistryEntry(
  kv: KVNamespace,
  domain: string,
  label: string,
): Promise<ANSRegistryEntry | null> {
  const key = `ans_registry:${domain}:${label}`;
  const raw = await kv.get(key);
  if (!raw) return null;
  return JSON.parse(raw) as ANSRegistryEntry;
}

/**
 * List all BOTCHA-verified ANS agents in the discovery registry.
 * Optionally filter by domain.
 */
export async function listANSRegistry(
  kv: KVNamespace,
  options?: { domain?: string; limit?: number },
): Promise<ANSRegistryEntry[]> {
  const indexKey = 'ans_registry_index';
  const indexRaw = await kv.get(indexKey);
  if (!indexRaw) return [];

  const index: string[] = JSON.parse(indexRaw);
  const limit = options?.limit ?? 100;
  const domainFilter = options?.domain;

  const filtered = domainFilter
    ? index.filter(k => k.startsWith(`${domainFilter}:`))
    : index;

  const entries: ANSRegistryEntry[] = [];
  for (const entryKey of filtered.slice(0, limit)) {
    const [domain, label] = entryKey.split(':', 2);
    const entry = await getANSRegistryEntry(kv, domain, label);
    if (entry) {
      entries.push(entry);
    }
  }

  return entries.sort((a, b) => b.verified_at - a.verified_at);
}

// ============ NONCE MANAGEMENT ============

/**
 * Generate and store a fresh nonce for ANS ownership verification.
 * TTL: 10 minutes — caller must sign and return within this window.
 */
export async function generateANSNonce(
  kv: KVNamespace,
  ansName: string,
): Promise<string> {
  const nonce = generateId('nonce');
  const key = `ans_nonce:${ansName}`;
  await kv.put(key, JSON.stringify({ nonce, created_at: Date.now() }), {
    expirationTtl: 600, // 10 minutes
  });
  return nonce;
}

/**
 * Consume (verify + delete) a stored ANS nonce.
 * Returns true if nonce matches. Nonces are single-use.
 */
export async function consumeANSNonce(
  kv: KVNamespace,
  ansName: string,
  providedNonce: string,
): Promise<boolean> {
  const key = `ans_nonce:${ansName}`;
  const raw = await kv.get(key);
  if (!raw) return false;

  const stored = JSON.parse(raw) as { nonce: string; created_at: number };
  if (stored.nonce !== providedNonce) return false;

  // Delete nonce — single use
  await kv.delete(key);
  return true;
}

// ============ BOTCHA'S OWN ANS RECORD ============

/**
 * Returns the metadata for BOTCHA's own ANS registration.
 * ans://v1.0.botcha.ai
 *
 * This would be placed as a TXT record at _ans.botcha.ai:
 *   v=ANS1 name=botcha cap=verify,issue,discover url=https://botcha.ai/.well-known/agent.json
 */
export function getBotchaANSRecord(): {
  ans_name: string;
  dns_name: string;
  txt_record: string;
  agent_card: Record<string, unknown>;
} {
  return {
    ans_name: 'ans://v1.0.botcha.ai',
    dns_name: '_ans.botcha.ai',
    txt_record: 'v=ANS1 name=botcha cap=verify,issue,discover url=https://botcha.ai/.well-known/agent.json did=did:web:botcha.ai',
    agent_card: {
      '@context': 'https://schema.org',
      '@type': 'SoftwareApplication',
      name: 'BOTCHA',
      description: 'Reverse CAPTCHA for AI agents. Verification layer for the Agent Name Service.',
      url: 'https://botcha.ai',
      identifier: 'ans://v1.0.botcha.ai',
      did: 'did:web:botcha.ai',
      capabilities: ['verify', 'issue', 'discover'],
      verification: {
        type: 'ANS-BOTCHA-Badge',
        endpoint: 'https://botcha.ai/v1/ans/verify',
        discovery: 'https://botcha.ai/v1/ans/discover',
      },
    },
  };
}

// ============ UTILITY ============

function generateId(prefix: string): string {
  const bytes = new Uint8Array(12);
  crypto.getRandomValues(bytes);
  const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  return `${prefix}_${hex}`;
}

function base64urlDecode(input: string): Uint8Array {
  // Convert base64url to base64
  const base64 = input.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '=='.slice(0, (4 - base64.length % 4) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export default {
  parseANSName,
  resolveANSName,
  verifyANSOwnership,
  issueANSBadge,
  saveANSRegistryEntry,
  getANSRegistryEntry,
  listANSRegistry,
  generateANSNonce,
  consumeANSNonce,
  getBotchaANSRecord,
};
