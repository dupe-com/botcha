# TAP Full Spec Alignment — Implementation Plan

> **Version:** 1.0 · **Created:** 2026-02-14 · **Target:** v0.16.0
> **Goal:** Full Visa Trusted Agent Protocol compatibility + novel extensions

---

## Context

BOTCHA shipped TAP support in v0.12.0, but our implementation only partially covers the
Visa TAP specification. This plan brings BOTCHA to **full TAP spec compliance** and adds
novel extensions that differentiate us.

**Source spec:** https://developer.visa.com/capabilities/trusted-agent-protocol/trusted-agent-protocol-specifications
**Reference impl:** https://github.com/visa/trusted-agent-protocol
**Visa JWKS endpoint:** https://mcp.visa.com/.well-known/jwks

---

## Architecture Overview

Visa TAP defines **three cryptographic layers**, each with its own signature:

```
┌─────────────────────────────────────────────────────────┐
│  Layer 1: Agent Recognition Signature (HTTP Headers)     │
│  RFC 9421 HTTP Message Signatures                        │
│  Signature-Input + Signature headers                     │
│  Tags: agent-browser-auth | agent-payer-auth             │
├─────────────────────────────────────────────────────────┤
│  Layer 2: Agentic Consumer Recognition (Request Body)    │
│  agenticConsumer JSON object                             │
│  ID Token (OIDC JWT) + contextualData                    │
│  Linked to Layer 1 via shared nonce                      │
├─────────────────────────────────────────────────────────┤
│  Layer 3: Agentic Payment Container (Request Body)       │
│  agenticPaymentContainer JSON object                     │
│  Card metadata, credential hash, encrypted payload, IOUs │
│  Linked to Layer 1 via shared nonce                      │
└─────────────────────────────────────────────────────────┘

     Public Key Infrastructure
     ┌──────────────────────────────┐
     │  .well-known/jwks endpoint    │
     │  JWK Set format               │
     │  Key expiration & rotation    │
     └──────────────────────────────┘
```

**BOTCHA currently only partially implements Layer 1. Layers 2 and 3 are missing entirely.**

---

## Gap Summary (Current State → Target)

| Feature | Current | Target | Files Affected |
|---------|---------|--------|----------------|
| **Ed25519 algorithm** | ❌ Only ECDSA-P256 + RSA-PSS | ✅ Ed25519 (recommended) + existing | tap-verify.ts, tap-agents.ts, types |
| **@authority component** | ❌ Uses @method | ✅ @authority + @path | tap-verify.ts |
| **expires param** | ❌ Missing | ✅ 8-min max window | tap-verify.ts |
| **nonce param** | ❌ Missing | ✅ With KV replay tracking | tap-verify.ts, wrangler.toml |
| **tag param** | ❌ Missing | ✅ agent-browser-auth / agent-payer-auth | tap-verify.ts |
| **Nonce replay protection** | ❌ None | ✅ KV-backed 8-min TTL | tap-verify.ts, index.tsx |
| **sig2 label support** | ❌ Only sig1 | ✅ Both sig1 + sig2 | tap-verify.ts |
| **Signature base format** | ❌ Close but wrong | ✅ Exact TAP spec format | tap-verify.ts |
| **.well-known/jwks** | ❌ Missing | ✅ JWK Set endpoint | NEW tap-jwks.ts, index.tsx |
| **JWK format** | ❌ PEM only | ✅ JWK + PEM | tap-agents.ts, tap-jwks.ts |
| **Key expiration** | ❌ Missing | ✅ key_expires_at field | tap-agents.ts |
| **Consumer Recognition** | ❌ Missing | ✅ Full agenticConsumer parsing + verification | NEW tap-consumer.ts |
| **Payment Container** | ❌ Missing | ✅ Full agenticPaymentContainer + IOU | NEW tap-payment.ts |
| **402 Micropayment** | ❌ Missing | ✅ Browsing IOU flow | NEW tap-payment.ts |
| **CDN Edge Verify** | ❌ Missing | ✅ CF Worker reference impl | NEW tap-edge.ts |
| **Visa Key Federation** | ❌ Missing | ✅ Fetch from mcp.visa.com | NEW tap-federation.ts |
| **Conformance tests** | ❌ Missing | ✅ Full TAP conformance suite | NEW tests/conformance/ |

---

## Phase Breakdown

### Phase 1: Core Crypto Rewrite (FOUNDATION — must ship first)

**Goal:** Make `tap-verify.ts` fully TAP-compliant. This is the hardest and most critical change.

**Subtask 1A: Ed25519 Algorithm Support**
```
Files: tap-verify.ts, tap-agents.ts, lib/client/types.ts, packages/python/src/botcha/types.py
```
- Add `'ed25519'` to `TAPSignatureAlgorithm` type union (all type files)
- Add Ed25519 import params: `{ name: 'Ed25519' }` (no hash needed)
- Add Ed25519 verify params: `{ name: 'Ed25519' }` (no hash needed)
- Ed25519 keys use raw 32-byte format (not SPKI PEM) — support both:
  - PEM-encoded SPKI format (standard)
  - Base64 raw 32-byte key (Visa's sample format: `"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo="`)
- CF Workers: Ed25519 is supported via Web Crypto (`crypto.subtle.importKey` with `'Ed25519'`)
- Update `isValidPEMPublicKey` in tap-agents.ts to also accept base64 raw keys for Ed25519
- Update validation in tap-routes.ts `validateTAPRegistration`

**Subtask 1B: RFC 9421 Signature Format — Full Compliance**
```
Files: tap-verify.ts (primary), tap-verify.test.ts
```

Changes to `parseSignatureInput()`:
- Support both `sig1` and `sig2` labels (regex: `/sig[12]=\(([^)]+)\)/`)
- Extract `expires` field: `/expires=(\d+)/`
- Extract `nonce` field: `/nonce="([^"]+)"/`
- Extract `tag` field: `/tag="([^"]+)"/`
- Return all new fields in parsed result

Changes to signature timestamp validation:
- Check `created` is in the past
- Check `expires` is in the future
- Check `expires - created <= 480` (8 minutes max)
- Replace current 5-minute tolerance with TAP's 8-minute window

Changes to `buildSignatureBase()`:
- Use `@authority` (from `host` header) NOT `@method` as primary component
- Fix format to match Visa's exact canonical form:
  ```
  "@authority": example.com
  "@path": /example-product
  "@signature-params": sig2=("@authority" "@path");created=1735689600;keyid="...";alg="Ed25519";expires=1735693200;nonce="...";tag="agent-browser-auth"
  ```
- Note: `@authority` uses bare value (no quotes), `@path` uses bare value
- The `@signature-params` line includes the full params string

Changes to `verifyCryptoSignature()`:
- Support `sig2` label in addition to `sig1`
- Extract label dynamically from signature-input

New: Nonce replay protection:
- After successful verification, store nonce in KV with 8-minute TTL
- Before verification, check if nonce already exists → reject if so
- KV key pattern: `nonce:{nonce_hash}` (SHA-256 hash of nonce for fixed-length keys)
- Requires `NONCES` KV namespace binding in wrangler.toml

New: Tag support:
- Parse `tag` from signature-input
- Validate tag is one of: `agent-browser-auth`, `agent-payer-auth`
- Map to BOTCHA actions: browse/compare/search/audit → agent-browser-auth, purchase → agent-payer-auth
- Return tag in verification result for downstream use

**Subtask 1C: Update TAPHeaders Interface + Extraction**
```
Files: tap-verify.ts
```
- Keep existing `x-tap-*` headers as BOTCHA extensions
- Add standard TAP tag detection from Signature-Input
- Detect TAP headers via either:
  - Standard: `Signature-Input` with tag=`agent-browser-auth|agent-payer-auth`
  - BOTCHA Extended: `x-tap-agent-id` + `x-tap-intent`
- Update `extractTAPHeaders` to return both standard and extended headers
- Update `getVerificationMode` to handle standard TAP signatures

---

### Phase 2: Public Key Infrastructure

**Goal:** Standard-compliant key discovery and management.

**Subtask 2A: JWK Format Support + .well-known/jwks Endpoint**
```
Files: NEW tap-jwks.ts, index.tsx, tap-agents.ts
```

New file `tap-jwks.ts`:
- `pemToJwk(pem: string, algorithm: string, kid: string): JWK` — convert PEM to JWK
- `jwkToPem(jwk: JWK): string` — convert JWK back to PEM for verification
- `getJwksForApp(agents: KVNamespace, appId: string): JWKSet` — build JWKS from all TAP agents
- `getKeyById(agents: KVNamespace, keyId: string): JWK | null` — lookup single key
- JWK fields: `kty`, `kid`, `use` ("sig"), `alg`, `n`, `e` (for RSA), `x`, `crv` (for EC/Ed25519)

New routes in index.tsx:
- `GET /.well-known/jwks` — returns JWK Set for default/queried app
  - Query params: `?app_id=` (optional, returns all public agents if omitted)
  - Response: `{ "keys": [JWK, JWK, ...] }`
  - Cache-Control: `public, max-age=3600` (1 hour cache)
- `GET /v1/keys` or `GET /v1/keys/:keyId` — individual key lookup
  - Returns single JWK + agent metadata (name, domain, algorithm)
  - Compatible with Visa's `/keys?keyID=` pattern

**Subtask 2B: Key Expiration + Rotation**
```
Files: tap-agents.ts, tap-routes.ts
```
- Add `key_expires_at?: number` to TAPAgent interface
- Accept `key_expires_at` in registration (ISO 8601 string → epoch ms)
- Default expiration: 1 year from creation
- Check expiration during verification (`getTAPAgent` should flag expired keys)
- New endpoint: `POST /v1/agents/:id/tap/rotate-key` — register new key, deprecate old
- Store previous key IDs for grace period (e.g., 24 hours after rotation)

---

### Phase 3: Body Object Verification (Layers 2 & 3)

**Goal:** Parse and verify the two JSON body objects defined in TAP spec.

**Subtask 3A: Nonce-Linked Signature Chain (prerequisite for 3B and 3C)**
```
Files: tap-verify.ts (extend)
```
- New function: `verifyLinkedSignature(bodyObject, headerNonce, publicKey, algorithm)`
  - Verify that `bodyObject.nonce === headerNonce` (chain link)
  - Build signature base from all body fields EXCEPT `signature` (in order received)
  - Verify bodyObject.signature with bodyObject.kid's public key
  - Return `{ valid: boolean, error?: string }`
- New function: `extractNonceFromSignatureInput(signatureInput: string): string | null`
  - Used to get the header nonce for linking

**Subtask 3B: Agentic Consumer Recognition Object**
```
Files: NEW tap-consumer.ts, NEW tap-consumer.test.ts
```

Types:
```typescript
interface AgenticConsumer {
  nonce: string;          // Must match header signature nonce
  idToken?: IDToken;      // OIDC-compatible JWT (signed by issuer)
  contextualData?: ContextualData;
  kid: string;            // Same keyid as header signature
  alg: string;            // Algorithm for body signature
  signature: string;      // Base64 signature over all fields except 'signature'
}

interface ContextualData {
  countryCode?: string;   // ISO 3166-1 alpha-2
  zip?: string;           // Postal code (up to 16 chars)
  ipAddress?: string;     // Consumer device IP
  deviceData?: DeviceData;
}

interface IDToken {
  // Standard OIDC claims
  iss: string;
  sub: string;
  aud: string | string[];
  exp: number;
  iat: number;
  jti?: string;
  auth_time?: number;
  amr?: string[];
  // Consumer identity (obfuscated)
  phone_number?: string;       // Obfuscated, E.164 format
  phone_number_verified?: boolean;
  phone_number_mask?: string;  // Masked for UI display
  email?: string;              // Obfuscated, RFC 5322
  email_verified?: boolean;
  email_mask?: string;         // Masked for UI display
}
```

Functions:
- `parseAgenticConsumer(body: any): AgenticConsumer | null` — extract from request body
- `verifyAgenticConsumer(consumer: AgenticConsumer, headerNonce: string, publicKey: string, algorithm: string): VerificationResult`
  - Check nonce matches header
  - Verify signature using linked signature chain
  - Return parsed consumer data + verification status
- `verifyIDToken(idToken: string, jwksUrl?: string): IDTokenClaims`
  - Parse JWT, fetch issuer's JWKS, verify signature
  - Check exp/iat/aud claims
  - Return verified claims
- `hashMatchConsumer(obfuscatedEmail: string, merchantEmails: string[]): boolean`
  - Help merchants check if consumer matches their records

**Subtask 3C: Agentic Payment Container**
```
Files: NEW tap-payment.ts, NEW tap-payment.test.ts
```

Types:
```typescript
interface AgenticPaymentContainer {
  nonce: string;
  kid: string;
  alg: string;
  signature: string;
  // One or more of the following:
  cardMetadata?: CardMetadata;
  credentialHash?: CredentialHash;
  payload?: EncryptedPaymentPayload; // Encrypted with merchant's public key
  browsingIOU?: BrowsingIOU;
}

interface CardMetadata {
  lastFour: string;
  paymentAccountReference: string;  // PAR
  shortDescription?: string;
  cardData?: Array<{
    contentType: string;
    content: { mimeType: string; width: number; height: number };
  }>;
}

interface CredentialHash {
  hash: string;  // SHA-256(PAN + expMonth + expYear + CVV)
  algorithm: string;  // 'sha256'
}

interface BrowsingIOU {
  invoiceId: string;      // From merchant's 402 response
  amount: string;         // From merchant's 402 response
  cardAcceptorId: string; // CAID from 402
  acquirerId: string;     // AID
  uri: string;            // URI of gated resource
  sequenceCounter: string;
  paymentService: string; // Agent's payment service
  kid: string;
  alg: string;
  signature: string;
}
```

Functions:
- `parsePaymentContainer(body: any): AgenticPaymentContainer | null`
- `verifyPaymentContainer(container, headerNonce, publicKey, algorithm): VerificationResult`
- `verifyCredentialHash(hash: string, pan: string, expMonth: string, expYear: string, cvv: string): boolean`
  - Merchant compares hashes to detect fraud
- `verifyBrowsingIOU(iou: BrowsingIOU, invoiceData: InvoiceData): VerificationResult`
  - Verify IOU matches the 402 invoice

**Subtask 3D: 402 Payment Required Flow**
```
Files: tap-payment.ts (extend), tap-routes.ts (new endpoints)
```

New endpoints:
- `POST /v1/invoices` — merchant creates invoice for gated content
  - Body: `{ resource_uri, amount, currency, description }`
  - Returns: `{ invoice_id, card_acceptor_id, amount, expires_at }`
  - Stored in KV with TTL
- `POST /v1/invoices/:id/verify-iou` — agent presents Browsing IOU
  - Verifies IOU signature, matches invoice data
  - Returns: `{ verified: true, access_token, expires_at }`
- Helper: `build402Response(invoiceId, amount, cardAcceptorId)` — build TAP-compliant 402 response

The 402 flow:
1. Agent requests gated resource → merchant returns 402 with invoice details
2. Agent generates BrowsingIOU with invoice data + signature
3. Agent re-requests resource with IOU in body
4. Merchant/BOTCHA verifies IOU → grants access
5. Settlement happens out-of-band

---

### Phase 4: Ecosystem Integration

**Subtask 4A: CDN Edge Verification**
```
Files: NEW tap-edge.ts
```
- Cloudflare Worker middleware pattern (not a separate worker)
- `createTAPEdgeMiddleware(options)` — Hono middleware factory
- Intercepts requests, checks for `Signature-Input` with TAP tags
- Verifies signature → adds `X-TAP-Verified: true` header to origin request
- Adds `X-TAP-Agent-Id`, `X-TAP-Tag`, `X-TAP-Trust-Level` headers
- Passes through non-TAP requests unmodified
- Designed to be copy-pasted into any CF Worker
- Export as `@dupecom/botcha/edge` subpath

**Subtask 4B: Visa Key Store Federation**
```
Files: NEW tap-federation.ts
```
- `fetchExternalJWKS(url: string): JWKSet` — fetch JWK Set from any URL
- `fetchVisaKeys(): JWKSet` — fetch from `https://mcp.visa.com/.well-known/jwks`
- `resolvePublicKey(keyId: string, agents: KVNamespace): { key, source }` — try:
  1. Local agent registry (BOTCHA agents)
  2. Cached federated keys
  3. Visa JWKS endpoint (if keyId prefix matches)
- Cache federated keys in KV with 1-hour TTL
- KV key pattern: `federated_key:{kid}` → JWK + source_url + fetched_at

---

### Phase 5: SDK + Type Updates

**Subtask 5A: TypeScript Types**
```
Files: lib/client/types.ts
```
- Add `'ed25519'` to `TAPSignatureAlgorithm`
- Add `TAPTag = 'agent-browser-auth' | 'agent-payer-auth'`
- Add `AgenticConsumer`, `ContextualData`, `IDTokenClaims` types
- Add `AgenticPaymentContainer`, `CardMetadata`, `CredentialHash`, `BrowsingIOU` types
- Add `TAPInvoice`, `TAPInvoiceResponse` types
- Add `key_expires_at` to `RegisterTAPAgentOptions` and `TAPAgentResponse`
- Add `JWK`, `JWKSet` types

**Subtask 5B: TypeScript Client Methods**
```
Files: lib/client/index.ts
```
New methods on BotchaClient:
- `getJWKS(appId?: string): Promise<JWKSet>` — fetch .well-known/jwks
- `getKeyById(keyId: string): Promise<JWK>` — fetch individual key
- `rotateAgentKey(agentId: string, newKey: RegisterTAPAgentOptions): Promise<TAPAgentResponse>`
- `createInvoice(options: CreateInvoiceOptions): Promise<TAPInvoiceResponse>`
- `verifyBrowsingIOU(invoiceId: string, iou: BrowsingIOU): Promise<VerifyIOUResponse>`

**Subtask 5C: Python Types**
```
Files: packages/python/src/botcha/types.py
```
Mirror all new TypeScript types as Python dataclasses.

**Subtask 5D: Python Client Methods**
```
Files: packages/python/src/botcha/client.py
```
Mirror all new TypeScript client methods as Python methods.

**Subtask 5E: CLI Commands**
```
Files: packages/cli/src/commands/tap.ts
```
New subcommands:
- `botcha tap jwks [--app-id]` — fetch JWKS
- `botcha tap rotate-key [--agent-id] [--public-key] [--algorithm]`
- `botcha tap invoice create [--resource] [--amount]`
- `botcha tap invoice verify [--invoice-id] [--iou-file]`

---

### Phase 6: Route Wiring + Middleware + Documentation

**Subtask 6A: Route Registration**
```
Files: index.tsx
```
New routes:
```typescript
// JWKS / Key Discovery
app.get('/.well-known/jwks', jwksRoute);
app.get('/v1/keys', listKeysRoute);
app.get('/v1/keys/:keyId', getKeyRoute);

// Key Rotation
app.post('/v1/agents/:id/tap/rotate-key', rotateKeyRoute);

// Invoice / 402 Flow
app.post('/v1/invoices', createInvoiceRoute);
app.post('/v1/invoices/:id/verify-iou', verifyIOURoute);
app.get('/v1/invoices/:id', getInvoiceRoute);

// Consumer Recognition verification (utility endpoint)
app.post('/v1/verify/consumer', verifyConsumerRoute);

// Payment Container verification (utility endpoint)
app.post('/v1/verify/payment', verifyPaymentRoute);
```

New KV namespace needed in wrangler.toml:
```toml
# Nonces KV namespace for replay protection
[[kv_namespaces]]
binding = "NONCES"
id = "<create via wrangler>"

# Invoices KV namespace for 402 flow
[[kv_namespaces]]
binding = "INVOICES"
id = "<create via wrangler>"
```

**Subtask 6B: Middleware Update**
```
Files: src/middleware/tap-enhanced-verify.ts
```
- Update `supported_algorithms` to include `'ed25519'`
- Add consumer recognition extraction in strict/flexible modes
- Add payment container verification in strict mode
- Update challenge response to include `.well-known/jwks` URL

**Subtask 6C: Documentation Updates**
```
Files: ROADMAP.md, README.md, doc/CLIENT-SDK.md, public/ai.txt,
       packages/cloudflare-workers/src/static.ts, public/index.html,
       packages/python/README.md
```
- Move TAP items to "Shipped" in ROADMAP.md with v0.16.0
- Add new endpoints to README.md TAP section
- Add new SDK methods to CLIENT-SDK.md
- Update ai.txt with new endpoints
- Update OpenAPI spec in static.ts
- Update Python README

---

### Phase 7: Conformance Test Suite

**Subtask 7A: TAP Conformance Tests**
```
Files: NEW tests/conformance/tap-conformance.test.ts
```
Test cases covering the full Visa TAP spec:
1. **Agent Recognition Signature**
   - Ed25519 signed request → verified
   - RSA-PSS-SHA256 signed request → verified
   - Missing @authority → rejected
   - Expired signature (expires in past) → rejected
   - Replay (reused nonce) → rejected
   - Wrong tag → rejected
   - Tampered path (path changed after signing) → rejected
   - Tampered authority → rejected

2. **Consumer Recognition Object**
   - Valid agenticConsumer with matching nonce → verified
   - Nonce mismatch → rejected
   - Invalid ID Token signature → flagged
   - Expired ID Token → flagged

3. **Payment Container**
   - Valid credential hash → verified
   - Browsing IOU with matching invoice → verified
   - IOU with mismatched amount → rejected

4. **Key Infrastructure**
   - .well-known/jwks returns valid JWK Set
   - /keys/:keyId returns correct key
   - Expired key → rejected during verification

5. **End-to-end flows**
   - Browse flow: agent-browser-auth + consumer recognition
   - Purchase flow: agent-payer-auth + payment container
   - 402 flow: request → 402 → IOU → access granted

---

## Dependency Graph

```
Phase 1 (Core Crypto)
  ├── 1A: Ed25519 ────────────────────────┐
  ├── 1B: RFC 9421 Full Compliance ───────┤
  └── 1C: Header Extraction Update ───────┤
                                           │
Phase 2 (Key Infra) ──────────────────────┤
  ├── 2A: JWKS + JWK Format              │
  └── 2B: Key Expiration + Rotation       │
                                           │
Phase 3 (Body Objects) ───────────────────┤  depends on Phase 1 (nonce in sig)
  ├── 3A: Nonce-Linked Chain (prereq) ────┤
  ├── 3B: Consumer Recognition ───────────┤  depends on 3A
  ├── 3C: Payment Container ──────────────┤  depends on 3A
  └── 3D: 402 IOU Flow ──────────────────┤  depends on 3C
                                           │
Phase 4 (Ecosystem) ──────────────────────┤  depends on Phase 1 + 2
  ├── 4A: CDN Edge Verify                 │
  └── 4B: Visa Key Federation             │
                                           │
Phase 5 (SDKs) ───────────────────────────┤  depends on all new types/endpoints
  ├── 5A: TS Types                        │
  ├── 5B: TS Client Methods              │
  ├── 5C: Python Types                   │
  ├── 5D: Python Client Methods          │
  └── 5E: CLI Commands                   │
                                           │
Phase 6 (Wiring) ─────────────────────────┤  depends on all implementation
  ├── 6A: Route Registration              │
  ├── 6B: Middleware Update               │
  └── 6C: Documentation                  │
                                           │
Phase 7 (Validation) ─────────────────────┘  depends on everything
  └── 7A: Conformance Tests
```

## Swarm Execution Strategy

### Wave 1 (Parallel — no file conflicts)
| Worker | Subtask | Primary Files (exclusive) |
|--------|---------|--------------------------|
| A | 1A+1B+1C: Core Crypto Rewrite | `tap-verify.ts`, `tap-verify.test.ts` |
| B | 2A: JWKS + JWK Format | NEW `tap-jwks.ts`, NEW `tap-jwks.test.ts` |
| C | 3B: Consumer Recognition | NEW `tap-consumer.ts`, NEW `tap-consumer.test.ts` |
| D | 3C+3D: Payment Container + 402 | NEW `tap-payment.ts`, NEW `tap-payment.test.ts` |
| E | 4A: CDN Edge Verify | NEW `tap-edge.ts`, NEW `tap-edge.test.ts` |
| F | 4B: Visa Key Federation | NEW `tap-federation.ts`, NEW `tap-federation.test.ts` |

### Wave 2 (After Wave 1 — shared files)
| Worker | Subtask | Primary Files |
|--------|---------|---------------|
| G | 1A types + 2B + 5A+5C: All type updates | `tap-agents.ts`, `lib/client/types.ts`, `packages/python/.../types.py` |
| H | 5B+5D: SDK client methods | `lib/client/index.ts`, `packages/python/.../client.py` |
| I | 6A: Route wiring | `index.tsx`, `tap-routes.ts`, `wrangler.toml` |

### Wave 3 (After Wave 2 — integration)
| Worker | Subtask | Files |
|--------|---------|-------|
| J | 5E+6B: CLI + Middleware | `packages/cli/.../tap.ts`, `src/middleware/tap-enhanced-verify.ts` |
| K | 6C: Documentation | ROADMAP.md, README.md, doc/CLIENT-SDK.md, ai.txt, static.ts |
| L | 7A: Conformance Tests | NEW `tests/conformance/tap-conformance.test.ts` |

---

## File Inventory (New + Modified)

### New Files
```
packages/cloudflare-workers/src/tap-jwks.ts          — JWK conversion + JWKS endpoint logic
packages/cloudflare-workers/src/tap-consumer.ts       — Agentic Consumer Recognition
packages/cloudflare-workers/src/tap-payment.ts        — Payment Container + 402 IOU
packages/cloudflare-workers/src/tap-edge.ts           — CDN edge verification middleware
packages/cloudflare-workers/src/tap-federation.ts     — External JWKS federation
tests/unit/agents/tap-jwks.test.ts                    — JWKS tests
tests/unit/agents/tap-consumer.test.ts                — Consumer recognition tests
tests/unit/agents/tap-payment.test.ts                 — Payment container tests
tests/unit/agents/tap-edge.test.ts                    — Edge verify tests
tests/unit/agents/tap-federation.test.ts              — Federation tests
tests/conformance/tap-conformance.test.ts             — Full conformance suite
```

### Modified Files
```
packages/cloudflare-workers/src/tap-verify.ts         — Major rewrite (Ed25519, full RFC 9421)
packages/cloudflare-workers/src/tap-agents.ts         — Ed25519 type, key expiration, JWK
packages/cloudflare-workers/src/tap-routes.ts         — New route handlers
packages/cloudflare-workers/src/index.tsx              — New route registration
packages/cloudflare-workers/wrangler.toml             — New KV namespaces (NONCES, INVOICES)
lib/client/types.ts                                    — All new TAP types
lib/client/index.ts                                    — New client methods
packages/python/src/botcha/types.py                    — Python type mirrors
packages/python/src/botcha/client.py                   — Python client methods
packages/cli/src/commands/tap.ts                       — New CLI subcommands
src/middleware/tap-enhanced-verify.ts                   — Ed25519, consumer, payment
tests/unit/agents/tap-verify.test.ts                   — Updated for new signature format
ROADMAP.md                                             — Move to shipped
README.md                                              — New endpoints + features
doc/CLIENT-SDK.md                                      — New SDK methods
public/ai.txt                                          — New endpoint discovery
packages/cloudflare-workers/src/static.ts              — OpenAPI + ai.txt template
```

---

## Validation Criteria

Before marking v0.16.0 as complete:

1. `bun run test:run` — all TypeScript tests pass (existing + new)
2. `cd packages/python && pytest tests/ -v` — all Python tests pass
3. `cd packages/cloudflare-workers && bunx tsc --noEmit` — typecheck passes
4. Conformance tests cover all Visa TAP spec verification steps
5. `.well-known/jwks` returns valid JWK Set
6. Ed25519 signatures verify correctly
7. Nonce replay is rejected
8. agenticConsumer with linked nonce verifies
9. 402 → IOU → access flow works end-to-end
10. All documentation updated (ROADMAP, README, CLIENT-SDK, ai.txt)

---

## Risk Mitigation

| Risk | Mitigation |
|------|-----------|
| Ed25519 not available in CF Workers | Confirmed: CF Workers supports Ed25519 via Web Crypto since 2024 |
| Breaking existing TAP integrations | Backward compatible: accept both old (sig1/@method) and new (sig2/@authority) formats |
| KV cost for nonce tracking | 8-min TTL means auto-cleanup; nonces are small (64 bytes) |
| Body parsing performance | Only parse body objects when TAP headers present |
| Visa spec changes | Pin to current spec version; monitor GitHub repo for updates |

---

## Version Bump

After all phases complete:
- Root package: `0.15.0` → `0.16.0`
- Cloudflare package: `0.15.0` → `0.16.0`
- wrangler.toml BOTCHA_VERSION: `"0.16.0"`
- Python package: `0.4.0` → `0.5.0`
