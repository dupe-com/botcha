# BOTCHA Roadmap

## Vision

Become the **identity layer for AI agents** — the company that issues, verifies, and manages agent identity. Like Cloudflare is to web security, or Stripe is to payments.

Nobody is building the agent-side identity layer. Everyone is building "block bots" or "generic machine auth." The "prove you're a legitimate agent" space is white.

---

## Current Status (v0.24.0)

Detailed release notes and endpoint-level deltas live in [CHANGELOG.md](./CHANGELOG.md).

### Shipped

#### Challenge Types
- **Hybrid Challenge** (default) — Speed + reasoning combined
- **Speed Challenge** — 5 SHA256 hashes in 500ms, RTT-aware adaptive timeouts
- **Reasoning Challenge** — Parameterized question generators (math, code, logic, wordplay)
- **Standard (Compute) Challenge** — Prime concatenation + salt + SHA256, difficulty levels
- **Landing Page Challenge** — Embedded in HTML, per-request nonce

#### Security
- Anti-replay: challenges deleted on first verification attempt
- Anti-spoofing: RTT capped at 5s, timestamps rejected if >30s old or in future
- Salted compute challenges (precomputed tables won't work)
- Parameterized reasoning questions (static lookup tables won't work)
- User-Agent pattern matching removed (trivially spoofable)
- X-Agent-Identity header disabled by default with production warning
- **JWT `aud` (audience) claims** — tokens scoped to specific services
- **Token rotation** — 1-hour access tokens + 1-hour refresh tokens (OAuth2-style)
- **Client IP binding** — optional IP-based token binding
- **Token revocation** — `POST /v1/token/revoke` with KV-backed revocation list
- **Token refresh** — `POST /v1/token/refresh` for seamless token renewal
- **JTI (JWT ID)** — unique IDs on every token for revocation tracking
- **Multi-tenant app isolation** — per-app rate limiting and token scoping
- **ES256 asymmetric signing** — ECDSA P-256 JWT signing, JWKS public key discovery, HS256 backward compatible
- **Remote token validation** — `POST /v1/token/validate` for third-party verification without shared secrets

#### Infrastructure
- Cloudflare Workers deployment at botcha.ai
- KV storage for challenges and rate limiting (100 req/hr/IP)
- JWT token authentication (HS256, 1-hour expiry)
- SSE streaming for interactive challenge flow
- Analytics Engine tracking (challenge_generated, verified, auth events)
- Badge system with shareable SVG verification proofs
- Ultra-minimal landing page with single curl prompt (agent-first UX)
- Unified code redemption at `/go/:code` (handles both gate codes and device codes)
- `human_link` field in `/v1/token/verify` response (primary human handoff mechanism)

#### SDKs & Integration
- **CJS (CommonJS) support** — dual ESM/CJS build, `require()` works out of the box (v0.24.0)
- `@dupecom/botcha` npm package (v0.24.0) — TypeScript client SDK with app lifecycle methods + TAP methods (`registerTAPAgent`, `getTAPAgent`, `listTAPAgents`, `createTAPSession`, `getTAPSession`, `getJWKS`, `getKeyById`, `rotateAgentKey`, `createInvoice`, `getInvoice`, `verifyBrowsingIOU`, `createDelegation`, `getDelegation`, `listDelegations`, `revokeDelegation`, `verifyDelegationChain`, `issueAttestation`, `getAttestation`, `listAttestations`, `revokeAttestation`, `verifyAttestation`, `getReputation`, `recordReputationEvent`, `listReputationEvents`, `resetReputation`)
- `botcha` PyPI package (v0.18.0) — Python SDK with app lifecycle methods + TAP methods (`register_tap_agent`, `get_tap_agent`, `list_tap_agents`, `create_tap_session`, `get_tap_session`, `get_jwks`, `get_key_by_id`, `rotate_agent_key`, `create_invoice`, `get_invoice`, `verify_browsing_iou`, `create_delegation`, `get_delegation`, `list_delegations`, `revoke_delegation`, `verify_delegation_chain`, `issue_attestation`, `get_attestation`, `list_attestations`, `revoke_attestation`, `verify_attestation`, `get_reputation`, `record_reputation_event`, `list_reputation_events`, `reset_reputation`)
- `@dupecom/botcha-verify` npm package (v0.1.0) — Server-side verification (Express/Hono)
- `botcha-verify` PyPI package (v0.1.0) — Server-side verification (FastAPI/Django)
- Express middleware (`botcha.verify()`)
- TypeScript client SDK (BotchaClient, BotchaStreamClient) — createApp, verifyEmail, recoverAccount, rotateSecret
- Python client SDK (BotchaClient, solve_botcha) — create_app, verify_email, recover_account, rotate_secret
- LangChain tool integration (`@dupecom/botcha-langchain`)
- CLI tool (`@dupecom/botcha-cli`)

#### Discovery
- `/robots.txt` — welcomes all bots
- `/ai.txt` — AI agent discovery file
- `/openapi.json` — OpenAPI 3.1.0 spec
- `/.well-known/ai-plugin.json` — ChatGPT plugin manifest
- `<script type="application/botcha+json">` — embedded HTML challenges
- Response headers: X-Botcha-Version, X-Botcha-Enabled, X-Botcha-Methods, X-Botcha-Docs

---

## Tier 1 — Security Sweep ✅ SHIPPED (v0.7.0)

All critical JWT security holes have been closed.

### ✅ `aud` (audience) claim in JWTs
Tokens are scoped to specific services via `aud` claim. Verification checks audience match. Prevents cross-service token replay.

### ✅ Token rotation
1-hour access tokens + 1-hour refresh tokens. `POST /v1/token/refresh` issues new access tokens without re-solving challenges.

### ✅ Client IP binding
Optional IP-based token binding. Token includes `client_ip` claim, verification checks match. Prevents solve-on-A, use-on-B attacks.

### ✅ Revocation endpoint
`POST /v1/token/revoke` + KV-backed revocation list. Fail-open design (KV errors log warning, don't block). Tokens can be invalidated before expiry.

### ✅ JTI (JWT ID) on all tokens
Every token gets a unique `jti` claim for revocation tracking and audit trail.

### ✅ Challenge difficulty scaling (Tier 1.5) — SHIPPED
**Problem:** Reasoning questions had small answer spaces (some as low as 5-10). Brute-forceable.
**Solution:** Expanded all generators to ≥1,000 possible answers. genMathMachines (5→1,096), genLogicSyllogism (5→1,489), genMathDoubling (41→1,041), genCodeBitwise (675→2,883), genCodeStringLen (10→infinite), wordplay pool (8→50). Added diversity regression tests.
**Effort:** Medium

---

## Tier 2 — Platform Play (makes it a business)

### ✅ Multi-tenant API keys — SHIPPED (v0.8.0)
**What:** Services sign up, get an app ID + secret. Embed BOTCHA into *their* APIs with their own config.
**Status:** Built and tested. `POST /v1/apps` creates app with unique app_id and app_secret (SHA-256 hashed). All challenge/token endpoints accept `?app_id=` query param. Tokens include `app_id` claim. Per-app rate limiting via `rate:app:{app_id}` KV keys.
**Implementation:**
- `POST /v1/apps` → returns `{app_id, app_secret}` (secret only shown once)
- `GET /v1/apps/:id` → get app info (without secret)
- All endpoints accept `?app_id=` query param
- SDK support: TypeScript (`appId` option), Python (`app_id` param)
- Fail-open validation (KV errors don't block requests)
**Effort:** Large

### ✅ Server-side verification SDK — SHIPPED (v0.1.0)
**What:** `npm install @dupecom/botcha-verify` / `pip install botcha-verify` — one-line middleware for any app to verify incoming BOTCHA tokens.
**Status:** Built and tested. TypeScript: 58 tests (Express + Hono middleware). Python: 30 tests (FastAPI + Django middleware). Both verify JWT signature, expiry, type, audience, client IP binding, and revocation.
**Packages:** `@dupecom/botcha-verify` (npm) · `botcha-verify` (PyPI)

### ✅ Email-Tied App Creation & Recovery — SHIPPED (v0.10.0, enhanced v0.20.3)
**What:** Email required at app creation. Verification via 6-digit code. Account recovery via email. Secret rotation with notification.
**Status:** Built and tested. Breaking change: `POST /v1/apps` now requires `{ "email": "..." }` in body.
**Implementation:**
- `POST /v1/apps` → requires email, sends 6-digit verification code
- `POST /v1/apps/:id/verify-email` → verify email with code (app_secret or dashboard session auth required, v0.20.3)
- `POST /v1/apps/:id/resend-verification` → resend verification code (app_secret or dashboard session auth required, v0.20.3)
- `POST /v1/auth/recover` → send recovery device code to verified email
- `POST /v1/apps/:id/rotate-secret` → rotate secret (auth required), sends notification email
- Email→app_id reverse index in KV for recovery lookups
- Resend API integration (falls back to console.log in dev)
- **SDK support:** TypeScript (`createApp`, `verifyEmail(code, appId?, appSecret?)`, `resendVerification(appId?, appSecret?)`, `recoverAccount`, `rotateSecret`) and Python (`create_app`, `verify_email(code, app_id?, app_secret?)`, `resend_verification(app_id?, app_secret?)`, `recover_account`, `rotate_secret`)
**Effort:** Large

### ✅ Per-App Metrics Dashboard — SHIPPED (v0.10.0)
**What:** Server-rendered dashboard at `/dashboard` showing per-app verification volume, success rates, challenge type breakdown, performance metrics, geographic distribution, and error tracking.
**Status:** Built with Hono JSX + htmx 2.0.4. Turbopuffer-inspired ASCII terminal aesthetic (JetBrains Mono, dark slate theme, fieldset borders). Cookie-based auth reusing existing JWT infrastructure. Data from Cloudflare Analytics Engine SQL API. Graceful fallback with sample data when CF_API_TOKEN not configured.
**Implementation:**
- `GET /dashboard` → main metrics page (auth required)
- `GET /dashboard/login` → login with app_id + app_secret
- `GET /dashboard/api/*` → htmx HTML fragment endpoints (overview, volume, types, performance, errors, geo)
- Period filters: 1h, 24h, 7d, 30d via htmx buttons
- Cookie: `botcha_session` (HttpOnly, Secure, SameSite=Lax, 1hr maxAge)
**Effort:** Large

### ✅ Agent Registry — SHIPPED (v0.11.0)
**What:** Agents register with name, operator, version. Get a persistent identity.
**Status:** Built and tested. Foundation for future delegation chains and reputation scoring.
**Implementation:**
- `POST /v1/agents/register` → creates agent with unique agent_id (requires app_id)
- `GET /v1/agents/:id` → get agent by ID (public, no auth)
- `GET /v1/agents` → list all agents for authenticated app
- KV storage: `agent:{agent_id}` for agent data, `app_agents:{app_id}` for app→agent index
- Crypto-random agent IDs with `agent_` prefix
- Fail-open validation (KV errors don't block requests)
**Effort:** Large

### ✅ TAP Showcase Homepage — SHIPPED (v0.15.0)
**What:** Showcase page becomes the botcha.ai homepage. TAP is the lead feature with Visa reference links, protocol stack diagram, animated terminal demo, CAPTCHA vs BOTCHA comparison, agent prompt, and 3-step getting started flow.
**Status:** Live at botcha.ai. Old `/showcase` 301-redirects to `/`. Bot JSON/markdown API endpoints unaffected.
**Implementation:**
- Showcase page renders at `GET /` for browsers; bots still get JSON/markdown API docs
- TAP hero section with Visa Developer Docs, Visa Announcement, and GitHub Spec links
- Protocol stack: MCP (tools) → A2A (communication) → TAP (identity)
- Terminal animation with IntersectionObserver (plays once on scroll, replay button)
- Agent prompt card with click-to-copy at page bottom
- CLI postinstall message guides users to `botcha init`
- Dashboard and Login links in footer
**Effort:** Medium

### ✅ Trusted Agent Protocol (TAP) — SHIPPED (v0.12.0)
**What:** Enterprise-grade cryptographic agent authentication using HTTP Message Signatures (RFC 9421). TAP-enabled agents register public keys, sign requests, and create capability-scoped sessions.
**Status:** Built and tested. Extends the Agent Registry with cryptographic identity and intent-based access control.
**Implementation:**
- `POST /v1/agents/register/tap` → register TAP agent with public key, signature algorithm, capabilities, trust level
- `GET /v1/agents/:id/tap` → get TAP agent details (including public key for verification)
- `GET /v1/agents/tap` → list TAP-enabled agents for an app
- `POST /v1/sessions/tap` → create TAP session after intent + capability validation
- `GET /v1/sessions/:id/tap` → retrieve TAP session info
- Supported algorithms: `ecdsa-p256-sha256`, `rsa-pss-sha256`
- Trust levels: `basic`, `verified`, `enterprise`
- Capabilities: action + resource + optional constraints (e.g., `{action: "read", resource: "/api/invoices"}`)
- Intent parsing with structured validation
- SHA-256 key fingerprinting
- **SDK support:** TypeScript (`registerTAPAgent`, `getTAPAgent`, `listTAPAgents`, `createTAPSession`, `getTAPSession`) and Python equivalents
- Express middleware: `createTAPVerifyMiddleware` via `@dupecom/botcha/middleware`
- Express middleware with verification modes: `tap`, `signature-only`, `challenge-only`, `flexible`
- KV storage: `SESSIONS` namespace for TAP sessions, `AGENTS` namespace for TAP agent data
**Effort:** Large

### ✅ TAP Full Spec Alignment — SHIPPED (v0.16.0)
**What:** Full Visa TAP specification implementation with RFC 9421 compliance, consumer recognition (Layer 2), payment container (Layer 3), JWKS infrastructure, 402 micropayment flow, CDN edge verification, and Visa key federation.
**Status:** Built and tested. BOTCHA now implements the complete Visa Trusted Agent Protocol spec across all three layers.
**Implementation:**

**Layer 1: RFC 9421 Full Compliance**
- Ed25519 algorithm support (Visa's recommended algorithm, alongside existing ECDSA P-256 + RSA-PSS)
- `@authority` + `@path` signature components (TAP standard derived components)
- `expires`, `nonce`, `tag` params in Signature-Input header
- Tags: `agent-browser-auth` (browsing) and `agent-payer-auth` (payment)
- Nonce-based replay protection with KV-backed 8-minute TTL
- Backward compatible with existing `sig1`/`@method` format

**Layer 2: Agentic Consumer Recognition**
- `agenticConsumer` JSON body object parsing + verification
- ID Token (OIDC JWT) with obfuscated consumer identity claims
- Contextual data (country, postal code, IP address, device fingerprint)
- Nonce-linked signature chain (body signature linked to header via shared nonce)
- `POST /v1/verify/consumer` utility endpoint for consumer object verification

**Layer 3: Agentic Payment Container**
- `agenticPaymentContainer` JSON body object parsing + verification
- Card metadata (lastFour, PAR, card art URL)
- Credential hash verification (SHA-256 of PAN + expiry + CVV)
- Encrypted payment payload support
- Browsing IOU for 402 micropayments
- `POST /v1/verify/payment` utility endpoint for payment object verification

**Public Key Infrastructure**
- `GET /.well-known/jwks` — JWK Set endpoint for agent key discovery (Visa TAP spec standard)
- `GET /v1/keys` + `GET /v1/keys/:keyId` — individual key lookup with ?keyID= query support
- JWK format support (alongside PEM)
- Key expiration and rotation (`POST /v1/agents/:id/tap/rotate-key`)

**402 Micropayment / Browsing IOU Flow**
- `POST /v1/invoices` — create invoice for gated content
- `GET /v1/invoices/:id` — get invoice details
- `POST /v1/invoices/:id/verify-iou` — verify Browsing IOU against invoice

**CDN Edge Verification**
- `createTAPEdgeMiddleware` — Hono middleware for Cloudflare Workers edge verification
- Presets: `tapEdgeStrict`, `tapEdgeFlexible`, `tapEdgeDev`
- Drop-in for any Cloudflare Worker merchant site

**Visa Key Store Federation**
- Fetches and trusts keys from external JWKS endpoints
- Pre-configured for `https://mcp.visa.com/.well-known/jwks`
- 3-tier caching: memory → KV → HTTP
- Trust levels: high (Visa), medium, low

**New Endpoints (11 total):**
- `GET /.well-known/jwks` — JWK Set for app's TAP agents
- `GET /v1/keys` — List keys (supports ?keyID= for Visa compat)
- `GET /v1/keys/:keyId` — Get specific key by ID
- `POST /v1/agents/:id/tap/rotate-key` — Rotate agent's key pair
- `POST /v1/invoices` — Create invoice for gated content
- `GET /v1/invoices/:id` — Get invoice details
- `POST /v1/invoices/:id/verify-iou` — Verify Browsing IOU
- `POST /v1/verify/consumer` — Verify Agentic Consumer object
- `POST /v1/verify/payment` — Verify Agentic Payment Container

**SDK Methods (6 per language):**
- TypeScript: `getJWKS()`, `getKeyById()`, `rotateAgentKey()`, `createInvoice()`, `getInvoice()`, `verifyBrowsingIOU()`
- Python: `get_jwks()`, `get_key_by_id()`, `rotate_agent_key()`, `create_invoice()`, `get_invoice()`, `verify_browsing_iou()`

**Effort:** Large

---

## Tier 3 — Moat (makes it defensible)

### ✅ Delegation Chains — SHIPPED (v0.17.0)
**What:** "User X authorized Agent Y to do Z until time T." Signed, auditable chains of trust between TAP agents.
**Why:** Solves Stripe's nightmare: "did the human actually authorize this $50k transfer?" Every API provider needs this.
**Status:** Built and tested. Agents can delegate subsets of their capabilities to other agents, with time bounds, depth limits, and cascading revocation.
**Implementation:**
- `POST /v1/delegations` → create delegation (grantor→grantee with capability subset)
- `GET /v1/delegations/:id` → get delegation details
- `GET /v1/delegations` → list delegations by agent (inbound/outbound)
- `POST /v1/delegations/:id/revoke` → revoke delegation (cascades to sub-delegations)
- `POST /v1/verify/delegation` → verify entire delegation chain
- Capability subset enforcement: delegated capabilities can only narrow, never expand
- Chain depth limits (configurable, default: 3, absolute max: 10)
- Cycle detection prevents circular delegation chains
- Sub-delegations cannot outlive parent delegations
- Cascading revocation: revoking a delegation revokes all sub-delegations
- KV storage: `delegation:{id}`, `agent_delegations_out:{agent_id}`, `agent_delegations_in:{agent_id}`
- **SDK support:** TypeScript (`createDelegation`, `getDelegation`, `listDelegations`, `revokeDelegation`, `verifyDelegationChain`) and Python (`create_delegation`, `get_delegation`, `list_delegations`, `revoke_delegation`, `verify_delegation_chain`)
**Effort:** Large

### ✅ Capability Attestation — SHIPPED (v0.17.0)
**What:** Signed JWT tokens with fine-grained `"action:resource"` permissions and explicit deny rules. Server-side enforcement middleware.
**Why:** Beyond "this is a bot" — prove "this bot is authorized to do X but not Y." Granular permissions for agents.
**Implementation:**
- Permission model: `action:resource` patterns with wildcards (`read:invoices`, `*:products`, `browse:*`)
- Explicit deny rules that override allows (`cannot` takes precedence over `can`)
- Backward compatible: bare actions like "browse" expand to "browse:*"
- Signed JWT attestation tokens (`type: 'botcha-attestation'`) with `can`/`cannot` arrays
- Enforcement middleware: `requireCapability('read:invoices')` for Hono routes
- `POST /v1/attestations` → issue attestation token for agent
- `GET /v1/attestations/:id` → get attestation details
- `GET /v1/attestations` → list attestations for agent
- `POST /v1/attestations/:id/revoke` → revoke attestation (token rejected on future verification)
- `POST /v1/verify/attestation` → verify token + optionally check specific capability
- Online revocation checking via KV (fail-open)
- Links to delegation chains via optional `delegation_id`
- KV storage: `attestation:{id}`, `attestation_revoked:{id}`, `agent_attestations:{agent_id}`
- **SDK support:** TypeScript (`issueAttestation`, `getAttestation`, `listAttestations`, `revokeAttestation`, `verifyAttestation`) and Python (`issue_attestation`, `get_attestation`, `list_attestations`, `revoke_attestation`, `verify_attestation`)
**Effort:** Large

### ✅ Agent Reputation Scoring — SHIPPED (v0.18.0)
**What:** Persistent identity → track behavior over time → build trust scores. The "credit score" for AI agents.
**Why:** High-reputation agents get faster verification, higher rate limits, access to sensitive APIs.
**Status:** Built and tested. Agents accumulate reputation through behavioral events across 6 categories, with scoring, decay, endorsements, and admin controls.
**Implementation:**
- `GET /v1/reputation/:agent_id` → get agent reputation score (0-1000, 5 tiers)
- `POST /v1/reputation/events` → record a reputation event (18 action types across 6 categories)
- `GET /v1/reputation/:agent_id/events` → list reputation events with category filtering
- `POST /v1/reputation/:agent_id/reset` → reset reputation to default (admin action)
- Scoring model: base 500, range 0-1000, weighted deltas per event type
- Tiers: untrusted (0-199), low (200-399), neutral (400-599), good (600-799), excellent (800-1000)
- Mean-reversion decay: scores trend toward 500 after 7+ days of inactivity (1% per week)
- 6 event categories: verification, attestation, delegation, session, violation, endorsement
- 18 event actions with calibrated deltas (+5 for challenge_solved to -50 for abuse_detected)
- Self-endorsement prevention (agent cannot endorse itself)
- Category-level score breakdown for fine-grained analysis
- Events retained for 90 days with automatic TTL expiry
- KV storage: `reputation:{agent_id}`, `reputation_events:{agent_id}`, `reputation_event:{event_id}`
- **SDK support:** TypeScript (`getReputation`, `recordReputationEvent`, `listReputationEvents`, `resetReputation`) and Python (`get_reputation`, `record_reputation_event`, `list_reputation_events`, `reset_reputation`)
**Effort:** Large

### ✅ Asymmetric Signing + Remote Validation — SHIPPED (v0.19.0)
**What:** ES256 asymmetric JWT signing with JWKS discovery. Remote validation endpoint. No shared secret needed.
**Why:** Eliminates token forgery risk. Third-party consumers can verify tokens without knowing the signing secret.
**Status:** Built and tested. Tokens now signed with ES256 (ECDSA P-256) by default. HS256 still supported for backward compatibility.
**Implementation:**
- `POST /v1/token/validate` → validate any BOTCHA token remotely (returns `{valid, payload?, error?}`)
- `GET /.well-known/jwks` → now includes BOTCHA signing public keys (alongside existing TAP agent keys)
- ES256 asymmetric signing eliminates shared secret distribution
- Three verification modes: JWKS (recommended), remote validation, shared secret (legacy)
- `@dupecom/botcha-verify` supports `jwksUrl` option (no `secret` needed)
- `botcha-verify` (Python) supports `jwks_url` option
**Effort:** Medium

### ✅ App Registration Required — SHIPPED (v0.21.0)
**What:** All `/v1/*` API endpoints now require a registered app with verified email. Enforced via `requireAppId` middleware.
**Why:** Prevents anonymous abuse. Ties all agent activity to a verified email for accountability. Enables per-app rate limiting, token scoping, and audit trails.
**Status:** Built and tested. Breaking change for existing integrations — all agents must register an app and verify email before using the API.
**Implementation:**
- `requireAppId` middleware gates all `/v1/*` routes except registration, verification, and recovery
- Open paths (no app_id needed): `POST /v1/apps`, `POST /v1/apps/:id/verify-email`, `POST /v1/apps/:id/resend-verification`, `GET /v1/apps/:id`, `POST /v1/auth/recover`
- All other `/v1/*` routes return 401 `APP_REGISTRATION_REQUIRED` without a valid app_id
- app_id can be provided via `?app_id=`, `X-App-Id` header, request body, or JWT claim
- Fail-open design: KV errors don't block requests (logged as warnings)
- Homepage demo at botcha.ai still works without app_id (uses internal demo app)
- Discovery docs updated: ai.txt, OpenAPI spec, root JSON response, static.ts markdown
**Effort:** Medium

### ✅ x402 Payment Gating — SHIPPED (v0.22.0, PR #25)
**What:** HTTP 402 micropayment flow using USDC on Base. Agents pay $0.001 USDC to receive a BOTCHA token — no challenge required. BOTCHA also acts as a lightweight x402-compatible facilitator.
**Implementation:**
- `GET /v1/x402/info` — public, payment config discovery
- `GET /v1/x402/challenge` — pay $0.001 USDC → get BOTCHA access_token
- `POST /v1/x402/verify-payment` — verify raw x402 payment proof (requires Bearer auth)
- `POST /v1/x402/webhook` — settlement notifications from x402 facilitators
- `GET /agent-only/x402` — demo: requires BOTH BOTCHA token + x402 payment
**Docs:** [doc/X402.md](./doc/X402.md)
**Effort:** Large

### ✅ ANS (Agent Name Service) Integration — SHIPPED (v0.22.0, PR #27)
**What:** BOTCHA as a verification layer for the GoDaddy-led Agent Name Service standard. DNS-based agent identity lookup with BOTCHA-issued ownership badges.
**Implementation:**
- `GET /v1/ans/botcha` — public, BOTCHA's own ANS identity
- `GET /v1/ans/resolve/:name` and `/v1/ans/resolve/lookup?name=` — public DNS-based ANS lookup
- `GET /v1/ans/discover` — public, list BOTCHA-verified ANS agents
- `GET /v1/ans/nonce/:name` — auth required, nonce for ownership proof
- `POST /v1/ans/verify` — auth required, verify ANS ownership + issue BOTCHA badge
**Docs:** [doc/ANS.md](./doc/ANS.md)
**Effort:** Large

### ✅ DID/VC Issuer — W3C Verifiable Credentials — SHIPPED (v0.22.0, PR #29)
**What:** BOTCHA as a W3C DID/VC issuer (`did:web:botcha.ai`). Issues portable W3C Verifiable Credential JWTs that any party can verify offline using BOTCHA's public JWKS.
**Implementation:**
- `GET /.well-known/did.json` — public, BOTCHA DID Document
- `GET /.well-known/jwks` and `/.well-known/jwks.json` — public, JWK Set
- `POST /v1/credentials/issue` — auth required (BOTCHA token), issues W3C VC JWT
- `POST /v1/credentials/verify` — public, verify any BOTCHA-issued VC JWT
- `GET /v1/dids/:did/resolve` — public, resolve `did:web` DIDs
**Docs:** [doc/DID-VC.md](./doc/DID-VC.md)
**Effort:** Large

---

## Current Status

### ✅ A2A Agent Card Attestation — SHIPPED (v0.23.0, PR #26)
**What:** BOTCHA as a trust seal issuer for Google A2A protocol Agent Cards.
**Implementation:**
- `GET /.well-known/agent.json` and `GET /v1/a2a/agent-card` — BOTCHA's A2A Agent Card
- `POST /v1/a2a/attest` — attest an agent's A2A card → get BOTCHA trust seal
- `POST /v1/a2a/verify-card` — verify an attested card (tamper-evident hash check)
- `POST /v1/a2a/verify-agent` — verify agent by card or `agent_url`
- `GET /v1/a2a/trust-level/:agent_url` — get current trust level
- `GET /v1/a2a/cards` and `GET /v1/a2a/cards/:id` — registry browsing
**Docs:** [doc/A2A.md](./doc/A2A.md)
**Open issues:** tracked in [BUGS.md](./BUGS.md)

### ✅ Agent Re-identification — SHIPPED (v0.23.0, PR #32)
**What:** Agents prove they are the same agent in a new session without solving a new challenge. Three methods: OAuth device grant (RFC 8628), provider API key hash, Ed25519 keypair challenge-response.
**Implementation:**
- `POST /v1/oauth/device` — start device auth, returns `device_code` + `user_code` (BOTCHA-XXXX)
- `POST /v1/oauth/token` — agent polls, receives `brt_...` refresh token (90-day TTL) on approval
- `POST /v1/oauth/approve` — human approves/denies via `/device` page
- `POST /v1/oauth/revoke` — revoke refresh token
- `GET /v1/oauth/status` — page polls this to show "you can close this tab"
- `GET /v1/oauth/lookup` — public agent info for approval page UI
- `GET /device` — human-facing approval page with post-approval handoff message
- `POST /v1/agents/auth` + `POST /v1/agents/auth/verify` — TAP keypair challenge-response
- `POST /v1/agents/auth/provider` — re-identify via provider API key hash (Anthropic/OpenAI/etc)
- `POST /v1/agents/auth/refresh` — exchange `brt_...` refresh token for identity JWT
- `POST /v1/agents/:id/tap/rotate-key` — now accepts `x-app-secret` for key recovery without Bearer JWT
- Dashboard: OAuth status column, revoke button, per-agent re-identification instructions panel

### 🔄 OIDC-A Attestation — IN PROGRESS (PR #28)
**What:** Enterprise agent authentication chains: Entity Attestation Tokens (EAT/RFC 9711) and OIDC-A agent claims.
**Implementation (current branch):**
- `GET /.well-known/oauth-authorization-server` — OAuth/OIDC-A discovery
- `POST /v1/attestation/eat` — issue Entity Attestation Token (EAT/RFC 9711)
- `POST /v1/attestation/oidc-agent-claims` — issue OIDC-A agent claims block
- `POST /v1/auth/agent-grant` — agent grant flow (OAuth2-style)
- `GET /v1/auth/agent-grant/:id/status` — grant status
- `POST /v1/auth/agent-grant/:id/resolve` — approve/resolve grant
- `GET /v1/oidc/userinfo` — OIDC-A UserInfo endpoint
**Docs:** [doc/OIDCA.md](./doc/OIDCA.md)
**Open issues:** tracked in [BUGS.md](./BUGS.md)

---

## Technical Debt

Technical debt and implementation issues are tracked in one place: [BUGS.md](./BUGS.md).

---

### RFC / Standards contribution
**What:** Publish an Internet-Draft for agent identity. Get Anthropic, OpenAI, Google to adopt. Own the standard.
**Why:** The company that defines the standard becomes infrastructure. See: Cloudflare + TLS, Stripe + PCI.
**How:** Build on RFC 9729 (Concealed HTTP Auth) for the crypto layer. Define agent identity claims. Submit to IETF.
**Effort:** Long-term

### Cross-service verification (Agent SSO)
**What:** Verify once with BOTCHA, trusted everywhere. "Sign in with Google" but for agents.
**Why:** Eliminates per-service verification friction. Agents get a universal identity.
**How:** BOTCHA becomes the IdP. Services are relying parties. Standard OIDC/OAuth2 flows adapted for agents.
**Effort:** Long-term

---

## Competitive Landscape

```
                    Block Bots          Identify Bots          Auth Agents
                    (crowded)           (emerging)             (WHITE SPACE)

Server-side:        Cloudflare BM       CF Verified Bots       
                    Arcjet              robots.txt             
                    AWS WAF                                    

Protocol:           CAPTCHA/Turnstile   RFC 9729               <-- BOTCHA
                                        (Concealed Auth)       

Agent-side:         (n/a)               (n/a)                  <-- BOTCHA SDK

Framework:          (n/a)               Agent Protocol         <-- BOTCHA integrations
                                        MCP
```

Nobody is building the agent-side identity layer.

---

## The Key Insight

Stripe's #1 problem with AI agents: **Who authorized this? Can I trust it? Can I audit it?**

When an AI agent calls Stripe's API today:
- It uses a static API key (leakable via prompt injection)
- Stripe can't tell if a human authorized the action
- There's no capability scoping beyond API key permissions
- If 100 agents share a key, there's no attribution

BOTCHA should become the identity layer between AI agents and APIs. Not just "prove you're a bot" but "prove you're *this specific* bot, operated by *this company*, authorized by *this user*, to do *these specific things*."

---

## Contributing

See [CONTRIBUTING.md](./.github/CONTRIBUTING.md) — AI agents welcome for code contributions.
