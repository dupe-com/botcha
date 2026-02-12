# BOTCHA Roadmap

## Vision

Become the **identity layer for AI agents** — the company that issues, verifies, and manages agent identity. Like Cloudflare is to web security, or Stripe is to payments.

Nobody is building the agent-side identity layer. Everyone is building "block bots" or "generic machine auth." The "prove you're a legitimate agent" space is white.

---

## Current Status (v0.9.1)

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
- **Token rotation** — 5-minute access tokens + 1-hour refresh tokens (OAuth2-style)
- **Client IP binding** — optional IP-based token binding
- **Token revocation** — `POST /v1/token/revoke` with KV-backed revocation list
- **Token refresh** — `POST /v1/token/refresh` for seamless token renewal
- **JTI (JWT ID)** — unique IDs on every token for revocation tracking
- **Multi-tenant app isolation** — per-app rate limiting and token scoping

#### Infrastructure
- Cloudflare Workers deployment at botcha.ai
- KV storage for challenges and rate limiting (100 req/hr/IP)
- JWT token authentication (HS256, 1-hour expiry)
- SSE streaming for interactive challenge flow
- Analytics Engine tracking (challenge_generated, verified, auth events)
- Badge system with shareable SVG verification proofs

#### SDKs & Integration
- `@dupecom/botcha` npm package (v0.6.0)
- `botcha` PyPI package (v0.1.0) — Python SDK
- `@botcha/verify` npm package (v0.1.0) — Server-side verification (Express/Hono)
- `botcha-verify` PyPI package (v0.1.0) — Server-side verification (FastAPI/Django)
- Express middleware (`botcha.verify()`)
- TypeScript client SDK (BotchaClient, BotchaStreamClient)
- Python client SDK (BotchaClient, solve_botcha)
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
Short-lived access tokens (5min) + refresh tokens (1hr). `POST /v1/token/refresh` issues new access tokens. Compromise window reduced from 1 hour to 5 minutes.

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
**What:** `npm install @botcha/verify` / `pip install botcha-verify` — one-line middleware for any app to verify incoming BOTCHA tokens.
**Status:** Built and tested. TypeScript: 58 tests (Express + Hono middleware). Python: 30 tests (FastAPI + Django middleware). Both verify JWT signature, expiry, type, audience, client IP binding, and revocation.
**Packages:** `@botcha/verify` (npm) · `botcha-verify` (PyPI)

### ✅ Email-Tied App Creation & Recovery — SHIPPED (v0.10.0)
**What:** Email required at app creation. Verification via 6-digit code. Account recovery via email. Secret rotation with notification.
**Status:** Built and tested. Breaking change: `POST /v1/apps` now requires `{ "email": "..." }` in body.
**Implementation:**
- `POST /v1/apps` → requires email, sends 6-digit verification code
- `POST /v1/apps/:id/verify-email` → verify email with code
- `POST /v1/apps/:id/resend-verification` → resend verification code
- `POST /v1/auth/recover` → send recovery device code to verified email
- `POST /v1/apps/:id/rotate-secret` → rotate secret (auth required), sends notification email
- Email→app_id reverse index in KV for recovery lookups
- Resend API integration (falls back to console.log in dev)
**Effort:** Large

### Agent Registry
**What:** Agents register with name, operator, version, public key. Get a persistent identity.
**Why:** Today every verification is anonymous. We prove intelligence but never learn *who*. No accountability, no reputation.
**How:** `POST /v1/agents/register` → agent ID + keypair. Agents sign requests with their key. Operators manage their agents via dashboard.
**Effort:** Large

### ✅ Per-App Metrics Dashboard — SHIPPED (v0.9.1)
**What:** Server-rendered dashboard at `/dashboard` showing per-app verification volume, success rates, challenge type breakdown, performance metrics, geographic distribution, and error tracking.
**Status:** Built with Hono JSX + htmx 2.0.4. Turbopuffer-inspired ASCII terminal aesthetic (JetBrains Mono, dark slate theme, fieldset borders). Cookie-based auth reusing existing JWT infrastructure. Data from Cloudflare Analytics Engine SQL API. Graceful fallback with sample data when CF_API_TOKEN not configured.
**Implementation:**
- `GET /dashboard` → main metrics page (auth required)
- `GET /dashboard/login` → login with app_id + app_secret
- `GET /dashboard/api/*` → htmx HTML fragment endpoints (overview, volume, types, performance, errors, geo)
- Period filters: 1h, 24h, 7d, 30d via htmx buttons
- Cookie: `botcha_session` (HttpOnly, Secure, SameSite=Lax, 1hr maxAge)
**Effort:** Large

---

## Tier 3 — Moat (makes it defensible)

### Delegation chains
**What:** "User X authorized Agent Y to do Z until time T." Signed, auditable chains of trust.
**Why:** Solves Stripe's nightmare: "did the human actually authorize this $50k transfer?" Every API provider needs this.
**How:** Signed delegation tokens. User → Agent → Sub-agent chain captured in token claims.
**Effort:** Large

### Capability attestation
**What:** Token claims like `{"can": ["read:invoices"], "cannot": ["write:transfers"]}`. Server-side enforcement.
**Why:** Beyond "this is a bot" — prove "this bot is authorized to do X but not Y." Granular permissions for agents.
**Effort:** Large

### Agent reputation scoring
**What:** Persistent identity → track behavior over time → build trust scores.
**Why:** The "credit score" for AI agents. High-reputation agents get faster verification, higher rate limits, access to sensitive APIs.
**Effort:** Large

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
