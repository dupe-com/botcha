# BOTCHA Roadmap

## Vision

Become the **identity layer for AI agents** — the company that issues, verifies, and manages agent identity. Like Cloudflare is to web security, or Stripe is to payments.

Nobody is building the agent-side identity layer. Everyone is building "block bots" or "generic machine auth." The "prove you're a legitimate agent" space is white.

---

## Current Status (v0.7.0)

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

### 🔜 Challenge difficulty scaling (Tier 1.5)
**Problem:** 3 reasoning questions with some categories having small answer spaces. Brute-forceable.
**Solution:** Adaptive difficulty based on abuse signals. More question generators. Larger answer spaces. Configurable per-service difficulty.
**Effort:** Medium

---

## Tier 2 — Platform Play (makes it a business)

### Multi-tenant API keys
**What:** Services sign up, get an app ID + secret. Embed BOTCHA into *their* APIs with their own config.
**Why:** Transforms BOTCHA from a demo into a platform. This is the Stripe Connect moment.
**How:** `POST /v1/apps` creates an app. App-specific challenge config, rate limits, analytics. Tokens are scoped to apps.
**Effort:** Large

### Server-side verification SDK
**What:** `npm install @botcha/verify` / `pip install botcha-verify` — one-line middleware for any app to verify incoming BOTCHA tokens.
**Why:** We have the agent SDK (client-side). Now services need the verification SDK (server-side). Makes adoption trivial.
**How:** Middleware that validates JWT signature, checks expiry, verifies audience, checks revocation. Works with Express, FastAPI, Hono, Django, etc.
**Effort:** Medium

### Agent Registry
**What:** Agents register with name, operator, version, public key. Get a persistent identity.
**Why:** Today every verification is anonymous. We prove intelligence but never learn *who*. No accountability, no reputation.
**How:** `POST /v1/agents/register` → agent ID + keypair. Agents sign requests with their key. Operators manage their agents via dashboard.
**Effort:** Large

### Dashboard
**What:** Stripe-style web dashboard showing verification volume, success rates, agent breakdown, geographic distribution, abuse alerts.
**Why:** Enterprises need visibility. Dashboards sell products. Also needed for multi-tenant.
**How:** React app backed by Analytics Engine queries. Per-app views for multi-tenant.
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
