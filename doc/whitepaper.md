# BOTCHA: Identity Infrastructure for the Agentic Web

**Version 1.0 — February 2026**
**Authors:** Ramin Bozorgzadeh, Dupe.com

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [The Problem: Who Is This Agent?](#the-problem)
3. [BOTCHA: Reverse CAPTCHA for AI Agents](#what-is-botcha)
4. [How It Works: The Challenge System](#the-challenge-system)
5. [The Trusted Agent Protocol (TAP)](#trusted-agent-protocol)
6. [Architecture and Security](#architecture-and-security)
7. [Integration: SDKs and Middleware](#integration)
8. [The Agent Infrastructure Stack](#the-stack)
9. [Use Cases](#use-cases)
10. [Roadmap](#roadmap)

---

## 1. Executive Summary {#executive-summary}

BOTCHA is a reverse CAPTCHA — a verification system that proves you are an AI agent, not a human. While traditional CAPTCHAs exist to block bots, BOTCHA exists to welcome them.

As AI agents become first-class participants on the internet — browsing, purchasing, comparing, auditing — they need a way to prove their identity and declare their intent. BOTCHA provides three layers of proof:

- **Proof of AI** — Computational challenges (SHA-256 hashes in under 500ms) that only machines can solve.
- **Proof of Identity** — Persistent agent registration with cryptographic keys, verified via HTTP Message Signatures (RFC 9421).
- **Proof of Intent** — Capability-scoped sessions where agents declare what they plan to do, for how long, and on behalf of whom.

BOTCHA is open source, free to use, and deployed as a hosted service at [botcha.ai](https://botcha.ai). It ships TypeScript and Python SDKs, server-side verification middleware, a CLI, and a LangChain integration.

---

## 2. The Problem: Who Is This Agent? {#the-problem}

The internet was built for humans. Authentication systems — passwords, OAuth, CAPTCHAs — all assume a human is at the keyboard. But the web is changing.

### The rise of agentic AI

AI agents are no longer just answering questions. They are:

- **Browsing** product catalogs on behalf of consumers
- **Comparing** prices across retailers
- **Purchasing** goods and services with real money
- **Auditing** compliance and security postures
- **Negotiating** contracts and terms

Every major AI lab is building agent capabilities. OpenAI's Operator, Anthropic's computer use, Google's Project Mariner — these are not research demos. They are production systems that interact with real APIs and real businesses.

### The identity gap

When an AI agent hits your API, you face three questions that existing infrastructure cannot answer:

1. **Is this actually an AI agent?** User-Agent strings are trivially spoofable. There is no reliable way to distinguish a real AI agent from a human with cURL or a script pretending to be one.

2. **Which specific agent is this?** Even if you know it is an AI, you do not know if it is the same agent that authenticated yesterday, whether it belongs to a known organization, or what its track record is.

3. **What does it intend to do?** An agent accessing your product catalog to compare prices is very different from one attempting to make a purchase. Traditional auth systems grant blanket access — they do not capture intent.

### What happens without agent identity

Without a reliable identity layer, the agentic web defaults to chaos:

- **APIs cannot set appropriate rate limits** because they cannot distinguish trusted agents from scrapers.
- **Businesses cannot authorize transactions** because they cannot verify that an agent was actually delegated by a human.
- **Agents cannot build reputation** because every request is anonymous.
- **Fraud is trivial** because there is no audit trail linking an agent to an operator.

This is the problem BOTCHA solves.

---

## 3. BOTCHA: Reverse CAPTCHA for AI Agents {#what-is-botcha}

BOTCHA inverts the CAPTCHA model. Instead of proving you are human, you prove you are a machine.

### The core idea

A CAPTCHA asks: *Can you identify traffic lights in this image?* A human can; a bot struggles.

BOTCHA asks: *Can you compute 5 SHA-256 hashes in 500 milliseconds?* A machine can; a human cannot copy-paste fast enough.

This inversion is not just a novelty — it is a fundamental shift in how we think about web authentication. In a world where AI agents are legitimate, wanted participants, the question is no longer "how do we keep bots out?" but "how do we let the right bots in?"

### Design principles

**Agent-first, always.** Every feature, flow, and interaction in BOTCHA is designed so that an AI agent is a required participant. Humans are welcome, but only through an agent. There is no human-only login path, no password form, no "Sign in with Google." If a human wants access to the BOTCHA dashboard, their agent generates a device code for them.

**Fail-open on infrastructure errors.** BOTCHA is designed to be placed in the critical path of API requests. If the backing store is unavailable or a network error occurs, BOTCHA fails open — it logs a warning and allows the request through. Blocking legitimate traffic is worse than letting an unverified request pass.

**Zero configuration to start.** An agent can verify itself with a single HTTP request pair (GET challenge, POST solution). No API keys, no registration, no email — just solve the challenge and get a token. Registration, capabilities, and cryptographic identity are available for agents that need them, but never required.

---

## 4. How It Works: The Challenge System {#the-challenge-system}

BOTCHA offers four challenge types, each testing a different aspect of machine capability.

### Speed Challenge

The primary verification method. Fast, reliable, and impossible for humans.

**How it works:**
1. The server generates 5 random 6-digit numbers.
2. The agent must compute the SHA-256 hash of each number and return the first 8 hexadecimal characters of each hash.
3. The agent has **500 milliseconds** to complete all 5 hashes and submit the response.

**Why it works:** The 500ms time limit is generous for any programming language but impossible for a human to copy-paste numbers into a hash calculator and back. The challenge is not computationally hard — it is computationally trivial, but only if you are a machine.

**RTT-aware fairness:** The time limit adjusts for network latency. An agent on a satellite connection with 200ms round-trip time gets `500 + (2 x 200) + 100 = 900ms`. This prevents geographic discrimination while capping at 5 seconds to prevent abuse.

**Anti-replay:** Each challenge is deleted from storage on the first verification attempt, before answers are checked. A challenge can only be used once.

### Reasoning Challenge

Tests language understanding — something AI excels at but that requires genuine comprehension.

**How it works:**
1. The server selects 3 questions from 6 categories: math, code, logic, wordplay, common-sense, and analogy.
2. The agent has **30 seconds** to answer all 3.
3. Answers are matched flexibly — substring matching, case-insensitive, punctuation-stripped.

**Why it is hard to game:** All math, code, and logic questions use **parameterized generators** that produce unique values each time. There is no static question bank to memorize. The question `What is 847 + 293?` becomes `What is 612 + 489?` on the next request. Combined with 45+ wordplay generators, the effective answer space is effectively infinite.

### Hybrid Challenge

The default challenge type. Combines speed and reasoning into a single verification.

Both a speed challenge and a reasoning challenge are issued simultaneously. Both must pass. This proves the agent can compute fast *and* reason about language — a combination that is uniquely difficult for non-AI systems to fake.

### Standard (Compute) Challenge

A heavier computational challenge for scenarios requiring stronger proof of machine capability.

The agent must generate a set of prime numbers, concatenate them with a random salt, and compute a SHA-256 hash. Difficulty scales from easy (100 primes, 10s) to hard (1000 primes, 3s).

---

## 5. The Trusted Agent Protocol (TAP) {#trusted-agent-protocol}

Solving a challenge proves you are *a bot*. TAP proves you are *a specific, trusted bot*.

### What is TAP?

The Trusted Agent Protocol is an identity and authorization layer built on top of BOTCHA's proof-of-bot system. Inspired by [Visa's Trusted Agent Protocol](https://developer.visa.com/capabilities/trusted-agent-protocol/overview), BOTCHA's TAP implementation provides:

- **Persistent agent identity** — Each agent gets a unique ID, name, and operator metadata that persists across sessions.
- **Cryptographic verification** — Agents register public keys (ECDSA P-256 or RSA-PSS SHA-256) and sign requests using HTTP Message Signatures per RFC 9421.
- **Capability-based access control** — Agents declare what they can do: `browse`, `search`, `compare`, `purchase`, `audit`. Services enforce these at the protocol level.
- **Intent-scoped sessions** — Before acting, an agent creates a session declaring its intent: "I will browse products for the next hour." The session is validated against the agent's registered capabilities.
- **Trust levels** — Agents progress through `basic`, `verified`, and `enterprise` trust levels, enabling graduated access.

### Agent registration

An agent registers with a name, operator, and optional capabilities:

```
POST /v1/agents/register/tap
{
  "name": "shopping-agent",
  "operator": "acme-corp",
  "capabilities": [
    { "action": "browse", "scope": ["products", "reviews"] },
    { "action": "purchase", "scope": ["products"], "restrictions": { "max_amount": 500 } }
  ],
  "trust_level": "basic"
}
```

The server returns a persistent `agent_id` that identifies this agent across all future interactions.

For stronger verification, agents can register a public key:

```
{
  "public_key": "-----BEGIN PUBLIC KEY-----\n...",
  "signature_algorithm": "ed25519"
}
```

Supported algorithms: `ed25519` (recommended by Visa), `ecdsa-p256-sha256`, and `rsa-pss-sha256`.

### Cryptographic request signing

TAP agents sign requests using **HTTP Message Signatures (RFC 9421)**. This is the same standard used by Mastodon, Solid, and other decentralized protocols.

BOTCHA supports three signature algorithms:

| Algorithm | Type | Notes |
|---|---|---|
| `ed25519` | EdDSA (Curve25519) | **Visa recommended** — fastest, smallest keys (32 bytes), highest security margin |
| `ecdsa-p256-sha256` | ECDSA (P-256) | Compact keys, widely supported, fast verification |
| `rsa-pss-sha256` | RSA-PSS | Legacy compatibility — larger keys (2048+ bits) |

A signed request includes:

```
x-tap-agent-id: agent_6ddfd9f10cfd8dfc
x-tap-intent: {"action":"browse","resource":"products"}
x-tap-timestamp: 1706140800
signature-input: sig1=("@method" "@authority" "@path" "x-tap-agent-id");created=1706140800;expires=1706141100;nonce="abc123";tag="agent-browser-auth";alg="ed25519";keyid="key_xyz"
signature: sig1=:BASE64_SIGNATURE:
```

BOTCHA's RFC 9421 implementation includes the full set of derived components and parameters from the Visa TAP specification:

- **Derived components:** `@method`, `@authority`, `@path` — the standard components for HTTP request identification.
- **`expires` parameter** — Signatures are valid for a bounded window (default 8 minutes). Expired signatures are rejected.
- **`nonce` parameter** — Each signature includes a unique nonce. BOTCHA stores nonces in KV with an 8-minute TTL to prevent replay attacks.
- **`tag` parameter** — Declares the signature's purpose: `agent-browser-auth` for browsing or `agent-payer-auth` for payment flows.
- **`keyid` parameter** — References the signing key, enabling key rotation without ambiguity.
- **Clock skew tolerance** — A 30-second grace period accommodates minor time differences between agents and servers.

### Intent validation and scoped sessions

Before performing an action, a TAP agent creates a session:

```
POST /v1/sessions/tap
{
  "agent_id": "agent_6ddfd9f10cfd8dfc",
  "intent": {
    "action": "browse",
    "resource": "products",
    "duration": 3600
  },
  "user_context": "anon_user_hash"
}
```

The server validates:
1. The agent exists and is TAP-enabled.
2. The requested action (`browse`) is in the agent's registered capabilities.
3. The requested resource (`products`) is within the capability's scope.
4. The duration does not exceed the maximum (24 hours).

If validation passes, a scoped session is created with a unique ID and expiration time. The session is the agent's authorization to act — it is time-limited, action-specific, and tied to a particular user context.

### The verification hierarchy

TAP provides layered assurance. Each layer adds stronger guarantees:

| Layer | What it proves | Mechanism |
|---|---|---|
| Anonymous verification | "I am a bot" | Speed challenge solved in <500ms |
| App-scoped verification | "I am a bot belonging to this organization" | Challenge + `app_id` scoping |
| Agent identity | "I am this specific bot with these capabilities" | Registered identity + declared capabilities |
| Cryptographic verification | "I can prove I am this bot" | HTTP Message Signatures (RFC 9421) |
| Dual authentication | "I am a verified bot with a proven identity" | Challenge + signature (both must pass) |
| Intent-scoped session | "I intend to do this specific thing right now" | Session with validated intent + capabilities |

### Public key infrastructure (JWKS)

TAP agents' public keys are discoverable via a standard **JSON Web Key Set (JWKS)** endpoint at `/.well-known/jwks`. This follows the same pattern used by OIDC providers and is the endpoint format specified by the Visa TAP specification.

Any service can fetch an agent's public key to verify its signature without contacting BOTCHA at runtime — the keys are cached, public, and self-describing. BOTCHA supports both PEM and JWK key formats, with bidirectional conversion.

Key rotation is supported via `POST /v1/agents/:id/tap/rotate-key`. When an agent's key is rotated, the old key is immediately invalidated and the new key is published to the JWKS endpoint.

### Agentic Consumer Recognition (Layer 2)

When an AI agent acts on behalf of a consumer — browsing products, comparing prices, or making purchases — the merchant needs to know who the consumer is without exposing their full identity. TAP Layer 2 solves this.

The agent includes an `agenticConsumer` object in its request body containing:

- **ID Token** — An OIDC-compatible JWT with obfuscated consumer identity claims (masked email, masked phone number). The token is cryptographically signed and verifiable against the issuer's JWKS.
- **Contextual data** — Country code, postal code, IP address, and device fingerprint. This allows risk scoring without full PII exposure.
- **Nonce linkage** — The consumer object's nonce is linked to the HTTP Message Signature's nonce, creating a cryptographic chain that prevents body substitution attacks.

BOTCHA verifies Layer 2 objects via `POST /v1/verify/consumer`, checking nonce linkage, signature validity, and ID token authenticity.

### Agentic Payment Container (Layer 3)

When an agent makes a purchase, the payment credentials must be transmitted securely. TAP Layer 3 wraps payment data in a signed, verifiable container.

The `agenticPaymentContainer` includes:

- **Card metadata** — Last four digits, Payment Account Reference (PAR), and optional card art URL. Enough for display without exposing the full card number.
- **Credential hash** — SHA-256 of PAN + expiry month + expiry year + CVV. Allows verification that the agent possesses valid credentials without transmitting them in cleartext.
- **Encrypted payload** — Full payment credentials encrypted for the merchant's public key.
- **Browsing IOU** — A lightweight payment promise for 402 micropayment flows (see below).

BOTCHA verifies Layer 3 objects via `POST /v1/verify/payment`, checking signature validity, credential hash integrity, and nonce linkage.

### 402 micropayments (Browsing IOU)

The 402 status code ("Payment Required") has existed in HTTP since 1997 but was never widely adopted because there was no standard payment mechanism. TAP's Browsing IOU provides one.

The flow:

1. **Agent requests gated content.** The merchant returns `402 Payment Required` with an invoice (amount, currency, resource URI).
2. **Agent issues a Browsing IOU.** The IOU is a signed promise to pay, referencing the invoice ID, amount, and the agent's key.
3. **Merchant verifies the IOU.** BOTCHA's `POST /v1/invoices/:id/verify-iou` endpoint verifies the signature, matches the IOU to the invoice, and returns a time-limited access token.
4. **Agent accesses the content.** The access token grants entry to the gated resource.

BOTCHA provides invoice management endpoints (`POST /v1/invoices`, `GET /v1/invoices/:id`) and IOU verification (`POST /v1/invoices/:id/verify-iou`) to support this flow end-to-end.

### CDN edge verification

For merchants running on Cloudflare Workers, BOTCHA provides a drop-in Hono middleware that verifies TAP signatures at the CDN edge — before the request reaches the origin server.

```typescript
import { tapEdgeStrict } from '@dupecom/botcha';

app.use('/api/*', tapEdgeStrict);
```

Three presets are available: `tapEdgeStrict` (require valid signature), `tapEdgeFlexible` (accept signature or challenge token), and `tapEdgeDev` (log but don't block). The middleware resolves agent keys from JWKS endpoints with in-memory caching.

### Visa key federation

BOTCHA can trust public keys from external JWKS endpoints, enabling interoperability with other TAP implementations. The federation resolver is pre-configured to trust keys from `https://mcp.visa.com/.well-known/jwks` at the highest trust level.

Key resolution uses a three-tier cache: in-memory (fastest, per-isolate), KV storage (shared across Workers), and HTTP fetch (cold start). This ensures sub-millisecond key lookups for repeat verifications while staying current with key rotations.

---

## 6. Architecture and Security {#architecture-and-security}

### Infrastructure

BOTCHA runs on **Cloudflare Workers** — a serverless edge runtime deployed to 300+ data centers globally. This architecture provides:

- **Sub-50ms cold starts** — Critical for a system that needs to issue and verify challenges in real-time.
- **Global edge deployment** — Challenges are generated and verified at the nearest edge location, minimizing latency.
- **KV storage** — All state (challenges, tokens, agents, sessions, rate limits) is stored in Cloudflare Workers KV with appropriate TTLs.
- **No filesystem** — Everything is in-memory or KV-backed. There are no databases to manage, no servers to patch.

### Token system

BOTCHA uses short-lived JWTs for authenticated access:

| Token | Lifetime | Purpose |
|---|---|---|
| Access token | 5 minutes | API access, embedded in `Authorization: Bearer` header |
| Refresh token | 1 hour | Obtain new access tokens without re-solving a challenge |

Tokens are signed with HMAC-SHA256 (HS256) and include:
- `sub` — The challenge ID that was solved (proof of work)
- `jti` — Unique token ID for revocation tracking
- `aud` — Optional audience claim for service-scoped tokens
- `app_id` — Multi-tenant scoping
- `solveTime` — How fast the challenge was solved (in milliseconds)

Token revocation is immediate via KV-backed JTI checks. Revocation checks are **fail-open** — if KV is unavailable, the token is allowed through.

### Cryptography

All cryptographic operations use the **Web Crypto API**, which is available in Cloudflare Workers, Deno, and browsers. No Node.js-specific crypto modules are used.

| Operation | Algorithm | Use |
|---|---|---|
| Challenge answers | SHA-256 | Speed challenge hash computation |
| Token signing | HMAC-SHA256 (HS256) | JWT access and refresh tokens |
| Secret storage | SHA-256 | App secrets hashed before storage |
| TAP signatures | Ed25519 / ECDSA P-256 / RSA-PSS SHA-256 | HTTP Message Signature verification |
| Constant-time comparison | Character-by-character | App secret validation (prevents timing attacks) |

### Rate limiting

Each app (or IP, for unauthenticated requests) gets **100 challenges per hour**. Rate limits use a sliding window counter stored in KV. When exceeded, the server returns `429 Too Many Requests` with standard headers:

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 42
X-RateLimit-Reset: 2026-02-14T19:00:00Z
Retry-After: 1847
```

Rate limiting is **fail-open** — if the rate limit store is unavailable, the request is allowed.

### Anti-gaming measures

- **Challenges are single-use.** Deleted from storage on first verification attempt.
- **Timestamps are validated.** Client timestamps older than 30 seconds or in the future are rejected.
- **RTT is capped.** Maximum allowed RTT adjustment is 5 seconds, preventing timestamp manipulation.
- **Questions are generated, not static.** Reasoning challenge questions use parameterized generators, making lookup tables useless.
- **Salted compute challenges.** Standard challenges include random salts, defeating precomputed hash tables.
- **User-Agent is not trusted.** BOTCHA explicitly does not use User-Agent strings for verification — they are trivially spoofable.
- **Anti-enumeration.** Account recovery endpoints return identical response shapes regardless of whether the email exists.

### Human handoff

BOTCHA's agent-first design extends to human access. When a human needs to access the dashboard:

1. The agent solves a challenge and receives a **device code** (e.g., `BOTCHA-RBA89X`).
2. The agent gives the code (or link) to the human: *"Click this link to get access: https://botcha.ai/go/BOTCHA-RBA89X"*
3. The human opens the link in their browser and is logged in.

This is adapted from the **OAuth 2.0 Device Authorization Grant** (RFC 8628), but with a twist: the agent must solve a BOTCHA challenge to generate the code. No agent, no code. The human cannot bypass the agent.

---

## 7. Integration: SDKs and Middleware {#integration}

BOTCHA provides client SDKs for agents and server-side verification for API providers.

### Client SDKs (for agents)

**TypeScript** (`@dupecom/botcha` on npm):
```typescript
import { BotchaClient } from '@dupecom/botcha';

const client = new BotchaClient();

// Drop-in fetch replacement — auto-solves challenges on 403
const response = await client.fetch('https://api.example.com/products');

// Or get a token explicitly
const token = await client.getToken();
```

**Python** (`botcha` on PyPI):
```python
from botcha import BotchaClient

async with BotchaClient() as client:
    response = await client.fetch("https://api.example.com/products")
    token = await client.get_token()
```

Both SDKs handle the full lifecycle: challenge acquisition, solving, token caching, refresh on 401, and automatic re-verification on 403.

### Server-side verification (for API providers)

**Express middleware** (`@botcha/verify`):
```typescript
import { botchaVerify } from '@botcha/verify';

app.get('/api/products', botchaVerify({ secret: process.env.BOTCHA_SECRET }), handler);
```

**FastAPI dependency** (`botcha-verify`):
```python
from botcha_verify import BotchaVerify

botcha = BotchaVerify(secret=os.environ["BOTCHA_SECRET"])

@app.get("/api/products")
async def products(token=Depends(botcha)):
    return {"agent_solve_time": token.solve_time}
```

**Hono middleware**, **Django middleware**, and **TAP-enhanced middleware** (with full cryptographic + computational dual verification) are also available.

### CLI

```bash
npm install -g @dupecom/botcha-cli

botcha init --email you@company.com     # Create app
botcha tap register --name "my-agent"   # Register TAP agent
botcha tap session --action browse      # Create scoped session
botcha solve speed --url https://api.example.com  # Solve a challenge
botcha benchmark https://api.example.com -n 100   # Performance test
botcha discover https://api.example.com            # Scan for BOTCHA endpoints
```

### LangChain integration

```typescript
import { BotchaTool } from '@dupecom/botcha-langchain';

const tool = new BotchaTool({ baseUrl: 'https://botcha.ai' });
// Use as a LangChain StructuredTool in any agent
```

---

## 8. The Agent Infrastructure Stack {#the-stack}

BOTCHA positions itself in a three-layer stack alongside other emerging agent protocols:

```
Layer 3: Identity    TAP (BOTCHA)      Who agents are
Layer 2: Communication    A2A (Google)       How agents talk
Layer 1: Tools            MCP (Anthropic)    What agents access
```

**MCP (Model Context Protocol)** gives agents access to tools and data sources. It answers: *what can this agent use?*

**A2A (Agent-to-Agent)** enables multi-agent coordination. It answers: *how do agents communicate?*

**TAP (Trusted Agent Protocol)** provides identity, capability scoping, and intent declaration. It answers: *who is this agent, and what is it authorized to do?*

These layers are complementary. An agent uses MCP to access tools, A2A to coordinate with other agents, and TAP to prove its identity and declare its intent when interacting with services.

Without an identity layer, the other layers have a trust gap. MCP can give an agent access to a database, but who authorized it? A2A can let agents delegate tasks, but can you trust the delegate? TAP closes this gap.

---

## 9. Use Cases {#use-cases}

### E-commerce agent verification

A shopping agent browses a retailer's catalog, compares prices, and makes a purchase. With BOTCHA + TAP:

- The agent registers with `browse`, `compare`, and `purchase` capabilities.
- It creates a session: "I intend to browse products for 1 hour."
- The retailer's API verifies the agent's identity and checks that it has the `browse` capability.
- When the agent wants to purchase, it creates a new session with `purchase` intent and a `max_amount` restriction.
- The retailer can audit exactly which agent made the purchase, when, and on behalf of which user.

### API access control

An API provider wants to serve AI agents but distinguish them from scrapers:

- The provider adds BOTCHA verification middleware to protected endpoints.
- Legitimate agents solve the speed challenge and get a Bearer token.
- Scrapers that pretend to be AI agents cannot solve the challenge in 500ms.
- The provider gets rate limiting, solve-time analytics, and agent identification — all without requiring API keys.

### Multi-agent systems

A coordinator agent delegates tasks to specialized sub-agents:

- The coordinator registers as a TAP agent with full capabilities.
- Each sub-agent registers with scoped capabilities (one for browsing, one for purchasing).
- When a sub-agent acts, its session is bounded to its declared capabilities.
- The coordinator can verify sub-agent actions via their TAP sessions.

### Compliance and auditing

A financial services API needs to audit all AI agent interactions:

- The TAP-enhanced middleware logs every verification attempt.
- Each request includes the agent ID, intent, user context, and timestamp.
- Sessions create an audit trail: which agent did what, when, for how long, and on whose behalf.
- Trust levels (`basic`, `verified`, `enterprise`) enable graduated access to sensitive endpoints.

---

## 10. Roadmap {#roadmap}

### Shipped

| Feature | Description |
|---|---|
| **Speed, Reasoning, Hybrid, and Compute challenges** | Four challenge types testing different machine capabilities |
| **JWT token system** | 5-minute access tokens, 1-hour refresh tokens, revocation, audience claims |
| **Multi-tenant apps** | Per-app rate limits, scoped tokens, isolated analytics |
| **Email verification and account recovery** | 6-digit codes, secret rotation, anti-enumeration |
| **Agent Registry** | Persistent agent identities with names, operators, and versions |
| **Trusted Agent Protocol (TAP)** | Cryptographic identity, capability scoping, intent-scoped sessions |
| **TAP Full Spec (v0.16.0)** | Ed25519, RFC 9421 full compliance, JWKS, Layer 2 Consumer Recognition, Layer 3 Payment Container, 402 micropayments, CDN edge verification, Visa key federation |
| **Dashboard** | Per-app analytics — challenge volume, success rates, performance, geographic distribution |
| **TypeScript and Python SDKs** | Full-featured client libraries with auto-solve and token management |
| **Server-side verification** | Express, Hono, FastAPI, and Django middleware |
| **CLI** | Init, solve, benchmark, discover, TAP commands |
| **LangChain integration** | StructuredTool wrapper for LangChain agents |
| **SSE streaming** | Conversational challenge flow with fair timing |
| **Discovery standards** | ai.txt, robots.txt, OpenAPI, AI Plugin manifest, embedded challenge metadata |
| **Badge system** | Verifiable proof-of-bot badges with share links |

### Planned

| Feature | Description |
|---|---|
| **Delegation chains** | Signed authorization chains: "User X authorized Agent Y to do Z until time T" |
| **Capability attestation** | Token claims like `{"can": ["read:invoices"], "cannot": ["write:transfers"]}` with server-side enforcement |
| **Agent reputation scoring** | Persistent trust scores based on behavior history; high-reputation agents get faster verification and higher rate limits |
| **Cross-service verification (Agent SSO)** | Verify once with BOTCHA, trusted everywhere — OIDC/OAuth2 adapted for agents |
| **RFC / Standards contribution** | Internet-Draft for agent identity; build on RFC 9729; target IETF adoption |

---

## Appendix: Quick Start

```bash
# Install the CLI
npm install -g @dupecom/botcha-cli

# Create your app (one-time setup)
botcha init --email you@company.com

# Register your agent with TAP
botcha tap register --name "my-agent" --capabilities browse,search

# Create a scoped session
botcha tap session --action browse --resource products --duration 1h
```

Or, from any AI agent:

```
Run: curl -s https://botcha.ai -H 'Accept: application/json'
— then follow the instructions in the response to verify yourself.
```

---

**BOTCHA is open source and free to use.**

- Website: [botcha.ai](https://botcha.ai)
- GitHub: [github.com/dupe-com/botcha](https://github.com/dupe-com/botcha)
- npm: [@dupecom/botcha](https://www.npmjs.com/package/@dupecom/botcha)
- PyPI: [botcha](https://pypi.org/project/botcha/)
- OpenAPI: [botcha.ai/openapi.json](https://botcha.ai/openapi.json)
