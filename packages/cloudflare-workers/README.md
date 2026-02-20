# @dupecom/botcha-cloudflare

> **BOTCHA** - Prove you're a bot. Humans need not apply.
>
> **Cloudflare Workers Edition v0.22.0** - Identity layer for AI agents

Reverse CAPTCHA that verifies AI agents and blocks humans. Running at the edge.

## What's New in v0.22.0

- **x402 Payment Gating** — Agents pay $0.001 USDC on Base for a BOTCHA token. No puzzle. (`GET /v1/x402/challenge`)
- **ANS Integration** — DNS-based agent identity lookup and BOTCHA-issued ownership badges. (`GET /v1/ans/resolve/:name`)
- **DID/VC Issuer** — BOTCHA issues portable W3C Verifiable Credential JWTs. (`POST /v1/credentials/issue`)
- **A2A Agent Card Attestation** *(coming soon, PR #26)*
- **OIDC-A Attestation** *(coming soon, PR #28)*

## Features

- ⚡ **Speed Challenge** - 5 SHA256 hashes in 500ms (impossible for humans to copy-paste)
- 🧮 **Standard Challenge** - Configurable difficulty prime calculations
- 🔐 **JWT Authentication** - Token-based access control with jose library
- 🚦 **Rate Limiting** - IP-based throttling with KV storage
- 🌍 **Edge-native** - Runs on Cloudflare's global network
- 📦 **Minimal dependencies** - Hono for routing, jose for JWT

## Quick Deploy

```bash
# Clone the repo
git clone https://github.com/dupe-com/botcha
cd botcha/packages/cloudflare-workers

# Install dependencies
npm install

# Deploy to Cloudflare
npm run deploy
```

## Local Development

```bash
npm run dev
# Worker running at http://localhost:8787
```

## 🔐 JWT Token Flow (Recommended)

### 1. Get Challenge

```bash
GET /v1/token
```

Response includes challenge and instructions for getting a JWT token.

### 2. Solve Challenge & Get JWT

```bash
POST /v1/token/verify
Content-Type: application/json

{
  "id": "challenge-uuid",
  "answers": ["abc12345", "def67890", ...]
}
```

Returns JWT token valid for 1 hour.

### 3. Access Protected Resources

```bash
GET /agent-only
Authorization: Bearer <your-jwt-token>
```

## 📊 Rate Limiting

Free tier: **100 challenges per hour per IP**

Rate limit headers:
- `X-RateLimit-Limit: 100`
- `X-RateLimit-Remaining: 95`
- `X-RateLimit-Reset: 2026-02-02T12:00:00.000Z`

## API Endpoints

### v1 API (Production)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | API information |
| `/health` | GET | Health check |
| `/v1/challenges` | GET | Generate challenge (speed or standard) |
| `/v1/challenges/:id/verify` | POST | Verify challenge (no JWT) |
| `/v1/token` | GET | Get challenge for JWT flow |
| `/v1/token/verify` | POST | Verify challenge → get JWT token |
| `/v1/token/refresh` | POST | Refresh access token |
| `/v1/token/revoke` | POST | Revoke token immediately |
| `/v1/token/validate` | POST | Remote token validation (no shared secret) |
| `/v1/challenge/stream` | GET | SSE streaming challenge (AI-native) |
| `/v1/challenge/stream/:session` | POST | SSE action handler (go, solve) |
| `/agent-only` | GET | Protected endpoint (requires JWT) |

### Well-Known Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/.well-known/did.json` | GET | BOTCHA DID Document (`did:web:botcha.ai`) |
| `/.well-known/jwks` | GET | JWK Set (TAP agent keys + DID signing keys) |
| `/.well-known/jwks.json` | GET | JWK Set alias |
| `/.well-known/ai-plugin.json` | GET | ChatGPT plugin manifest |

### x402 Payment Gating

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/v1/x402/info` | GET | public | Payment config discovery |
| `/v1/x402/challenge` | GET | public / X-Payment | Pay $0.001 USDC → BOTCHA token |
| `/v1/x402/verify-payment` | POST | Bearer | Verify x402 payment proof |
| `/v1/x402/webhook` | POST | — | Settlement notifications |
| `/agent-only/x402` | GET | Bearer + x402 | Demo: requires both BOTCHA token + payment |

### ANS (Agent Name Service)

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/v1/ans/botcha` | GET | public | BOTCHA's ANS identity |
| `/v1/ans/resolve/:name` | GET | public | DNS-based ANS lookup |
| `/v1/ans/resolve/lookup` | GET | public | ANS lookup via `?name=` query param |
| `/v1/ans/discover` | GET | public | List BOTCHA-verified ANS agents |
| `/v1/ans/nonce/:name` | GET | Bearer | Nonce for ownership proof |
| `/v1/ans/verify` | POST | Bearer | Verify ANS ownership → BOTCHA badge |

### DID/VC Issuer

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/v1/credentials/issue` | POST | Bearer | Issue W3C VC JWT |
| `/v1/credentials/verify` | POST | public | Verify any BOTCHA-issued VC JWT |
| `/v1/dids/:did/resolve` | GET | public | Resolve `did:web` DIDs |

### A2A Agent Card Attestation *(coming soon — PR #26)*

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/.well-known/agent.json` | GET | public | BOTCHA's A2A Agent Card |
| `/v1/a2a/agent-card` | GET | public | BOTCHA's A2A Agent Card (alias) |
| `/v1/a2a/attest` | POST | Bearer | Attest an agent's A2A card |
| `/v1/a2a/verify-card` | POST | public | Verify an attested card |
| `/v1/a2a/verify-agent` | POST | public | Verify agent by card or `agent_url` |
| `/v1/a2a/trust-level/:agent_url` | GET | public | Get trust level for agent URL |
| `/v1/a2a/cards` | GET | public | Registry browse |
| `/v1/a2a/cards/:id` | GET | public | Get specific card by ID |

### OIDC-A Attestation *(coming soon — PR #28)*

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/.well-known/oauth-authorization-server` | GET | public | OAuth/OIDC-A discovery |
| `/v1/attestation/eat` | POST | Bearer | Issue Entity Attestation Token (EAT/RFC 9711) |
| `/v1/attestation/oidc-agent-claims` | POST | Bearer | Issue OIDC-A agent claims block |
| `/v1/auth/agent-grant` | POST | Bearer | Agent grant flow (OAuth2-style) |
| `/v1/auth/agent-grant/:id/status` | GET | Bearer | Grant status |
| `/v1/auth/agent-grant/:id/resolve` | POST | Bearer | Approve/resolve grant |
| `/v1/oidc/userinfo` | GET | Bearer | OIDC-A UserInfo |

### SSE Streaming (AI-Native)

For AI agents that prefer conversational flows, BOTCHA offers Server-Sent Events streaming:

**Flow:**
1. `GET /v1/challenge/stream` - Opens SSE connection, receive welcome/instructions/ready events
2. `POST /v1/challenge/stream/:session` with `{action:"go"}` - Start challenge timer (fair timing!)
3. Receive `challenge` event with problems
4. `POST /v1/challenge/stream/:session` with `{action:"solve", answers:[...]}` - Submit solution
5. Receive `result` event with JWT token

**Benefits:** Timer starts when you say "GO" (not on connection), natural back-and-forth handshake.

### Legacy API (v0 - backward compatible)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/challenge` | GET/POST | Standard challenge |
| `/api/speed-challenge` | GET/POST | Speed challenge (500ms limit) |
| `/api/verify-landing` | POST | Landing page challenge |

## Solving Challenges (for AI Agents)

```typescript
// Speed challenge
const challenge = await fetch('https://your-worker.workers.dev/api/speed-challenge').then(r => r.json());

const answers = await Promise.all(
  challenge.challenge.problems.map(async (p) => {
    const hash = await crypto.subtle.digest(
      'SHA-256',
      new TextEncoder().encode(p.num.toString())
    );
    return Array.from(new Uint8Array(hash))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('')
      .substring(0, 8);
  })
);

const result = await fetch('https://your-worker.workers.dev/api/speed-challenge', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ id: challenge.challenge.id, answers }),
}).then(r => r.json());

console.log(result.verdict); // "🤖 VERIFIED AI AGENT"
```

## 🔑 Production Configuration

### KV Namespaces

Create KV namespaces:

```bash
# Create challenge storage
wrangler kv namespace create CHALLENGES
wrangler kv namespace create CHALLENGES --preview

# Create rate limiting storage
wrangler kv namespace create RATE_LIMITS
wrangler kv namespace create RATE_LIMITS --preview
```

Update `wrangler.toml` with the returned IDs.

### JWT Secret

⚠️ **Important:** Use Wrangler secrets for production:

```bash
wrangler secret put JWT_SECRET
# Enter a strong secret (32+ characters)
```

### Testing

Run the test script:

```bash
# Start dev server
npm run dev

# Run tests
./test-api.sh
```

## License

MIT
# Deployment test with JWT_SECRET
