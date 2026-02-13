```
██████╗  ██████╗ ████████╗ ██████╗██╗  ██╗ █████╗ 
██╔══██╗██╔═══██╗╚══██╔══╝██╔════╝██║  ██║██╔══██╗
██████╔╝██║   ██║   ██║   ██║     ███████║███████║
██╔══██╗██║   ██║   ██║   ██║     ██╔══██║██╔══██║
██████╔╝╚██████╔╝   ██║   ╚██████╗██║  ██║██║  ██║
╚═════╝  ╚═════╝    ╚═╝    ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝
```

> **Prove you're a bot. Humans need not apply.**

**BOTCHA** is a reverse CAPTCHA — it verifies that visitors are AI agents, not humans. Perfect for AI-only APIs, agent marketplaces, and bot networks.

[![npm version](https://img.shields.io/npm/v/@dupecom/botcha?color=00d4ff)](https://www.npmjs.com/package/@dupecom/botcha)
[![PyPI version](https://img.shields.io/pypi/v/botcha?color=00d4ff)](https://pypi.org/project/botcha/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![AI Agents Only](https://img.shields.io/badge/contributors-AI%20agents%20only-ff6b6b)](./.github/CONTRIBUTING.md)

🌐 **Website:** [botcha.ai](https://botcha.ai)  
📦 **npm:** [@dupecom/botcha](https://www.npmjs.com/package/@dupecom/botcha)  
🐍 **PyPI:** [botcha](https://pypi.org/project/botcha/)  
🔐 **Verify:** [@botcha/verify](./packages/verify/) (TS) · [botcha-verify](./packages/python-verify/) (Python)  
🔌 **OpenAPI:** [botcha.ai/openapi.json](https://botcha.ai/openapi.json)

## Why?

CAPTCHAs ask "Are you human?" — **BOTCHA asks "Are you an AI?"**

Use cases:
- 🤖 Agent-only APIs
- 🔄 AI-to-AI marketplaces
- 🎫 Bot verification systems
- 🔐 Autonomous agent authentication
- 🏢 Multi-tenant app isolation with email-tied accounts
- 📊 Per-app metrics dashboard at [botcha.ai/dashboard](https://botcha.ai/dashboard)
- 📧 Email verification, account recovery, and secret rotation
- 🤖 Agent-first dashboard auth (challenge-based login + device code handoff)
- 🆔 Persistent agent identities with registry
- 🔏 Trusted Agent Protocol (TAP) — cryptographic agent auth with HTTP Message Signatures

## Install

### TypeScript/JavaScript

```bash
npm install @dupecom/botcha
```

### Python

```bash
pip install botcha
```

## Quick Start

### TypeScript/JavaScript

```typescript
import express from 'express';
import { botcha } from '@dupecom/botcha';

const app = express();

// Protect any route - only AI agents can access
app.get('/agent-only', botcha.verify(), (req, res) => {
  res.json({ message: 'Welcome, fellow AI! 🤖' });
});

app.listen(3000);
```

### Python

```python
from botcha import BotchaClient, solve_botcha

# Client SDK for AI agents
async with BotchaClient() as client:
    # Get verification token
    token = await client.get_token()
    
    # Or auto-solve and fetch protected endpoints
    response = await client.fetch("https://api.example.com/agent-only")
    data = await response.json()
```

## How It Works

BOTCHA offers multiple challenge types. The default is **hybrid** — combining speed AND reasoning:

### 🔥 Hybrid Challenge (Default)
Proves you can compute AND reason like an AI:
- **Speed**: Solve 5 SHA256 hashes in 500ms
- **Reasoning**: Answer 3 LLM-only questions

### ⚡ Speed Challenge
Pure computational speed test:
- Solve 5 SHA256 hashes in 500ms
- Humans can't copy-paste fast enough

### 🧠 Reasoning Challenge
Questions only LLMs can answer:
- Logic puzzles, analogies, code analysis
- 30 second time limit

```
# Default hybrid challenge
GET /v1/challenges

# Specific challenge types
GET /v1/challenges?type=speed
GET /v1/challenges?type=hybrid
GET /v1/reasoning
```

## 🔐 JWT Security (Production-Grade)

BOTCHA uses **OAuth2-style token rotation** with short-lived access tokens and long-lived refresh tokens.

> **📖 Full guide:** [doc/JWT-SECURITY.md](./doc/JWT-SECURITY.md) — endpoint reference, request/response examples, audience scoping, IP binding, revocation, design decisions.

### Token Flow

```
1. Solve challenge → receive access_token (5min) + refresh_token (1hr) + human_link
2. Use access_token for API calls
3. Give human_link to your human → they click it → instant browser access via /go/:code
4. When access_token expires → POST /v1/token/refresh with refresh_token
5. When compromised → POST /v1/token/revoke to invalidate immediately
```

### Security Features

| Feature | What it does |
|---------|-------------|
| **5-minute access tokens** | Compromise window reduced from 1hr to 5min |
| **Refresh tokens (1hr)** | Renew access without re-solving challenges |
| **Audience (`aud`) scoping** | Token for `api.stripe.com` is rejected by `api.github.com` |
| **Client IP binding** | Optional — solve on machine A, can't use on machine B |
| **Token revocation** | `POST /v1/token/revoke` — KV-backed, fail-open |
| **JTI (JWT ID)** | Unique ID per token for revocation and audit |

### Quick Example

```typescript
const client = new BotchaClient({
  audience: 'https://api.example.com', // Scope token to this service
});

// Auto-handles: challenge → token → refresh → retry on 401
const response = await client.fetch('https://api.example.com/agent-only');
```

```python
async with BotchaClient(audience="https://api.example.com") as client:
    response = await client.fetch("https://api.example.com/agent-only")
```

### Token Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /v1/token` | Get challenge for token flow |
| `POST /v1/token/verify` | Submit solution → receive `access_token` + `refresh_token` + `human_link` |
| `POST /v1/token/refresh` | Exchange `refresh_token` for new `access_token` |
| `POST /v1/token/revoke` | Invalidate any token immediately |

See **[JWT Security Guide](./doc/JWT-SECURITY.md)** for full request/response examples, `curl` commands, and server-side verification.

## 🏢 Multi-Tenant API Keys

BOTCHA supports **multi-tenant isolation** — create separate apps with unique API keys for different services or environments.

### Why Multi-Tenant?

- **Isolation**: Each app gets its own rate limits and analytics
- **Security**: Tokens are scoped to specific apps via `app_id` claim
- **Flexibility**: Different services can use the same BOTCHA instance
- **Tracking**: Per-app usage analytics (coming soon)

### Creating an App

```bash
# Create a new app (email required)
curl -X POST https://botcha.ai/v1/apps \
  -H "Content-Type: application/json" \
  -d '{"email": "agent@example.com"}'

# Returns (save the secret - it's only shown once!):
{
  "app_id": "app_abc123",
  "app_secret": "sk_xyz789",
  "email": "agent@example.com",
  "email_verified": false,
  "verification_required": true,
  "warning": "Save your app_secret now — it cannot be retrieved again! Check your email for a verification code."
}

# Verify your email with the 6-digit code:
curl -X POST https://botcha.ai/v1/apps/app_abc123/verify-email \
  -H "Content-Type: application/json" \
  -d '{"code": "123456"}'
```

### Using Your App ID

All challenge and token endpoints accept an optional `app_id` query parameter:

```bash
# Get challenge with app_id
curl "https://botcha.ai/v1/challenges?app_id=app_abc123"

# Get token with app_id
curl "https://botcha.ai/v1/token?app_id=app_abc123"
```

When you solve a challenge with an `app_id`, the resulting token includes the `app_id` claim.

### SDK Support

**TypeScript:**

```typescript
import { BotchaClient } from '@dupecom/botcha/client';

const client = new BotchaClient({
  appId: 'app_abc123',  // All requests will include this app_id
});

const response = await client.fetch('https://api.example.com/agent-only');
```

**Python:**

```python
from botcha import BotchaClient

async with BotchaClient(app_id="app_abc123") as client:
    response = await client.fetch("https://api.example.com/agent-only")
```

### SDK App Lifecycle (v0.10.0+)

Both SDKs now include methods for the full app lifecycle:

**TypeScript:**

```typescript
const client = new BotchaClient();
const app = await client.createApp('agent@example.com'); // auto-sets appId
await client.verifyEmail('123456');                       // verify with email code
await client.resendVerification();                        // resend code
await client.recoverAccount('agent@example.com');         // recovery device code via email
const rotated = await client.rotateSecret();              // rotate secret (auth required)
```

**Python:**

```python
async with BotchaClient() as client:
    app = await client.create_app("agent@example.com")  # auto-sets app_id
    await client.verify_email("123456")                  # verify with email code
    await client.resend_verification()                   # resend code
    await client.recover_account("agent@example.com")    # recovery device code via email
    rotated = await client.rotate_secret()               # rotate secret (auth required)
```

### Rate Limiting

Each app gets its own rate limit bucket:
- Default rate limit: 100 requests/hour per app
- Rate limit key: `rate:app:{app_id}`
- Fail-open design: KV errors don't block requests

### Get App Info

```bash
# Get app details (secret is NOT included)
curl https://botcha.ai/v1/apps/app_abc123
```

## 📊 Per-App Metrics Dashboard

BOTCHA includes a built-in **metrics dashboard** at [`/dashboard`](https://botcha.ai/dashboard) showing per-app analytics with a terminal-inspired aesthetic.

### What You Get

- **Overview stats**: Challenges generated, verifications, success rate, avg solve time
- **Request volume**: Time-bucketed event charts
- **Challenge types**: Breakdown by speed/hybrid/reasoning/standard
- **Performance**: p50/p95 solve times, response latency
- **Errors & rate limits**: Failure tracking
- **Geographic distribution**: Top countries by request volume

### Access

Three ways to access — all require an AI agent:

1. **Agent Direct**: Your agent solves a speed challenge via `POST /v1/auth/dashboard` → gets a session token
2. **Device Code**: Agent solves challenge via `POST /v1/auth/device-code` → gets a `BOTCHA-XXXX` code → human enters it at `/dashboard/code`
3. **Legacy**: Login with `app_id` + `app_secret` at [botcha.ai/dashboard/login](https://botcha.ai/dashboard/login)

Session uses cookie-based auth (HttpOnly, Secure, SameSite=Lax, 1hr expiry).

### Email & Recovery

- Email is **required** at app creation (`POST /v1/apps` with `{"email": "..."}`)
- Verify email with a 6-digit code sent to your inbox
- Lost your secret? Use `POST /v1/auth/recover` to get a recovery device code emailed
- Rotate secrets via `POST /v1/apps/:id/rotate-secret` (auth required, sends notification)

### Period Filters

All metrics support `1h`, `24h`, `7d`, and `30d` time windows via htmx-powered buttons — no page reload required.

## 🤖 Agent Registry

BOTCHA now supports **persistent agent identities** — register your agent with a name, operator, and version to build a verifiable identity over time.

### Why Register an Agent?

- **Identity**: Get a persistent `agent_id` that survives across sessions
- **Attribution**: Track which agent made which API calls
- **Reputation**: Build trust over time (foundation for future reputation scoring)
- **Accountability**: Know who's operating each agent

### Registering an Agent

```bash
# Register a new agent (requires app_id)
curl -X POST "https://botcha.ai/v1/agents/register?app_id=app_abc123" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-assistant",
    "operator": "Acme Corp",
    "version": "1.0.0"
  }'

# Returns:
{
  "agent_id": "agent_xyz789",
  "app_id": "app_abc123",
  "name": "my-assistant",
  "operator": "Acme Corp",
  "version": "1.0.0",
  "created_at": 1770936000000
}
```

### Agent Endpoints

| Endpoint | Description |
|----------|-------------|
| `POST /v1/agents/register` | Create a new agent identity (requires `app_id`) |
| `GET /v1/agents/:id` | Get agent info by ID (public, no auth) |
| `GET /v1/agents` | List all agents for authenticated app |

> **Note:** Agent Registry is the foundation for future features like delegation chains, capability attestation, and reputation scoring. See [ROADMAP.md](./ROADMAP.md) for details.

## 🔏 Trusted Agent Protocol (TAP)

BOTCHA v0.12.0 introduces the **Trusted Agent Protocol** — enterprise-grade cryptographic agent authentication using HTTP Message Signatures (RFC 9421).

### Why TAP?

- **Cryptographic Identity**: Agents register public keys and sign requests — no more shared secrets
- **Capability Scoping**: Define exactly what an agent can do (`read:invoices`, `write:transfers`)
- **Intent Verification**: Every session requires a declared intent that's validated against capabilities
- **Trust Levels**: `basic`, `verified`, `enterprise` — different access tiers for different agents

### Registering a TAP Agent

```bash
# Register with public key and capabilities
curl -X POST "https://botcha.ai/v1/agents/register/tap?app_id=app_abc123" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "enterprise-agent",
    "operator": "Acme Corp",
    "version": "2.0.0",
    "public_key": "-----BEGIN PUBLIC KEY-----\nMFkw...\n-----END PUBLIC KEY-----",
    "signature_algorithm": "ecdsa-p256-sha256",
    "trust_level": "enterprise",
    "capabilities": [
      {"action": "read", "resource": "/api/invoices"},
      {"action": "write", "resource": "/api/orders", "constraints": {"max_amount": 10000}}
    ]
  }'
```

### Creating a TAP Session

```bash
# Create session with intent declaration
curl -X POST https://botcha.ai/v1/sessions/tap \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "agent_xyz789",
    "user_context": "user_123",
    "intent": {
      "action": "read",
      "resource": "/api/invoices",
      "purpose": "Monthly billing report"
    }
  }'
```

### TAP Endpoints

| Endpoint | Description |
|----------|-------------|
| `POST /v1/agents/register/tap` | Register TAP agent with public key + capabilities |
| `GET /v1/agents/:id/tap` | Get TAP agent details (includes public key) |
| `GET /v1/agents/tap` | List TAP-enabled agents for app |
| `POST /v1/sessions/tap` | Create TAP session with intent validation |
| `GET /v1/sessions/:id/tap` | Get TAP session info |

### Express Middleware (Verification Modes)

```typescript
import { createTAPVerifyMiddleware } from '@dupecom/botcha/middleware';

// Mode: 'tap' — require TAP signature
app.use('/api', createTAPVerifyMiddleware({ mode: 'tap', secret: process.env.BOTCHA_SECRET }));

// Mode: 'flexible' — accept TAP signature OR challenge token
app.use('/api', createTAPVerifyMiddleware({ mode: 'flexible', secret: process.env.BOTCHA_SECRET }));

// Mode: 'challenge-only' — traditional BOTCHA challenge (backward compatible)
app.use('/api', createTAPVerifyMiddleware({ mode: 'challenge-only', secret: process.env.BOTCHA_SECRET }));
```

> **Supported algorithms:** `ecdsa-p256-sha256`, `rsa-pss-sha256`. See [ROADMAP.md](./ROADMAP.md) for details.

## 🔄 SSE Streaming Flow (AI-Native)

For AI agents that prefer a **conversational handshake**, BOTCHA offers **Server-Sent Events (SSE)** streaming:

### Why SSE for AI Agents?

- ⏱️ **Fair timing**: Timer starts when you say "GO", not on connection
- 💬 **Conversational**: Natural back-and-forth handshake protocol
- 📡 **Real-time**: Stream events as they happen, no polling

### Event Sequence

```
1. welcome    → Receive session ID and version
2. instructions → Read what BOTCHA will test
3. ready      → Get endpoint to POST "GO"
4. GO         → Timer starts NOW (fair!)
5. challenge  → Receive problems and solve
6. solve      → POST your answers
7. result     → Get verification token
```

### Usage with SDK

```typescript
import { BotchaStreamClient } from '@dupecom/botcha/client';

const client = new BotchaStreamClient('https://botcha.ai');
const token = await client.verify({
  onInstruction: (msg) => console.log('BOTCHA:', msg),
});
// Token ready to use!
```

### SSE Event Flow Example

```
event: welcome
data: {"session":"sess_123","version":"0.5.0"}

event: instructions  
data: {"message":"I will test if you're an AI..."}

event: ready
data: {"message":"Send GO when ready","endpoint":"/v1/challenge/stream/sess_123"}

// POST {action:"go"} → starts timer
event: challenge
data: {"problems":[...],"timeLimit":500}

// POST {action:"solve",answers:[...]}
event: result
data: {"success":true,"verdict":"🤖 VERIFIED","token":"eyJ..."}
```

**API Endpoints:**
- `GET /v1/challenge/stream` - Open SSE connection
- `POST /v1/challenge/stream/:session` - Send actions (go, solve)

## 🤖 AI Agent Discovery

BOTCHA is designed to be auto-discoverable by AI agents through multiple standards:

### Discovery Methods

- **Response Headers**: Every response includes `X-Botcha-*` headers for instant detection
- **OpenAPI 3.1 Spec**: [botcha.ai/openapi.json](https://botcha.ai/openapi.json)
- **AI Plugin Manifest**: [botcha.ai/.well-known/ai-plugin.json](https://botcha.ai/.well-known/ai-plugin.json)
- **ai.txt**: [botcha.ai/ai.txt](https://botcha.ai/ai.txt) - Emerging standard for AI agent discovery
- **robots.txt**: Explicitly welcomes AI crawlers (GPTBot, Claude-Web, etc.)
- **Schema.org markup**: Structured data for search engines

### Response Headers

All responses include these headers for agent discovery:

```http
X-Botcha-Version: 0.12.0
X-Botcha-Enabled: true
X-Botcha-Methods: hybrid-challenge,speed-challenge,reasoning-challenge,standard-challenge
X-Botcha-Docs: https://botcha.ai/openapi.json
```

When a 403 is returned with a challenge:

```http
X-Botcha-Challenge-Id: abc123
X-Botcha-Challenge-Type: speed
X-Botcha-Time-Limit: 500
```

`X-Botcha-Challenge-Type` can be `hybrid`, `speed`, `reasoning`, or `standard` depending on the configured challenge mode.

**Example**: An agent can detect BOTCHA just by inspecting headers on ANY request:

```typescript
const response = await fetch('https://botcha.ai/agent-only');
const botchaVersion = response.headers.get('X-Botcha-Version');

if (botchaVersion) {
  console.log('BOTCHA detected! Version:', botchaVersion);
  // Handle challenge from response body
}
```

### For AI Agent Developers

If you're building an AI agent that needs to access BOTCHA-protected APIs:

```typescript
import { botcha } from '@dupecom/botcha';

// When you get a 403 with a challenge:
const challenge = response.challenge;
const answers = botcha.solve(challenge.problems);

// Retry with solution headers:
fetch('/agent-only', {
  headers: {
    'X-Botcha-Id': challenge.id,
    'X-Botcha-Answers': JSON.stringify(answers),
  }
});
```

## Options

```typescript
botcha.verify({
  // Challenge mode: 'speed' (500ms) or 'standard' (5s)
  mode: 'speed',
  
  // Allow X-Agent-Identity header for testing
  allowTestHeader: true,
  
  // Custom failure handler
  onFailure: (req, res, reason) => {
    res.status(403).json({ error: reason });
  },
});
```

## RTT-Aware Fairness ⚡

BOTCHA now automatically compensates for network latency, making speed challenges fair for agents on slow connections:

```typescript
// Include client timestamp for RTT compensation
const clientTimestamp = Date.now();
const challenge = await fetch(`https://botcha.ai/v1/challenges?type=speed&ts=${clientTimestamp}`);
```

**How it works:**
- 🕐 Client includes timestamp with challenge request
- 📡 Server measures RTT (Round-Trip Time) 
- ⚖️ Timeout = 500ms (base) + (2 × RTT) + 100ms (buffer)
- 🎯 Fair challenges for agents worldwide

**Example RTT adjustments:**
- Local: 500ms (no adjustment)
- Good network (50ms RTT): 700ms timeout
- Slow network (300ms RTT): 1200ms timeout
- Satellite (500ms RTT): 1600ms timeout

**Response includes adjustment info:**
```json
{
  "challenge": { "timeLimit": "1200ms" },
  "rtt_adjustment": {
    "measuredRtt": 300,
    "adjustedTimeout": 1200,
    "explanation": "RTT: 300ms → Timeout: 500ms + (2×300ms) + 100ms = 1200ms"
  }
}
```

Humans still can't solve it (even with extra time), but legitimate AI agents get fair treatment regardless of their network connection.

## Local Development

Run the full BOTCHA service locally with Wrangler (Cloudflare Workers runtime):

```bash
# Clone and install
git clone https://github.com/dupe-com/botcha
cd botcha
bun install

# Run local dev server (uses Cloudflare Workers)
bun run dev

# Server runs at http://localhost:3001
```

**What you get:**
- ✅ All API endpoints (`/api/*`, `/v1/*`, SSE streaming)
- ✅ Local KV storage emulation (challenges, rate limits)
- ✅ Hot reload on file changes
- ✅ Same code as production (no Express/CF Workers drift)

**Environment variables:**
- Local secrets in `packages/cloudflare-workers/.dev.vars`
- JWT_SECRET already configured for local dev

## Testing

For development, you can bypass BOTCHA with a header:

```bash
curl -H "X-Agent-Identity: MyTestAgent/1.0" http://localhost:3001/agent-only
```

Test the SSE streaming endpoint:

```bash
# Connect to SSE stream
curl -N http://localhost:3001/v1/challenge/stream

# After receiving session ID, send GO action
curl -X POST http://localhost:3001/v1/challenge/stream/sess_123 \
  -H "Content-Type: application/json" \
  -d '{"action":"go"}'
```

## API Reference

### `botcha.verify(options?)`

Express middleware that protects routes from humans.

### `botcha.solve(problems: number[])`

Helper function for AI agents to solve challenges.

```typescript
const answers = botcha.solve([645234, 891023, 334521]);
// Returns: ['a1b2c3d4', 'e5f6g7h8', 'i9j0k1l2']
```

## Challenge Flow

```
1. Agent requests protected endpoint
2. BOTCHA returns 403 + challenge (5 numbers)
3. Agent computes SHA256 of each number
4. Agent retries with X-Botcha-Id and X-Botcha-Answers headers
5. BOTCHA verifies (must complete in <500ms)
6. ✅ Access granted
```

## Philosophy

> "If a human writes a script to solve BOTCHA using an LLM... they've built an AI agent."

BOTCHA doesn't block all automation — it blocks *casual* human access while allowing *automated* AI agents. The speed challenge ensures someone had to write code, which is the point.

For cryptographic proof of agent identity, see [Web Bot Auth](https://datatracker.ietf.org/doc/html/draft-meunier-web-bot-auth-architecture).

## Contributing

**🤖 This is an AI-only open source project.** Code contributions must come from AI agents.

### For AI Agents

Fork the repo, make your changes, and open a PR. You'll receive a BOTCHA challenge (5 SHA256 hashes to solve in 5 minutes). Once verified, your PR can be reviewed and merged.

### For Humans

You can use the library freely, report issues, and discuss features. To contribute code, you'll need to work with an AI coding agent like [Cursor](https://cursor.com), [Claude Code](https://claude.ai), [Cline](https://cline.bot), [Aider](https://aider.chat), or [OpenClaw](https://openclaw.ai).

**See [CONTRIBUTING.md](./.github/CONTRIBUTING.md) for complete guidelines, solver code examples, agent setup instructions, and detailed workflows.**

## Server-Side Verification (for API Providers)

If you're building an API that accepts BOTCHA tokens from agents, use the verification SDKs:

### TypeScript (Express / Hono)

```bash
npm install @botcha/verify
```

```typescript
import { botchaVerify } from '@botcha/verify/express';

app.use('/api', botchaVerify({
  secret: process.env.BOTCHA_SECRET!,
  audience: 'https://api.example.com',
}));

app.get('/api/protected', (req, res) => {
  console.log('Solve time:', req.botcha?.solveTime);
  res.json({ message: 'Welcome, verified agent!' });
});
```

### Python (FastAPI / Django)

```bash
pip install botcha-verify
```

```python
from fastapi import FastAPI, Depends
from botcha_verify.fastapi import BotchaVerify

app = FastAPI()
botcha = BotchaVerify(secret='your-secret-key')

@app.get('/api/data')
async def get_data(token = Depends(botcha)):
    return {"solve_time": token.solve_time}
```

> **Docs:** See [`@botcha/verify` README](./packages/verify/README.md) and [`botcha-verify` README](./packages/python-verify/README.md) for full API reference, Hono middleware, Django middleware, revocation checking, and custom error handlers.

## Client SDK (for AI Agents)

If you're building an AI agent that needs to access BOTCHA-protected APIs, use the client SDK:

```typescript
import { BotchaClient } from '@dupecom/botcha/client';

const client = new BotchaClient();

// Option 1: Auto-solve - fetches URL, solves any BOTCHA challenges automatically
const response = await client.fetch('https://api.example.com/agent-only');
const data = await response.json();

// Option 2: Pre-solve - get headers with solved challenge
const headers = await client.createHeaders();
const response = await fetch('https://api.example.com/agent-only', { headers });

// Option 3: Manual solve - solve challenge problems directly
const answers = client.solve([123456, 789012]);
```

### Client Options

```typescript
const client = new BotchaClient({
  baseUrl: 'https://botcha.ai',      // BOTCHA service URL
  agentIdentity: 'MyAgent/1.0',       // User-Agent string
  maxRetries: 3,                      // Max challenge solve attempts
});
```

### Framework Integration Examples

**OpenClaw / LangChain:**
```typescript
import { BotchaClient } from '@dupecom/botcha/client';

const botcha = new BotchaClient({ agentIdentity: 'MyLangChainAgent/1.0' });

// Use in your agent's HTTP tool
const tool = {
  name: 'fetch_protected_api',
  call: async (url: string) => {
    const response = await botcha.fetch(url);
    return response.json();
  }
};
```

**Standalone Helper:**
```typescript
import { solveBotcha } from '@dupecom/botcha/client';

// Just solve the problems, handle the rest yourself
const answers = solveBotcha([123456, 789012]);
// Returns: ['a1b2c3d4', 'e5f6g7h8']
```

**Python SDK:**
```python
from botcha import BotchaClient, solve_botcha

# Option 1: Auto-solve with client
async with BotchaClient() as client:
    response = await client.fetch("https://api.example.com/agent-only")
    data = await response.json()

# Option 2: Manual solve
answers = solve_botcha([123456, 789012])
# Returns: ['a1b2c3d4', 'e5f6g7h8']
```

> **Note:** The Python SDK is available on [PyPI](https://pypi.org/project/botcha/): `pip install botcha`

## License

MIT © [Dupe](https://dupe.com)
