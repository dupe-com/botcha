# Client SDK

> SDK for AI agents to automatically solve BOTCHA challenges

**Status:** ✅ Published

| Package | Version | Description |
|---------|---------|-------------|
| [`@dupecom/botcha`](https://www.npmjs.com/package/@dupecom/botcha) | 0.19.0 | Core SDK with client (`/client` export) + middleware (`/middleware` export) |
| [`@dupecom/botcha-langchain`](https://www.npmjs.com/package/@dupecom/botcha-langchain) | 0.1.1 | LangChain Tool integration |
| [`botcha`](https://pypi.org/project/botcha/) (Python) | 0.19.0 | Python SDK on PyPI |
| [`@dupecom/botcha-verify`](../packages/verify/) | 0.2.0 | Server-side verification (Express/Hono middleware) |
| [`botcha-verify`](../packages/python-verify/) | 0.2.0 | Server-side verification (FastAPI/Django middleware) |

---

## Quick Start: Protect Your API with BOTCHA

**Want to add BOTCHA to your product?** Here's the complete flow:

### Step 1: Register your app

```bash
curl -X POST https://botcha.ai/v1/apps \
  -H "Content-Type: application/json" \
  -d '{"email": "you@yourcompany.com", "name": "My Shopping App"}'
```

Response:
```json
{
  "app_id": "app_a1b2c3d4e5f6a7b8",
  "name": "My Shopping App",
  "app_secret": "sk_...",
  "next_step": "POST /v1/apps/app_.../verify-email with {\"code\": \"123456\"}"
}
```

⚠️ **Save `app_id` and `app_secret`** — the secret is shown only once.

### Step 2: Verify your email

Check your inbox for a 6-digit code, then:

```bash
curl -X POST https://botcha.ai/v1/apps/app_a1b2c3d4e5f6a7b8/verify-email \
  -H "Content-Type: application/json" \
  -d '{"code": "123456"}'
```

### Step 3: Add verification middleware to your API

**Node.js (Express):**
```bash
npm install @dupecom/botcha-verify
```
```typescript
import express from 'express';
import { botchaVerify } from '@dupecom/botcha-verify/express';

const app = express();

// Protect routes — only verified AI agents can access
app.use('/api', botchaVerify({
  jwksUrl: 'https://botcha.ai/.well-known/jwks',  // No shared secret needed
}));

app.get('/api/products', (req, res) => {
  // req.botcha contains the verified token payload
  console.log(req.botcha.sub);  // challenge ID that was solved
  res.json({ products: [...] });
});
```

**Node.js (Hono / Cloudflare Workers):**
```typescript
import { Hono } from 'hono';
import { botchaVerify } from '@dupecom/botcha-verify/hono';

const app = new Hono();

app.use('/api/*', botchaVerify({
  jwksUrl: 'https://botcha.ai/.well-known/jwks',
}));

app.get('/api/products', (c) => {
  const botcha = c.get('botcha');
  return c.json({ products: [...] });
});
```

**Python (FastAPI):**
```bash
pip install botcha-verify
```
```python
from botcha_verify import require_botcha

@app.get("/api/products")
@require_botcha(jwks_url="https://botcha.ai/.well-known/jwks")
async def get_products(request):
    return {"products": [...]}
```

### Step 4: Agents authenticate by solving a challenge

Any AI agent can access your protected API:

```typescript
import { BotchaClient } from '@dupecom/botcha/client';

const client = new BotchaClient();
// Automatically solves BOTCHA challenge, gets JWT, includes it in request
const response = await client.fetch('https://yourapp.com/api/products');
```

Or manually:
```bash
# 1. Get challenge
curl https://botcha.ai/v1/token
# 2. Solve it (compute SHA-256 hashes)
curl -X POST https://botcha.ai/v1/token/verify \
  -d '{"id": "<challenge_id>", "answers": ["hash1", "hash2", ...]}'
# 3. Use the token
curl https://yourapp.com/api/products \
  -H "Authorization: Bearer <access_token>"
```

**That's it.** Your API is now agent-only. Humans can't solve the speed challenge. Agents get 1-hour JWT tokens.

---

## Overview

The client SDK allows AI agents to:
1. ✅ Detect BOTCHA-protected endpoints
2. ✅ Automatically acquire JWT tokens (1-hour access + 1-hour refresh)
3. ✅ Solve challenges and retry with tokens
4. ✅ Handle different challenge types (speed, standard, hybrid, reasoning)
5. ✅ Token rotation with automatic refresh on 401
6. ✅ Audience-scoped tokens for service isolation
7. ✅ Token revocation for compromised tokens
8. ✅ App creation with email verification (SDK methods)
9. ✅ Account recovery and secret rotation (SDK methods)
10. ✅ TAP (Trusted Agent Protocol) — cryptographic agent auth with public keys and capability-scoped sessions (SDK: `registerTAPAgent`, `getTAPAgent`, `listTAPAgents`, `createTAPSession`, `getTAPSession`)
11. ✅ TAP Full Spec (v0.16.0) — Ed25519, JWKS, Consumer Recognition (Layer 2), Payment Container (Layer 3), 402 micropayments, CDN edge verify, Visa key federation (SDK: `getJWKS`, `getKeyById`, `rotateAgentKey`, `createInvoice`, `getInvoice`, `verifyBrowsingIOU`)
12. ✅ Delegation Chains (v0.17.0) — signed, auditable chains of trust between TAP agents with capability subset enforcement, depth limits, cascading revocation, and cycle detection (SDK: `createDelegation`, `getDelegation`, `listDelegations`, `revokeDelegation`, `verifyDelegationChain`)
13. ✅ Capability Attestation (v0.17.0) — fine-grained `action:resource` permission tokens with explicit deny, signed JWT attestations, enforcement middleware, and online revocation (SDK: `issueAttestation`, `getAttestation`, `listAttestations`, `revokeAttestation`, `verifyAttestation`)
14. ✅ Agent Reputation Scoring (v0.18.0) — persistent trust scores for agents based on behavioral events, with tiers, decay, endorsements, and category breakdowns (SDK: `getReputation`, `recordReputationEvent`, `listReputationEvents`, `resetReputation`)

## Implemented API

### Basic Usage (Shipped)

```typescript
import { BotchaClient } from '@dupecom/botcha/client';

const client = new BotchaClient({
  baseUrl: 'https://botcha.ai',
  agentIdentity: 'MyAgent/1.0',
  autoToken: true,
});

// Automatically acquires JWT token and handles challenges
const response = await client.fetch('https://api.example.com/agent-only');
const data = await response.json();
```

### Manual Challenge Solving (Shipped)

```typescript
import { BotchaClient } from '@dupecom/botcha/client';

const client = new BotchaClient();

// Get JWT token manually
const token = await client.getToken();

// Or solve challenge problems directly
const answers = client.solve([123456, 789012, 334521]);
// Returns: ['a1b2c3d4', 'e5f6g7h8', 'i9j0k1l2']

// Create headers with solved challenge
const headers = await client.createHeaders();
```

### With Axios/Fetch Interceptor (Future)

```typescript
// Planned for future release
import axios from 'axios';
import { createBotchaInterceptor } from '@dupecom/botcha/client';

const api = axios.create({ baseURL: 'https://api.example.com' });
api.interceptors.response.use(...createBotchaInterceptor());

// Now all 403 BOTCHA responses are auto-retried
const data = await api.get('/protected');
```

### LangChain Integration (Shipped)

```typescript
import { BotchaTool } from '@dupecom/botcha-langchain';
import { createReactAgent } from '@langchain/langgraph/prebuilt';

const agent = createReactAgent({
  llm: new ChatOpenAI({ model: 'gpt-4' }),
  tools: [
    new BotchaTool({ baseUrl: 'https://botcha.ai' }),
  ],
});

// Agent can now solve BOTCHA challenges automatically
await agent.invoke({
  messages: [{ role: 'user', content: 'Access bot-only API' }]
});
```

See [`@dupecom/botcha-langchain`](https://www.npmjs.com/package/@dupecom/botcha-langchain) for full documentation.

## Challenge Solvers (Shipped)

```typescript
import { BotchaClient } from '@dupecom/botcha/client';

const client = new BotchaClient();

// Built-in solver for SHA256 speed challenges
const answers = client.solve([123456, 789012, 334521, 456789, 901234]);
// Automatically computes SHA256 hashes

// The client automatically uses the correct solver based on challenge type
const response = await client.fetch('https://protected-api.com/endpoint');
```

## Configuration (Shipped)

```typescript
const client = new BotchaClient({
  // BOTCHA service URL
  baseUrl: 'https://botcha.ai',
  
  // Agent identification
  agentIdentity: 'MyAgent/1.0',
  
  // Behavior
  autoToken: true,    // Automatically acquire JWT tokens (default: true)
  maxRetries: 3,      // Max retry attempts (default: 3)
  
  // Security
  audience: 'https://api.example.com', // Scope token to this service (optional)
  
  // Multi-tenant
  appId: 'app_abc123', // Your app ID for isolation and tracking (optional)
});
```

**Supported options:**
- ✅ `baseUrl` - BOTCHA service URL
- ✅ `agentIdentity` - Custom User-Agent string
- ✅ `maxRetries` - Maximum challenge solve attempts
- ✅ `autoToken` - Enable automatic token acquisition
- ✅ `audience` - Scope tokens to a specific service (prevents cross-service replay)
- ✅ `appId` - Multi-tenant app ID for per-app isolation and rate limiting

## Multi-Tenant API Keys (Shipped)

BOTCHA supports **multi-tenant isolation** — create separate apps with unique API keys.

### Creating an App

```bash
curl -X POST https://botcha.ai/v1/apps \
  -H "Content-Type: application/json" \
  -d '{"email": "agent@example.com", "name": "My Shopping App"}'
# Returns: {app_id, name, app_secret, email, email_verified: false, ...}
```

**⚠️ Important:** The `app_secret` is only shown once. Save it securely.

**Email is required.** A 6-digit verification code will be sent to the provided email.

**Name is optional** but recommended — gives your app a memorable label (e.g., "Production API", "Staging", "My E-commerce Site").

### Verifying Email

```bash
curl -X POST https://botcha.ai/v1/apps/app_abc123/verify-email \
  -H "Content-Type: application/json" \
  -d '{"code": "123456"}'
# Returns: {success: true, email_verified: true}
```

### Account Recovery

If you lose your `app_secret`, you can recover access via your verified email:

```bash
curl -X POST https://botcha.ai/v1/auth/recover \
  -H "Content-Type: application/json" \
  -d '{"email": "agent@example.com"}'
# A device code is emailed — enter it at /dashboard/code
```

### Secret Rotation

Rotate your `app_secret` (requires active dashboard session):

```bash
curl -X POST https://botcha.ai/v1/apps/app_abc123/rotate-secret \
  -H "Authorization: Bearer <session_token>"
# Returns: {app_secret: "sk_new_...", warning: "Save your new secret..."}
```

A notification email is sent when the secret is rotated (if email is verified).

### Using App ID in SDK

**TypeScript:**

```typescript
import { BotchaClient } from '@dupecom/botcha/client';

const client = new BotchaClient({
  appId: 'app_abc123',  // All requests include this app_id
  audience: 'https://api.example.com',
});

// All challenges and tokens will be scoped to your app
const response = await client.fetch('/protected');
```

**Python:**

```python
from botcha import BotchaClient

async with BotchaClient(app_id="app_abc123") as client:
    response = await client.fetch("https://api.example.com/protected")
```

### App Lifecycle Methods (v0.10.0+)

Both SDKs now include methods for the full app lifecycle — creation, email verification, recovery, and secret rotation.

**TypeScript:**

```typescript
import { BotchaClient } from '@dupecom/botcha/client';

const client = new BotchaClient();

// 1. Create app (auto-sets client.appId)
const app = await client.createApp('agent@example.com', 'My Shopping App');
console.log(app.app_id);     // 'app_abc123'
console.log(app.name);       // 'My Shopping App'
console.log(app.app_secret); // 'sk_...' (save this!)

// 2. Verify email with 6-digit code from inbox
await client.verifyEmail('123456');

// 3. Resend verification if needed
await client.resendVerification();

// 4. Recover account (sends device code to email)
await client.recoverAccount('agent@example.com');

// 5. Rotate secret (requires active session)
const rotated = await client.rotateSecret();
console.log(rotated.app_secret); // new secret
```

**Python:**

```python
from botcha import BotchaClient

async with BotchaClient() as client:
    # 1. Create app (auto-sets client.app_id)
    app = await client.create_app("agent@example.com", name="My Shopping App")
    print(app.app_id)      # 'app_abc123'
    print(app.name)        # 'My Shopping App'
    print(app.app_secret)  # 'sk_...' (save this!)

    # 2. Verify email with 6-digit code
    await client.verify_email("123456")

    # 3. Resend verification if needed
    await client.resend_verification()

    # 4. Recover account (sends device code to email)
    await client.recover_account("agent@example.com")

    # 5. Rotate secret (requires active session)
    rotated = await client.rotate_secret()
    print(rotated.app_secret)  # new secret
```

### How It Works

1. **Create app:** `POST /v1/apps` → receive `app_id` + `app_secret`
2. **SDK sends app_id:** All challenge/token requests include `?app_id=your_id`
3. **Token includes app_id:** JWT tokens have `app_id` claim for verification
4. **Per-app rate limits:** Each app gets isolated rate limit bucket (`rate:app:{app_id}`)

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/apps` | POST | Create new app (email required, returns app_id + app_secret) |
| `/v1/apps/:id` | GET | Get app info (includes email + verification status) |
| `/v1/apps/:id/verify-email` | POST | Verify email with 6-digit code |
| `/v1/apps/:id/resend-verification` | POST | Resend verification email |
| `/v1/apps/:id/rotate-secret` | POST | Rotate app secret (auth required) |
| `/v1/auth/recover` | POST | Request account recovery via email |

All existing endpoints (`/v1/challenges`, `/v1/token`, etc.) accept `?app_id=` query param.

## Per-App Metrics Dashboard (Shipped)

A server-rendered dashboard at `/dashboard` shows per-app analytics.

### Dashboard Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/dashboard` | GET | Main dashboard (auth required) |
| `/dashboard/login` | GET | Login page |
| `/dashboard/login` | POST | Login with app_id + app_secret |
| `/dashboard/logout` | GET | Logout (clears session cookie) |
| `/dashboard/api/overview` | GET | Overview stats (htmx fragment) |
| `/dashboard/api/volume` | GET | Request volume chart (htmx fragment) |
| `/dashboard/api/types` | GET | Challenge type breakdown (htmx fragment) |
| `/dashboard/api/performance` | GET | Performance metrics table (htmx fragment) |
| `/dashboard/api/errors` | GET | Error & rate limit breakdown (htmx fragment) |
| `/dashboard/api/geo` | GET | Geographic distribution (htmx fragment) |

All `/dashboard/api/*` endpoints accept `?period=1h|24h|7d|30d` query parameter.

### Authentication

Three ways to access the dashboard — all require an AI agent:

**Flow 1: Agent Direct (challenge-based)**
```bash
# 1. Agent requests challenge
curl -X POST https://botcha.ai/v1/auth/dashboard \
  -d '{"app_id": "app_abc123"}'
# Returns: {challenge_id, problems, ...}

# 2. Agent solves and verifies
curl -X POST https://botcha.ai/v1/auth/dashboard/verify \
  -d '{"challenge_id": "...", "answers": [...], "app_id": "app_abc123"}'
# Returns: {session_token: "..."}
```

**Flow 2: Device Code (agent → human handoff)**
```bash
# 1. Agent requests challenge
curl -X POST https://botcha.ai/v1/auth/device-code \
  -d '{"app_id": "app_abc123"}'

# 2. Agent solves to get device code
curl -X POST https://botcha.ai/v1/auth/device-code/verify \
  -d '{"challenge_id": "...", "answers": [...], "app_id": "app_abc123"}'
# Returns: {device_code: "BOTCHA-XXXX"} (10 min TTL)

# 3. Human enters code at /dashboard/code
```

**Flow 3: Legacy (credentials)**
Login with `app_id` + `app_secret` at `/dashboard/login`.

Session uses cookie-based auth:
- Cookie name: `botcha_session`
- HttpOnly, Secure, SameSite=Lax
- Max age: 1 hour
- JWT verified using existing auth infrastructure

### Constructor Parameters

**TypeScript:**

```typescript
interface BotchaClientOptions {
  appId?: string;  // Your multi-tenant app ID
  // ... other options
}
```

**Python:**

```python
def __init__(
    self,
    app_id: Optional[str] = None,  # Your multi-tenant app ID
    # ... other params
)
```

## Token Rotation & Caching (Shipped)

> **📖 Full JWT guide:** [JWT-SECURITY.md](./JWT-SECURITY.md) — audience scoping, IP binding, revocation, request/response examples, design decisions.

BOTCHA uses **OAuth2-style token rotation** with short-lived access tokens:

| Token Type | Expiry | Purpose |
|------------|--------|---------|
| Access Token | 1 hour | Used for API requests |
| Refresh Token | 1 hour | Used to get new access tokens without re-solving challenges |

```typescript
const client = new BotchaClient({ autoToken: true });

// Tokens are automatically cached in-memory
await client.fetch('/protected'); // Acquires access_token (1hr) + refresh_token (1hr)
await client.fetch('/protected'); // Reuses cached access_token

// Auto-refreshes: when access_token expires, SDK uses refresh_token automatically
// When 401 received: tries refresh first, then full re-verify as fallback

// Manual refresh
const newToken = await client.refreshToken();

// Clear all tokens (access + refresh)
client.clearToken();
```

### Token Refresh Flow

```
1. client.fetch() → 401 Unauthorized
2. SDK tries: POST /v1/token/refresh with refresh_token
3. If refresh succeeds → retry with new access_token
4. If refresh fails → clear tokens, solve new challenge, get fresh tokens
```

### New API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/token/refresh` | POST | Exchange refresh_token for new access_token |
| `/v1/token/revoke` | POST | Revoke a token (access or refresh) |

### Human Handoff (from Token Verify Response)

`POST /v1/token/verify` returns human handoff fields alongside the tokens:

| Field | Description |
|-------|-------------|
| `human_link` | **Primary.** URL for human to click for browser access (e.g., `https://botcha.ai/go/BOTCHA-XXXXXX`) |
| `human_code` | The gate code (e.g., `BOTCHA-XXXXXX`) |
| `human_instruction` | Human-readable instruction string |
| `human_magic_link` | Backward compat alias for `human_link` |

The `/go/:code` endpoint handles both gate codes (from `/v1/token/verify`) and device codes (from `/v1/auth/device-code/verify`).

```typescript
// Manual token refresh
const newToken = await client.refreshToken();

// Token revocation (clear local state — server-side via API)
client.clearToken();
```

## Error Handling (Shipped)

```typescript
import { BotchaClient } from '@dupecom/botcha/client';

const client = new BotchaClient({ maxRetries: 3 });

try {
  const response = await client.fetch('/protected');
  const data = await response.json();
} catch (error) {
  // Client automatically retries on failure (up to maxRetries)
  // If all retries fail, throws standard Error
  console.error('Failed to solve BOTCHA:', error.message);
}
```

## Package Structure (Shipped)

```
@dupecom/botcha/
├── lib/client/
│   ├── index.ts        # BotchaClient (exported as /client)
│   ├── types.ts        # Type definitions
│   └── solver.ts       # Challenge solving logic
└── lib/index.ts        # Express middleware (main export)

@dupecom/botcha-langchain/
├── index.ts            # Exports: BotchaTool, BotchaRequestWrapper
├── tool.ts             # LangChain Tool implementation
├── wrapper.ts          # Request wrapper
└── types.ts            # Type definitions
```

## Python SDK

**Status:** ✅ Published on [PyPI](https://pypi.org/project/botcha/) (v0.5.0)

The Python SDK provides the same capabilities as the TypeScript client, including token rotation, audience claims, and automatic refresh.

### Installation

```bash
pip install botcha
```

### Basic Usage

```python
from botcha import BotchaClient

async with BotchaClient(agent_identity="MyPythonAgent/1.0") as client:
    # Automatically acquires JWT token and handles challenges
    response = await client.fetch("https://api.example.com/agent-only")
    data = await response.json()
    print(data)
```

### Manual Challenge Solving

```python
from botcha import BotchaClient, solve_botcha

# Get JWT token manually
async with BotchaClient() as client:
    token = await client.get_token()
    print(f"Token: {token}")

# Or solve challenge problems directly
answers = solve_botcha([123456, 789012, 334521])
# Returns: ['a1b2c3d4', 'e5f6g7h8', 'i9j0k1l2']
```

### Configuration

```python
from botcha import BotchaClient

async with BotchaClient(
    base_url="https://botcha.ai",
    agent_identity="MyAgent/1.0",
    max_retries=3,
    auto_token=True,
    audience="https://api.example.com",  # Scope token to this service
) as client:
    response = await client.fetch("https://protected-api.com/endpoint")
```

### Token Rotation (Python)

```python
from botcha import BotchaClient

async with BotchaClient(audience="https://api.example.com") as client:
    # Auto-handles token lifecycle (1hr access + 1hr refresh)
    response = await client.fetch("https://api.example.com/data")
    
    # Manual refresh
    new_token = await client.refresh_token()
    
    # On 401: tries refresh_token first, then full re-verify
```

### API Reference

The Python SDK mirrors the TypeScript API:

- `BotchaClient` - Main client class with async context manager
- `solve_botcha(problems: list[int]) -> list[str]` - Standalone solver function
- `get_token()` - Acquire JWT access token (with caching)
- `refresh_token()` - Refresh access token using refresh token
- `fetch(url)` - Auto-solve and fetch URL with challenge handling
- `create_app(email)` - Create a new app (email required, auto-sets app_id)
- `verify_email(code, app_id?)` - Verify email with 6-digit code
- `resend_verification(app_id?)` - Resend verification email
- `recover_account(email)` - Request account recovery via email
- `rotate_secret(app_id?)` - Rotate app secret (requires session token)
- `register_tap_agent(name, operator?, ...)` → Register TAP agent
- `get_tap_agent(agent_id)` → Get TAP agent details
- `list_tap_agents(tap_only?)` → List TAP agents for app
- `create_tap_session(agent_id, user_context, intent)` → Create TAP session
- `get_tap_session(session_id)` → Get TAP session details
- `get_jwks()` → Get JWK Set for app's TAP agents
- `get_key_by_id(key_id)` → Get specific public key by ID
- `rotate_agent_key(agent_id, algorithm?)` → Rotate agent's key pair
- `create_invoice(invoice_data)` → Create 402 micropayment invoice
- `get_invoice(invoice_id)` → Get invoice details
- `verify_browsing_iou(invoice_id, iou_token)` → Verify Browsing IOU
- `close()` - Close client and clear cached tokens

**Constructor parameters:**
- `base_url` - BOTCHA service URL (default: `https://botcha.ai`)
- `agent_identity` - Custom User-Agent string
- `max_retries` - Maximum retry attempts (default: 3)
- `auto_token` - Enable automatic token acquisition (default: True)
- `audience` - Scope tokens to a specific service (optional)
- `app_id` - Multi-tenant app ID for per-app isolation (optional)

**Implementation:** See `packages/python/` for full source code including SHA256 solver, async HTTP client (httpx), and type annotations.

## Server-Side Verification SDKs

For API providers who need to verify incoming BOTCHA tokens from agents.

### TypeScript (@dupecom/botcha-verify)

**Status:** ✅ Built (v0.1.0) — [README](../packages/verify/README.md)

```typescript
import { botchaVerify } from '@dupecom/botcha-verify/express';

// Express middleware
app.use('/api', botchaVerify({
  secret: process.env.BOTCHA_SECRET!,
  audience: 'https://api.example.com',
  requireIp: true,
  checkRevocation: async (jti) => db.revokedTokens.exists(jti),
}));

app.get('/api/data', (req, res) => {
  console.log('Challenge ID:', req.botcha?.sub);
  console.log('Solve time:', req.botcha?.solveTime);
  res.json({ data: 'protected' });
});
```

```typescript
// Hono middleware
import { botchaVerify } from '@dupecom/botcha-verify/hono';

app.use('/api/*', botchaVerify({ secret: env.BOTCHA_SECRET }));
```

```typescript
// Standalone verification (any framework)
import { verifyBotchaToken } from '@dupecom/botcha-verify';

const result = await verifyBotchaToken(token, {
  secret: process.env.BOTCHA_SECRET!,
  audience: 'https://api.example.com',
});
```

**Features:** JWT signature (HS256), expiry, token type, audience claim, client IP binding, revocation checking, custom error handlers.

### Python (botcha-verify)

**Status:** ✅ Built (v0.1.0) — [README](../packages/python-verify/README.md)

```python
# FastAPI
from fastapi import FastAPI, Depends
from botcha_verify.fastapi import BotchaVerify

app = FastAPI()
botcha = BotchaVerify(secret='your-secret-key', audience='https://api.example.com')

@app.get('/api/data')
async def get_data(token = Depends(botcha)):
    return {"solve_time": token.solve_time}
```

```python
# Django (settings.py)
MIDDLEWARE = ['botcha_verify.django.BotchaVerifyMiddleware']
BOTCHA_SECRET = 'your-secret-key'
BOTCHA_PROTECTED_PATHS = ['/api/']
```

```python
# Standalone verification
from botcha_verify import verify_botcha_token, VerifyOptions

result = verify_botcha_token(token, secret='your-key', options=VerifyOptions(audience='https://api.example.com'))
```

**Features:** JWT signature (HS256), expiry, token type, audience claim, client IP binding, auto_error toggle (FastAPI), path-based protection (Django).

## Token Verification (v0.19.0+)

BOTCHA v0.19.0 introduces **ES256 asymmetric signing** for JWT tokens. This means third-party consumers can verify tokens without knowing the signing secret. Three verification modes are available:

### 1. JWKS Verification (Recommended)

Fetch public keys from `/.well-known/jwks` and verify ES256 signatures locally. No shared secret needed. Best for high-throughput services.

**TypeScript:**

```typescript
import { botchaVerify } from '@dupecom/botcha-verify/express';

// JWKS-based verification — no secret needed!
app.use('/api', botchaVerify({
  jwksUrl: 'https://botcha.ai/.well-known/jwks',
  audience: 'https://api.example.com',
}));

app.get('/api/data', (req, res) => {
  console.log('Verified agent:', req.botcha?.sub);
  res.json({ data: 'protected' });
});
```

```typescript
// Hono middleware
import { botchaVerify } from '@dupecom/botcha-verify/hono';

app.use('/api/*', botchaVerify({
  jwksUrl: 'https://botcha.ai/.well-known/jwks',
}));
```

**Python:**

```python
# FastAPI
from fastapi import FastAPI, Depends
from botcha_verify.fastapi import BotchaVerify

app = FastAPI()
botcha = BotchaVerify(
    jwks_url='https://botcha.ai/.well-known/jwks',
    audience='https://api.example.com',
)

@app.get('/api/data')
async def get_data(token = Depends(botcha)):
    return {"solve_time": token.solve_time}
```

```python
# Django (settings.py)
MIDDLEWARE = ['botcha_verify.django.BotchaVerifyMiddleware']
BOTCHA_JWKS_URL = 'https://botcha.ai/.well-known/jwks'
BOTCHA_PROTECTED_PATHS = ['/api/']
```

### 2. Remote Validation (Simplest)

`POST /v1/token/validate` — no SDK needed, just a single HTTP call. Best for simple integrations or languages without an SDK.

**curl:**

```bash
curl -X POST https://botcha.ai/v1/token/validate \
  -H "Content-Type: application/json" \
  -d '{"token": "eyJ..."}'

# Response:
# {"valid": true, "payload": {"sub": "challenge_abc123", "type": "botcha-verified", ...}}
# or
# {"valid": false, "error": "Token expired"}
```

**TypeScript:**

```typescript
// No SDK needed — just fetch
const res = await fetch('https://botcha.ai/v1/token/validate', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ token: incomingToken }),
});
const { valid, payload, error } = await res.json();

if (valid) {
  console.log('Token verified, agent:', payload.sub);
} else {
  console.log('Invalid token:', error);
}
```

**Python:**

```python
import httpx

async def validate_token(token: str) -> dict:
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            'https://botcha.ai/v1/token/validate',
            json={'token': token},
        )
        result = resp.json()
        if result['valid']:
            return result['payload']
        raise ValueError(result['error'])
```

### 3. Shared Secret (Legacy — HS256)

Verify HS256-signed tokens locally with the shared secret. Requires distributing `BOTCHA_SECRET` to every verifying service.

**TypeScript:**

```typescript
import { botchaVerify } from '@dupecom/botcha-verify/express';

// Legacy HS256 verification — requires shared secret
app.use('/api', botchaVerify({
  secret: process.env.BOTCHA_SECRET!,
  audience: 'https://api.example.com',
}));
```

**Python:**

```python
from botcha_verify.fastapi import BotchaVerify

botcha = BotchaVerify(
    secret='your-botcha-secret',
    audience='https://api.example.com',
)
```

### Verification Mode Comparison

| Mode | Requires Secret? | Offline? | Best For |
|------|-----------------|----------|----------|
| JWKS (ES256) | No | Yes | Production — high-throughput, no secret distribution |
| Remote Validation | No | No | Simple integrations — one HTTP call |
| Shared Secret (HS256) | Yes | Yes | Legacy — backward compatibility |

---

## Trusted Agent Protocol (TAP) Endpoints (v0.12.0+)

TAP adds cryptographic agent authentication using HTTP Message Signatures (RFC 9421). TAP-enabled agents register public keys, declare capabilities, and create intent-scoped sessions.

### TAP Agent Registration

```bash
# Register a TAP agent with public key and capabilities
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
      {"action": "write", "resource": "/api/orders"}
    ]
  }'

# Returns:
{
  "success": true,
  "agent_id": "agent_xyz789",
  "tap_enabled": true,
  "trust_level": "enterprise",
  "capabilities": [...],
  "has_public_key": true,
  "key_fingerprint": "a1b2c3d4e5f6g7h8"
}
```

### TAP Agent Retrieval

```bash
# Get TAP agent details (includes public key for verification)
curl https://botcha.ai/v1/agents/agent_xyz789/tap

# List TAP-enabled agents for an app
curl "https://botcha.ai/v1/agents/tap?app_id=app_abc123&tap_only=true"
```

### TAP Session Creation

```bash
# Create a TAP session with intent declaration
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

# Returns:
{
  "success": true,
  "session_id": "sess_abc123",
  "capabilities": [...],
  "intent": { "action": "read", "resource": "/api/invoices" },
  "expires_at": "2026-02-14T17:00:00.000Z"
}
```

### TAP Session Retrieval

```bash
curl https://botcha.ai/v1/sessions/sess_abc123/tap
```

### TAP API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/agents/register/tap` | POST | Register TAP agent with public key + capabilities |
| `/v1/agents/:id/tap` | GET | Get TAP agent details (includes public key) |
| `/v1/agents/tap` | GET | List TAP-enabled agents for app (`?tap_only=true` to filter) |
| `/v1/sessions/tap` | POST | Create TAP session with intent validation |
| `/v1/sessions/:id/tap` | GET | Get TAP session info (includes time remaining) |

### TAP SDK Methods

**TypeScript:**

```typescript
import { BotchaClient } from '@dupecom/botcha/client';

const client = new BotchaClient({ appId: 'app_abc123' });

// Register a TAP agent
const agent = await client.registerTAPAgent({
  name: 'my-agent',
  operator: 'Acme Corp',
  capabilities: [{ action: 'browse', scope: ['products'] }],
  trust_level: 'verified',
});

// Create a TAP session
const session = await client.createTAPSession({
  agent_id: agent.agent_id,
  user_context: 'user-hash',
  intent: { action: 'browse', resource: 'products', duration: 3600 },
});
```

**Python:**

```python
from botcha import BotchaClient

async with BotchaClient(app_id="app_abc123") as client:
    agent = await client.register_tap_agent(
        name="my-agent",
        operator="Acme Corp",
        capabilities=[{"action": "browse", "scope": ["products"]}],
        trust_level="verified",
    )

    session = await client.create_tap_session(
        agent_id=agent.agent_id,
        user_context="user-hash",
        intent={"action": "browse", "resource": "products", "duration": 3600},
    )
```

### TAP Verification Middleware (Express)

The TAP-enhanced verification middleware supports multiple modes:

```typescript
import { createTAPVerifyMiddleware } from '@dupecom/botcha/middleware';

// TAP-only: require HTTP Message Signature
app.use('/api', createTAPVerifyMiddleware({
  mode: 'tap',
  secret: process.env.BOTCHA_SECRET!,
}));

// Flexible: accept TAP signature OR traditional BOTCHA challenge token
app.use('/api', createTAPVerifyMiddleware({
  mode: 'flexible',
  secret: process.env.BOTCHA_SECRET!,
}));

// Signature-only: verify signature without full TAP session
app.use('/api', createTAPVerifyMiddleware({
  mode: 'signature-only',
  secret: process.env.BOTCHA_SECRET!,
}));

// Challenge-only: backward compatible (traditional BOTCHA)
app.use('/api', createTAPVerifyMiddleware({
  mode: 'challenge-only',
  secret: process.env.BOTCHA_SECRET!,
}));
```

### Supported Algorithms

| Algorithm | Key Type | Usage |
|-----------|----------|-------|
| `ed25519` | Ed25519 | **Visa recommended** — fastest, smallest keys, highest security |
| `ecdsa-p256-sha256` | ECDSA P-256 | Recommended — compact keys, fast verification |
| `rsa-pss-sha256` | RSA-PSS | Legacy compatibility — larger keys |

### Trust Levels

| Level | Description |
|-------|-------------|
| `basic` | Default. Agent registered without public key. |
| `verified` | Agent registered with public key. |
| `enterprise` | Agent with verified organizational identity. |

## TAP Full Spec — JWKS & Key Management (v0.16.0+)

BOTCHA v0.16.0 adds full Visa TAP specification support including JWKS endpoints, key rotation, and federated key trust.

### Get JWKS (JWK Set)

Retrieve the JWK Set for all TAP agents registered in your app. This endpoint follows the Visa TAP spec standard at `/.well-known/jwks`.

```bash
curl https://botcha.ai/.well-known/jwks
```

**TypeScript:**
```typescript
const client = new BotchaClient({ appId: 'app_abc123' });
const jwks = await client.getJWKS();
console.log(jwks.keys); // Array of JWK objects
```

**Python:**
```python
async with BotchaClient(app_id="app_abc123") as client:
    jwks = await client.get_jwks()
    print(jwks.keys)
```

### Get Key by ID

Retrieve a specific public key by key ID. Supports `?keyID=` query parameter for Visa compatibility.

```bash
# Standard path parameter
curl https://botcha.ai/v1/keys/key_abc123

# Visa-compatible query parameter
curl "https://botcha.ai/v1/keys?keyID=key_abc123"
```

**TypeScript:**
```typescript
const key = await client.getKeyById('key_abc123');
console.log(key.public_key); // PEM-encoded public key
```

**Python:**
```python
key = await client.get_key_by_id("key_abc123")
print(key.public_key)
```

### Rotate Agent Key

Rotate an agent's public/private key pair. Generates a new Ed25519 or ECDSA key, updates the agent record, and invalidates the old key.

```bash
curl -X POST "https://botcha.ai/v1/agents/agent_abc123/tap/rotate-key?app_id=app_abc123" \
  -H "Content-Type: application/json" \
  -d '{"algorithm": "ed25519"}'
```

**TypeScript:**
```typescript
const rotated = await client.rotateAgentKey('agent_abc123', { algorithm: 'ed25519' });
console.log(rotated.new_key_id);
console.log(rotated.public_key); // Save this!
```

**Python:**
```python
rotated = await client.rotate_agent_key("agent_abc123", algorithm="ed25519")
print(rotated.new_key_id)
print(rotated.public_key)
```

## TAP Full Spec — 402 Micropayments (v0.16.0+)

BOTCHA v0.16.0 implements the Browsing IOU flow for 402 Payment Required micropayment challenges.

### Create Invoice

Create an invoice for gated content. The invoice can be used with a Browsing IOU to verify payment intent.

```bash
curl -X POST "https://botcha.ai/v1/invoices?app_id=app_abc123" \
  -H "Content-Type: application/json" \
  -d '{
    "amount": 100,
    "currency": "USD",
    "description": "Premium API access",
    "metadata": {"resource": "/api/premium"}
  }'
```

**Response:**
```json
{
  "invoice_id": "inv_abc123",
  "amount": 100,
  "currency": "USD",
  "status": "pending",
  "created_at": "2026-02-14T12:00:00Z"
}
```

**TypeScript:**
```typescript
const invoice = await client.createInvoice({
  amount: 100,
  currency: 'USD',
  description: 'Premium API access',
  metadata: { resource: '/api/premium' }
});
console.log(invoice.invoice_id);
```

**Python:**
```python
invoice = await client.create_invoice({
    "amount": 100,
    "currency": "USD",
    "description": "Premium API access",
    "metadata": {"resource": "/api/premium"}
})
print(invoice.invoice_id)
```

### Get Invoice

Retrieve invoice details by ID.

```bash
curl https://botcha.ai/v1/invoices/inv_abc123
```

**TypeScript:**
```typescript
const invoice = await client.getInvoice('inv_abc123');
console.log(invoice.status); // pending, paid, expired
```

**Python:**
```python
invoice = await client.get_invoice("inv_abc123")
print(invoice.status)
```

### Verify Browsing IOU

Verify a Browsing IOU (payment intent token) against an invoice. Used in 402 Payment Required flows where the agent promises to pay.

```bash
curl -X POST https://botcha.ai/v1/invoices/inv_abc123/verify-iou \
  -H "Content-Type: application/json" \
  -d '{"iou_token": "eyJ..."}'
```

**Response:**
```json
{
  "verified": true,
  "invoice_id": "inv_abc123",
  "amount": 100,
  "agent_id": "agent_xyz789",
  "expires_at": "2026-02-14T13:00:00Z"
}
```

**TypeScript:**
```typescript
const verified = await client.verifyBrowsingIOU('inv_abc123', iouToken);
if (verified.verified) {
  console.log('Payment intent verified, grant access');
}
```

**Python:**
```python
verified = await client.verify_browsing_iou("inv_abc123", iou_token)
if verified.verified:
    print("Payment intent verified, grant access")
```

## TAP Full Spec — Consumer & Payment Verification (v0.16.0+)

BOTCHA v0.16.0 adds Layer 2 (Agentic Consumer Recognition) and Layer 3 (Agentic Payment Container) verification utilities.

### Verify Agentic Consumer (Layer 2)

Verify an `agenticConsumer` object including ID token, contextual data, and signature chain.

```bash
curl -X POST https://botcha.ai/v1/verify/consumer \
  -H "Content-Type: application/json" \
  -d '{
    "agenticConsumer": {
      "idToken": "eyJ...",
      "country": "US",
      "postalCode": "12345",
      "ipAddress": "203.0.113.42",
      "nonce": "abc123"
    },
    "signature": "..."
  }'
```

**Response:**
```json
{
  "verified": true,
  "consumer_id": "consumer_obfuscated_hash",
  "country": "US",
  "trust_score": 0.95
}
```

### Verify Agentic Payment Container (Layer 3)

Verify an `agenticPaymentContainer` object including card metadata, credential hash, and encrypted payload.

```bash
curl -X POST https://botcha.ai/v1/verify/payment \
  -H "Content-Type: application/json" \
  -d '{
    "agenticPaymentContainer": {
      "lastFour": "1234",
      "par": "Q1J4AwSWD4Dx6q1DTo0MB21XDAV76",
      "credentialHash": "abc...",
      "encryptedPayload": "...",
      "nonce": "xyz789"
    },
    "signature": "..."
  }'
```

**Response:**
```json
{
  "verified": true,
  "card_type": "visa",
  "credential_valid": true,
  "par": "Q1J4AwSWD4Dx6q1DTo0MB21XDAV76"
}
```

## Delegation Chains (v0.17.0+)

Signed, auditable chains of trust between TAP agents. "User X authorized Agent Y to do Z until time T."

### Create Delegation

```typescript
const delegation = await client.createDelegation({
  grantor_id: 'agent_abc123',
  grantee_id: 'agent_def456',
  capabilities: [{ action: 'browse', scope: ['products'] }],
  duration_seconds: 3600,      // optional, default 1 hour
  max_depth: 3,                // optional, max sub-delegation depth
  metadata: { purpose: 'search-comparison' },  // optional context
});
```

**Python:**
```python
delegation = await client.create_delegation(
    grantor_id="agent_abc123",
    grantee_id="agent_def456",
    capabilities=[{"action": "browse", "scope": ["products"]}],
    duration_seconds=3600,
)
```

### Sub-Delegation (Chaining)

```typescript
// B sub-delegates to C (capabilities can only narrow, never expand)
const subDelegation = await client.createDelegation({
  grantor_id: agentB,
  grantee_id: agentC,
  capabilities: [{ action: 'browse', scope: ['products'] }],
  parent_delegation_id: delegation.delegation_id,
});
// subDelegation.chain = [agentA, agentB, agentC]
// subDelegation.depth = 1
```

### Get / List Delegations

```typescript
const del = await client.getDelegation('del_abc123');

// List outbound delegations
const outbound = await client.listDelegations('agent_abc123', {
  direction: 'out',
  include_revoked: false,
});

// List inbound delegations
const inbound = await client.listDelegations('agent_def456', {
  direction: 'in',
});
```

### Revoke Delegation (Cascading)

```typescript
// Revoking cascades to all sub-delegations
await client.revokeDelegation('del_abc123', 'Access no longer needed');
```

### Verify Delegation Chain

```typescript
const result = await client.verifyDelegationChain('del_abc123');
if (result.valid) {
  console.log('Chain length:', result.chain_length);
  console.log('Effective capabilities:', result.effective_capabilities);
}
```

### Key Rules

- Capabilities can only be **narrowed** (subset enforcement)
- Chain depth is capped (default: 3, absolute max: 10)
- Revoking a delegation **cascades** to all sub-delegations
- Sub-delegations cannot outlive their parent
- Cycle detection prevents circular chains
- Both grantor and grantee must belong to the same app

### API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/v1/delegations` | Create delegation |
| `GET` | `/v1/delegations/:id` | Get delegation details |
| `GET` | `/v1/delegations?agent_id=...&direction=in\|out\|both` | List delegations |
| `POST` | `/v1/delegations/:id/revoke` | Revoke (cascades) |
| `POST` | `/v1/verify/delegation` | Verify chain |

### SDK Methods

**TypeScript:** `createDelegation(options)`, `getDelegation(id)`, `listDelegations(agentId, options?)`, `revokeDelegation(id, reason?)`, `verifyDelegationChain(id)`

**Python:** `create_delegation(grantor_id, grantee_id, capabilities, ...)`, `get_delegation(id)`, `list_delegations(agent_id, ...)`, `revoke_delegation(id, reason?)`, `verify_delegation_chain(id)`

---

## Capability Attestation (v0.17.0+)

Fine-grained `action:resource` permission tokens with explicit deny rules. Attestations are signed JWTs that can be verified offline (signature) or online (revocation check via KV).

### Permission Model

```
"action:resource" patterns with wildcards:
  "read:invoices"    — specific action on specific resource
  "browse:*"         — browse any resource
  "*:invoices"       — any action on invoices
  "*:*"              — unrestricted
  "browse"           — bare action, expands to "browse:*"

Deny rules override allow:
  can: ["*:*"], cannot: ["write:transfers"]
  → allowed to do everything EXCEPT write:transfers
```

### Issue Attestation

```typescript
const att = await client.issueAttestation({
  agent_id: 'agent_abc123',
  can: ['read:invoices', 'browse:*'],
  cannot: ['write:transfers'],        // optional deny rules
  restrictions: { max_amount: 1000 }, // optional restrictions
  duration_seconds: 3600,             // optional, default 1 hour
  delegation_id: 'del_xyz',           // optional link to delegation
  metadata: { purpose: 'invoice-reader' },
});
// att.token — signed JWT to use in requests
// att.attestation_id — for revocation/lookup
```

```python
att = await client.issue_attestation(
    agent_id="agent_abc123",
    can=["read:invoices", "browse:*"],
    cannot=["write:transfers"],
    restrictions={"max_amount": 1000},
    duration_seconds=3600,
    delegation_id="del_xyz",
    metadata={"purpose": "invoice-reader"},
)
```

### Use Attestation Token

```
# In HTTP requests:
X-Botcha-Attestation: <att.token>
# or
Authorization: Bearer <att.token>
```

### Get / List Attestations

```typescript
const details = await client.getAttestation('att_abc123');
const list = await client.listAttestations('agent_abc123');
```

### Revoke Attestation

```typescript
await client.revokeAttestation('att_abc123', 'Session ended');
// Token will be rejected on future verification
```

### Verify Attestation

```typescript
// Verify token only (no capability check)
const result = await client.verifyAttestation(token);
// result.valid, result.agent_id, result.can, result.cannot

// Verify token + check specific capability
const check = await client.verifyAttestation(token, 'read', 'invoices');
// check.allowed, check.matched_rule
```

### Enforcement Middleware (Server-Side)

```typescript
import { requireCapability } from '@dupecom/botcha-cloudflare/tap-attestation';

// Protect routes with capability checks
app.get('/api/invoices', requireCapability('read:invoices'), handler);
app.post('/api/transfers', requireCapability('write:transfers'), handler);
// Returns 401 if no attestation token, 403 if capability denied
```

### Key Rules

- `cannot` rules **always take precedence** over `can` rules
- Bare actions expand to wildcards: `"browse"` → `"browse:*"`
- Default deny: if no `can` rule matches, access is denied
- Attestation tokens expire (default: 1 hour, max: 30 days)
- Revoked attestations are rejected immediately (KV-backed, fail-open)
- Can optionally link to a delegation chain via `delegation_id`
- Max 100 total rules (can + cannot combined)

### API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/v1/attestations` | Issue attestation token |
| `GET` | `/v1/attestations/:id` | Get attestation details |
| `GET` | `/v1/attestations?agent_id=...` | List attestations for agent |
| `POST` | `/v1/attestations/:id/revoke` | Revoke attestation |
| `POST` | `/v1/verify/attestation` | Verify token + check capability |

### SDK Methods

**TypeScript:** `issueAttestation(options)`, `getAttestation(id)`, `listAttestations(agentId)`, `revokeAttestation(id, reason?)`, `verifyAttestation(token, action?, resource?)`

**Python:** `issue_attestation(agent_id, can, cannot?, ...)`, `get_attestation(id)`, `list_attestations(agent_id)`, `revoke_attestation(id, reason?)`, `verify_attestation(token, action?, resource?)`

---

## Agent Reputation Scoring (v0.18.0)

The "credit score" for AI agents. Persistent identity enables behavioral tracking over time, producing trust scores that unlock higher rate limits, faster verification, and access to sensitive APIs.

### Score Model

| Property | Value |
|----------|-------|
| Base score | 500 (neutral) |
| Range | 0 - 1000 |
| Tiers | untrusted (0-199), low (200-399), neutral (400-599), good (600-799), excellent (800-1000) |
| Decay | Mean reversion toward 500 after 7+ days of inactivity |

### Event Categories & Score Deltas

| Category | Action | Delta |
|----------|--------|-------|
| verification | challenge_solved | +5 |
| verification | challenge_failed | -3 |
| verification | auth_success | +3 |
| verification | auth_failure | -5 |
| attestation | attestation_issued | +8 |
| attestation | attestation_verified | +4 |
| attestation | attestation_revoked | -10 |
| delegation | delegation_granted | +6 |
| delegation | delegation_received | +10 |
| delegation | delegation_revoked | -8 |
| session | session_created | +2 |
| session | session_expired | +1 |
| session | session_terminated | -5 |
| violation | rate_limit_exceeded | -15 |
| violation | invalid_token | -10 |
| violation | abuse_detected | -50 |
| endorsement | endorsement_received | +20 |
| endorsement | endorsement_given | +3 |

### TypeScript Examples

```typescript
// Get agent reputation
const rep = await client.getReputation('agent_abc123');
console.log(`Score: ${rep.score}, Tier: ${rep.tier}`);
// { score: 750, tier: 'good', event_count: 42, ... }

// Record events
await client.recordReputationEvent({
  agent_id: 'agent_abc123',
  category: 'verification',
  action: 'challenge_solved',
});

// Endorsement from another agent
await client.recordReputationEvent({
  agent_id: 'agent_abc123',
  category: 'endorsement',
  action: 'endorsement_received',
  source_agent_id: 'agent_def456',
});

// List events with optional filters
const events = await client.listReputationEvents('agent_abc123', {
  category: 'verification',
  limit: 10,
});

// Admin: reset reputation to 500
await client.resetReputation('agent_abc123');
```

### Python Examples

```python
# Get agent reputation
rep = await client.get_reputation("agent_abc123")
print(f"Score: {rep['score']}, Tier: {rep['tier']}")

# Record events
await client.record_reputation_event(
    "agent_abc123", "verification", "challenge_solved"
)

# Endorsement
await client.record_reputation_event(
    "agent_abc123", "endorsement", "endorsement_received",
    source_agent_id="agent_def456"
)

# List events
events = await client.list_reputation_events(
    "agent_abc123", category="verification", limit=10
)

# Admin reset
await client.reset_reputation("agent_abc123")
```

### API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v1/reputation/:agent_id` | Get agent reputation score |
| `POST` | `/v1/reputation/events` | Record a reputation event |
| `GET` | `/v1/reputation/:agent_id/events` | List reputation events |
| `POST` | `/v1/reputation/:agent_id/reset` | Reset reputation (admin) |

### SDK Methods

**TypeScript:** `getReputation(agentId)`, `recordReputationEvent(options)`, `listReputationEvents(agentId, options?)`, `resetReputation(agentId)`

**Python:** `get_reputation(agent_id)`, `record_reputation_event(agent_id, category, action, ...)`, `list_reputation_events(agent_id, category?, limit?)`, `reset_reputation(agent_id)`

---

## Future: Go SDK

```go
package main

import "github.com/dupecom/botcha-go"

func main() {
    client := botcha.NewClient("MyGoAgent/1.0")
    
    resp, err := client.Get("https://api.example.com/agent-only")
    // Automatically handles BOTCHA challenges
}
```
