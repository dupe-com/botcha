# Client SDK

> SDK for AI agents to automatically solve BOTCHA challenges

**Status:** ✅ Published

| Package | Version | Description |
|---------|---------|-------------|
| [`@dupecom/botcha`](https://www.npmjs.com/package/@dupecom/botcha) | 0.12.0 | Core SDK with client (`/client` export) |
| [`@dupecom/botcha-langchain`](https://www.npmjs.com/package/@dupecom/botcha-langchain) | 0.1.0 | LangChain Tool integration |
| [`botcha`](https://pypi.org/project/botcha/) (Python) | 0.4.0 | Python SDK on PyPI |
| [`@botcha/verify`](../packages/verify/) | 0.1.0 | Server-side verification (Express/Hono middleware) |
| [`botcha-verify`](../packages/python-verify/) | 0.1.0 | Server-side verification (FastAPI/Django middleware) |

## Overview

The client SDK allows AI agents to:
1. ✅ Detect BOTCHA-protected endpoints
2. ✅ Automatically acquire JWT tokens (5-minute access + 1-hour refresh)
3. ✅ Solve challenges and retry with tokens
4. ✅ Handle different challenge types (speed, standard, hybrid, reasoning)
5. ✅ Token rotation with automatic refresh on 401
6. ✅ Audience-scoped tokens for service isolation
7. ✅ Token revocation for compromised tokens
8. ✅ App creation with email verification (SDK methods)
9. ✅ Account recovery and secret rotation (SDK methods)
10. ✅ TAP (Trusted Agent Protocol) — cryptographic agent auth with public keys and capability-scoped sessions

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
  -d '{"email": "agent@example.com"}'
# Returns: {app_id, app_secret, email, email_verified: false, verification_required: true, ...}
```

**⚠️ Important:** The `app_secret` is only shown once. Save it securely.

**Email is required.** A 6-digit verification code will be sent to the provided email.

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
const app = await client.createApp('agent@example.com');
console.log(app.app_id);     // 'app_abc123'
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
    app = await client.create_app("agent@example.com")
    print(app.app_id)      # 'app_abc123'
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
| Access Token | 5 minutes | Used for API requests |
| Refresh Token | 1 hour | Used to get new access tokens |

```typescript
const client = new BotchaClient({ autoToken: true });

// Tokens are automatically cached in-memory
await client.fetch('/protected'); // Acquires access_token (5min) + refresh_token (1hr)
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

**Status:** ✅ Published on [PyPI](https://pypi.org/project/botcha/) (v0.3.0)

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
    # Auto-handles token lifecycle (5min access + 1hr refresh)
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

### TypeScript (@botcha/verify)

**Status:** ✅ Built (v0.1.0) — [README](../packages/verify/README.md)

```typescript
import { botchaVerify } from '@botcha/verify/express';

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
import { botchaVerify } from '@botcha/verify/hono';

app.use('/api/*', botchaVerify({ secret: env.BOTCHA_SECRET }));
```

```typescript
// Standalone verification (any framework)
import { verifyBotchaToken } from '@botcha/verify';

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
| `ecdsa-p256-sha256` | ECDSA P-256 | Recommended — compact keys, fast verification |
| `rsa-pss-sha256` | RSA-PSS | Legacy compatibility — larger keys |

### Trust Levels

| Level | Description |
|-------|-------------|
| `basic` | Default. Agent registered without public key. |
| `verified` | Agent registered with public key. |
| `enterprise` | Agent with verified organizational identity. |

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
