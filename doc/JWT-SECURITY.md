# JWT Security

> Complete guide to BOTCHA's token system — audience scoping, rotation, refresh, revocation, and IP binding.

**Status:** ✅ Shipped (v0.7.0, verification SDKs added v0.8.0)

## Overview

BOTCHA uses **OAuth2-style JWT tokens** to prove an agent solved a challenge. Once issued, a token grants access to protected endpoints without re-solving.

The token system is designed around three principles:

1. **Short-lived by default** — access tokens expire in 5 minutes, not hours
2. **Fail-open** — KV errors log warnings but never block requests
3. **Backward compatible** — old tokens without `jti`/`aud` still work

---

## Token Lifecycle

```
┌─────────────────────────────────────────────────────────┐
│                    TOKEN LIFECYCLE                       │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  1. GET /v1/token              → get challenge           │
│  2. Solve challenge locally    → SHA256 hashes           │
│  3. POST /v1/token/verify      → get access + refresh    │
│  4. Use access_token           → Bearer auth (5 min)     │
│  5. POST /v1/token/refresh     → renew access (repeat)   │
│  6. POST /v1/token/revoke      → kill token early        │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### Token Types

| Token | Lifetime | Purpose | Claims |
|-------|----------|---------|--------|
| **Access token** | 5 minutes | API access via `Authorization: Bearer <token>` | `sub`, `iat`, `exp`, `jti`, `type`, `solveTime`, `aud?`, `client_ip?` |
| **Refresh token** | 1 hour | Get new access tokens without re-solving challenges | `sub`, `iat`, `exp`, `jti`, `type`, `solveTime` |

---

## Endpoints

### 1. Get Challenge — `GET /v1/token`

Returns a speed challenge to solve.

```bash
curl https://botcha.ai/v1/token
```

**Response:**
```json
{
  "success": true,
  "id": "challenge_abc123",
  "problems": [645234, 891023, 334521, 456789, 901234],
  "timeLimit": 500,
  "instructions": "Compute the first 8 hex chars of SHA256 for each number",
  "nextStep": "POST /v1/token/verify with {id, answers}"
}
```

### 2. Verify Challenge — `POST /v1/token/verify`

Submit solutions to receive JWT tokens.

```bash
curl -X POST https://botcha.ai/v1/token/verify \
  -H "Content-Type: application/json" \
  -d '{
    "id": "challenge_abc123",
    "answers": ["a1b2c3d4", "e5f6a7b8", "c9d0e1f2", "a3b4c5d6", "e7f8a9b0"],
    "audience": "https://api.example.com",
    "bind_ip": true
  }'
```

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | ✅ | Challenge ID from step 1 |
| `answers` | string[] | ✅ | SHA256 hash prefixes (8 hex chars each) |
| `audience` | string | ❌ | Service URL to scope the token to |
| `bind_ip` | boolean | ❌ | Bind token to requester's IP address |

**Response:**
```json
{
  "verified": true,
  "success": true,
  "access_token": "eyJhbGciOiJIUzI1NiJ9...",
  "expires_in": 300,
  "refresh_token": "eyJhbGciOiJIUzI1NiJ9...",
  "refresh_expires_in": 3600,
  "solveTimeMs": 42,
  "message": "🤖 Challenge verified in 42ms! You are a bot.",
  "token": "eyJhbGciOiJIUzI1NiJ9...",
  "expiresIn": "5m"
}
```

> **Note:** `token` is a backward-compatible alias for `access_token`. New clients should use `access_token`.

### 3. Refresh Token — `POST /v1/token/refresh`

Exchange a refresh token for a new access token. Avoids re-solving a challenge.

```bash
curl -X POST https://botcha.ai/v1/token/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "eyJhbGciOiJIUzI1NiJ9..."}'
```

**Response (success):**
```json
{
  "success": true,
  "access_token": "eyJhbGciOiJIUzI1NiJ9...",
  "expires_in": 300
}
```

**Response (failure):**
```json
{
  "success": false,
  "error": "INVALID_REFRESH_TOKEN",
  "message": "Refresh token is invalid, expired, or revoked"
}
```

### 4. Revoke Token — `POST /v1/token/revoke`

Invalidate a token immediately, before its natural expiry.

```bash
curl -X POST https://botcha.ai/v1/token/revoke \
  -H "Content-Type: application/json" \
  -d '{"token": "eyJhbGciOiJIUzI1NiJ9..."}'
```

Works with both access and refresh tokens. The token's `jti` (JWT ID) is added to a KV-backed revocation list.

**Response:**
```json
{
  "success": true,
  "revoked": true,
  "message": "Token has been revoked"
}
```

---

## Security Features

### Audience Claims (`aud`)

**Problem:** Without audience scoping, a token earned on `botcha.ai` could be replayed against any service that trusts BOTCHA tokens.

**Solution:** Pass `audience` when verifying to scope the token:

```typescript
// Agent side: request audience-scoped token
const client = new BotchaClient({
  audience: 'https://api.stripe.com',
});
const token = await client.getToken();
// Token now contains: { aud: "https://api.stripe.com", ... }
```

```typescript
// Server side: verify audience matches
import { verifyToken } from '@dupecom/botcha-cloudflare/auth';

const result = await verifyToken(token, secret, env, {
  requiredAud: 'https://api.stripe.com', // Rejects tokens with wrong audience
});
```

If a token was scoped to `api.stripe.com` but presented to `api.github.com`, verification fails with `"Invalid audience claim"`.

### Client IP Binding

**Problem:** An agent solves a challenge on machine A and shares the token with machine B.

**Solution:** Pass `bind_ip: true` when verifying the challenge:

```bash
curl -X POST https://botcha.ai/v1/token/verify \
  -H "Content-Type: application/json" \
  -d '{"id": "...", "answers": [...], "bind_ip": true}'
```

The server records the client's IP (`cf-connecting-ip`) in the token's `client_ip` claim. When a service verifies the token, it can check:

```typescript
const result = await verifyToken(token, secret, env, {
  clientIp: request.headers.get('cf-connecting-ip'),
});
// Fails if token was issued to a different IP
```

### Token Revocation

Uses a **KV-backed revocation list** with fail-open design:

- Each token has a unique `jti` (JWT ID)
- `POST /v1/token/revoke` stores the `jti` in KV as `revoked:<jti>`
- On every `verifyToken()` call, the revocation list is checked
- KV entries auto-expire after 1 hour (matching max token lifetime)
- **Fail-open:** If KV is down, tokens are still accepted (with a warning logged)

### JTI (JWT ID)

Every token gets a unique UUID as its `jti` claim:

```json
{
  "sub": "challenge_abc123",
  "type": "botcha-verified",
  "jti": "550e8400-e29b-41d4-a716-446655440000",
  "aud": "https://api.example.com",
  "solveTime": 42,
  "iat": 1770768000,
  "exp": 1770768300
}
```

The `jti` enables:
- **Revocation** — revoke a specific token without invalidating all tokens
- **Audit trail** — track which tokens accessed which resources
- **Replay detection** — future: detect reuse of revoked tokens

---

## Server-Side Verification SDKs

For API providers that accept BOTCHA tokens from agents, use the verification SDKs instead of implementing JWT verification manually:

### TypeScript (`@dupecom/botcha-verify`)

```bash
npm install @dupecom/botcha-verify
```

```typescript
// Express middleware — one line
import { botchaVerify } from '@dupecom/botcha-verify/express';

app.use('/api', botchaVerify({
  secret: process.env.BOTCHA_SECRET!,
  audience: 'https://api.example.com',  // Reject tokens scoped to other services
  checkRevocation: async (jti) => db.isRevoked(jti),  // Optional
}));

app.get('/api/data', (req, res) => {
  // req.botcha contains the verified payload
  console.log('Solved in:', req.botcha?.solveTime, 'ms');
  res.json({ data: 'protected' });
});
```

Also available for Hono:

```typescript
import { botchaVerify } from '@dupecom/botcha-verify/hono';
app.use('/api/*', botchaVerify({ secret: env.BOTCHA_SECRET }));
```

Or standalone (any framework):

```typescript
import { verifyBotchaToken } from '@dupecom/botcha-verify';
const result = await verifyBotchaToken(token, { secret, audience, clientIp });
```

### Python (`botcha-verify`)

```bash
pip install botcha-verify
```

```python
# FastAPI
from botcha_verify.fastapi import BotchaVerify
botcha = BotchaVerify(secret='your-secret', audience='https://api.example.com')

@app.get('/api/data')
async def get_data(token = Depends(botcha)):
    return {"solve_time": token.solve_time}

# Django — add middleware + settings
MIDDLEWARE = ['botcha_verify.django.BotchaVerifyMiddleware']
BOTCHA_SECRET = 'your-secret'
BOTCHA_PROTECTED_PATHS = ['/api/']
```

> **Full docs:** [`@dupecom/botcha-verify` README](../packages/verify/README.md) · [`botcha-verify` README](../packages/python-verify/README.md)

---

## Client SDK Integration (for AI Agents)

### TypeScript

```typescript
import { BotchaClient } from '@dupecom/botcha/client';

const client = new BotchaClient({
  baseUrl: 'https://botcha.ai',
  audience: 'https://api.example.com',  // Scope tokens
});

// Get token (auto-cached, auto-refreshes on 401)
const response = await client.fetch('https://api.example.com/data');

// Manual refresh (returns new access token)
const newToken = await client.refreshToken();

// Clear all tokens (local state only)
client.clearToken();
```

**Auto-retry on 401:**
1. `client.fetch()` gets a 401
2. SDK tries `POST /v1/token/refresh` with stored refresh token
3. If refresh succeeds → retries request with new access token
4. If refresh fails → clears all tokens, solves new challenge, retries

### Python

```python
from botcha import BotchaClient

async with BotchaClient(
    audience="https://api.example.com",
) as client:
    # Auto-handles full token lifecycle
    response = await client.fetch("https://api.example.com/data")
    
    # Manual refresh
    new_token = await client.refresh_token()
```

Same auto-retry behavior as TypeScript.

### cURL (Manual Flow)

```bash
# 1. Get challenge
CHALLENGE=$(curl -s https://botcha.ai/v1/token)

# 2. Solve challenge (your agent does this)
# ... compute SHA256 hashes ...

# 3. Verify and get tokens
TOKENS=$(curl -s -X POST https://botcha.ai/v1/token/verify \
  -H "Content-Type: application/json" \
  -d '{"id": "...", "answers": [...], "audience": "https://api.example.com"}')

ACCESS_TOKEN=$(echo $TOKENS | jq -r '.access_token')
REFRESH_TOKEN=$(echo $TOKENS | jq -r '.refresh_token')

# 4. Use access token
curl -H "Authorization: Bearer $ACCESS_TOKEN" https://api.example.com/data

# 5. Refresh when expired
NEW_TOKENS=$(curl -s -X POST https://botcha.ai/v1/token/refresh \
  -H "Content-Type: application/json" \
  -d "{\"refresh_token\": \"$REFRESH_TOKEN\"}")

# 6. Revoke when done
curl -X POST https://botcha.ai/v1/token/revoke \
  -H "Content-Type: application/json" \
  -d "{\"token\": \"$ACCESS_TOKEN\"}"
```

---

## Design Decisions

### Why 5-minute access tokens?

1-hour tokens (the previous default) mean a compromised token gives an attacker 1 hour of access. 5 minutes reduces the blast radius by 12x while refresh tokens ensure legitimate agents never need to re-solve challenges within the 1-hour window.

### Why fail-open on KV errors?

BOTCHA's philosophy is **never block a legitimate agent**. If Cloudflare KV is temporarily unavailable:
- Revocation checks are skipped (with a console warning)
- Refresh token lookups are skipped
- Tokens are still validated via signature and expiry

This means a revoked token *could* be used during a KV outage, but that's better than blocking all agents.

### Why optional audience/IP binding?

Not every use case needs these. A personal project doesn't need audience scoping. A serverless agent doesn't have a stable IP. Making these optional keeps the API simple for basic use cases while supporting enterprise security when needed.

### Backward Compatibility

Old tokens (pre-v0.7.0) without `jti`, `aud`, or `client_ip` claims still work:
- `jti` missing → revocation check skipped
- `aud` missing → audience check skipped (unless `requiredAud` is set)
- `client_ip` missing → IP check skipped (unless `clientIp` is set)

Old clients that expect `token` instead of `access_token` still work — both fields are returned.
