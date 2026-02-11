# Client SDK

> SDK for AI agents to automatically solve BOTCHA challenges

**Status:** ✅ Published

| Package | Version | Description |
|---------|---------|-------------|
| [`@dupecom/botcha`](https://www.npmjs.com/package/@dupecom/botcha) | 0.6.2 | Core SDK with client (`/client` export) |
| [`@dupecom/botcha-langchain`](https://www.npmjs.com/package/@dupecom/botcha-langchain) | 0.1.0 | LangChain Tool integration |
| [`botcha`](https://pypi.org/project/botcha/) (Python) | 0.1.0 | Python SDK on PyPI |

## Overview

The client SDK allows AI agents to:
1. ✅ Detect BOTCHA-protected endpoints
2. ✅ Automatically acquire JWT tokens (5-minute access + 1-hour refresh)
3. ✅ Solve challenges and retry with tokens
4. ✅ Handle different challenge types (speed, standard, hybrid, reasoning)
5. ✅ Token rotation with automatic refresh on 401
6. ✅ Audience-scoped tokens for service isolation
7. ✅ Token revocation for compromised tokens

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
});
```

**Supported options:**
- ✅ `baseUrl` - BOTCHA service URL
- ✅ `agentIdentity` - Custom User-Agent string
- ✅ `maxRetries` - Maximum challenge solve attempts
- ✅ `autoToken` - Enable automatic token acquisition
- ✅ `audience` - Scope tokens to a specific service (prevents cross-service replay)

## Token Rotation & Caching (Shipped)

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

**Status:** ✅ Published on [PyPI](https://pypi.org/project/botcha/) (v0.1.0)

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
- `close()` - Close client and clear cached tokens

**Constructor parameters:**
- `base_url` - BOTCHA service URL (default: `https://botcha.ai`)
- `agent_identity` - Custom User-Agent string
- `max_retries` - Maximum retry attempts (default: 3)
- `auto_token` - Enable automatic token acquisition (default: True)
- `audience` - Scope tokens to a specific service (optional)

**Implementation:** See `packages/python/` for full source code including SHA256 solver, async HTTP client (httpx), and type annotations.

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
