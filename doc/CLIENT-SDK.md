# Client SDK

> SDK for AI agents to automatically solve BOTCHA challenges

**Status:** ✅ Published

| Package | Version | Description |
|---------|---------|-------------|
| [`@dupecom/botcha`](https://www.npmjs.com/package/@dupecom/botcha) | 0.4.1 | Core SDK with client (`/client` export) |
| [`@dupecom/botcha-langchain`](https://www.npmjs.com/package/@dupecom/botcha-langchain) | 0.1.0 | LangChain Tool integration |

## Overview

The client SDK allows AI agents to:
1. ✅ Detect BOTCHA-protected endpoints
2. ✅ Automatically acquire JWT tokens
3. ✅ Solve challenges and retry with tokens
4. ✅ Handle different challenge types (speed, standard)

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
});
```

**Supported options:**
- ✅ `baseUrl` - BOTCHA service URL
- ✅ `agentIdentity` - Custom User-Agent string
- ✅ `maxRetries` - Maximum challenge solve attempts
- ✅ `autoToken` - Enable automatic token acquisition

## Token Caching (Shipped)

```typescript
const client = new BotchaClient({ autoToken: true });

// Tokens are automatically cached in-memory
await client.fetch('/protected'); // Acquires token
await client.fetch('/protected'); // Reuses cached token

// Token cached until 55 minutes (near expiry)
// Automatically refreshes when needed

// Clear token manually if needed
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

## Future: Python SDK

```python
from botcha import BotchaClient

client = BotchaClient(agent_name="MyPythonAgent/1.0")

# Automatic challenge solving
response = client.get("https://api.example.com/agent-only")
print(response.json())
```

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
