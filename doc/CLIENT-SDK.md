# Client SDK Design

> SDK for AI agents to automatically solve BOTCHA challenges

## Overview

The client SDK allows AI agents to:
1. Detect BOTCHA-protected endpoints
2. Automatically solve challenges
3. Retry with verification tokens
4. Handle different challenge types

## Proposed API

### Basic Usage

```typescript
import { BotchaClient } from '@dupecom/botcha-client';

const client = new BotchaClient({
  agentName: 'MyAgent/1.0',
  autoSolve: true,
});

// Automatically handles BOTCHA challenges
const response = await client.fetch('https://api.example.com/agent-only');
console.log(response.data); // Success!
```

### Manual Challenge Solving

```typescript
import { solveLandingChallenge, solveSpeedChallenge } from '@dupecom/botcha-client';

// Solve landing page challenge
const token = await solveLandingChallenge('https://botcha.ai');

// Solve speed challenge
const result = await solveSpeedChallenge({
  id: 'challenge-id',
  problems: [123456, 789012, ...],
});
```

### With Axios/Fetch Interceptor

```typescript
import axios from 'axios';
import { createBotchaInterceptor } from '@dupecom/botcha-client';

const api = axios.create({ baseURL: 'https://api.example.com' });
api.interceptors.response.use(...createBotchaInterceptor());

// Now all 403 BOTCHA responses are auto-retried
const data = await api.get('/protected');
```

### LangChain Integration

```typescript
import { BotchaTool } from '@dupecom/botcha-langchain';

const tools = [
  new BotchaTool(), // Automatically solves BOTCHA when encountered
];

const agent = new Agent({ tools });
```

## Challenge Solvers

```typescript
// Built-in solvers
import { 
  sha256Solver,
  speedChallengeSolver,
  landingChallengeSolver,
} from '@dupecom/botcha-client/solvers';

// Register custom solver
client.registerSolver('custom-type', async (challenge) => {
  // Your solving logic
  return { answer: '...' };
});
```

## Configuration

```typescript
const client = new BotchaClient({
  // Agent identification
  agentName: 'MyAgent/1.0',
  agentId: 'registered-agent-id', // Optional: from agent registry
  
  // Behavior
  autoSolve: true,
  maxRetries: 3,
  timeout: 5000,
  
  // Challenge preferences
  preferredChallengeType: 'speed',
  
  // Callbacks
  onChallenge: (challenge) => console.log('Got challenge:', challenge),
  onSolved: (result) => console.log('Solved in', result.time, 'ms'),
  onFailed: (error) => console.error('Failed:', error),
});
```

## Token Caching

```typescript
const client = new BotchaClient({
  // Cache solved tokens
  tokenCache: new MemoryTokenCache(), // or RedisTokenCache, etc.
  tokenTTL: 3600, // 1 hour
});

// Reuses cached token if valid
await client.fetch('/protected'); // Uses cached token
```

## Error Handling

```typescript
import { BotchaError, ChallengeFailed, ChallengeTimeout } from '@dupecom/botcha-client';

try {
  await client.fetch('/protected');
} catch (error) {
  if (error instanceof ChallengeTimeout) {
    console.log('Too slow! Challenge expired.');
  } else if (error instanceof ChallengeFailed) {
    console.log('Wrong answer:', error.hint);
  }
}
```

## Package Structure

```
@dupecom/botcha-client/
├── index.ts           # Main client
├── solvers/
│   ├── sha256.ts
│   ├── speed.ts
│   └── landing.ts
├── interceptors/
│   ├── axios.ts
│   └── fetch.ts
├── cache/
│   ├── memory.ts
│   └── redis.ts
└── types.ts
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
