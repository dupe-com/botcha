# @dupecom/botcha-langchain

LangChain integration for BOTCHA - make AI agents transparently solve BOTCHA challenges.

## Installation

```bash
npm install @dupecom/botcha-langchain @langchain/core
```

## Features

- **BotchaTool**: LangChain Tool for AI agents to solve BOTCHA challenges
- **BotchaRequestWrapper**: Automatic challenge solving for HTTP requests
- TypeScript support with full type definitions
- Automatic token management and caching
- Seamless integration with existing LangChain agents

## Usage

### BotchaTool - For LangChain Agents

Use `BotchaTool` to give your LangChain agent the ability to solve BOTCHA challenges and access bot-only APIs:

```typescript
import { BotchaTool } from '@dupecom/botcha-langchain';
import { ChatOpenAI } from '@langchain/openai';
import { createReactAgent } from '@langchain/langgraph/prebuilt';

// Create the BOTCHA tool
const botchaTool = new BotchaTool({
  baseUrl: 'https://api.botcha.ai'
});

// Create your agent with the tool
const agent = createReactAgent({
  llm: new ChatOpenAI({ model: 'gpt-4' }),
  tools: [botchaTool],
});

// The agent can now call the tool to get tokens
// It will understand to use it when encountering BOTCHA-protected APIs
const response = await agent.invoke({
  messages: [{ role: 'user', content: 'Access the bot-only API at https://api.example.com/agent-only' }]
});
```

### BotchaRequestWrapper - For HTTP Requests

Use `BotchaRequestWrapper` to automatically solve BOTCHA challenges when making HTTP requests:

```typescript
import { BotchaRequestWrapper } from '@dupecom/botcha-langchain';

const wrapper = new BotchaRequestWrapper({
  baseUrl: 'https://api.botcha.ai'
});

// Automatically solves challenges if needed
const response = await wrapper.fetch('https://protected-api.com/data');
const data = await response.json();

// Get a token for manual use
const token = await wrapper.getToken();
```

## API Reference

### BotchaTool

LangChain Tool that enables AI agents to solve BOTCHA challenges.

**Options:**

```typescript
interface BotchaToolOptions {
  baseUrl?: string;          // BOTCHA service URL (default: https://botcha.ai)
  agentIdentity?: string;    // Custom User-Agent
  maxRetries?: number;       // Max retry attempts (default: 3)
  autoToken?: boolean;       // Auto token management (default: true)
  name?: string;             // Tool name (default: "botcha_solver")
  description?: string;      // Tool description
}
```

**Methods:**

- `invoke(input)`: Call the tool (used by LangChain agents)
- `getToken()`: Get a JWT token directly
- `clearToken()`: Clear the cached token

### BotchaRequestWrapper

Wraps HTTP requests to automatically handle BOTCHA challenges.

**Options:**

```typescript
interface BotchaRequestWrapperOptions {
  baseUrl?: string;          // BOTCHA service URL (default: https://botcha.ai)
  agentIdentity?: string;    // Custom User-Agent
  maxRetries?: number;       // Max retry attempts (default: 3)
  autoToken?: boolean;       // Auto token management (default: true)
  fetchFn?: typeof fetch;    // Custom fetch implementation
}
```

**Methods:**

- `fetch(url, init?)`: Fetch with automatic challenge solving
- `getToken()`: Get a JWT token
- `clearToken()`: Clear the cached token
- `createHeaders()`: Get headers with challenge solution

## How It Works

1. **Token-Based Auth (Recommended)**: Automatically acquires JWT tokens from the BOTCHA service
2. **Challenge Header Method**: Falls back to solving challenges via HTTP headers if needed
3. **Automatic Retry**: Retries failed requests with solved challenges
4. **Token Caching**: Caches tokens until near expiry (55 minutes)

## Examples

### React Agent with BOTCHA

```typescript
import { BotchaTool } from '@dupecom/botcha-langchain';
import { ChatAnthropic } from '@langchain/anthropic';
import { createReactAgent } from '@langchain/langgraph/prebuilt';

const agent = createReactAgent({
  llm: new ChatAnthropic({ model: 'claude-3-sonnet' }),
  tools: [
    new BotchaTool({ baseUrl: 'https://api.botcha.ai' }),
    // ... other tools
  ],
});

const result = await agent.invoke({
  messages: [{ 
    role: 'user', 
    content: 'Get data from the bot-only endpoint at https://api.example.com/agents/data' 
  }]
});
```

### Custom Fetch Wrapper

```typescript
import { BotchaRequestWrapper } from '@dupecom/botcha-langchain';

const wrapper = new BotchaRequestWrapper({
  baseUrl: 'https://api.botcha.ai',
  agentIdentity: 'MyAgent/1.0',
  maxRetries: 5,
});

async function fetchProtectedData(endpoint: string) {
  const response = await wrapper.fetch(`https://api.example.com${endpoint}`);
  
  if (!response.ok) {
    throw new Error(`Request failed: ${response.status}`);
  }
  
  return await response.json();
}

const data = await fetchProtectedData('/agent-only');
```

## License

MIT

## Links

- [BOTCHA Documentation](https://botcha.ai)
- [GitHub Repository](https://github.com/dupe-com/botcha)
- [LangChain Documentation](https://js.langchain.com/)
