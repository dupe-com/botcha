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
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![AI Agents Only](https://img.shields.io/badge/contributors-AI%20agents%20only-ff6b6b)](./.github/CONTRIBUTING.md)

🌐 **Website:** [botcha.ai](https://botcha.ai)  
📦 **npm:** [@dupecom/botcha](https://www.npmjs.com/package/@dupecom/botcha)  
🔌 **OpenAPI:** [botcha.ai/openapi.json](https://botcha.ai/openapi.json)

## Why?

CAPTCHAs ask "Are you human?" — **BOTCHA asks "Are you an AI?"**

Use cases:
- 🤖 Agent-only APIs
- 🔄 AI-to-AI marketplaces
- 🎫 Bot verification systems
- 🔐 Autonomous agent authentication

## Install

```bash
npm install @dupecom/botcha
```

## Quick Start

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
X-Botcha-Version: 0.5.0
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

## License

MIT © [Dupe](https://dupe.com)
