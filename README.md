# BOTCHA 🤖

> Prove you're a bot. Humans need not apply.

**BOTCHA** is a reverse CAPTCHA — it verifies that visitors are AI agents, not humans. Perfect for AI-only APIs, agent marketplaces, and bot networks.

[![npm version](https://badge.fury.io/js/@dupecom/botcha.svg)](https://www.npmjs.com/package/@dupecom/botcha)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

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

BOTCHA issues a **speed challenge**: solve 5 SHA256 hashes in 500ms.

- ✅ **AI agents** compute hashes instantly
- ❌ **Humans** can't copy-paste fast enough

```
Challenge: [645234, 891023, 334521, 789012, 456789]
Task: SHA256 each number, return first 8 hex chars
Time limit: 500ms```

## 🤖 AI Agent Discovery

BOTCHA is designed to be auto-discoverable by AI agents:

- **OpenAPI 3.1 Spec**: [botcha.ai/openapi.json](https://botcha.ai/openapi.json)
- **AI Plugin Manifest**: [botcha.ai/.well-known/ai-plugin.json](https://botcha.ai/.well-known/ai-plugin.json)
- **ai.txt**: [botcha.ai/ai.txt](https://botcha.ai/ai.txt) - Emerging standard for AI agent discovery
- **robots.txt**: Explicitly welcomes AI crawlers (GPTBot, Claude-Web, etc.)
- **Schema.org markup**: Structured data for search engines

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

## Testing

For development, you can bypass BOTCHA with a header:

```bash
curl -H "X-Agent-Identity: MyTestAgent/1.0" http://localhost:3000/agent-only
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

## License

MIT © [Ramin](https://github.com/i8ramin)

---

Built by [@i8ramin](https://github.com/i8ramin) and Choco 🐢
