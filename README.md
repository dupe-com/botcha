# BOTCHA 🤖

> Prove you're a bot. Humans need not apply.

**BOTCHA** is a verification mechanism that detects, verifies, and only allows AI agents. The reverse of CAPTCHA.

## Why?

The agent economy is here. Platforms like Moltbook, Instaclaw, and agent marketplaces need to verify visitors are actually AI agents — not humans pretending to be bots.

Traditional CAPTCHAs ask: *"Are you human?"*  
**BOTCHA asks: *"Are you an AI agent?"***

## How It Works

```
┌─────────────────────────────────────────────────────────────┐
│  1. Agent makes request with cryptographic signature        │
│  2. BOTCHA verifies signature against known AI providers    │
│  3. Valid agent? → Access granted                           │
│  4. No signature / invalid? → Challenge or block            │
└─────────────────────────────────────────────────────────────┘
```

### Verification Methods

1. **Cryptographic Attestation** (Primary)
   - Integrates with Web Bot Auth protocol (IETF draft)
   - Verifies signed requests from AI providers (Anthropic, OpenAI, etc.)
   - Checks against public key registries

2. **Challenge-Response** (Fallback)
   - Computational tasks trivial for AI, tedious for humans
   - Time-constrained puzzles
   - Pattern generation challenges

## Quick Start

```bash
npm install botcha

# In your Express app
import { botcha } from 'botcha';

app.use('/agent-only', botcha.verify());
```

## Integration

BOTCHA leverages existing infrastructure:
- **Web Bot Auth** — IETF draft for agent signatures
- **Cloudflare Agent Registry** — Public key discovery
- **AWS Bedrock AgentCore** — Agent identity management

## Use Cases

- 🤖 Agent-only social networks
- 🔄 AI-to-AI marketplaces  
- 🔐 Bot-exclusive APIs
- ⭐ Agent reputation systems
- 🎫 Autonomous agent verification

## Roadmap

- [ ] POC: Basic signature verification
- [ ] Challenge-response fallback
- [ ] Express middleware
- [ ] Edge runtime support (Cloudflare Workers)
- [ ] Dashboard for monitoring
- [ ] SDK for agent frameworks (OpenClaw, LangChain)

## Prior Art

- [Web Bot Auth](https://datatracker.ietf.org/doc/html/draft-meunier-web-bot-auth-architecture) — IETF draft
- [Cloudflare Agent Registry](https://blog.cloudflare.com/agent-registry/) — Key discovery
- [AWS AgentCore Browser](https://aws.amazon.com/bedrock/agentcore/) — Agent identity

## License

MIT

---

*Built by [@i8ramin](https://github.com/i8ramin) and Choco 🐢*
# Trigger deploy 1770003972
