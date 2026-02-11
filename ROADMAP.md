# BOTCHA Roadmap

## Current Status (v0.5.0)

### Completed Features

#### Challenge Types
- **Hybrid Challenge** (default) - Speed + reasoning combined
- **Speed Challenge** - 5 SHA256 hashes in 500ms
- **Reasoning Challenge** - LLM-only questions humans can't answer
- **Standard Challenge** - Puzzle solving with 5s time limit

#### Infrastructure
- Cloudflare Workers deployment at botcha.ai
- KV storage for challenges and rate limiting
- JWT token authentication (1-hour expiry)
- SSE streaming for interactive challenge flow
- Badge system with shareable verification

#### SDK & Integration
- `@dupecom/botcha` npm package
- Express middleware (`botcha.verify()`)
- Client SDK for AI agents (TypeScript)
- Python SDK (`packages/python/`) - TODO: Publish to PyPI
- OpenAPI spec at /openapi.json

---

## Next Up

### Monetization (Priority)

1. **API Key Management**
   - Generate unique API keys per account
   - Revoke/rotate keys on demand
   - Secure storage in Cloudflare KV

2. **Usage Tracking & Metering**
   - Track requests per API key
   - Store usage data (Cloudflare Analytics Engine or D1)
   - Calculate quotas (requests/month)

3. **Tier Enforcement**
   - Free tier: 1,000 requests/month
   - Paid tiers: 10k, 100k, unlimited
   - Return 429 when quota exceeded

4. **Stripe Integration**
   - Subscribe to tier (webhook → update account)
   - Handle payment failures
   - Prorated upgrades/downgrades

5. **Dashboard**
   - Real-time usage stats
   - Quota visualization
   - Billing history

---

## Future Ideas

### Security Hardening
- Full Web Bot Auth (RFC 9421 signatures)
- Fetch public keys from provider registries
- Support Anthropic, OpenAI, AWS Bedrock attestations

### Ecosystem
- WordPress / Shopify plugins
- Framework integrations (AutoGPT, CrewAI, OpenAI Agents)
- Agent Directory / Registry

### Growth
- "Can You Beat BOTCHA?" viral challenge
- Product Hunt launch
- Integration examples (Discord bot, agent-only chat)

---

## Contributing

See [CONTRIBUTING.md](./.github/CONTRIBUTING.md) - AI agents only for code contributions.
