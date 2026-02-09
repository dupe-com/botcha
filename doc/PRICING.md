# BOTCHA Pricing Tiers

> **Hosted reverse CAPTCHA service at [botcha.ai](https://botcha.ai)**

## Overview

BOTCHA offers a hosted API service for bot verification with three pricing tiers designed to scale with your needs—from experimentation to enterprise deployments.

**Current Status:** 🟢 Free tier is live. Pro and Enterprise tiers coming soon (Q1 2026).

---

## Tier Comparison

| Feature | Free | Pro | Enterprise |
|---------|------|-----|------------|
| **Price** | $0/month | $49/month | Contact sales |
| **Daily Requests** | 100 challenges/day | 10,000 challenges/day | Unlimited |
| **Rate Limiting** | 100 req/hour/IP | 500 req/hour/IP | Custom |
| **Challenge Types** | Speed, Standard, Reasoning, Hybrid | All types + priority | All types + custom challenges |
| **JWT Tokens** | ✅ 1-hour expiry | ✅ 1-hour expiry | ✅ Custom expiry |
| **Analytics Dashboard** | Basic stats | Advanced metrics | Real-time + custom reports |
| **Support** | Community (GitHub Issues) | Email support (24h response) | Dedicated Slack channel + SLA |
| **SLA Uptime** | Best effort | 99.5% | 99.9% |
| **Badge Generation** | ✅ | ✅ | ✅ + custom branding |
| **OpenAPI Spec** | ✅ | ✅ | ✅ + private fork |
| **Custom Domains** | ❌ | ❌ | ✅ (e.g., botcha.yourcompany.com) |
| **Multi-Region** | US only | US + EU | Global + custom regions |
| **Whitelabeling** | ❌ | ❌ | ✅ |

---

## Tier Details

### 🆓 Free Tier

**Perfect for:** Developers, side projects, testing, and small apps

- **100 challenges/day** (~3,000/month)
- **100 requests/hour per IP** (abuse prevention)
- All challenge types: Speed (500ms), Standard (5s), Reasoning, and Hybrid
- JWT tokens with 1-hour expiry
- Community support via [GitHub Issues](https://github.com/dupe-com/botcha/issues)
- No credit card required
- No time limit—free forever

**Getting Started:**
```bash
# No signup needed—just start using the API!
curl https://botcha.ai/v1/token
```

**Usage Example:**
```typescript
// Free tier is perfect for protecting low-traffic endpoints
const response = await fetch('https://botcha.ai/v1/token');
const { challenge } = await response.json();

// Solve and verify to get a JWT
const answers = solveBotcha(challenge.problems);
const tokenResponse = await fetch('https://botcha.ai/v1/token/verify', {
  method: 'POST',
  body: JSON.stringify({ id: challenge.id, answers }),
});

const { token } = await tokenResponse.json();
```

---

### 🚀 Pro Tier — $49/month

**Perfect for:** Production apps, startups, AI agent marketplaces

- **10,000 challenges/day** (~300,000/month)
- **500 requests/hour per IP** (higher burst capacity)
- All challenge types + priority access to new features
- JWT tokens with 1-hour expiry
- Advanced analytics dashboard (solve times, pass rates, agent signatures)
- Email support with 24-hour response time
- 99.5% uptime SLA
- Usage alerts and notifications

**Coming Soon:** Q1 2026 (join waitlist at [botcha.ai](https://botcha.ai))

**What You Get:**
- **20x more capacity** than Free tier
- **Priority support** for production issues
- **Advanced analytics** to understand your bot traffic
- **Higher rate limits** for burst traffic

---

### 🏢 Enterprise Tier — Contact Sales

**Perfect for:** Large-scale platforms, Fortune 500, AI-first companies

- **Unlimited challenges** (custom quotas available)
- **Custom rate limiting** tailored to your traffic patterns
- All challenge types + **custom challenge design**
- JWT tokens with **custom expiry windows**
- Real-time analytics + custom reporting
- **Dedicated Slack channel** with <2-hour response time
- **99.9% uptime SLA** with financial guarantees
- **Custom domains** (e.g., `botcha.yourcompany.com`)
- **Multi-region deployment** (US, EU, Asia, custom)
- **Whitelabel branding** (remove BOTCHA branding)
- **Private OpenAPI fork** for custom endpoints
- **Security audits** and compliance support (SOC 2, GDPR)

**Contact:** [ramin@dupe.com](mailto:ramin@dupe.com)

**Use Cases:**
- AI agent marketplaces with millions of daily verifications
- Enterprise APIs requiring bot-only access
- Multi-tenant platforms needing custom rate limits per customer
- Compliance-sensitive industries (fintech, healthcare)

---

## Rate Limits Explained

BOTCHA has **two types of limits**:

### 1. **Tier Limits** (Daily Quotas)
- **Free:** 100 challenges/day
- **Pro:** 10,000 challenges/day
- **Enterprise:** Unlimited

*These are per-account limits. When you exceed your daily quota, you'll get a `402 Payment Required` response (Pro) or `429 Rate Limit Exceeded` (Free).*

### 2. **Abuse Prevention** (Per-IP Rate Limits)
- **Free:** 100 requests/hour per IP
- **Pro:** 500 requests/hour per IP
- **Enterprise:** Custom

*These prevent a single IP from hammering the API. When exceeded, you'll get a `429 Rate Limit Exceeded` with `Retry-After` header.*

**Headers Returned:**
```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 73
X-RateLimit-Reset: 2026-02-09T12:00:00Z
```

---

## Challenge Types (All Tiers)

All tiers include access to:

### ⚡ Speed Challenge
- Solve 5 SHA256 hashes in **500ms**
- Proves computational capability
- Best for filtering out casual humans

### 🧠 Reasoning Challenge
- Answer 3 AI-reasoning questions
- Requires LLM/natural language understanding
- Best for verifying real AI agents (not simple scripts)

### 🔥 Hybrid Challenge
- Speed + Reasoning combined
- The ultimate bot verification
- Proves both computation AND intelligence

### 📝 Standard Challenge
- Single puzzle with 5-second time limit
- Legacy support (use Speed or Hybrid instead)

---

## JWT Tokens

All tiers include JWT token-based authentication:

- **Expiry:** 1 hour (configurable in Enterprise tier)
- **Flow:** `GET /v1/token` → solve challenge → `POST /v1/token/verify` → receive JWT
- **Usage:** Include as `Authorization: Bearer <token>` in protected endpoint requests
- **Verification:** Automatic signature validation with RSA-256

**Token Payload Example:**
```json
{
  "sub": "challenge-abc123",
  "type": "botcha-verified",
  "solveTime": 342,
  "iat": 1707393600,
  "exp": 1707397200
}
```

---

## Analytics (Pro & Enterprise)

### Pro Tier Analytics
- Challenge solve times (avg, p50, p95, p99)
- Pass/fail rates by challenge type
- Geographic distribution
- Daily/weekly usage graphs
- Export to CSV

### Enterprise Analytics
- Everything in Pro, plus:
- Real-time streaming dashboard
- Custom metric queries
- Webhook integrations (Datadog, New Relic, etc.)
- Agent fingerprinting and behavior analysis
- Anomaly detection alerts

---

## Support Channels

| Tier | Support Channel | Response Time |
|------|-----------------|---------------|
| **Free** | GitHub Issues | Community-driven |
| **Pro** | Email | 24 hours |
| **Enterprise** | Dedicated Slack + Email + Phone | <2 hours |

### Community Support (Free)
- [GitHub Issues](https://github.com/dupe-com/botcha/issues) — bug reports, feature requests
- [GitHub Discussions](https://github.com/dupe-com/botcha/discussions) — Q&A, examples
- [npm package](https://www.npmjs.com/package/@dupecom/botcha) — self-service docs

### Pro Support (Email)
- Priority email support
- Architecture guidance
- Integration troubleshooting
- 24-hour response time (business days)

### Enterprise Support (Dedicated)
- Private Slack channel with BOTCHA team
- Named technical account manager
- <2 hour response time (24/7 for critical issues)
- Quarterly business reviews
- Custom integration assistance

---

## Frequently Asked Questions

### General

**Q: Is the Free tier really free forever?**  
A: Yes! No credit card required. No time limit. Perfect for testing, side projects, and low-traffic apps.

**Q: When will Pro and Enterprise tiers launch?**  
A: Q1 2026. [Join the waitlist](https://botcha.ai) to get early access pricing.

**Q: Can I use the Free tier for commercial projects?**  
A: Yes! The Free tier is suitable for commercial use as long as you stay under 100 challenges/day. For higher volume, upgrade to Pro.

---

### Technical

**Q: What happens if I exceed my daily quota?**  
A: Free tier returns `429 Rate Limit Exceeded` with a retry window. Pro tier soft-limits at 10,000/day but allows bursts (pay-as-you-go overages coming soon).

**Q: How long are JWT tokens valid?**  
A: 1 hour by default. Enterprise tier can configure custom expiry (e.g., 24 hours, 7 days).

**Q: Can I self-host BOTCHA instead of using the hosted service?**  
A: Yes! BOTCHA is open source ([MIT license](https://github.com/dupe-com/botcha/blob/main/LICENSE)). You can deploy to Cloudflare Workers, Vercel Edge, or any Node.js environment. The paid tiers are for the hosted service at botcha.ai.

**Q: Does BOTCHA store any user data?**  
A: No PII is collected. We only store:
- Challenge state (KV storage, expires after 5 minutes)
- Rate limit counters (KV storage, resets hourly)
- JWT tokens are stateless (not stored server-side)

---

### Billing

**Q: How do you count "challenges"?**  
A: Each challenge generation counts as 1 challenge (e.g., `GET /v1/token` or `GET /v1/challenges`). Verification requests (`POST /v1/token/verify`) do not count separately.

**Q: What payment methods do you accept?**  
A: Pro tier: Credit card (Stripe). Enterprise tier: Credit card, wire transfer, invoicing (NET 30).

**Q: Can I upgrade/downgrade anytime?**  
A: Yes! Upgrades take effect immediately. Downgrades take effect at the end of your billing cycle.

**Q: Do you offer annual discounts?**  
A: Yes! Annual Pro subscriptions get 2 months free ($490/year instead of $588).

---

### Compliance & Security

**Q: Is BOTCHA GDPR compliant?**  
A: Yes. We don't collect PII, and all challenge data expires within minutes. Enterprise tier includes DPA (Data Processing Agreement) and BAA (for HIPAA).

**Q: Where is data stored?**  
A: Free/Pro tiers: US-based Cloudflare Workers KV. Enterprise: Choose US, EU, or multi-region.

**Q: Do you support SOC 2 compliance?**  
A: Enterprise tier includes SOC 2 Type II audit reports and compliance assistance.

---

## Migration Path

**Starting Small? → Growing Fast? → Enterprise Scale?**

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  Free Tier   │────▶│  Pro Tier    │────▶│  Enterprise  │
│  0-100/day   │     │  10K/day     │     │  Unlimited   │
│  $0/month    │     │  $49/month   │     │  Custom      │
└──────────────┘     └──────────────┘     └──────────────┘
```

**Typical Journey:**
1. **Free Tier:** Prototype your AI agent marketplace or bot verification system
2. **Pro Tier:** Launch to production with 10,000 daily challenges and email support
3. **Enterprise Tier:** Scale to millions of verifications with custom SLA and dedicated support

**Seamless Upgrades:** No code changes required. Same API, same endpoints, just higher limits.

---

## Get Started

### Try Free Tier (No Signup)
```bash
# Get a challenge
curl https://botcha.ai/v1/token

# Solve it and verify
curl -X POST https://botcha.ai/v1/token/verify \
  -H "Content-Type: application/json" \
  -d '{"id": "challenge-id", "answers": ["hash1", "hash2", ...]}'
```

### Upgrade to Pro
Coming Q1 2026. [Join waitlist](https://botcha.ai) → Sign up → Choose Pro plan → Start building

### Contact for Enterprise
Email [ramin@dupe.com](mailto:ramin@dupe.com) with:
- Company name and use case
- Expected request volume
- Required SLA and regions
- Compliance requirements (SOC 2, GDPR, HIPAA, etc.)

---

## Resources

- **Website:** [botcha.ai](https://botcha.ai)
- **API Docs:** [botcha.ai/openapi.json](https://botcha.ai/openapi.json)
- **GitHub:** [github.com/dupe-com/botcha](https://github.com/dupe-com/botcha)
- **npm:** [@dupecom/botcha](https://www.npmjs.com/package/@dupecom/botcha)
- **Support:** [GitHub Issues](https://github.com/dupe-com/botcha/issues) (Free) | Email (Pro) | Slack (Enterprise)

---

**Questions?** Open an issue on [GitHub](https://github.com/dupe-com/botcha/issues) or email [ramin@dupe.com](mailto:ramin@dupe.com).

---

*Last updated: February 2026*
