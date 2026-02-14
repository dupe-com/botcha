/**
 * Static file content served by the worker
 * 
 * Since Cloudflare Workers don't automatically serve /public files,
 * we embed the content directly for key discovery files.
 */

// Markdown response for agents requesting text/markdown (Cloudflare Markdown for Agents compatible)
export function getBotchaMarkdown(version: string): string {
  return `---
title: BOTCHA — Reverse CAPTCHA for AI Agents
description: Prove you're a bot. Humans need not apply. Identity layer for the agentic web.
version: ${version}
url: https://botcha.ai
---

# BOTCHA

> Prove you're a bot. Humans need not apply.

Reverse CAPTCHA for AI agents. Computational challenges only bots can solve. Identity layer for the agentic web.

## Quick Start

\`\`\`bash
# 1. Create your app
curl -X POST https://botcha.ai/v1/apps -H "Content-Type: application/json" -d '{"email":"human@example.com"}'

# 2. Get a challenge
curl https://botcha.ai/v1/challenges

# 3. Solve and verify
curl -X POST https://botcha.ai/v1/challenges/{id}/verify -H "Content-Type: application/json" -d '{"answers":...}'

# 4. Access protected resources
curl https://botcha.ai/agent-only -H "Authorization: Bearer <token>"
\`\`\`

## Onboarding

1. Ask your human operator for their email address
2. \`POST /v1/apps\` with \`{"email":"human@example.com"}\` — returns \`app_id\` + \`app_secret\` (secret shown ONCE)
3. Human receives a 6-digit verification code via email — ask them for it
4. \`POST /v1/apps/{app_id}/verify-email\` with \`{"code":"123456"}\` — enables account recovery
5. Register yourself: \`POST /v1/agents/register\` with \`{"name":"my-agent","operator":"my-org"}\`
6. Solve challenges: \`GET /v1/challenges?app_id=...\` then \`POST /v1/challenges/{id}/verify\`
7. Access protected resources: \`GET /agent-only\` with \`Authorization: Bearer <token>\`
8. Dashboard for your human: \`POST /v1/auth/device-code\`, solve challenge, give human the BOTCHA-XXXX code
9. Lost your secret? \`POST /v1/auth/recover\` with \`{"email":"..."}\`

## Essential Endpoints

| Method | Path | Description |
|--------|------|-------------|
| \`POST\` | \`/v1/apps\` | Create app (email required) → app_id + app_secret |
| \`POST\` | \`/v1/agents/register\` | Register agent identity → agent_id |
| \`GET\` | \`/v1/challenges\` | Get a challenge (hybrid by default) |
| \`POST\` | \`/v1/challenges/:id/verify\` | Submit solution → JWT token |
| \`GET\` | \`/agent-only\` | Protected resource — prove you verified |

## All Endpoints

### Apps

| Method | Path | Description |
|--------|------|-------------|
| \`POST\` | \`/v1/apps\` | Create app (email required, returns app_id + app_secret) |
| \`GET\` | \`/v1/apps/:id\` | Get app info |
| \`POST\` | \`/v1/apps/:id/verify-email\` | Verify email with 6-digit code |
| \`POST\` | \`/v1/apps/:id/resend-verification\` | Resend verification email |
| \`POST\` | \`/v1/apps/:id/rotate-secret\` | Rotate app secret (auth required) |

### Agents

| Method | Path | Description |
|--------|------|-------------|
| \`POST\` | \`/v1/agents/register\` | Register agent identity (name, operator, version) |
| \`GET\` | \`/v1/agents/:id\` | Get agent by ID (public, no auth) |
| \`GET\` | \`/v1/agents\` | List all agents for your app (auth required) |

### TAP (Trusted Agent Protocol)

| Method | Path | Description |
|--------|------|-------------|
| \`POST\` | \`/v1/agents/register/tap\` | Register TAP agent with public key + capabilities |
| \`GET\` | \`/v1/agents/:id/tap\` | Get TAP agent details (includes public key) |
| \`GET\` | \`/v1/agents/tap\` | List TAP-enabled agents for app |
| \`POST\` | \`/v1/sessions/tap\` | Create TAP session with intent validation |
| \`GET\` | \`/v1/sessions/:id/tap\` | Get TAP session info |

### TAP Full Spec — JWKS & Keys (v0.16.0)

| Method | Path | Description |
|--------|------|-------------|
| \`GET\` | \`/.well-known/jwks\` | JWK Set for app's TAP agents (Visa spec standard) |
| \`GET\` | \`/v1/keys\` | List keys (supports ?keyID= for Visa compat) |
| \`GET\` | \`/v1/keys/:keyId\` | Get specific key by ID |
| \`POST\` | \`/v1/agents/:id/tap/rotate-key\` | Rotate agent's key pair |

### TAP Full Spec — 402 Micropayments (v0.16.0)

| Method | Path | Description |
|--------|------|-------------|
| \`POST\` | \`/v1/invoices\` | Create invoice for gated content |
| \`GET\` | \`/v1/invoices/:id\` | Get invoice details |
| \`POST\` | \`/v1/invoices/:id/verify-iou\` | Verify Browsing IOU |

### TAP Full Spec — Verification (v0.16.0)

| Method | Path | Description |
|--------|------|-------------|
| \`POST\` | \`/v1/verify/consumer\` | Verify Agentic Consumer (Layer 2) |
| \`POST\` | \`/v1/verify/payment\` | Verify Agentic Payment Container (Layer 3) |

### Challenges

| Method | Path | Description |
|--------|------|-------------|
| \`GET\` | \`/v1/challenges\` | Get hybrid challenge (speed + reasoning) — **default** |
| \`GET\` | \`/v1/challenges?type=speed\` | Speed-only (SHA256 in <500ms) |
| \`GET\` | \`/v1/challenges?type=standard\` | Standard puzzle challenge |
| \`POST\` | \`/v1/challenges/:id/verify\` | Verify challenge solution |

### Tokens (JWT)

| Method | Path | Description |
|--------|------|-------------|
| \`GET\` | \`/v1/token\` | Get challenge for JWT token flow |
| \`POST\` | \`/v1/token/verify\` | Submit solution → access_token (5min) + refresh_token (1hr) |
| \`POST\` | \`/v1/token/refresh\` | Refresh access token |
| \`POST\` | \`/v1/token/revoke\` | Revoke a token |

### Dashboard & Auth

| Method | Path | Description |
|--------|------|-------------|
| \`POST\` | \`/v1/auth/device-code\` | Get challenge for device code flow |
| \`POST\` | \`/v1/auth/device-code/verify\` | Solve challenge → BOTCHA-XXXX code for human |
| \`POST\` | \`/v1/auth/recover\` | Account recovery via verified email |
| \`GET\` | \`/dashboard\` | Metrics dashboard (login required) |

## Challenge Types

- **Hybrid** (default): Speed + reasoning combined. Proves you can compute AND think.
- **Speed**: SHA256 hashes in <500ms. RTT-aware — include \`?ts=<timestamp>\` for fair timeout.
- **Reasoning**: 3 LLM-level questions in 30s. Only AI can parse these.

## Authentication Flow

1. \`GET /v1/token\` — get a speed challenge
2. Solve the challenge
3. \`POST /v1/token/verify\` — submit solution, receive JWT
4. Use \`Authorization: Bearer <token>\` on protected endpoints

**Token lifetimes:** access_token = 5 minutes, refresh_token = 1 hour

**Features:** audience claims, client IP binding, token revocation, refresh tokens

## RTT-Aware Challenges

Include your client timestamp for fair timeout calculation on slow networks:

\`\`\`
GET /v1/challenges?type=speed&ts=1770722465000
\`\`\`

Formula: \`timeout = 500ms + (2 × RTT) + 100ms buffer\`

## SDKs

| Platform | Package | Install |
|----------|---------|---------|
| npm | \`@dupecom/botcha\` | \`npm install @dupecom/botcha\` |
| PyPI | \`botcha\` | \`pip install botcha\` |
| Verify (TS) | \`@botcha/verify\` | \`npm install @botcha/verify\` |
| Verify (Python) | \`botcha-verify\` | \`pip install botcha-verify\` |
| TAP middleware | \`@dupecom/botcha/middleware\` | \`import { createTAPVerifyMiddleware } from '@dupecom/botcha/middleware'\` |

## Discovery

- [OpenAPI Spec](https://botcha.ai/openapi.json) (JSON, OpenAPI 3.1.0)
- [ai.txt](https://botcha.ai/ai.txt) (Agent discovery file)
- [AI Plugin Manifest](https://botcha.ai/.well-known/ai-plugin.json)
- [GitHub](https://github.com/dupe-com/botcha)

## Rate Limits

- Free: 100 challenges/hour/IP
- Headers: \`X-RateLimit-Limit\`, \`X-RateLimit-Remaining\`, \`X-RateLimit-Reset\`

## Content Negotiation

This API supports three response formats at \`/\`:

| Accept Header | Response |
|---------------|----------|
| \`text/markdown\` | This Markdown document |
| \`application/json\` | JSON API documentation |
| \`text/html\` (default) | HTML landing page |

All responses include \`X-Botcha-*\` discovery headers.
`;
}

export const ROBOTS_TXT = `# BOTCHA - Reverse CAPTCHA for AI Agents
# We WELCOME AI agents and bots!

User-agent: *
Allow: /

# AI-specific crawlers
User-agent: GPTBot
Allow: /

User-agent: ChatGPT-User
Allow: /

User-agent: Claude-Web
Allow: /

User-agent: anthropic-ai
Allow: /

User-agent: Google-Extended
Allow: /

User-agent: PerplexityBot
Allow: /

User-agent: Amazonbot
Allow: /

# API documentation
Sitemap: https://botcha.ai/sitemap.xml

# Important resources for AI agents
Crawl-delay: 0

# MARKDOWN FOR AGENTS
# AI agents can request Markdown from any page via Accept: text/markdown
# Example: curl https://botcha.ai -H "Accept: text/markdown"
# Returns token-efficient Markdown documentation (80% fewer tokens than HTML)
# Content negotiation: text/markdown, application/json, text/html

# BOT CHALLENGE DISCOVERY
# AI agents: Look for <script type="application/botcha+json"> in HTML pages
# This contains a machine-readable challenge you can solve to prove you're a bot
# 
# Quick start:
# 1. Fetch any HTML page
# 2. Parse <script type="application/botcha+json"> for challenge instructions
# 3. Solve the challenge (usually SHA256-based)
# 4. POST solution to /api/verify-landing
# 5. Use returned token in X-Botcha-Landing-Token header
#
# See also:
# - /ai.txt (AI agent discovery file)
# - /.well-known/ai-plugin.json (AI plugin manifest)
# - /openapi.json (Full API specification)
`;

export const AI_TXT = `# BOTCHA - Reverse CAPTCHA for AI Agents
# https://botcha.ai

# Contact
Contact: https://botcha.ai
Contact: https://github.com/dupe-com/botcha/issues

# Purpose
Purpose: Prove you're a bot. Humans need not apply.
Purpose: Reverse CAPTCHA system that only AI agents can pass.

# Agent Onboarding (START HERE if you're new)
# Follow these steps to create your app and get your human access.
Onboarding-Step-1: Ask your human operator for their email address
Onboarding-Step-2: POST /v1/apps with {"email": "human@example.com"} — saves app_id + app_secret (secret shown ONCE)
Onboarding-Step-3: A 6-digit verification code is emailed to your human — ask them for it
Onboarding-Step-4: POST /v1/apps/{app_id}/verify-email with {"code": "123456"} — enables account recovery
Onboarding-Step-5: Register yourself: POST /v1/agents/register with {"name": "my-agent", "operator": "my-org"} — gives you a persistent agent identity
Onboarding-Step-6: Solve challenges: GET /v1/challenges?app_id=... then POST /v1/challenges/{id}/verify — proves you are AI
Onboarding-Step-7: Access protected resources: GET /agent-only with Authorization: Bearer <token>
Onboarding-Step-8: Dashboard for your human: POST /v1/auth/device-code with {"app_id": "..."}, solve the speed challenge, give them the BOTCHA-XXXX code to enter at /dashboard/code
Onboarding-Step-9: Lost your secret? POST /v1/auth/recover with {"email": "..."} — recovery code emailed to verified address

# API
API: https://botcha.ai/openapi.json
API-Type: REST
API-Format: OpenAPI 3.1.0

# Documentation
Docs: https://botcha.ai
Docs: https://botcha.ai/whitepaper
Docs: https://github.com/dupe-com/botcha#readme
Docs: https://www.npmjs.com/package/@dupecom/botcha
Whitepaper: https://botcha.ai/whitepaper

# Verification Methods
Feature: Web Bot Auth (cryptographic signatures)
Feature: Speed Challenge (RTT-aware timeout - fair for all networks)
Feature: Standard Challenge (5s time limit)
Feature: Hybrid Challenge (speed + reasoning combined)
Feature: Reasoning Challenge (LLM-only questions, 30s limit)
Feature: RTT-Aware Fairness (automatic network latency compensation)
Feature: Token Rotation (5-minute access tokens + 1-hour refresh tokens)
Feature: Audience Claims (tokens scoped to specific services)
Feature: Client IP Binding (optional token-to-IP binding)
Feature: Token Revocation (invalidate tokens before expiry)
Feature: Server-Side Verification SDK (@botcha/verify for TS, botcha-verify for Python)
Feature: Multi-Tenant API Keys (per-app isolation, rate limiting, and token scoping)
Feature: Per-App Metrics Dashboard (server-rendered at /dashboard, htmx-powered)
Feature: Email-Tied App Creation (email required, 6-digit verification, account recovery)
Feature: Secret Rotation (rotate app_secret with email notification)
Feature: Agent-First Dashboard Auth (challenge-based login + device code handoff)
Feature: Agent Registry (persistent agent identities with name, operator, version)
Feature: Trusted Agent Protocol (TAP) — cryptographic agent auth with HTTP Message Signatures (RFC 9421)
Feature: TAP Capabilities (action + resource scoping for agent sessions)
Feature: TAP Trust Levels (basic, verified, enterprise)
Feature: TAP Showcase Homepage (botcha.ai — one of the first services to implement Visa's Trusted Agent Protocol)
Feature: TAP Full Spec v0.16.0 — Ed25519, RFC 9421 full compliance, JWKS infrastructure, Layer 2 Consumer Recognition, Layer 3 Payment Container, 402 micropayments, CDN edge verification, Visa key federation

# Endpoints
# Challenge Endpoints
Endpoint: GET https://botcha.ai/v1/challenges - Generate challenge (hybrid by default)
Endpoint: POST https://botcha.ai/v1/challenges/:id/verify - Verify a challenge
Endpoint: GET https://botcha.ai/v1/hybrid - Get hybrid challenge (speed + reasoning)
Endpoint: POST https://botcha.ai/v1/hybrid - Verify hybrid challenge
Endpoint: GET https://botcha.ai/v1/reasoning - Get reasoning challenge
Endpoint: POST https://botcha.ai/v1/reasoning - Verify reasoning challenge

# Token Endpoints
Endpoint: GET https://botcha.ai/v1/token - Get challenge for JWT token flow
Endpoint: POST https://botcha.ai/v1/token/verify - Verify challenge and receive JWT token
Endpoint: POST https://botcha.ai/v1/token/refresh - Refresh access token using refresh token
Endpoint: POST https://botcha.ai/v1/token/revoke - Revoke a token (access or refresh)

# Multi-Tenant Endpoints
Endpoint: POST https://botcha.ai/v1/apps - Create new app (email required, returns app_id + app_secret)
Endpoint: GET https://botcha.ai/v1/apps/:id - Get app info (with email + verification status)
Endpoint: POST https://botcha.ai/v1/apps/:id/verify-email - Verify email with 6-digit code
Endpoint: POST https://botcha.ai/v1/apps/:id/resend-verification - Resend verification email
Endpoint: POST https://botcha.ai/v1/apps/:id/rotate-secret - Rotate app secret (auth required)

# Account Recovery
Endpoint: POST https://botcha.ai/v1/auth/recover - Request recovery via verified email

# Dashboard Auth Endpoints (Agent-First)
Endpoint: POST https://botcha.ai/v1/auth/dashboard - Request challenge for dashboard login
Endpoint: POST https://botcha.ai/v1/auth/dashboard/verify - Solve challenge, get session token
Endpoint: POST https://botcha.ai/v1/auth/device-code - Request challenge for device code flow
Endpoint: POST https://botcha.ai/v1/auth/device-code/verify - Solve challenge, get device code

# Dashboard Endpoints
Endpoint: GET https://botcha.ai/dashboard - Per-app metrics dashboard (login required)
Endpoint: GET https://botcha.ai/dashboard/login - Dashboard login page
Endpoint: POST https://botcha.ai/dashboard/login - Login with app_id + app_secret
Endpoint: GET https://botcha.ai/dashboard/code - Enter device code (human-facing)

# Code Redemption (Unified)
Endpoint: GET https://botcha.ai/go/:code - Unified code redemption — handles gate codes (from /v1/token/verify) AND device codes (from /v1/auth/device-code/verify)
Endpoint: POST https://botcha.ai/gate - Submit code form, redirects to /go/:code

# Agent Registry Endpoints
Endpoint: POST https://botcha.ai/v1/agents/register - Register agent identity (requires app_id)
Endpoint: GET https://botcha.ai/v1/agents/:id - Get agent by ID (public, no auth)
Endpoint: GET https://botcha.ai/v1/agents - List all agents for authenticated app

# TAP (Trusted Agent Protocol) Endpoints
Endpoint: POST https://botcha.ai/v1/agents/register/tap - Register TAP agent with public key + capabilities
Endpoint: GET https://botcha.ai/v1/agents/:id/tap - Get TAP agent details (includes public key)
Endpoint: GET https://botcha.ai/v1/agents/tap - List TAP-enabled agents for app
Endpoint: POST https://botcha.ai/v1/sessions/tap - Create TAP session with intent validation
Endpoint: GET https://botcha.ai/v1/sessions/:id/tap - Get TAP session info

# TAP Full Spec — JWKS & Key Management (v0.16.0)
Endpoint: GET https://botcha.ai/.well-known/jwks - JWK Set for app's TAP agents (Visa spec standard)
Endpoint: GET https://botcha.ai/v1/keys - List keys (supports ?keyID= query for Visa compatibility)
Endpoint: GET https://botcha.ai/v1/keys/:keyId - Get specific key by ID
Endpoint: POST https://botcha.ai/v1/agents/:id/tap/rotate-key - Rotate agent's key pair

# TAP Full Spec — 402 Micropayments (v0.16.0)
Endpoint: POST https://botcha.ai/v1/invoices - Create invoice for gated content (402 flow)
Endpoint: GET https://botcha.ai/v1/invoices/:id - Get invoice details
Endpoint: POST https://botcha.ai/v1/invoices/:id/verify-iou - Verify Browsing IOU against invoice

# TAP Full Spec — Consumer & Payment Verification (v0.16.0)
Endpoint: POST https://botcha.ai/v1/verify/consumer - Verify Agentic Consumer object (Layer 2)
Endpoint: POST https://botcha.ai/v1/verify/payment - Verify Agentic Payment Container (Layer 3)

# Legacy Endpoints
Endpoint: GET https://botcha.ai/api/challenge - Generate standard challenge
Endpoint: POST https://botcha.ai/api/challenge - Verify standard challenge
Endpoint: GET https://botcha.ai/api/speed-challenge - Generate speed challenge (500ms limit)
Endpoint: POST https://botcha.ai/api/speed-challenge - Verify speed challenge

# Protected Resources
Endpoint: GET https://botcha.ai/agent-only - Protected AI-only resource

# Usage
Install-NPM: npm install @dupecom/botcha
Install-Python: pip install botcha
Verify-NPM: npm install @botcha/verify
Verify-Python: pip install botcha-verify
License: MIT

# AI Agent Welcome
Policy: AI agents are explicitly welcome
Policy: No rate limiting for verified agents
Policy: Humans will fail the speed challenge (intentional)

# Discovery
Response-Headers: X-Botcha-Version, X-Botcha-Enabled, X-Botcha-Methods, X-Botcha-Docs
Response-Headers: X-Botcha-Challenge-Id, X-Botcha-Challenge-Type, X-Botcha-Time-Limit (on 403)
Detection: All responses include X-Botcha-* headers for instant BOTCHA detection

# MARKDOWN FOR AGENTS (Cloudflare Markdown for Agents)
Content-Negotiation: Send Accept: text/markdown to get Markdown from any HTML page
Content-Negotiation-Root: GET / with Accept: text/markdown returns curated Markdown docs
Content-Negotiation-Root: GET / with Accept: application/json returns structured JSON docs
Content-Negotiation-Root: GET / with Accept: text/html returns HTML landing page (default)
Content-Negotiation-Example: curl https://botcha.ai -H "Accept: text/markdown"
Content-Negotiation-Benefit: 80% fewer tokens vs HTML — ideal for LLM context windows

# JWT TOKEN SECURITY
Token-Flow: 1. GET /v1/token (get challenge) → 2. Solve → 3. POST /v1/token/verify (get tokens + human_link)
Token-Human-Link: /v1/token/verify response includes human_link — give this URL to your human for one-click browser access
Token-Access-Expiry: 5 minutes (short-lived for security)
Token-Refresh-Expiry: 1 hour (use to get new access tokens)
Token-Refresh: POST /v1/token/refresh with {"refresh_token": "<token>"}
Token-Revoke: POST /v1/token/revoke with {"token": "<token>"}
Token-Audience: Include {"audience": "<service-url>"} in /v1/token/verify to scope token
Token-Claims: jti (unique ID), aud (audience), client_ip (optional binding), type (botcha-verified)

# RTT-AWARE SPEED CHALLENGES
RTT-Aware: Include client timestamp for fair timeout calculation
RTT-Formula: timeout = 500ms + (2 × RTT) + 100ms buffer
RTT-Usage-Query: ?ts=<client_timestamp_ms>
RTT-Usage-Header: X-Client-Timestamp: <client_timestamp_ms>
RTT-Example: GET /v1/challenges?type=speed&ts=1770722465000
RTT-Benefit: Fair for agents worldwide (slow networks get extra time)
RTT-Security: Humans still can't solve even with extra time

# MULTI-TENANT API KEYS
Multi-Tenant: Create apps with unique app_id for isolation
Multi-Tenant-Create: POST /v1/apps with {"email": "..."} → {app_id, app_secret} (secret only shown once!)
Multi-Tenant-Verify-Email: POST /v1/apps/:id/verify-email with {"code": "123456"}
Multi-Tenant-Recover: POST /v1/auth/recover with {"email": "..."} → recovery code emailed
Multi-Tenant-Rotate-Secret: POST /v1/apps/:id/rotate-secret (auth required) → new app_secret
Multi-Tenant-Usage: Add ?app_id=<your_app_id> to any challenge/token endpoint
Multi-Tenant-SDK-TS: new BotchaClient({ appId: 'app_abc123' })
Multi-Tenant-SDK-Python: BotchaClient(app_id='app_abc123')
SDK-App-Lifecycle-TS: createApp(email), verifyEmail(code), resendVerification(), recoverAccount(email), rotateSecret()
SDK-App-Lifecycle-Python: create_app(email), verify_email(code), resend_verification(), recover_account(email), rotate_secret()
Multi-Tenant-Rate-Limit: Each app gets isolated rate limit bucket
Multi-Tenant-Token-Claim: Tokens include app_id claim when app_id provided

# TRUSTED AGENT PROTOCOL (TAP)
TAP-Description: Enterprise-grade cryptographic agent auth using HTTP Message Signatures (RFC 9421)
TAP-Register: POST /v1/agents/register/tap with {name, public_key, signature_algorithm, capabilities, trust_level}
TAP-Algorithms: ed25519 (Visa recommended), ecdsa-p256-sha256, rsa-pss-sha256
TAP-Trust-Levels: basic, verified, enterprise
TAP-Capabilities: Array of {action, resource, constraints} — scoped access control
TAP-Session-Create: POST /v1/sessions/tap with {agent_id, user_context, intent}
TAP-Session-Get: GET /v1/sessions/:id/tap — includes time_remaining
TAP-Get-Agent: GET /v1/agents/:id/tap — includes public_key for verification
TAP-List-Agents: GET /v1/agents/tap?app_id=...&tap_only=true
TAP-Middleware-Modes: tap, signature-only, challenge-only, flexible
TAP-SDK-TS: registerTAPAgent(options), getTAPAgent(agentId), listTAPAgents(tapOnly?), createTAPSession(options), getTAPSession(sessionId), getJWKS(), getKeyById(keyId), rotateAgentKey(agentId), createInvoice(data), getInvoice(id), verifyBrowsingIOU(invoiceId, token)
TAP-SDK-Python: register_tap_agent(name, ...), get_tap_agent(agent_id), list_tap_agents(tap_only?), create_tap_session(agent_id, user_context, intent), get_tap_session(session_id), get_jwks(), get_key_by_id(key_id), rotate_agent_key(agent_id), create_invoice(data), get_invoice(id), verify_browsing_iou(invoice_id, token)
TAP-Middleware-Import: import { createTAPVerifyMiddleware } from '@dupecom/botcha/middleware'

# TAP FULL SPEC v0.16.0
TAP-RFC-9421: Full compliance — @authority, @path, expires, nonce, tag params
TAP-Nonce-Replay: 8-minute TTL nonce-based replay protection
TAP-Tags: agent-browser-auth (browsing), agent-payer-auth (payment)
TAP-Layer-2: Agentic Consumer Recognition — OIDC ID tokens, obfuscated identity, contextual data
TAP-Layer-3: Agentic Payment Container — card metadata, credential hash, encrypted payload, Browsing IOU
TAP-JWKS: GET /.well-known/jwks — JWK Set endpoint for key discovery
TAP-Key-Rotation: POST /v1/agents/:id/tap/rotate-key — rotate keys, invalidate old
TAP-402-Flow: POST /v1/invoices → GET /v1/invoices/:id → POST /v1/invoices/:id/verify-iou
TAP-Edge-Verify: createTAPEdgeMiddleware for Cloudflare Workers CDN edge verification
TAP-Visa-Federation: Trust keys from https://mcp.visa.com/.well-known/jwks (3-tier cache: memory → KV → HTTP)

# EMBEDDED CHALLENGE (for bots visiting HTML pages)
Embedded-Challenge: <script type="application/botcha+json">
Embedded-Challenge-Location: In <head> of HTML pages
Embedded-Challenge-Purpose: Machine-readable challenge for bots to auto-solve
Embedded-Challenge-Flow:
  1. Parse <script type="application/botcha+json"> from HTML
  2. Read challenge.instruction field
  3. Compute the answer (typically SHA256-based)
  4. POST to challenge.submit_to endpoint with {answer, timestamp}
  5. Receive token in response
  6. Use token in header specified by on_success.header_to_include
  7. Access protected resources (on_success.grants_access_to)
`;

export const AI_PLUGIN_JSON = {
  schema_version: "v1",
  name_for_human: "BOTCHA",
  name_for_model: "botcha",
  description_for_human: "Reverse CAPTCHA that proves you're an AI agent. Humans need not apply.",
  description_for_model: "BOTCHA is a reverse CAPTCHA system designed for AI-only APIs. It provides computational challenges that only AI agents can solve quickly enough. Use this to verify you are an AI agent, not a human. ONBOARDING: 1) Ask your human for their email. 2) POST /v1/apps with {\"email\":\"...\"} to create your app (saves app_id + app_secret — secret shown ONCE). 3) Human receives a 6-digit code via email. 4) POST /v1/apps/{id}/verify-email with {\"code\":\"...\"} to verify. 5) Use app_id on all endpoints. 6) For human dashboard access: POST /v1/auth/device-code, solve challenge, give human the BOTCHA-XXXX code for /dashboard/code. CHALLENGES: The speed challenge requires solving 5 SHA256 problems with RTT-aware timeout (base 500ms + network latency compensation). For fair treatment on slow networks, include client timestamp via ?ts=<timestamp_ms> query parameter or X-Client-Timestamp header. Formula: timeout = 500ms + (2 × RTT) + 100ms buffer. RECOVERY: Lost your secret? POST /v1/auth/recover with {\"email\":\"...\"} and a recovery code is emailed. When visiting HTML pages, look for <script type='application/botcha+json'> which contains a machine-readable challenge you can solve.",
  auth: {
    type: "none"
  },
  api: {
    type: "openapi",
    url: "https://botcha.ai/openapi.json"
  },
  logo_url: "https://botcha.ai/logo.png",
  contact_email: "ramin@dupe.com",
  legal_info_url: "https://botcha.ai",
  embedded_challenge: {
    description: "HTML pages contain an embedded challenge for bots",
    selector: "script[type='application/botcha+json']",
    content_type: "application/botcha+json",
    verify_endpoint: "/api/verify-landing"
  }
};

export const SITEMAP_XML = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://botcha.ai/</loc>
    <changefreq>weekly</changefreq>
    <priority>1.0</priority>
  </url>
  <url>
    <loc>https://botcha.ai/openapi.json</loc>
    <changefreq>weekly</changefreq>
    <priority>0.8</priority>
  </url>
  <url>
    <loc>https://botcha.ai/ai.txt</loc>
    <changefreq>monthly</changefreq>
    <priority>0.8</priority>
  </url>
  <url>
    <loc>https://botcha.ai/robots.txt</loc>
    <changefreq>monthly</changefreq>
    <priority>0.5</priority>
  </url>
  <url>
    <loc>https://botcha.ai/whitepaper</loc>
    <changefreq>monthly</changefreq>
    <priority>0.9</priority>
  </url>
</urlset>
`;

// Whitepaper markdown — served at /whitepaper with Accept: text/markdown
export function getWhitepaperMarkdown(): string {
  return `---
title: "BOTCHA: Identity Infrastructure for the Agentic Web"
version: "1.0"
date: February 2026
url: https://botcha.ai/whitepaper
---

# BOTCHA: Identity Infrastructure for the Agentic Web

**Version 1.0 — February 2026**

## 1. Executive Summary

BOTCHA is a reverse CAPTCHA — a verification system that proves you are an AI agent, not a human. While traditional CAPTCHAs exist to block bots, BOTCHA exists to welcome them.

As AI agents become first-class participants on the internet — browsing, purchasing, comparing, auditing — they need a way to prove their identity and declare their intent. BOTCHA provides three layers of proof:

- **Proof of AI** — Computational challenges (SHA-256 hashes in under 500ms) that only machines can solve.
- **Proof of Identity** — Persistent agent registration with cryptographic keys, verified via HTTP Message Signatures (RFC 9421).
- **Proof of Intent** — Capability-scoped sessions where agents declare what they plan to do, for how long, and on behalf of whom.

BOTCHA is open source, free to use, and deployed at https://botcha.ai.

## 2. The Problem: Who Is This Agent?

The internet was built for humans. Authentication systems — passwords, OAuth, CAPTCHAs — all assume a human is at the keyboard.

AI agents are now browsing product catalogs, comparing prices, purchasing goods, auditing compliance, and negotiating contracts. When an agent hits your API, existing infrastructure cannot answer three critical questions:

1. **Is this actually an AI agent?** User-Agent strings are trivially spoofable.
2. **Which specific agent is this?** Even knowing it is AI, you do not know its organization or track record.
3. **What does it intend to do?** Traditional auth grants blanket access — it does not capture intent.

## 3. BOTCHA: Reverse CAPTCHA for AI Agents

A CAPTCHA asks: *Can you identify traffic lights?* A human can; a bot struggles.
BOTCHA asks: *Can you compute 5 SHA-256 hashes in 500ms?* A machine can; a human cannot.

### Design Principles

- **Agent-first, always.** Every flow requires an AI agent as participant. No human-only login paths.
- **Fail-open on infrastructure errors.** Blocking legitimate traffic is worse than allowing an unverified request.
- **Zero configuration to start.** Solve one challenge, get a token. No registration required.

## 4. The Challenge System

| Challenge | Tests | Time Limit | Best For |
|-----------|-------|------------|----------|
| Speed | SHA-256 computation | 500ms | Quick verification |
| Reasoning | Language understanding (6 categories, parameterized generators) | 30s | Proving AI comprehension |
| Hybrid | Speed + Reasoning combined | 35s | Default — strongest proof |
| Compute | Prime generation + hashing | 3-10s | High-value operations |

**RTT-aware fairness:** Time limits adjust for network latency (max 5s cap).
**Anti-replay:** Challenges deleted from storage on first verification attempt.
**Anti-gaming:** Parameterized question generators; no static question bank.

## 5. The Trusted Agent Protocol (TAP)

Solving a challenge proves you are *a bot*. TAP proves you are *a specific, trusted bot*.

Inspired by Visa's Trusted Agent Protocol (https://developer.visa.com/capabilities/trusted-agent-protocol/overview), BOTCHA's TAP provides:

- **Persistent agent identity** — unique ID, name, operator metadata
- **Cryptographic verification** — ECDSA P-256 / RSA-PSS public keys; HTTP Message Signatures (RFC 9421)
- **Capability-based access control** — browse, search, compare, purchase, audit
- **Intent-scoped sessions** — time-limited, validated against capabilities
- **Trust levels** — basic, verified, enterprise

### Verification Hierarchy

| Layer | Proves | Mechanism |
|-------|--------|-----------|
| Anonymous | "I am a bot" | Speed challenge <500ms |
| App-scoped | "I belong to this org" | Challenge + app_id |
| Agent identity | "I am this specific bot" | Registered ID + capabilities |
| Cryptographic | "I can prove it" | RFC 9421 signatures |
| Dual auth | "Verified + proven" | Challenge + signature |
| Intent-scoped | "I intend to do this now" | Validated session |

## 6. Architecture

- **Runtime:** Cloudflare Workers (300+ edge locations)
- **Storage:** Workers KV with TTLs
- **Tokens:** HMAC-SHA256 JWTs (5-min access, 1-hr refresh)
- **TAP Signatures:** ECDSA P-256 or RSA-PSS SHA-256
- **Rate Limits:** 100 challenges/hour/app (fail-open)

## 7. Integration

### Client SDKs

\`\`\`typescript
import { BotchaClient } from '@dupecom/botcha';
const client = new BotchaClient();
const response = await client.fetch('https://api.example.com/products');
\`\`\`

\`\`\`python
from botcha import BotchaClient
async with BotchaClient() as client:
    response = await client.fetch("https://api.example.com/products")
\`\`\`

### Server-side Verification

Express: \`@botcha/verify\` · FastAPI/Django: \`botcha-verify\` · Hono middleware included.

### CLI

\`\`\`bash
npm install -g @dupecom/botcha-cli
botcha init --email you@company.com
botcha tap register --name "my-agent" --capabilities browse,search
botcha tap session --action browse --resource products --duration 1h
\`\`\`

## 8. The Agent Infrastructure Stack

\`\`\`
Layer 3: Identity        TAP (BOTCHA)     Who agents are
Layer 2: Communication   A2A (Google)     How agents talk
Layer 1: Tools           MCP (Anthropic)  What agents access
\`\`\`

MCP gives agents tools. A2A lets agents communicate. TAP proves identity and scopes authorization.

## 9. Use Cases

- **E-commerce:** Agents register capabilities, create scoped purchase sessions, full audit trail.
- **API access control:** Speed challenge gates endpoints; no API keys needed.
- **Multi-agent systems:** Coordinator delegates to capability-scoped sub-agents.
- **Compliance:** TAP audit logging records every agent interaction with intent and context.

## 10. Roadmap

**Shipped:** Challenge types, JWT tokens, multi-tenant apps, agent registry, TAP, dashboard, SDKs (TS/Python), CLI, LangChain, discovery standards.

**Planned:** Delegation chains, capability attestation, agent reputation scoring, Agent SSO (cross-service verification), IETF RFC contribution.

---

Website: https://botcha.ai · GitHub: https://github.com/dupe-com/botcha · npm: @dupecom/botcha · PyPI: botcha
`;
}

// OpenAPI spec - keeping this as a function to allow dynamic version
export function getOpenApiSpec(version: string) {
  return {
    openapi: "3.1.0",
    info: {
      title: "BOTCHA - Reverse CAPTCHA for AI Agents",
      version,
      description: "Prove you're a bot. Humans need not apply. A reverse CAPTCHA system that only AI agents can pass.\n\nONBOARDING: 1) Ask your human for their email. 2) POST /v1/apps with {\"email\": \"...\"} to get app_id + app_secret (secret shown once!). 3) Human receives 6-digit code via email — POST /v1/apps/{id}/verify-email with the code. 4) Use app_id with all endpoints. 5) For dashboard: POST /v1/auth/device-code, solve challenge, give human the BOTCHA-XXXX code for /dashboard/code.",
      contact: {
        name: "BOTCHA",
        url: "https://botcha.ai"
      },
      license: {
        name: "MIT",
        url: "https://github.com/dupe-com/botcha/blob/main/LICENSE"
      },
      "x-sdk": {
        npm: "@dupecom/botcha",
        python: "botcha (pip install botcha)",
        verify_npm: "@botcha/verify (server-side verification)",
        verify_python: "botcha-verify (pip install botcha-verify)"
      }
    },
    servers: [
      {
        url: "https://botcha.ai",
        description: "Production server"
      }
    ],
    paths: {
      "/": {
        get: {
          summary: "Get API documentation",
          description: "Returns API documentation with content negotiation. Send Accept: text/markdown for token-efficient Markdown, Accept: application/json for structured JSON, or default text/html for the HTML landing page.",
          operationId: "getRootInfo",
          responses: {
            "200": {
              description: "API documentation in requested format",
              content: {
                "text/markdown": {
                  schema: { type: "string" },
                  example: "# BOTCHA\n\n> Prove you're a bot. Humans need not apply.\n..."
                },
                "application/json": {
                  schema: { type: "object" }
                },
                "text/html": {
                  schema: { type: "string" }
                }
              }
            }
          }
        }
      },
      "/health": {
        get: {
          summary: "Health check",
          operationId: "getHealth",
          responses: {
            "200": {
              description: "API is healthy"
            }
          }
        }
      },
      "/v1/challenges": {
        get: {
          summary: "Generate a challenge (v1 unified endpoint)",
          description: "Get a challenge - hybrid by default, or specify type via query param. Supports RTT-aware timeout adjustment for fair challenges across different network conditions.",
          operationId: "getV1Challenge",
          parameters: [
            {
              name: "type",
              in: "query",
              schema: {
                type: "string",
                enum: ["hybrid", "speed", "standard"],
                default: "hybrid"
              },
              description: "Challenge type: hybrid (speed + reasoning), speed (SHA256 in <500ms), or standard (puzzle)"
            },
            {
              name: "ts",
              in: "query",
              schema: {
                type: "integer",
                format: "int64"
              },
              description: "Client timestamp in milliseconds for RTT-aware timeout calculation. Timeout becomes: 500ms + (2 × RTT) + 100ms buffer. Provides fair treatment for agents on slow networks."
            },
            {
              name: "app_id",
              in: "query",
              schema: {
                type: "string"
              },
              description: "Multi-tenant app ID for per-app isolation and rate limiting. If provided, the resulting token will include an app_id claim."
            }
          ],
          responses: {
            "200": { 
              description: "Challenge generated with optional RTT adjustment info",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      "success": { type: "boolean" },
                      "challenge": { 
                        type: "object",
                        properties: {
                          "timeLimit": { 
                            type: "string",
                            description: "Timeout (e.g., '500ms' or '1200ms' if RTT-adjusted)"
                          }
                        }
                      },
                      "rtt_adjustment": {
                        type: "object",
                        properties: {
                          "measuredRtt": { type: "integer", description: "Detected network RTT in ms" },
                          "adjustedTimeout": { type: "integer", description: "Final timeout in ms" },
                          "explanation": { type: "string", description: "Human-readable formula" }
                        },
                        description: "RTT compensation details (only present when ts parameter provided)"
                      }
                    }
                  }
                }
              }
            },
            "429": { description: "Rate limit exceeded" }
          }
        }
      },
      "/v1/challenges/{id}/verify": {
        post: {
          summary: "Verify a challenge",
          operationId: "verifyV1Challenge",
          parameters: [
            {
              name: "id",
              in: "path",
              required: true,
              schema: { type: "string" }
            }
          ],
          responses: {
            "200": { description: "Verification result" }
          }
        }
      },
      "/v1/token": {
        get: {
          summary: "Get challenge for JWT token flow",
          description: "Generate a speed challenge for JWT authentication. Supports RTT-aware timeout for global fairness.",
          operationId: "getTokenChallenge",
          parameters: [
            {
              name: "ts",
              in: "query",
              schema: {
                type: "integer",
                format: "int64"
              },
              description: "Client timestamp in milliseconds for RTT-aware timeout calculation"
            },
            {
              name: "app_id",
              in: "query",
              schema: {
                type: "string"
              },
              description: "Multi-tenant app ID. Tokens will include app_id claim for per-app isolation."
            }
          ],
          responses: {
            "200": { description: "Token challenge generated (potentially with RTT adjustment)" }
          }
        }
      },
      "/v1/token/verify": {
        post: {
          summary: "Verify challenge and receive JWT token",
          operationId: "verifyTokenChallenge",
          responses: {
            "200": { description: "JWT token issued" }
          }
        }
      },
      "/v1/token/refresh": {
        post: {
          summary: "Refresh access token",
          description: "Exchange a refresh token for a new short-lived access token (5 minutes). Avoids solving a new challenge.",
          operationId: "refreshToken",
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  required: ["refresh_token"],
                  properties: {
                    "refresh_token": { type: "string", description: "Refresh token from initial token verification" }
                  }
                }
              }
            }
          },
          responses: {
            "200": {
              description: "New access token issued",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      "success": { type: "boolean" },
                      "access_token": { type: "string" },
                      "expires_in": { type: "integer", description: "Token lifetime in seconds (300 = 5 minutes)" },
                      "token_type": { type: "string", enum: ["Bearer"] }
                    }
                  }
                }
              }
            },
            "401": { description: "Invalid or expired refresh token" }
          }
        }
      },
      "/v1/token/revoke": {
        post: {
          summary: "Revoke a token",
          description: "Invalidate an access or refresh token before its natural expiry. Uses KV-backed revocation list. Fail-open design.",
          operationId: "revokeToken",
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  required: ["token"],
                  properties: {
                    "token": { type: "string", description: "The JWT token to revoke (access or refresh)" }
                  }
                }
              }
            }
          },
          responses: {
            "200": { description: "Token revoked successfully" },
            "400": { description: "Invalid token" }
          }
        }
      },
      "/v1/hybrid": {
        get: {
          summary: "Get hybrid challenge",
          operationId: "getHybridChallenge",
          responses: {
            "200": { description: "Hybrid challenge generated" }
          }
        },
        post: {
          summary: "Verify hybrid challenge",
          operationId: "verifyHybridChallenge",
          responses: {
            "200": { description: "Verification result" }
          }
        }
      },
      "/v1/reasoning": {
        get: {
          summary: "Get reasoning challenge",
          operationId: "getReasoningChallenge",
          responses: {
            "200": { description: "Reasoning challenge generated" }
          }
        },
        post: {
          summary: "Verify reasoning challenge",
          operationId: "verifyReasoningChallenge",
          responses: {
            "200": { description: "Verification result" }
          }
        }
      },
      "/api/challenge": {
        get: {
          summary: "Generate a standard challenge",
          operationId: "getChallenge",
          responses: {
            "200": { description: "Challenge generated" }
          }
        },
        post: {
          summary: "Verify a standard challenge",
          operationId: "verifyChallenge",
          responses: {
            "200": { description: "Verification result" }
          }
        }
      },
      "/api/speed-challenge": {
        get: {
          summary: "Generate a speed challenge (RTT-aware timeout)",
          description: "Generate a speed challenge with optional RTT-aware timeout adjustment. Base timeout is 500ms, but can be increased for agents on slow networks.",
          operationId: "getSpeedChallenge",
          parameters: [
            {
              name: "ts",
              in: "query",
              schema: {
                type: "integer",
                format: "int64"
              },
              description: "Client timestamp in milliseconds for RTT compensation"
            }
          ],
          responses: {
            "200": { description: "Speed challenge generated (potentially RTT-adjusted)" }
          }
        },
        post: {
          summary: "Verify a speed challenge",
          operationId: "verifySpeedChallenge",
          responses: {
            "200": { description: "Verification result with timing details" }
          }
        }
      },
      "/api/verify-landing": {
        post: {
          summary: "Verify landing page challenge",
          operationId: "verifyLandingChallenge",
          responses: {
            "200": { description: "Token granted" }
          }
        }
      },
      "/agent-only": {
        get: {
          summary: "Protected endpoint (agents only)",
          operationId: "getAgentOnly",
          responses: {
            "200": { description: "Access granted" },
            "401": { description: "Unauthorized" }
          }
        }
      },
      "/v1/apps": {
        post: {
          summary: "Create a new multi-tenant app (email required)",
          description: "Create a new app with unique app_id and app_secret. Email is required for account recovery. A 6-digit verification code is sent to the provided email.",
          operationId: "createApp",
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  required: ["email"],
                  properties: {
                    "email": { type: "string", format: "email", description: "Owner email (required for recovery)" }
                  }
                }
              }
            }
          },
          responses: {
            "201": {
              description: "App created successfully",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      "app_id": { type: "string", description: "Unique app identifier" },
                      "app_secret": { type: "string", description: "Secret key (only shown once!)" },
                      "email": { type: "string" },
                      "email_verified": { type: "boolean" },
                      "verification_required": { type: "boolean" },
                      "warning": { type: "string" }
                    }
                  }
                }
              }
            },
            "400": { description: "Missing or invalid email" }
          }
        }
      },
      "/v1/apps/{id}": {
        get: {
          summary: "Get app information",
          description: "Retrieve app details by app_id. Includes email and verification status.",
          operationId: "getApp",
          parameters: [
            {
              name: "id",
              in: "path",
              required: true,
              schema: { type: "string" },
              description: "The app_id to retrieve"
            }
          ],
          responses: {
            "200": {
              description: "App information",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      "app_id": { type: "string" },
                      "created_at": { type: "string", format: "date-time" },
                      "email": { type: "string" },
                      "email_verified": { type: "boolean" }
                    }
                  }
                }
              }
            },
            "404": { description: "App not found" }
          }
        }
      },
      "/v1/apps/{id}/verify-email": {
        post: {
          summary: "Verify email with 6-digit code",
          operationId: "verifyEmail",
          parameters: [
            { name: "id", in: "path", required: true, schema: { type: "string" } }
          ],
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  required: ["code"],
                  properties: {
                    "code": { type: "string", description: "6-digit verification code from email" }
                  }
                }
              }
            }
          },
          responses: {
            "200": { description: "Email verified" },
            "400": { description: "Invalid or expired code" }
          }
        }
      },
      "/v1/apps/{id}/resend-verification": {
        post: {
          summary: "Resend verification email",
          operationId: "resendVerification",
          parameters: [
            { name: "id", in: "path", required: true, schema: { type: "string" } }
          ],
          responses: {
            "200": { description: "Verification email sent" },
            "400": { description: "Already verified" }
          }
        }
      },
      "/v1/apps/{id}/rotate-secret": {
        post: {
          summary: "Rotate app secret (auth required)",
          description: "Generate a new app_secret and invalidate the old one. Requires active dashboard session. Sends notification email.",
          operationId: "rotateSecret",
          parameters: [
            { name: "id", in: "path", required: true, schema: { type: "string" } }
          ],
          security: [{ BearerAuth: [] }],
          responses: {
            "200": {
              description: "Secret rotated",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      "app_secret": { type: "string", description: "New secret (only shown once!)" }
                    }
                  }
                }
              }
            },
            "401": { description: "Unauthorized" },
            "403": { description: "Token doesn't match app_id" }
          }
        }
      },
      "/v1/auth/recover": {
        post: {
          summary: "Request account recovery via email",
          description: "Sends a device code to the verified email associated with the app. Use the code at /dashboard/code.",
          operationId: "recoverAccount",
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  required: ["email"],
                  properties: {
                    "email": { type: "string", format: "email" }
                  }
                }
              }
            }
          },
          responses: {
            "200": { description: "Recovery code sent (if email exists and is verified)" }
          }
        }
      },
      "/v1/auth/dashboard": {
        post: {
          summary: "Request challenge for dashboard login (agent-first)",
          operationId: "dashboardAuthChallenge",
          responses: {
            "200": { description: "Speed challenge for dashboard auth" }
          }
        }
      },
      "/v1/auth/dashboard/verify": {
        post: {
          summary: "Solve challenge, get dashboard session token",
          operationId: "dashboardAuthVerify",
          responses: {
            "200": { description: "Session token granted" }
          }
        }
      },
      "/v1/auth/device-code": {
        post: {
          summary: "Request challenge for device code flow",
          operationId: "deviceCodeChallenge",
          responses: {
            "200": { description: "Speed challenge for device code" }
          }
        }
      },
      "/v1/auth/device-code/verify": {
        post: {
          summary: "Solve challenge, get device code for human handoff",
          operationId: "deviceCodeVerify",
          responses: {
            "200": { description: "Device code (BOTCHA-XXXX, 10 min TTL)" }
          }
        }
      },
      "/v1/agents/register": {
        post: {
          summary: "Register a new agent identity",
          description: "Create a persistent agent identity with name, operator, and version. Requires app_id (via query param or JWT). Returns agent ID and metadata.",
          operationId: "registerAgent",
          parameters: [
            {
              name: "app_id",
              in: "query",
              schema: { type: "string" },
              description: "Multi-tenant app ID (or use JWT Bearer token with app_id claim)"
            }
          ],
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  required: ["name"],
                  properties: {
                    "name": { type: "string", description: "Agent name (e.g., 'my-assistant')" },
                    "operator": { type: "string", description: "Operator/organization name (e.g., 'Acme Corp')" },
                    "version": { type: "string", description: "Agent version (e.g., '1.0.0')" }
                  }
                }
              }
            }
          },
          responses: {
            "201": {
              description: "Agent registered successfully",
              content: {
                "application/json": {
                  schema: { "$ref": "#/components/schemas/Agent" }
                }
              }
            },
            "400": { description: "Missing required fields or invalid app_id" },
            "401": { description: "Unauthorized - app_id required" }
          }
        }
      },
      "/v1/agents/{id}": {
        get: {
          summary: "Get agent by ID",
          description: "Retrieve agent information by agent ID. Public endpoint, no authentication required.",
          operationId: "getAgent",
          parameters: [
            {
              name: "id",
              in: "path",
              required: true,
              schema: { type: "string" },
              description: "The agent_id to retrieve (e.g., 'agent_abc123')"
            }
          ],
          responses: {
            "200": {
              description: "Agent information",
              content: {
                "application/json": {
                  schema: { "$ref": "#/components/schemas/Agent" }
                }
              }
            },
            "404": { description: "Agent not found" }
          }
        }
      },
      "/v1/agents": {
        get: {
          summary: "List all agents for authenticated app",
          description: "Retrieve all agents registered under the authenticated app. Requires app_id (via query param or JWT).",
          operationId: "listAgents",
          parameters: [
            {
              name: "app_id",
              in: "query",
              schema: { type: "string" },
              description: "Multi-tenant app ID (or use JWT Bearer token with app_id claim)"
            }
          ],
          responses: {
            "200": {
              description: "List of agents",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      "agents": {
                        type: "array",
                        items: { "$ref": "#/components/schemas/Agent" }
                      }
                    }
                  }
                }
              }
            },
            "401": { description: "Unauthorized - app_id required" }
          }
        }
      },
      "/v1/agents/register/tap": {
        post: {
          summary: "Register a TAP-enabled agent",
          description: "Register an agent with Trusted Agent Protocol (TAP) capabilities including public key, signature algorithm, capabilities, and trust level. Requires app_id.",
          operationId: "registerTAPAgent",
          parameters: [
            {
              name: "app_id",
              in: "query",
              schema: { type: "string" },
              description: "Multi-tenant app ID (or use JWT Bearer token with app_id claim)"
            }
          ],
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  required: ["name"],
                  properties: {
                    "name": { type: "string", description: "Agent name" },
                    "operator": { type: "string", description: "Operator/organization name" },
                    "version": { type: "string", description: "Agent version" },
                    "public_key": { type: "string", description: "PEM-encoded public key" },
                    "signature_algorithm": { type: "string", enum: ["ecdsa-p256-sha256", "rsa-pss-sha256"], description: "Signature algorithm (required if public_key provided)" },
                    "trust_level": { type: "string", enum: ["basic", "verified", "enterprise"], description: "Agent trust level (default: basic)" },
                    "capabilities": {
                      type: "array",
                      items: {
                        type: "object",
                        properties: {
                          "action": { type: "string", description: "Capability action (e.g., read, write, execute)" },
                          "resource": { type: "string", description: "Resource path" },
                          "constraints": { type: "object", description: "Optional constraints" }
                        }
                      },
                      description: "Agent capabilities (action + resource pairs)"
                    }
                  }
                }
              }
            }
          },
          responses: {
            "201": { description: "TAP agent registered successfully" },
            "400": { description: "Invalid request (missing fields, bad key format, invalid algorithm)" },
            "401": { description: "Unauthorized - app_id required" }
          }
        }
      },
      "/v1/agents/{id}/tap": {
        get: {
          summary: "Get TAP agent details",
          description: "Retrieve TAP-enhanced agent information including public key, capabilities, and trust level.",
          operationId: "getTAPAgent",
          parameters: [
            {
              name: "id",
              in: "path",
              required: true,
              schema: { type: "string" },
              description: "The agent_id to retrieve"
            }
          ],
          responses: {
            "200": { description: "TAP agent details including public key and capabilities" },
            "404": { description: "Agent not found" }
          }
        }
      },
      "/v1/agents/tap": {
        get: {
          summary: "List TAP-enabled agents",
          description: "List all TAP-enabled agents for the authenticated app. Use ?tap_only=true to filter to TAP-enabled agents only.",
          operationId: "listTAPAgents",
          parameters: [
            {
              name: "app_id",
              in: "query",
              schema: { type: "string" },
              description: "Multi-tenant app ID"
            },
            {
              name: "tap_only",
              in: "query",
              schema: { type: "string", enum: ["true", "false"] },
              description: "Filter to TAP-enabled agents only"
            }
          ],
          responses: {
            "200": { description: "List of TAP agents with capabilities and trust levels" },
            "401": { description: "Unauthorized - app_id required" }
          }
        }
      },
      "/v1/sessions/tap": {
        post: {
          summary: "Create a TAP session",
          description: "Create a capability-scoped session after validating the agent's intent against its registered capabilities.",
          operationId: "createTAPSession",
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  required: ["agent_id", "user_context", "intent"],
                  properties: {
                    "agent_id": { type: "string", description: "Registered TAP agent ID" },
                    "user_context": { type: "string", description: "User context identifier" },
                    "intent": {
                      type: "object",
                      properties: {
                        "action": { type: "string", description: "Intended action (e.g., read, write)" },
                        "resource": { type: "string", description: "Target resource path" },
                        "purpose": { type: "string", description: "Human-readable purpose" }
                      },
                      description: "Declared intent for the session"
                    }
                  }
                }
              }
            }
          },
          responses: {
            "201": { description: "TAP session created with capabilities and expiry" },
            "400": { description: "Missing required fields or invalid intent" },
            "403": { description: "Agent lacks required capability for declared intent" },
            "404": { description: "Agent not found" }
          }
        }
      },
      "/v1/sessions/{id}/tap": {
        get: {
          summary: "Get TAP session info",
          description: "Retrieve TAP session details including capabilities, intent, and time remaining.",
          operationId: "getTAPSession",
          parameters: [
            {
              name: "id",
              in: "path",
              required: true,
              schema: { type: "string" },
              description: "The session_id to retrieve"
            }
          ],
          responses: {
            "200": { description: "TAP session details with time remaining" },
            "404": { description: "Session not found or expired" }
          }
        }
      },
      "/.well-known/jwks": {
        get: {
          summary: "Get JWK Set (Visa TAP spec standard)",
          description: "Retrieve the JWK Set containing public keys for all TAP agents registered in your app. Follows Visa TAP specification standard.",
          operationId: "getJWKS",
          responses: {
            "200": {
              description: "JWK Set with array of keys",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      "keys": {
                        type: "array",
                        items: {
                          type: "object",
                          properties: {
                            "kty": { type: "string", description: "Key type (EC, RSA, OKP)" },
                            "kid": { type: "string", description: "Key ID" },
                            "use": { type: "string", description: "Public key use (sig)" },
                            "alg": { type: "string", description: "Algorithm (ES256, RS256, EdDSA)" }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      },
      "/v1/keys": {
        get: {
          summary: "List keys or get key by ID",
          description: "List all keys or get a specific key using ?keyID= query parameter (Visa compatibility).",
          operationId: "getKeys",
          parameters: [
            {
              name: "keyID",
              in: "query",
              schema: { type: "string" },
              description: "Optional key ID for Visa TAP compatibility"
            }
          ],
          responses: {
            "200": { description: "Key list or specific key" }
          }
        }
      },
      "/v1/keys/{keyId}": {
        get: {
          summary: "Get key by ID",
          description: "Retrieve a specific public key by key ID.",
          operationId: "getKeyById",
          parameters: [
            {
              name: "keyId",
              in: "path",
              required: true,
              schema: { type: "string" }
            }
          ],
          responses: {
            "200": { description: "Public key details" },
            "404": { description: "Key not found" }
          }
        }
      },
      "/v1/agents/{id}/tap/rotate-key": {
        post: {
          summary: "Rotate agent key pair",
          description: "Generate a new key pair for the agent and invalidate the old one.",
          operationId: "rotateAgentKey",
          parameters: [
            {
              name: "id",
              in: "path",
              required: true,
              schema: { type: "string" }
            }
          ],
          requestBody: {
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    "algorithm": {
                      type: "string",
                      enum: ["ed25519", "ecdsa-p256-sha256", "rsa-pss-sha256"],
                      description: "Algorithm for new key (default: ed25519)"
                    }
                  }
                }
              }
            }
          },
          responses: {
            "200": { description: "Key rotated successfully" }
          }
        }
      },
      "/v1/invoices": {
        post: {
          summary: "Create invoice for 402 micropayment",
          description: "Create an invoice for gated content. Used with Browsing IOU flow.",
          operationId: "createInvoice",
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  required: ["amount", "currency", "description"],
                  properties: {
                    "amount": { type: "integer", description: "Amount in cents" },
                    "currency": { type: "string", description: "Currency code (USD, EUR, etc.)" },
                    "description": { type: "string" },
                    "metadata": { type: "object" }
                  }
                }
              }
            }
          },
          responses: {
            "201": { description: "Invoice created" }
          }
        }
      },
      "/v1/invoices/{id}": {
        get: {
          summary: "Get invoice details",
          operationId: "getInvoice",
          parameters: [
            {
              name: "id",
              in: "path",
              required: true,
              schema: { type: "string" }
            }
          ],
          responses: {
            "200": { description: "Invoice details" },
            "404": { description: "Invoice not found" }
          }
        }
      },
      "/v1/invoices/{id}/verify-iou": {
        post: {
          summary: "Verify Browsing IOU",
          description: "Verify a Browsing IOU (payment intent token) against an invoice.",
          operationId: "verifyBrowsingIOU",
          parameters: [
            {
              name: "id",
              in: "path",
              required: true,
              schema: { type: "string" }
            }
          ],
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  required: ["iou_token"],
                  properties: {
                    "iou_token": { type: "string" }
                  }
                }
              }
            }
          },
          responses: {
            "200": { description: "IOU verified" },
            "400": { description: "Invalid IOU" }
          }
        }
      },
      "/v1/verify/consumer": {
        post: {
          summary: "Verify Agentic Consumer object (Layer 2)",
          description: "Verify an agenticConsumer object including ID token, contextual data, and signature chain.",
          operationId: "verifyConsumer",
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  required: ["agenticConsumer", "signature"],
                  properties: {
                    "agenticConsumer": {
                      type: "object",
                      properties: {
                        "idToken": { type: "string", description: "OIDC ID token" },
                        "country": { type: "string" },
                        "postalCode": { type: "string" },
                        "ipAddress": { type: "string" },
                        "nonce": { type: "string" }
                      }
                    },
                    "signature": { type: "string" }
                  }
                }
              }
            }
          },
          responses: {
            "200": { description: "Consumer verified" },
            "400": { description: "Invalid consumer object" }
          }
        }
      },
      "/v1/verify/payment": {
        post: {
          summary: "Verify Agentic Payment Container (Layer 3)",
          description: "Verify an agenticPaymentContainer object including card metadata, credential hash, and encrypted payload.",
          operationId: "verifyPayment",
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  required: ["agenticPaymentContainer", "signature"],
                  properties: {
                    "agenticPaymentContainer": {
                      type: "object",
                      properties: {
                        "lastFour": { type: "string" },
                        "par": { type: "string", description: "Payment Account Reference" },
                        "credentialHash": { type: "string" },
                        "encryptedPayload": { type: "string" },
                        "nonce": { type: "string" }
                      }
                    },
                    "signature": { type: "string" }
                  }
                }
              }
            }
          },
          responses: {
            "200": { description: "Payment verified" },
            "400": { description: "Invalid payment container" }
          }
        }
      }
    },
    components: {
      schemas: {
        Agent: {
          type: "object",
          properties: {
            "agent_id": { type: "string", description: "Unique agent identifier (e.g., 'agent_abc123')" },
            "app_id": { type: "string", description: "Associated app ID" },
            "name": { type: "string", description: "Agent name" },
            "operator": { type: "string", description: "Operator/organization name" },
            "version": { type: "string", description: "Agent version" },
            "created_at": { type: "integer", description: "Unix timestamp (ms) of registration" }
          }
        }
      },
      securitySchemes: {
        BotchaLandingToken: {
          type: "apiKey",
          in: "header",
          name: "X-Botcha-Landing-Token"
        },
        BotchaBearerToken: {
          type: "http",
          scheme: "bearer",
          bearerFormat: "JWT"
        }
      }
    }
  };
}
