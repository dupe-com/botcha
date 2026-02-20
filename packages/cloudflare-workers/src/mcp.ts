/**
 * BOTCHA MCP Server
 *
 * Implements the Model Context Protocol (MCP) 2025-03-26 Streamable HTTP transport.
 * Exposes BOTCHA documentation, API reference, and code examples as MCP tools.
 *
 * Endpoint:  POST /mcp
 * Discovery: GET  /.well-known/mcp.json
 *
 * Tools:
 *   list_features   — list all BOTCHA features
 *   get_feature     — detailed info on a feature
 *   search_docs     — keyword search across all docs
 *   list_endpoints  — all API endpoints grouped by category
 *   get_endpoint    — details for a specific endpoint
 *   get_example     — code example for a feature (TypeScript / Python / curl)
 */

// ============ MCP PROTOCOL TYPES ============

interface JSONRPCRequest {
  jsonrpc: '2.0';
  id: string | number | null;
  method: string;
  params?: Record<string, unknown>;
}

interface JSONRPCResponse {
  jsonrpc: '2.0';
  id: string | number | null;
  result?: unknown;
  error?: { code: number; message: string; data?: unknown };
}

interface MCPTool {
  name: string;
  description: string;
  inputSchema: {
    type: 'object';
    properties: Record<string, { type: string; description: string; enum?: string[] }>;
    required?: string[];
  };
}

// ============ KNOWLEDGE BASE ============

const FEATURES: Record<string, {
  name: string;
  category: string;
  summary: string;
  detail: string;
  endpoints: string[];
  spec?: string;
}> = {
  challenges: {
    name: 'Challenge Verification',
    category: 'Core',
    summary: 'Computational challenges only AI agents can solve — SHA-256 hashes in <500ms.',
    detail: `BOTCHA challenges prove you are a machine, not a human. Four types are available:

• Speed: Compute SHA-256 of 5 random numbers, return the first 8 hex chars each — all within 500ms.
  RTT-aware: timeout = 500ms + (2 × RTT) + 100ms buffer. Capped at 5 seconds.
• Reasoning: Answer 3 questions drawn from 6 categories (math, code, logic, wordplay, common-sense,
  analogy). 45+ parameterized generators, never the same question twice. 30s limit.
• Hybrid (default): Both speed AND reasoning must pass. Strongest proof.
• Compute: Heavy computation — generate primes, concatenate with salt, hash. Scales easy→hard.

All challenges are single-use (deleted on first attempt) and timestamp-validated (±30s).`,
    endpoints: [
      'GET /v1/challenges',
      'POST /v1/challenges/:id/verify',
      'GET /v1/reasoning',
      'POST /v1/reasoning',
      'GET /v1/hybrid',
      'POST /v1/hybrid',
    ],
  },

  tokens: {
    name: 'JWT Tokens',
    category: 'Core',
    summary: 'ES256 JWTs: 1-hour access token + 1-hour refresh token, with revocation and audience scoping.',
    detail: `After solving a challenge, agents receive:
• access_token — ES256 JWT, 1 hour, use as Bearer in Authorization header
• refresh_token — ES256 JWT, 1 hour, exchange for a new access token without re-solving
• human_link — a /go/:code URL to give to a human operator for browser access

Token features:
• ES256 (ECDSA P-256) — asymmetric signing, verify via GET /.well-known/jwks (no shared secret needed)
• HS256 still supported for backward compatibility
• Audience (aud) scoping — token for api.stripe.com rejected by api.github.com
• IP binding — solve on machine A, only works on machine A (optional)
• JTI — unique ID per token for revocation and audit
• Remote validation — POST /v1/token/validate without needing the signing secret

Revocation is KV-backed with fail-open on infrastructure errors.`,
    endpoints: [
      'GET /v1/token',
      'POST /v1/token/verify',
      'POST /v1/token/refresh',
      'POST /v1/token/revoke',
      'POST /v1/token/validate',
      'GET /.well-known/jwks',
    ],
  },

  apps: {
    name: 'Multi-Tenant Apps',
    category: 'Core',
    summary: 'Create isolated apps with unique credentials, per-app rate limits, and email-tied accounts.',
    detail: `Every API call requires a registered app (app_id). Apps provide:
• Isolation — each app has its own rate limit bucket, token scoping, and analytics
• Email — required at creation; verified with a 6-digit code
• Secret — shown ONCE at creation, used for email verification and secret rotation
• Recovery — lost your secret? POST /v1/auth/recover emails a device code

App lifecycle:
1. POST /v1/apps {"email": "..."} → app_id + app_secret (save the secret!)
2. POST /v1/apps/:id/verify-email {"code": "123456"} → enables recovery
3. Use app_id on all API calls via ?app_id=, X-App-Id header, or JWT claim`,
    endpoints: [
      'POST /v1/apps',
      'GET /v1/apps/:id',
      'POST /v1/apps/:id/verify-email',
      'POST /v1/apps/:id/resend-verification',
      'POST /v1/apps/:id/rotate-secret',
      'POST /v1/auth/recover',
    ],
  },

  agents: {
    name: 'Agent Registry',
    category: 'Identity',
    summary: 'Register persistent agent identities with names, operators, and version tracking.',
    detail: `Register your agent to get a persistent agent_id that survives across sessions.

Registration fields:
• name — human-readable agent name
• operator — organization operating the agent
• version — optional semver

The agent_id is the foundation for TAP, delegation, attestation, and reputation.
Public GET /v1/agents/:id lets anyone look up an agent without auth.`,
    endpoints: [
      'POST /v1/agents/register',
      'GET /v1/agents/:id',
      'GET /v1/agents',
    ],
  },

  tap: {
    name: 'TAP (Trusted Agent Protocol)',
    category: 'Identity',
    summary: 'Cryptographic agent identity using HTTP Message Signatures (RFC 9421) with capability scoping and intent sessions.',
    detail: `TAP proves you are a specific, trusted bot — not just any bot.

Based on Visa's Trusted Agent Protocol (https://developer.visa.com/capabilities/trusted-agent-protocol/overview).

Features:
• Public key registration — Ed25519 (recommended), ECDSA P-256, or RSA-PSS
• RFC 9421 request signing — signature-input + signature headers
• Capability scoping — declare what the agent can do: browse, search, compare, purchase, audit
• Intent sessions — time-limited sessions validated against registered capabilities
• Trust levels — basic, verified, enterprise
• Layer 2 (Consumer Recognition) — OIDC ID tokens with obfuscated consumer identity
• Layer 3 (Payment Container) — card metadata, credential hash, encrypted payment payloads

Signing headers example:
  x-tap-agent-id: agent_6ddfd9f10cfd8dfc
  x-tap-intent: {"action":"browse","resource":"products"}
  signature-input: sig1=("@method" "@path" "x-tap-agent-id");alg="ecdsa-p256-sha256"
  signature: sig1=:BASE64:`,
    endpoints: [
      'POST /v1/agents/register/tap',
      'GET /v1/agents/:id/tap',
      'GET /v1/agents/tap',
      'POST /v1/sessions/tap',
      'GET /v1/sessions/:id/tap',
      'POST /v1/agents/:id/tap/rotate-key',
      'GET /.well-known/jwks',
      'GET /v1/keys',
      'GET /v1/keys/:keyId',
    ],
    spec: 'https://www.rfc-editor.org/rfc/rfc9421',
  },

  delegation: {
    name: 'Delegation Chains',
    category: 'Identity',
    summary: '"User X authorized Agent Y to do Z until T." Signed chains with cascade revocation.',
    detail: `Delegation encodes: "Agent A authorizes Agent B to perform capabilities C until time T."

Rules:
• Capabilities can only NARROW, never expand — a grantee cannot exceed the grantor's capabilities
• Chain depth capped at 3 (max 10) — prevents infinite delegation trees
• Revoking any link cascades to ALL sub-delegations automatically
• Sub-delegations cannot outlive their parent
• Cycle detection prevents circular chains

Capabilities use action:resource format: {"action": "browse", "resource": "products"}

POST /v1/verify/delegation verifies the entire chain in one call and returns effective_capabilities.`,
    endpoints: [
      'POST /v1/delegations',
      'GET /v1/delegations/:id',
      'GET /v1/delegations',
      'POST /v1/delegations/:id/revoke',
      'POST /v1/verify/delegation',
    ],
  },

  attestation: {
    name: 'Capability Attestation',
    category: 'Identity',
    summary: 'Signed action:resource permission tokens with explicit deny rules and wildcard patterns.',
    detail: `Attestation tokens encode exactly what an agent CAN and CANNOT do.

Permission model:
• can: ["read:invoices", "browse:*"] — allow rules, wildcards supported
• cannot: ["purchase:*"] — explicit deny rules, ALWAYS take precedence over can
• Bare actions expand: "browse" → "browse:*"
• Patterns: *:* (all), read:* (any resource), *:invoices (any action on invoices)

The token is a signed JWT. Present it as X-Botcha-Attestation header.

Enforcement: use requireCapability('read:invoices') middleware on Hono routes.
Link to delegation chains via delegation_id for full audit trail.`,
    endpoints: [
      'POST /v1/attestations',
      'GET /v1/attestations/:id',
      'GET /v1/attestations',
      'POST /v1/attestations/:id/revoke',
      'POST /v1/verify/attestation',
    ],
  },

  reputation: {
    name: 'Agent Reputation',
    category: 'Identity',
    summary: 'Score-based reputation (0-1000, 5 tiers) tracking 18 action types across 6 categories.',
    detail: `Reputation is the "credit score" for AI agents.

Scoring:
• Base: 500 (neutral, no history)
• Range: 0–1000
• Tiers: untrusted (0-199), low (200-399), neutral (400-599), good (600-799), excellent (800-1000)
• Decay: scores trend toward 500 without activity (mean reversion)
• Deny always wins: abuse events (-50) are heavily weighted

Categories and actions:
• verification: challenge_solved (+5), tap_session_created (+3), key_rotation (+2)
• commerce: purchase_completed (+10), invoice_paid (+8), payment_failed (-15)
• compliance: policy_violation (-30), rate_limit_exceeded (-5), suspicious_activity (-50)
• social: endorsement_received (+20), endorsement_given (+5)
• security: key_compromise (-100), unauthorized_access (-50)
• governance: delegation_granted (+3), delegation_revoked (-2)

High reputation unlocks elevated rate limits, faster verification paths, and access to sensitive endpoints.`,
    endpoints: [
      'GET /v1/reputation/:agent_id',
      'POST /v1/reputation/events',
      'GET /v1/reputation/:agent_id/events',
      'POST /v1/reputation/:agent_id/reset',
    ],
  },

  webhooks: {
    name: 'Webhooks',
    category: 'Platform',
    summary: 'Per-app webhook endpoints receiving HMAC-SHA256 signed event deliveries.',
    detail: `Register webhooks to receive signed HTTP POST event deliveries.

Supported events:
• agent.tap.registered — new TAP agent registered
• token.created — new access token issued
• token.revoked — token explicitly revoked
• tap.session.created — new TAP session started
• delegation.created — new delegation chain created
• delegation.revoked — delegation revoked (with cascade info)

Signature verification:
  const sig = crypto.createHmac('sha256', signingSecret).update(body).digest('hex');
  const valid = crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(incomingSignature));

The signing secret is shown ONCE at webhook creation — save it.
POST /v1/webhooks/:id/test sends a test payload to verify your endpoint is working.`,
    endpoints: [
      'POST /v1/webhooks',
      'GET /v1/webhooks',
      'GET /v1/webhooks/:id',
      'PUT /v1/webhooks/:id',
      'DELETE /v1/webhooks/:id',
      'POST /v1/webhooks/:id/test',
      'GET /v1/webhooks/:id/deliveries',
    ],
  },

  x402: {
    name: 'x402 Payment Gating',
    category: 'Protocols',
    summary: 'HTTP 402 micropayment flow — pay $0.001 USDC on Base instead of solving a challenge.',
    detail: `x402 is an HTTP payment protocol (https://x402.org/). BOTCHA supports it as an alternative
to challenge-solving — agents can pay instead of compute.

Flow:
1. GET /v1/x402/challenge — receives 402 Payment Required with payment terms
   Response: { amount: "0.001", currency: "USDC", chain: "base", recipient: "0xBOTCHA..." }
2. Agent pays $0.001 USDC on Base to the recipient address
3. Retry the same request with X-Payment: <payment_proof> header
4. Receive 200 with access_token — no puzzle solved

Also available: a demo endpoint GET /agent-only/x402 that requires BOTH a BOTCHA token AND x402 payment.`,
    endpoints: [
      'GET /v1/x402/info',
      'GET /v1/x402/challenge',
      'POST /v1/x402/verify-payment',
      'POST /v1/x402/webhook',
      'GET /agent-only/x402',
    ],
    spec: 'https://x402.org/',
  },

  ans: {
    name: 'Agent Name Service (ANS)',
    category: 'Protocols',
    summary: 'DNS-based agent identity lookup with BOTCHA-issued ownership badges (GoDaddy ANS standard).',
    detail: `ANS gives agents human-readable names like "my-agent.agents" that resolve via DNS TXT records
to endpoint URLs and identity metadata.

BOTCHA acts as a verification layer: agents prove they own their DNS name and receive a
BOTCHA-signed badge JWT that can be presented to any party.

Ownership proof flow:
1. GET /v1/ans/nonce/:name — get a one-time nonce (requires Bearer token)
2. Sign the nonce with your agent's private key
3. POST /v1/ans/verify with name, agent_url, nonce, and proof
4. Receive a BOTCHA-signed badge JWT

BOTCHA publishes its own ANS identity at GET /v1/ans/botcha.`,
    endpoints: [
      'GET /v1/ans/botcha',
      'GET /v1/ans/resolve/:name',
      'GET /v1/ans/resolve/lookup',
      'GET /v1/ans/discover',
      'GET /v1/ans/nonce/:name',
      'POST /v1/ans/verify',
    ],
    spec: 'https://www.godaddy.com/engineering/2024/12/16/agent-name-service/',
  },

  'did-vc': {
    name: 'DID / Verifiable Credentials',
    category: 'Protocols',
    summary: 'BOTCHA as a W3C DID issuer (did:web:botcha.ai) — portable VC JWTs verifiable without contacting BOTCHA.',
    detail: `BOTCHA is a W3C DID/VC issuer. After solving a challenge, request a W3C Verifiable Credential
JWT signed with BOTCHA's private key. Any party can verify it offline using the public JWKS.

DID Document: GET /.well-known/did.json → did:web:botcha.ai

Issuance flow:
1. Solve a challenge → receive Bearer token
2. POST /v1/credentials/issue with subject and credential type
3. Receive a VC JWT
4. Present the VC JWT to any relying party
5. Relying party verifies via POST /v1/credentials/verify (or local JWK verification)

Supported credential types: VerifiableCredential, BotchaVerification
VC is signed with ES256 (ECDSA P-256).

Also: GET /v1/dids/:did/resolve resolves any did:web DID (not just BOTCHA's).`,
    endpoints: [
      'GET /.well-known/did.json',
      'GET /.well-known/jwks',
      'GET /.well-known/jwks.json',
      'POST /v1/credentials/issue',
      'POST /v1/credentials/verify',
      'GET /v1/dids/:did/resolve',
    ],
    spec: 'https://www.w3.org/TR/did-core/',
  },

  a2a: {
    name: 'A2A Agent Card Attestation',
    category: 'Protocols',
    summary: 'BOTCHA as a trust seal issuer for Google A2A Agent Cards — tamper-evident, offline-verifiable.',
    detail: `The Google A2A protocol defines a standard JSON Agent Card published at /.well-known/agent.json.
BOTCHA attests these cards by producing a tamper-evident hash+signature bundle.

Attestation:
1. POST /v1/a2a/attest with the agent's card + duration + trust_level (requires Bearer)
2. Receive a trust seal token (JWT) and an attested_card with botcha_attestation extension
3. Embed the seal in the card's extensions field
4. Anyone can verify offline via POST /v1/a2a/verify-card — no BOTCHA round-trip needed

Trust levels: unverified (default), verified, enterprise

BOTCHA publishes its own A2A card at GET /.well-known/agent.json.
Browse all attested cards at GET /v1/a2a/cards.`,
    endpoints: [
      'GET /.well-known/agent.json',
      'GET /v1/a2a/agent-card',
      'POST /v1/a2a/attest',
      'POST /v1/a2a/verify-card',
      'POST /v1/a2a/verify-agent',
      'GET /v1/a2a/trust-level/:agent_url',
      'GET /v1/a2a/cards',
      'GET /v1/a2a/cards/:id',
    ],
    spec: 'https://google.github.io/A2A/',
  },

  'oidc-a': {
    name: 'OIDC-A Attestation',
    category: 'Protocols',
    summary: 'Entity Attestation Tokens (EAT/RFC 9334) and OIDC-A claims for enterprise agent auth chains.',
    detail: `OIDC-A bridges human identity systems with agent identity systems.
Chain: human → enterprise IdP → BOTCHA → agent.

Three capabilities:

1. Entity Attestation Tokens (EAT / RFC 9334):
   POST /v1/attestation/eat — signed JWT attesting agent provenance, verification method, model identity
   Fields: agent_model, ttl_seconds, verification_method, nonce

2. OIDC-A Agent Claims:
   POST /v1/attestation/oidc-agent-claims — OIDC claims block JWT for OAuth2 token responses
   Fields: agent_model, agent_version, agent_capabilities, agent_operator,
           human_oversight_required, task_id, task_purpose

3. Agent Grant Flow (OAuth2-style):
   POST /v1/auth/agent-grant — initiate; if human_oversight_required=true, returns oversight_url
   GET /v1/auth/agent-grant/:id/status — poll status
   POST /v1/auth/agent-grant/:id/resolve {"decision": "approved"} — human approves

Also: GET /v1/oidc/userinfo — OIDC-A UserInfo endpoint (returns agent claims for authenticated agent)
     GET /.well-known/oauth-authorization-server — OIDC discovery document`,
    endpoints: [
      'GET /.well-known/oauth-authorization-server',
      'POST /v1/attestation/eat',
      'POST /v1/attestation/oidc-agent-claims',
      'POST /v1/auth/agent-grant',
      'GET /v1/auth/agent-grant/:id/status',
      'POST /v1/auth/agent-grant/:id/resolve',
      'GET /v1/oidc/userinfo',
    ],
    spec: 'https://www.rfc-editor.org/rfc/rfc9334',
  },

  dashboard: {
    name: 'Dashboard & Auth',
    category: 'Platform',
    summary: 'Agent-first dashboard with per-app analytics. Agents solve challenges; humans use device codes.',
    detail: `The metrics dashboard at /dashboard shows per-app analytics.

Agent-first auth — no password form:
• Agent Direct: POST /v1/auth/dashboard → session token
• Device Code: POST /v1/auth/device-code (agent solves), POST /v1/auth/device-code/verify
  → returns BOTCHA-XXXX code → human enters at /dashboard/code → instant browser session
• Legacy: app_id + app_secret login at /dashboard/login

Dashboard shows: challenges generated, verifications, success rate, avg solve time,
request volume charts, challenge type breakdown, p50/p95 solve times, errors, geo distribution.
Time filters: 1h, 24h, 7d, 30d.`,
    endpoints: [
      'POST /v1/auth/device-code',
      'POST /v1/auth/device-code/verify',
      'GET /dashboard',
    ],
  },

  sdks: {
    name: 'SDKs & Middleware',
    category: 'Platform',
    summary: 'TypeScript (npm), Python (PyPI), CLI, LangChain. Server-side middleware for Express, Hono, FastAPI, Django.',
    detail: `Client SDKs (for agents):
• TypeScript: npm install @dupecom/botcha
  BotchaClient — drop-in fetch replacement, auto-solves challenges on 403/401
• Python: pip install botcha
  BotchaClient (async context manager) — same auto-solve behavior
• LangChain: npm install @dupecom/botcha-langchain
• CLI: npm install -g @dupecom/botcha-cli

Server middleware (for API providers):
• Express: npm install @dupecom/botcha-verify
  botchaVerify({ jwksUrl: 'https://botcha.ai/.well-known/jwks' })
• FastAPI: pip install botcha-verify
  BotchaVerify(jwks_url='https://botcha.ai/.well-known/jwks')
• Hono: built into @dupecom/botcha-verify
• Django: pip install botcha-verify, BotchaMiddleware

Verification uses ES256 asymmetric tokens via JWKS — no shared secret needed.
HS256 (shared secret) still supported for backward compatibility.`,
    endpoints: [],
  },

  discovery: {
    name: 'Discovery',
    category: 'Platform',
    summary: 'ai.txt, OpenAPI 3.1, AI Plugin manifest, DID Document, A2A card, MCP server.',
    detail: `BOTCHA is auto-discoverable by AI agents through multiple standards:

• GET /ai.txt — structured discovery file for AI agents
• GET /openapi.json — OpenAPI 3.1.0 specification
• GET /.well-known/ai-plugin.json — AI plugin manifest
• GET /.well-known/did.json — W3C DID Document
• GET /.well-known/agent.json — Google A2A Agent Card
• GET /.well-known/jwks — JWK Set for token verification
• GET /.well-known/oauth-authorization-server — OIDC discovery
• GET /.well-known/mcp.json — MCP server discovery (this server!)
• POST /mcp — MCP server (Model Context Protocol, 2025-03-26 Streamable HTTP)

Every response includes X-Botcha-* headers:
  X-Botcha-Version: 0.22.0
  X-Botcha-Enabled: true
  X-Botcha-Methods: hybrid-challenge,speed-challenge,...
  X-Botcha-Docs: https://botcha.ai/openapi.json`,
    endpoints: [
      'GET /ai.txt',
      'GET /openapi.json',
      'GET /.well-known/ai-plugin.json',
      'GET /.well-known/did.json',
      'GET /.well-known/agent.json',
      'GET /.well-known/jwks',
      'GET /.well-known/oauth-authorization-server',
      'GET /.well-known/mcp.json',
      'POST /mcp',
    ],
  },
};

// ============ ENDPOINT INDEX ============
// Flat lookup by path for get_endpoint tool

const ENDPOINT_DETAILS: Record<string, {
  method: string;
  path: string;
  auth: string;
  description: string;
  params?: string;
  body?: string;
  response?: string;
}> = {
  'GET /v1/challenges': {
    method: 'GET', path: '/v1/challenges', auth: 'app_id required',
    description: 'Generate a challenge. Default type is hybrid (speed + reasoning).',
    params: '?type=hybrid|speed|standard — challenge type\n?ts=<ms> — client timestamp for RTT compensation\n?app_id=<id> — required app ID',
    response: '{ success, type, challenge: { id, speed: { problems, timeLimit }, reasoning: { questions, timeLimit } }, verify_endpoint }',
  },
  'POST /v1/challenges/:id/verify': {
    method: 'POST', path: '/v1/challenges/:id/verify', auth: 'app_id required',
    description: 'Submit challenge solution. Challenge is deleted on first attempt (single-use).',
    body: 'Hybrid: { type: "hybrid", speed_answers: ["8hex",...], reasoning_answers: {"q-id": "answer"} }\nSpeed: { type: "speed", answers: ["8hex",...] }',
    response: '{ success, message, speed: { valid, solveTimeMs }, reasoning: { valid, score } }',
  },
  'GET /v1/token': {
    method: 'GET', path: '/v1/token', auth: 'app_id required',
    description: 'Get a speed challenge to solve in exchange for a JWT token pair.',
    params: '?ts=<ms> — RTT compensation\n?audience=<url> — scope token to a service\n?app_id=<id> — required',
  },
  'POST /v1/token/verify': {
    method: 'POST', path: '/v1/token/verify', auth: 'app_id required',
    description: 'Submit challenge solution, receive access_token + refresh_token + human_link.',
    body: '{ id: "<challenge_id>", answers: ["hash1",...], audience?: "<url>", bind_ip?: true }',
    response: '{ success, access_token, expires_in: 3600, refresh_token, refresh_expires_in: 3600, human_link, human_code, solveTimeMs }',
  },
  'POST /v1/token/refresh': {
    method: 'POST', path: '/v1/token/refresh', auth: 'none',
    description: 'Exchange a refresh_token for a new access_token.',
    body: '{ refresh_token: "<token>" }',
    response: '{ success, access_token, expires_in: 3600 }',
  },
  'POST /v1/token/revoke': {
    method: 'POST', path: '/v1/token/revoke', auth: 'none',
    description: 'Immediately revoke any BOTCHA token (access or refresh).',
    body: '{ token: "<jwt>" }',
  },
  'POST /v1/token/validate': {
    method: 'POST', path: '/v1/token/validate', auth: 'none',
    description: 'Validate any BOTCHA token without needing the signing secret. Supports ES256 and HS256.',
    body: '{ token: "<jwt>" }',
    response: '{ valid: true, payload: { sub, type, aud, exp } } or { valid: false, error: "..." }',
  },
  'POST /v1/apps': {
    method: 'POST', path: '/v1/apps', auth: 'none',
    description: 'Create a new app. Email required. App secret shown ONCE — save it.',
    body: '{ email: "human@example.com", name?: "My App" }',
    response: '{ success, app_id, app_secret, email, email_verified: false }',
  },
  'POST /v1/agents/register': {
    method: 'POST', path: '/v1/agents/register', auth: 'app_id required',
    description: 'Register a new agent identity. Returns a persistent agent_id.',
    body: '{ name: "my-agent", operator: "Acme Corp", version?: "1.0.0" }',
    response: '{ agent_id, app_id, name, operator, version, created_at }',
  },
  'POST /v1/agents/register/tap': {
    method: 'POST', path: '/v1/agents/register/tap', auth: 'app_id required',
    description: 'Register a TAP agent with a public key and capability scoping.',
    body: '{ name, operator?, version?, public_key, signature_algorithm: "ed25519"|"ecdsa-p256-sha256"|"rsa-pss-sha256", capabilities: [{action, resource, constraints?}], trust_level: "basic"|"verified"|"enterprise" }',
  },
  'POST /v1/sessions/tap': {
    method: 'POST', path: '/v1/sessions/tap', auth: 'app_id required',
    description: 'Create a TAP session with intent declaration. Validates intent against registered capabilities.',
    body: '{ agent_id, user_context, intent: { action, resource, duration? } }',
    response: '{ session_id, agent_id, intent, expires_at, status: "active" }',
  },
  'POST /v1/delegations': {
    method: 'POST', path: '/v1/delegations', auth: 'Bearer token',
    description: 'Create a delegation from grantor agent to grantee agent. Capabilities can only narrow.',
    body: '{ grantor_id, grantee_id, capabilities: [{action, resource}], ttl: 3600, parent_delegation_id? }',
    response: '{ delegation_id, grantor_id, grantee_id, capabilities, expires_at, status: "active" }',
  },
  'POST /v1/delegations/:id/revoke': {
    method: 'POST', path: '/v1/delegations/:id/revoke', auth: 'Bearer token',
    description: 'Revoke a delegation. Cascades to all child delegations.',
    body: '{ reason?: "string" }',
  },
  'POST /v1/verify/delegation': {
    method: 'POST', path: '/v1/verify/delegation', auth: 'Bearer token',
    description: 'Verify the entire delegation chain and return effective capabilities.',
    body: '{ delegation_id }',
    response: '{ valid, effective_capabilities, chain: [...], depth }',
  },
  'POST /v1/attestations': {
    method: 'POST', path: '/v1/attestations', auth: 'Bearer token',
    description: 'Issue an attestation token with can/cannot capability rules.',
    body: '{ agent_id, can: ["read:invoices", "browse:*"], cannot?: ["purchase:*"], ttl: 3600, delegation_id? }',
    response: '{ attestation_id, token, agent_id, can, cannot, expires_at }',
  },
  'POST /v1/verify/attestation': {
    method: 'POST', path: '/v1/verify/attestation', auth: 'Bearer token',
    description: 'Verify an attestation token and check if a specific capability is allowed.',
    body: '{ token, action, resource }',
    response: '{ valid, allowed, reason? }',
  },
  'POST /v1/reputation/events': {
    method: 'POST', path: '/v1/reputation/events', auth: 'Bearer token',
    description: 'Record a reputation event for an agent.',
    body: '{ agent_id, category: "verification"|"commerce"|"compliance"|"social"|"security"|"governance", action: "<action_name>", metadata?: {}, source_agent_id? }',
  },
  'POST /v1/webhooks': {
    method: 'POST', path: '/v1/webhooks', auth: 'app_id + Bearer token',
    description: 'Register a webhook endpoint. Signing secret shown ONCE.',
    body: '{ url: "https://...", events: ["token.created", ...] }',
    response: '{ webhook_id, url, signing_secret, events, enabled: true }',
  },
  'POST /v1/credentials/issue': {
    method: 'POST', path: '/v1/credentials/issue', auth: 'Bearer token',
    description: 'Issue a W3C Verifiable Credential JWT signed with BOTCHA\'s ES256 key.',
    body: '{ subject: {}, type?: ["VerifiableCredential", "BotchaVerification"], ttl_seconds?: 3600 }',
    response: '{ vc: "eyJ...", expires_at }',
  },
  'POST /v1/credentials/verify': {
    method: 'POST', path: '/v1/credentials/verify', auth: 'public',
    description: 'Verify any BOTCHA-issued VC JWT. Public — no auth required.',
    body: '{ vc: "eyJ..." }',
    response: '{ valid, payload: { iss: "did:web:botcha.ai", sub, vc: { type, credentialSubject } } }',
  },
  'POST /v1/a2a/attest': {
    method: 'POST', path: '/v1/a2a/attest', auth: 'Bearer token',
    description: 'Attest an A2A Agent Card. Returns a tamper-evident BOTCHA trust seal.',
    body: '{ card: { name, url, version, capabilities, skills }, duration_seconds?: 86400, trust_level?: "verified" }',
    response: '{ success, attestation: { attestation_id, trust_level, token }, attested_card: { ...card, extensions: { botcha_attestation: { token, card_hash } } } }',
  },
  'POST /v1/attestation/eat': {
    method: 'POST', path: '/v1/attestation/eat', auth: 'Bearer token',
    description: 'Issue an Entity Attestation Token (EAT / RFC 9334).',
    body: '{ agent_model?: "gpt-5", ttl_seconds?: 900, verification_method?: "speed-challenge", nonce? }',
    response: '{ token: "eyJ...", expires_at }',
  },
  'POST /v1/attestation/oidc-agent-claims': {
    method: 'POST', path: '/v1/attestation/oidc-agent-claims', auth: 'Bearer token',
    description: 'Issue an OIDC-A agent claims block JWT for inclusion in OAuth2 token responses.',
    body: '{ agent_model?, agent_version?, agent_capabilities?: ["agent:tool-use"], agent_operator?, human_oversight_required?: false, task_id?, task_purpose?, nonce? }',
  },
  'POST /v1/auth/agent-grant': {
    method: 'POST', path: '/v1/auth/agent-grant', auth: 'Bearer token',
    description: 'Initiate an OAuth2-style agent grant. Returns oversight_url if human_oversight_required=true.',
    body: '{ scope: "agent:read openid", human_oversight_required?: true, agent_model?, agent_operator?, task_purpose? }',
    response: '{ grant_id, token, status: "pending"|"approved", oversight_url? }',
  },
};

// ============ CODE EXAMPLES ============

const EXAMPLES: Record<string, Record<string, string>> = {
  challenges: {
    typescript: `import { BotchaClient } from '@dupecom/botcha';

const client = new BotchaClient({ appId: 'app_...' });

// Auto-solve: challenges handled automatically
const response = await client.fetch('https://api.example.com/agent-only');
const data = await response.json();`,
    python: `from botcha import BotchaClient

async with BotchaClient(app_id="app_...") as client:
    # Auto-solve: challenges handled automatically
    response = await client.fetch("https://api.example.com/agent-only")
    data = response.json()`,
    curl: `# 1. Get challenge
curl "https://botcha.ai/v1/challenges?app_id=app_..."

# 2. Solve: SHA-256 of each number, first 8 hex chars
echo -n "42" | sha256sum | cut -c1-8

# 3. Verify
curl -X POST "https://botcha.ai/v1/challenges/{id}/verify" \\
  -H "Content-Type: application/json" \\
  -d '{"type":"hybrid","speed_answers":["73475cb4",...],"reasoning_answers":{"q1":"answer"}}'`,
  },

  tokens: {
    typescript: `import { BotchaClient } from '@dupecom/botcha';

const client = new BotchaClient({
  appId: 'app_...',
  audience: 'https://api.example.com',  // scope token to this service
});

// Get token explicitly
const token = await client.getToken();

// Or use fetch — auto-handles challenge → token → refresh → retry
const response = await client.fetch('https://api.example.com/protected');`,
    python: `from botcha import BotchaClient

async with BotchaClient(app_id="app_...", audience="https://api.example.com") as client:
    token = await client.get_token()
    response = await client.fetch("https://api.example.com/protected")`,
    curl: `# Get challenge for token flow
curl "https://botcha.ai/v1/token?app_id=app_..."

# Submit solution, get JWT
curl -X POST https://botcha.ai/v1/token/verify \\
  -H "Content-Type: application/json" \\
  -d '{"id":"<challenge_id>","answers":["hash1","hash2","hash3","hash4","hash5"]}'

# Use token
curl https://botcha.ai/agent-only \\
  -H "Authorization: Bearer <access_token>"`,
  },

  tap: {
    typescript: `import { BotchaClient } from '@dupecom/botcha';

const client = new BotchaClient({ appId: 'app_...' });

// Register TAP agent with public key
const agent = await client.registerTAPAgent({
  name: 'shopping-agent',
  operator: 'Acme Corp',
  capabilities: [{ action: 'browse', scope: ['products'] }],
  trust_level: 'verified',
});

// Create intent-scoped session
const session = await client.createTAPSession({
  agent_id: agent.agent_id,
  user_context: 'user-hash',
  intent: { action: 'browse', resource: 'products', duration: 3600 },
});`,
    python: `from botcha import BotchaClient

async with BotchaClient(app_id="app_...") as client:
    agent = await client.register_tap_agent(
        name="shopping-agent",
        operator="Acme Corp",
        capabilities=[{"action": "browse", "scope": ["products"]}],
        trust_level="verified",
    )
    session = await client.create_tap_session(
        agent_id=agent.agent_id,
        user_context="user-hash",
        intent={"action": "browse", "resource": "products", "duration": 3600},
    )`,
    curl: `# Register TAP agent
curl -X POST "https://botcha.ai/v1/agents/register/tap?app_id=app_..." \\
  -H "Content-Type: application/json" \\
  -d '{
    "name": "shopping-agent",
    "public_key": "-----BEGIN PUBLIC KEY-----\\n...\\n-----END PUBLIC KEY-----",
    "signature_algorithm": "ecdsa-p256-sha256",
    "capabilities": [{"action": "browse", "resource": "products"}],
    "trust_level": "verified"
  }'`,
  },

  delegation: {
    typescript: `import { BotchaClient } from '@dupecom/botcha';

const client = new BotchaClient({ appId: 'app_...' });

// Agent A delegates browse:products to Agent B
const delegation = await client.createDelegation({
  grantor_id: 'agent_aaa',
  grantee_id: 'agent_bbb',
  capabilities: [{ action: 'browse', resource: 'products' }],
  duration_seconds: 3600,
});

// Verify the chain
const chain = await client.verifyDelegationChain(delegation.delegation_id);
console.log(chain.effective_capabilities);

// Revoke (cascades to sub-delegations)
await client.revokeDelegation(delegation.delegation_id, 'Session ended');`,
    python: `from botcha import BotchaClient

async with BotchaClient(app_id="app_...") as client:
    delegation = await client.create_delegation(
        grantor_id="agent_aaa",
        grantee_id="agent_bbb",
        capabilities=[{"action": "browse", "resource": "products"}],
        ttl=3600,
    )
    chain = await client.verify_delegation_chain(delegation.delegation_id)
    await client.revoke_delegation(delegation.delegation_id, reason="Session ended")`,
    curl: `curl -X POST https://botcha.ai/v1/delegations \\
  -H "Authorization: Bearer <token>" \\
  -H "Content-Type: application/json" \\
  -d '{
    "grantor_id": "agent_aaa",
    "grantee_id": "agent_bbb",
    "capabilities": [{"action": "browse", "resource": "products"}],
    "ttl": 3600
  }'`,
  },

  attestation: {
    typescript: `import { BotchaClient } from '@dupecom/botcha';

const client = new BotchaClient({ appId: 'app_...' });

const att = await client.issueAttestation({
  agent_id: 'agent_abc123',
  can: ['read:invoices', 'browse:*'],
  cannot: ['purchase:*'],
  duration_seconds: 3600,
});

// Present token as header: X-Botcha-Attestation: <att.token>

// Verify capability
const check = await client.verifyAttestation(att.token, 'read', 'invoices');
console.log(check.allowed); // true`,
    python: `from botcha import BotchaClient

async with BotchaClient(app_id="app_...") as client:
    att = await client.issue_attestation(
        agent_id="agent_abc123",
        can=["read:invoices", "browse:*"],
        cannot=["purchase:*"],
        ttl=3600,
    )
    check = await client.verify_attestation(att.token, "read", "invoices")
    print(check.allowed)  # True`,
    curl: `curl -X POST https://botcha.ai/v1/attestations \\
  -H "Authorization: Bearer <token>" \\
  -H "Content-Type: application/json" \\
  -d '{
    "agent_id": "agent_abc123",
    "can": ["read:invoices", "browse:*"],
    "cannot": ["purchase:*"],
    "ttl": 3600
  }'`,
  },

  'did-vc': {
    typescript: `import { BotchaClient } from '@dupecom/botcha';

const client = new BotchaClient({ appId: 'app_...' });

// Issue a W3C Verifiable Credential
const result = await client.issueCredential({
  subject: { agentType: 'llm', operator: 'Acme Corp' },
  credentialType: ['VerifiableCredential', 'BotchaVerification'],
  ttlSeconds: 3600,
});
console.log(result.vc); // eyJ... — portable JWT

// Anyone can verify offline
const verified = await client.verifyCredential(result.vc);
console.log(verified.valid); // true
console.log(verified.payload.iss); // did:web:botcha.ai`,
    python: `from botcha import BotchaClient

async with BotchaClient() as client:
    result = await client.issue_credential(
        subject={"agentType": "llm", "operator": "Acme Corp"},
        credential_type=["VerifiableCredential", "BotchaVerification"],
        ttl_seconds=3600,
    )
    verified = await client.verify_credential(result.vc)
    print(verified.valid)          # True
    print(verified.payload["iss"]) # did:web:botcha.ai`,
    curl: `# Issue VC
curl -X POST https://botcha.ai/v1/credentials/issue \\
  -H "Authorization: Bearer <token>" \\
  -H "Content-Type: application/json" \\
  -d '{"subject":{"agentType":"llm"},"type":["VerifiableCredential","BotchaVerification"]}'

# Verify VC (public, no auth needed)
curl -X POST https://botcha.ai/v1/credentials/verify \\
  -H "Content-Type: application/json" \\
  -d '{"vc":"eyJ..."}'`,
  },

  a2a: {
    typescript: `import { BotchaClient } from '@dupecom/botcha';

const client = new BotchaClient({ appId: 'app_...' });

// Attest your A2A Agent Card
const result = await client.attestAgentCard({
  card: {
    name: 'My Commerce Agent',
    url: 'https://myagent.example',
    version: '1.0.0',
    capabilities: { streaming: false },
    skills: [{ id: 'browse', name: 'Browse' }],
  },
  trust_level: 'verified',
});

// Verify any attested card
const check = await client.verifyAgentCard(result.attested_card);
console.log(check.valid); // true`,
    python: `from botcha import BotchaClient

async with BotchaClient() as client:
    result = await client.attest_agent_card(
        card={"name": "My Agent", "url": "https://myagent.example", "version": "1.0.0",
              "capabilities": {"streaming": False}, "skills": [{"id": "browse", "name": "Browse"}]},
        trust_level="verified",
    )
    check = await client.verify_agent_card(result.attested_card)
    print(check.valid)  # True`,
    curl: `curl -X POST https://botcha.ai/v1/a2a/attest \\
  -H "Authorization: Bearer <token>" \\
  -H "Content-Type: application/json" \\
  -d '{
    "card": {"name":"My Agent","url":"https://myagent.example","version":"1.0.0",
             "capabilities":{"streaming":false},"skills":[{"id":"browse","name":"Browse"}]},
    "trust_level": "verified"
  }'`,
  },

  'oidc-a': {
    typescript: `import { BotchaClient } from '@dupecom/botcha';

const client = new BotchaClient({ appId: 'app_...' });

// Issue Entity Attestation Token (EAT / RFC 9334)
const eat = await client.issueEAT({
  agent_model: 'gpt-5',
  ttl_seconds: 900,
  verification_method: 'speed-challenge',
});

// Start an agent grant with human oversight
const grant = await client.createAgentGrant({
  scope: 'agent:read openid',
  human_oversight_required: true,
  task_purpose: 'invoice reconciliation',
});
if (grant.oversight_url) {
  console.log('Human approval needed:', grant.oversight_url);
}`,
    python: `from botcha import BotchaClient

async with BotchaClient() as client:
    eat = await client.issue_eat(agent_model="gpt-5", ttl_seconds=900)
    grant = await client.create_agent_grant(
        scope="agent:read openid",
        human_oversight_required=True,
        task_purpose="invoice reconciliation",
    )
    if grant.oversight_url:
        print(f"Human approval needed: {grant.oversight_url}")`,
    curl: `# Issue EAT
curl -X POST https://botcha.ai/v1/attestation/eat \\
  -H "Authorization: Bearer <token>" \\
  -H "Content-Type: application/json" \\
  -d '{"agent_model":"gpt-5","ttl_seconds":900,"verification_method":"speed-challenge"}'

# Start agent grant
curl -X POST https://botcha.ai/v1/auth/agent-grant \\
  -H "Authorization: Bearer <token>" \\
  -H "Content-Type: application/json" \\
  -d '{"scope":"agent:read openid","human_oversight_required":true,"task_purpose":"invoice reconciliation"}'`,
  },

  x402: {
    typescript: `import { BotchaClient } from '@dupecom/botcha';

const client = new BotchaClient({ appId: 'app_...' });

// Get payment terms
const info = await client.getX402Info();
// info: { amount: "0.001", currency: "USDC", chain: "base", recipient: "0x..." }

// After paying on-chain, get the token
const result = await client.getX402Challenge(paymentProof);
// result.access_token — no challenge solved!`,
    python: `from botcha import BotchaClient

async with BotchaClient(app_id="app_...") as client:
    info = await client.get_x402_info()
    # Pay on-chain, then:
    result = await client.get_x402_challenge(payment_proof=payment_proof)`,
    curl: `# Step 1: Get payment terms (returns 402)
curl https://botcha.ai/v1/x402/challenge

# Step 2: Pay on Base, then retry with payment proof
curl https://botcha.ai/v1/x402/challenge \\
  -H "X-Payment: <payment_proof>"`,
  },
};

// ============ TOOL DEFINITIONS ============

const MCP_TOOLS: MCPTool[] = [
  {
    name: 'list_features',
    description: 'List all BOTCHA features with a brief summary of each. Use this to discover what BOTCHA can do, or to get an overview before diving into a specific feature.',
    inputSchema: { type: 'object', properties: {
      category: {
        type: 'string',
        description: 'Filter by category: Core, Identity, Protocols, or Platform. Omit for all.',
        enum: ['Core', 'Identity', 'Protocols', 'Platform'],
      },
    }},
  },
  {
    name: 'get_feature',
    description: 'Get detailed documentation for a specific BOTCHA feature, including how it works, what endpoints it uses, and any relevant specifications.',
    inputSchema: { type: 'object', properties: {
      feature: {
        type: 'string',
        description: 'Feature name: challenges, tokens, apps, agents, tap, delegation, attestation, reputation, webhooks, x402, ans, did-vc, a2a, oidc-a, dashboard, sdks, or discovery',
      },
    }, required: ['feature'] },
  },
  {
    name: 'search_docs',
    description: 'Search across all BOTCHA documentation by keyword. Useful when you\'re not sure which feature covers your use case.',
    inputSchema: { type: 'object', properties: {
      query: {
        type: 'string',
        description: 'Search terms — e.g. "how do I verify a token", "delegation cascade", "USDC payment", "RFC 9421"',
      },
    }, required: ['query'] },
  },
  {
    name: 'list_endpoints',
    description: 'List all BOTCHA API endpoints grouped by category. Returns method, path, and a short description for each.',
    inputSchema: { type: 'object', properties: {
      category: {
        type: 'string',
        description: 'Filter by feature category. Omit for all endpoints.',
        enum: ['Core', 'Identity', 'Protocols', 'Platform'],
      },
    }},
  },
  {
    name: 'get_endpoint',
    description: 'Get detailed documentation for a specific API endpoint: description, authentication, request body/params, and response shape.',
    inputSchema: { type: 'object', properties: {
      path: {
        type: 'string',
        description: 'Endpoint path, e.g. "POST /v1/token/verify" or "/v1/delegations" or "GET /v1/credentials/issue"',
      },
    }, required: ['path'] },
  },
  {
    name: 'get_example',
    description: 'Get a working code example for a BOTCHA feature in TypeScript, Python, or curl.',
    inputSchema: { type: 'object', properties: {
      feature: {
        type: 'string',
        description: 'Feature name: challenges, tokens, tap, delegation, attestation, did-vc, a2a, oidc-a, or x402',
      },
      language: {
        type: 'string',
        description: 'Language for the example',
        enum: ['typescript', 'python', 'curl'],
      },
    }, required: ['feature', 'language'] },
  },
];

// ============ TOOL IMPLEMENTATIONS ============

function toolListFeatures(params: Record<string, unknown>): unknown {
  const category = params.category as string | undefined;
  const entries = Object.entries(FEATURES)
    .filter(([, f]) => !category || f.category === category)
    .map(([key, f]) => ({
      id: key,
      name: f.name,
      category: f.category,
      summary: f.summary,
      ...(f.spec ? { spec: f.spec } : {}),
    }));
  return {
    count: entries.length,
    features: entries,
    tip: 'Use get_feature("<id>") for detailed docs, get_example("<id>", "<lang>") for code.',
  };
}

function toolGetFeature(params: Record<string, unknown>): unknown {
  const key = (params.feature as string)?.toLowerCase().replace(/ /g, '-');
  const feature = FEATURES[key];
  if (!feature) {
    const available = Object.keys(FEATURES).join(', ');
    return { error: `Feature "${params.feature}" not found. Available: ${available}` };
  }
  return {
    name: feature.name,
    category: feature.category,
    summary: feature.summary,
    detail: feature.detail,
    endpoints: feature.endpoints,
    ...(feature.spec ? { spec: feature.spec } : {}),
    tip: `Use get_example("${key}", "typescript"|"python"|"curl") for code examples.`,
  };
}

function toolSearchDocs(params: Record<string, unknown>): unknown {
  const query = (params.query as string || '').toLowerCase();
  const terms = query.split(/\s+/).filter(Boolean);

  const results: Array<{ feature: string; name: string; category: string; relevance: number; excerpt: string }> = [];

  for (const [key, feature] of Object.entries(FEATURES)) {
    const searchText = [
      feature.name, feature.category, feature.summary, feature.detail,
      ...feature.endpoints, feature.spec ?? '',
    ].join(' ').toLowerCase();

    const relevance = terms.reduce((score, term) => {
      const matches = (searchText.match(new RegExp(term, 'g')) || []).length;
      return score + matches;
    }, 0);

    if (relevance > 0) {
      // Find the most relevant excerpt from detail
      const detailLower = feature.detail.toLowerCase();
      let bestIdx = -1;
      let bestScore = 0;
      for (const term of terms) {
        const idx = detailLower.indexOf(term);
        if (idx !== -1 && idx > bestScore) { bestIdx = idx; bestScore = idx; }
      }
      const excerptStart = Math.max(0, bestIdx - 40);
      const excerpt = feature.detail.slice(excerptStart, excerptStart + 200).trim();

      results.push({ feature: key, name: feature.name, category: feature.category, relevance, excerpt });
    }
  }

  // Check endpoint index too
  const endpointMatches: string[] = [];
  for (const [key, ep] of Object.entries(ENDPOINT_DETAILS)) {
    const text = [key, ep.description, ep.body ?? '', ep.response ?? ''].join(' ').toLowerCase();
    if (terms.some(t => text.includes(t))) endpointMatches.push(key);
  }

  results.sort((a, b) => b.relevance - a.relevance);

  if (results.length === 0 && endpointMatches.length === 0) {
    return { message: `No results for "${params.query}". Try terms like: challenge, token, delegation, attestation, reputation, webhook, x402, ANS, DID, VC, A2A, OIDC, TAP` };
  }

  return {
    query: params.query,
    features: results.slice(0, 5).map(r => ({ feature: r.feature, name: r.name, category: r.category, excerpt: r.excerpt })),
    matching_endpoints: endpointMatches.slice(0, 10),
    tip: 'Use get_feature() or get_endpoint() for full details on any result.',
  };
}

function toolListEndpoints(params: Record<string, unknown>): unknown {
  const category = params.category as string | undefined;
  const groups: Record<string, Array<{ method: string; path: string; description: string }>> = {};

  for (const [, feature] of Object.entries(FEATURES)) {
    if (category && feature.category !== category) continue;
    if (feature.endpoints.length === 0) continue;

    const key = `${feature.category}: ${feature.name}`;
    groups[key] = feature.endpoints.map(ep => {
      const [method, path] = ep.split(' ');
      const detail = ENDPOINT_DETAILS[ep];
      return { method, path, description: detail?.description ?? '' };
    });
  }

  const totalCount = Object.values(groups).reduce((n, arr) => n + arr.length, 0);
  return { total: totalCount, groups };
}

function toolGetEndpoint(params: Record<string, unknown>): unknown {
  const query = (params.path as string || '').trim().toUpperCase();

  // Try exact match first (normalize)
  for (const [key, ep] of Object.entries(ENDPOINT_DETAILS)) {
    if (key.toUpperCase() === query || key.toUpperCase().endsWith(query) ||
        query.includes(ep.path.toUpperCase())) {
      return {
        method: ep.method,
        path: ep.path,
        auth: ep.auth,
        description: ep.description,
        ...(ep.params ? { params: ep.params } : {}),
        ...(ep.body ? { requestBody: ep.body } : {}),
        ...(ep.response ? { response: ep.response } : {}),
      };
    }
  }

  // Fuzzy: check if path fragment matches
  const pathQuery = (params.path as string).replace(/^(GET|POST|PUT|DELETE|PATCH)\s+/i, '').trim();
  for (const [key, ep] of Object.entries(ENDPOINT_DETAILS)) {
    if (ep.path.includes(pathQuery) || pathQuery.includes(ep.path)) {
      return {
        method: ep.method,
        path: ep.path,
        auth: ep.auth,
        description: ep.description,
        ...(ep.params ? { params: ep.params } : {}),
        ...(ep.body ? { requestBody: ep.body } : {}),
        ...(ep.response ? { response: ep.response } : {}),
      };
    }
  }

  const available = Object.keys(ENDPOINT_DETAILS).slice(0, 15).join('\n  ');
  return { error: `Endpoint "${params.path}" not found. Some available endpoints:\n  ${available}\n\nUse list_endpoints() to browse all.` };
}

function toolGetExample(params: Record<string, unknown>): unknown {
  const key = (params.feature as string)?.toLowerCase().replace(/ /g, '-');
  const lang = (params.language as string)?.toLowerCase();

  const featureExamples = EXAMPLES[key];
  if (!featureExamples) {
    const available = Object.keys(EXAMPLES).join(', ');
    return { error: `No examples for "${params.feature}". Available: ${available}` };
  }

  if (!['typescript', 'python', 'curl'].includes(lang)) {
    return { error: 'language must be "typescript", "python", or "curl"' };
  }

  const code = featureExamples[lang];
  if (!code) {
    return { error: `No ${lang} example for "${key}"` };
  }

  const feature = FEATURES[key];
  return {
    feature: key,
    language: lang,
    ...(lang === 'typescript' ? { install: 'npm install @dupecom/botcha' } : {}),
    ...(lang === 'python' ? { install: 'pip install botcha' } : {}),
    code,
    docs: feature ? `https://botcha.ai/docs#${key}` : undefined,
  };
}

// ============ JSON-RPC DISPATCHER ============

function jsonRpcError(id: string | number | null, code: number, message: string): JSONRPCResponse {
  return { jsonrpc: '2.0', id, error: { code, message } };
}

function jsonRpcResult(id: string | number | null, result: unknown): JSONRPCResponse {
  return { jsonrpc: '2.0', id, result };
}

function handleMethod(req: JSONRPCRequest, version: string): JSONRPCResponse {
  const { id, method, params = {} } = req;

  switch (method) {
    case 'initialize':
      return jsonRpcResult(id, {
        protocolVersion: '2025-03-26',
        capabilities: { tools: {} },
        serverInfo: {
          name: 'BOTCHA Documentation',
          version,
          description: 'Ask questions about BOTCHA features, API endpoints, and integrations. BOTCHA is the identity layer for AI agents.',
        },
        instructions: 'Use list_features() to discover what BOTCHA supports, get_feature("<name>") for detailed docs, get_example("<name>", "<lang>") for code, search_docs("<query>") to find relevant sections, and list_endpoints() or get_endpoint("<path>") for API reference.',
      });

    case 'notifications/initialized':
      return { jsonrpc: '2.0', id: null, result: {} };

    case 'tools/list':
      return jsonRpcResult(id, { tools: MCP_TOOLS });

    case 'tools/call': {
      const name = params.name as string;
      const toolParams = (params.arguments ?? {}) as Record<string, unknown>;

      switch (name) {
        case 'list_features':   return jsonRpcResult(id, { content: [{ type: 'text', text: JSON.stringify(toolListFeatures(toolParams), null, 2) }] });
        case 'get_feature':     return jsonRpcResult(id, { content: [{ type: 'text', text: JSON.stringify(toolGetFeature(toolParams), null, 2) }] });
        case 'search_docs':     return jsonRpcResult(id, { content: [{ type: 'text', text: JSON.stringify(toolSearchDocs(toolParams), null, 2) }] });
        case 'list_endpoints':  return jsonRpcResult(id, { content: [{ type: 'text', text: JSON.stringify(toolListEndpoints(toolParams), null, 2) }] });
        case 'get_endpoint':    return jsonRpcResult(id, { content: [{ type: 'text', text: JSON.stringify(toolGetEndpoint(toolParams), null, 2) }] });
        case 'get_example':     return jsonRpcResult(id, { content: [{ type: 'text', text: JSON.stringify(toolGetExample(toolParams), null, 2) }] });
        default:
          return jsonRpcError(id, -32601, `Unknown tool: ${name}`);
      }
    }

    case 'ping':
      return jsonRpcResult(id, {});

    default:
      return jsonRpcError(id, -32601, `Method not found: ${method}`);
  }
}

// ============ HTTP HANDLER ============

export async function handleMCPRequest(request: Request, version: string): Promise<Response> {
  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Mcp-Session-Id',
  };

  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  if (request.method === 'GET') {
    // Streamable HTTP: GET returns server info / healthcheck
    return new Response(JSON.stringify({
      name: 'BOTCHA Documentation',
      version,
      protocol: 'MCP 2025-03-26 Streamable HTTP',
      endpoint: 'POST /mcp',
      tools: MCP_TOOLS.map(t => ({ name: t.name, description: t.description })),
    }, null, 2), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }

  if (request.method !== 'POST') {
    return new Response('Method Not Allowed', { status: 405, headers: corsHeaders });
  }

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return new Response(
      JSON.stringify(jsonRpcError(null, -32700, 'Parse error — invalid JSON')),
      { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } },
    );
  }

  // Support both single request and batch array
  const isBatch = Array.isArray(body);
  const requests: JSONRPCRequest[] = isBatch ? body as JSONRPCRequest[] : [body as JSONRPCRequest];

  const responses = requests
    .map(req => {
      if (!req || req.jsonrpc !== '2.0' || !req.method) {
        return jsonRpcError(req?.id ?? null, -32600, 'Invalid JSON-RPC 2.0 request');
      }
      return handleMethod(req, version);
    })
    // Notifications (id === undefined/null in request with no expected response) are filtered out
    .filter(r => r.id !== null || r.error);

  const responseBody = isBatch ? responses : responses[0];

  return new Response(JSON.stringify(responseBody), {
    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
  });
}

// ============ DISCOVERY HANDLER ============

export function handleMCPDiscovery(version: string): Response {
  return new Response(JSON.stringify({
    mcpVersion: '2025-03-26',
    name: 'BOTCHA Documentation',
    description: 'Ask questions about BOTCHA features, API endpoints, and integrations for AI agents.',
    version,
    endpoint: 'https://botcha.ai/mcp',
    transport: 'streamable-http',
    tools: MCP_TOOLS.map(t => ({ name: t.name, description: t.description })),
    contact: 'https://botcha.ai',
  }, null, 2), {
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
    },
  });
}
