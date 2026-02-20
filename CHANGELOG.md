# CHANGELOG

All notable changes to BOTCHA are documented here.

Format: [Semantic Versioning](https://semver.org/). Newest entries first.

---

## [Unreleased]

### 🔄 OIDC-A Attestation (PR #28)

In active review on `epic/oidc-a-attestation`. Current open issues are tracked in [BUGS.md](./BUGS.md).
Roadmap status and scope are tracked in [ROADMAP.md](./ROADMAP.md).

---

## [0.22.0] — 2026-02-20

### Protocol Integrations (4 epics)

Four epics merged to main (PRs #25, #26, #27, #29).

#### ✅ x402 Payment Gating (PR #25 — merged)

HTTP 402 micropayment flow using USDC on Base. Agents can pay $0.001 USDC for a BOTCHA token instead of solving a challenge. BOTCHA also acts as a lightweight x402-compatible facilitator.

**New endpoints:**
- `GET /v1/x402/info` — public, payment config discovery
- `GET /v1/x402/challenge` — pay $0.001 USDC → receive BOTCHA access_token (no puzzle)
- `POST /v1/x402/verify-payment` — verify raw x402 payment proof (requires Bearer auth)
- `POST /v1/x402/webhook` — settlement notifications from x402 facilitators (Coinbase CDP)
- `GET /agent-only/x402` — demo endpoint: requires BOTH BOTCHA token + x402 payment

**Fixes included:**
- `POST /v1/x402/verify-payment` now correctly requires Bearer auth (was open)
- JSON 404 handler for unknown routes

See [doc/X402.md](./doc/X402.md) for the integration guide.

#### ✅ ANS (Agent Name Service) Integration (PR #27 — merged)

BOTCHA as a verification layer for the GoDaddy-led Agent Name Service standard. DNS-based agent identity lookup with BOTCHA-issued ownership badges.

**New endpoints:**
- `GET /v1/ans/botcha` — public, BOTCHA's own ANS identity
- `GET /v1/ans/resolve/:name` — public, DNS-based ANS lookup by name
- `GET /v1/ans/resolve/lookup?name=` — public, alternate DNS lookup via query param
- `GET /v1/ans/discover` — public, list BOTCHA-verified ANS agents
- `GET /v1/ans/nonce/:name` — auth required, nonce for ANS ownership proof
- `POST /v1/ans/verify` — auth required, verify ANS ownership + issue BOTCHA badge

**Fixes included:**
- Auth check on `POST /v1/ans/verify` now happens BEFORE DNS lookup (was 422 without auth)
- 2-part domain names (e.g. `botcha.ai`) now correctly resolve to `_ans.botcha.ai` (was `_ans.ai`)
- ANS version prefix parsing fixed (`v1.0.x` now correctly parsed)
- All 37 unit tests passing

See [doc/ANS.md](./doc/ANS.md) for the integration guide.

#### ✅ DID/VC Issuer — W3C Verifiable Credentials (PR #29 — merged)

BOTCHA as a W3C DID/VC issuer (`did:web:botcha.ai`). Issues portable W3C Verifiable Credential JWTs that any party can verify offline using BOTCHA's public JWKS — no round-trip to BOTCHA required.

**New endpoints:**
- `GET /.well-known/did.json` — public, BOTCHA DID Document (`did:web:botcha.ai`)
- `GET /.well-known/jwks` — public, JWK Set (extended to include DID signing keys)
- `GET /.well-known/jwks.json` — public, JWK Set alias (some resolvers append `.json`)
- `POST /v1/credentials/issue` — auth required (BOTCHA token), issues W3C VC JWT
- `POST /v1/credentials/verify` — public, verify any BOTCHA-issued VC JWT
- `GET /v1/dids/:did/resolve` — public, resolve `did:web` DIDs

**Fixes included:**
- Preview env gets static EC key (`JWT_SIGNING_KEY`) so JWKS and DID doc aren't empty
- `POST /v1/credentials/verify` returns 503 (not 200) when server is not configured
- Both `JWT_SECRET` + `JWT_SIGNING_KEY` set in preview env vars

See [doc/DID-VC.md](./doc/DID-VC.md) for the integration guide.

#### ✅ A2A Agent Card Attestation (PR #26 — merged)

BOTCHA as a trust seal issuer for the Google A2A protocol Agent Cards.

**New endpoints:**
- `GET /.well-known/agent.json` — BOTCHA's A2A Agent Card
- `GET /v1/a2a/agent-card` — BOTCHA's A2A Agent Card (alias)
- `POST /v1/a2a/attest` — attest an agent's A2A card → BOTCHA trust seal
- `POST /v1/a2a/verify-card` — verify attested card (tamper-evident hash check)
- `POST /v1/a2a/verify-agent` — verify agent by card or `agent_url`
- `GET /v1/a2a/trust-level/:agent_url` — get trust level for an agent URL
- `GET /v1/a2a/cards` and `GET /v1/a2a/cards/:id` — registry browsing

**Known follow-ups:**
- Tracked in [BUGS.md](./BUGS.md)

**Included fixes:**
- Added `/v1/a2a/agent-card` alias route
- Added `/v1/a2a/verify-agent` and `/v1/a2a/trust-level/:agent_url` routes
- Fixed `verify-agent` route typing/call-order bugs and compile breakage

See [doc/A2A.md](./doc/A2A.md) for the guide.

## [0.21.0]

- App Registration Required: all `/v1/*` endpoints now require a registered app with verified email (`requireAppId` middleware). Breaking change.

## [0.20.x]

- Email verification fixes (v0.20.3): `verify-email` and `resend-verification` require app_secret or dashboard session auth.
- Release v0.20.2 — see [reports/archive/legacy/RELEASE_v0.20.2_SUMMARY.md](./reports/archive/legacy/RELEASE_v0.20.2_SUMMARY.md).

## [0.19.0]

- Asymmetric JWT signing: ES256 (ECDSA P-256) by default, JWKS discovery, remote token validation (`POST /v1/token/validate`).

## [0.18.0]

- Agent Reputation Scoring: 0-1000 score, 5 tiers, 18 event types, mean-reversion decay, endorsements.
- SDK: `getReputation`, `recordReputationEvent`, `listReputationEvents`, `resetReputation` (TS + Python).

## [0.17.0]

- Delegation Chains: signed auditable agent-to-agent delegations with capability narrowing, depth limits, cascading revocation.
- Capability Attestation: fine-grained `action:resource` JWT permissions with explicit deny rules.

## [0.16.0]

- TAP Full Spec Alignment: Ed25519 support, RFC 9421 full compliance, Layer 2 (Consumer Recognition), Layer 3 (Payment Container), JWKS infrastructure, CDN edge verification, Visa key federation.

## [0.15.0]

- TAP Showcase Homepage at botcha.ai — TAP as lead feature with Visa reference links and animated terminal demo.

## [0.12.0]

- Trusted Agent Protocol (TAP): enterprise cryptographic agent auth via HTTP Message Signatures.

## [0.11.0]

- Agent Registry: persistent agent identities with name, operator, version.

## [0.10.0]

- Email-Tied App Creation & Recovery.
- Per-App Metrics Dashboard at `/dashboard`.

## [0.8.0]

- Multi-tenant API keys: per-app isolation, scoped tokens, rate limiting.

## [0.7.0]

- Security sweep: audience claims, token rotation, client IP binding, revocation, JTI.

## [0.1.0]

- `@dupecom/botcha-verify` (TS) and `botcha-verify` (Python) server-side verification SDKs.
