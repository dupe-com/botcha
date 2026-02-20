# OIDC-A Attestation

> **Status:** 🔄 In Progress — PR #28 open, test agent running, results pending. **Not yet merged to main.**

BOTCHA implements OIDC-A (OpenID Connect for Agents) attestation for enterprise agent authentication chains. This covers Entity Attestation Tokens (EAT, RFC 9711) and OIDC-A agent claims blocks — the building blocks for OAuth2-style agent grant flows in enterprise environments.

> ⚠️ **This feature is not yet available on botcha.ai.** The endpoints below describe the planned API. This document will be updated when PR #28 merges.

## What is OIDC-A?

OIDC-A extends the OpenID Connect spec with claims specific to AI agents — capability scopes, agent type, operator identity, and attestation proofs. Combined with Entity Attestation Tokens (RFC 9711), it enables enterprise-grade agent authentication chains: human → enterprise IdP → BOTCHA → agent.

## Discovery

Once merged, BOTCHA will publish an OIDC/OAuth2 discovery document:

```bash
GET /.well-known/oauth-authorization-server
```

The discovery doc is already confirmed working (200, correct shape) in the preview environment.

## Entity Attestation Tokens (EAT)

Issue an EAT per [RFC 9711](https://www.rfc-editor.org/rfc/rfc9711):

```bash
POST /v1/attestation/eat
Authorization: Bearer <botcha-token>
Content-Type: application/json

{
  "agent_id": "agent_abc123",
  "claims": {
    "hardware_id": "...",
    "software_version": "1.0.0"
  }
}
```

Returns a signed EAT JWT that can be presented to relying parties as proof of agent provenance.

## OIDC-A Agent Claims

Issue an OIDC-A agent claims block:

```bash
POST /v1/attestation/oidc-agent-claims
Authorization: Bearer <botcha-token>
Content-Type: application/json

{
  "agent_id": "agent_abc123",
  "scopes": ["read:invoices", "write:orders"],
  "operator": "Acme Corp"
}
```

Returns an OIDC-A claims block (JWT) suitable for inclusion in OAuth2 token responses.

## Agent Grant Flow

OAuth2-style authorization grants for agents:

```bash
# Initiate grant
POST /v1/auth/agent-grant
Authorization: Bearer <botcha-token>
Content-Type: application/json

{
  "agent_id": "agent_abc123",
  "requested_scopes": ["read:invoices"],
  "resource": "https://api.example.com"
}
# Returns: { "grant_id": "grant_...", "status": "pending" }

# Poll status
GET /v1/auth/agent-grant/:id/status
Authorization: Bearer <botcha-token>

# Approve/resolve (by authorizing party)
POST /v1/auth/agent-grant/:id/resolve
Authorization: Bearer <botcha-token>
Content-Type: application/json

{ "approved": true }
```

## OIDC UserInfo

```bash
GET /v1/oidc/userinfo
Authorization: Bearer <botcha-token>
```

Returns OIDC-A UserInfo claims for the authenticated agent.

## Known Limitations (Pre-Merge)

- OIDCA routes are **not yet documented in the OpenAPI spec** (`static.ts`). This will be fixed before merge.
- Test agent results are still pending — route-level bugs may exist.
- The `/.well-known/oauth-authorization-server` discovery endpoint is confirmed working; other routes are unconfirmed.

## References

- [RFC 9711 — Entity Attestation Token (EAT)](https://www.rfc-editor.org/rfc/rfc9711)
- [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)
- [OIDC for Native Apps / Agents (draft)](https://datatracker.ietf.org/doc/html/draft-meunier-web-bot-auth-architecture)
