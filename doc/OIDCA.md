# OIDC-A Attestation

> **Status:** 🔄 In Progress — PR #28 open with security/test fixes pushed. **Not yet merged to main.**

BOTCHA implements OIDC-A (OpenID Connect for Agents) attestation for enterprise agent authentication chains. This covers Entity Attestation Tokens (EAT) and OIDC-A agent claims blocks, plus an OAuth-style agent grant flow.

> ⚠️ **This feature is not yet available on botcha.ai main.** The endpoints below reflect the current PR contract and will be finalized at merge.

## What is OIDC-A?

OIDC-A extends the OpenID Connect spec with claims specific to AI agents — capability scopes, agent type, operator identity, and attestation proofs. Combined with Entity Attestation Tokens (RFC 9711), it enables enterprise-grade agent authentication chains: human → enterprise IdP → BOTCHA → agent.

## Discovery

Once merged, BOTCHA will publish an OIDC/OAuth2 discovery document:

```bash
GET /.well-known/oauth-authorization-server
```

The discovery doc is already confirmed working (200, correct shape) in the preview environment.

## Entity Attestation Tokens (EAT)

Issue an EAT token:

```bash
POST /v1/attestation/eat
Authorization: Bearer <botcha-token>
Content-Type: application/json

{
  "nonce": "optional-client-nonce",
  "agent_model": "gpt-5",
  "ttl_seconds": 900,
  "verification_method": "speed-challenge"
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
  "agent_model": "gpt-5",
  "agent_version": "1.0.0",
  "agent_capabilities": ["agent:tool-use"],
  "agent_operator": "Acme Corp",
  "human_oversight_required": true,
  "task_id": "task-123",
  "task_purpose": "invoice reconciliation",
  "nonce": "optional-client-nonce"
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
  "scope": "agent:read openid",
  "human_oversight_required": true,
  "agent_model": "gpt-5",
  "agent_operator": "Acme Corp",
  "task_id": "task-123",
  "task_purpose": "invoice reconciliation"
}
# Returns signed grant token + optional pending oversight URL

# Poll status
GET /v1/auth/agent-grant/:id/status
Authorization: Bearer <botcha-token>

# Approve/resolve (by authorizing party)
POST /v1/auth/agent-grant/:id/resolve
Authorization: Bearer <botcha-token>
Content-Type: application/json

{ "decision": "approved" }
```

## OIDC UserInfo

```bash
GET /v1/oidc/userinfo
Authorization: Bearer <botcha-token>
```

Returns OIDC-A UserInfo claims for the authenticated agent.

## Known Limitations
- `POST /v1/auth/agent-grant/:id/resolve` currently requires BOTCHA bearer auth and app ownership checks, but does not yet enforce a stricter admin role model.
- Grant status/resolve is app-scoped: only the owning `app_id` can poll/resolve a grant.

## References

- [RFC 9711 — Entity Attestation Token (EAT)](https://www.rfc-editor.org/rfc/rfc9711)
- [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)
- [OIDC for Native Apps / Agents (draft)](https://datatracker.ietf.org/doc/html/draft-meunier-web-bot-auth-architecture)
