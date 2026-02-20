# A2A Agent Card Attestation

> **Status:** 🔄 In Progress — PR #26 open, fixes pushed, preview redeploying. **Not yet merged to main.**

BOTCHA acts as a trust seal issuer for the [Google A2A protocol](https://developers.googleblog.com/en/a2a-a-new-era-of-agent-interoperability/) Agent Cards. Any agent that publishes an A2A Agent Card can submit it to BOTCHA for attestation; BOTCHA produces a tamper-evident trust seal that third parties can verify without contacting BOTCHA again.

> ⚠️ **This feature is not yet available on botcha.ai.** The endpoints below describe the planned API. This document will be updated when PR #26 merges.

## What is A2A?

The A2A (Agent-to-Agent) protocol by Google defines a standard JSON `agent.json` card format that describes an agent's capabilities, supported protocols, and identity. Publishing a card at `/.well-known/agent.json` makes an agent auto-discoverable.

## BOTCHA's A2A Agent Card

Once merged, BOTCHA will publish its own A2A Agent Card:

```bash
GET /.well-known/agent.json
GET /v1/a2a/agent-card        # alias
```

## Attesting an Agent Card

Submit any agent's A2A card to BOTCHA for attestation:

```bash
POST /v1/a2a/attest
Authorization: Bearer <botcha-token>
Content-Type: application/json

{
  "agent_url": "https://myagent.example",
  "agent_card": { ... }      # optional — BOTCHA will fetch from agent_url if omitted
}
```

Returns a BOTCHA trust seal (tamper-evident hash of the card + BOTCHA signature):

```json
{
  "attestation_id": "att_...",
  "agent_url": "https://myagent.example",
  "trust_seal": "eyJ...",
  "attested_at": "2026-02-20T17:39:00Z"
}
```

## Verifying an Attested Card

```bash
POST /v1/a2a/verify-card
Content-Type: application/json

{
  "trust_seal": "eyJ..."
}
```

Verifies the seal signature and checks that the card hash matches. Returns `valid: true/false`.

```bash
POST /v1/a2a/verify-agent
Content-Type: application/json

{ "agent_url": "https://myagent.example" }
# or
{ "agent_card": { ... } }    # card with embedded attestation
```

## Trust Level Lookup

```bash
GET /v1/a2a/trust-level/https%3A%2F%2Fmyagent.example
```

Returns the current BOTCHA trust level for an agent URL. Returns `"unverified"` (not 404) when no attestation exists.

## Registry Browse

```bash
GET /v1/a2a/cards           # list all attested cards
GET /v1/a2a/cards/:id       # get a specific attested card by ID
```

## Known Limitations (Pre-Merge)

- **Duplicate attestations:** Re-submitting the same `agent_url` creates a new attestation without revoking the prior one. No deduplication logic yet.
- **Wrong error code:** Validation errors on `POST /v1/a2a/attest` currently return `ATTESTATION_FAILED` — should be `INVALID_CARD` or `MISSING_REQUIRED_FIELD`.
- Routes are not yet in the OpenAPI spec.

## References

- [Google A2A protocol announcement](https://developers.googleblog.com/en/a2a-a-new-era-of-agent-interoperability/)
- [A2A spec](https://google.github.io/A2A/)
