# A2A Agent Card Attestation

> **Status:** ✅ Shipped — merged via PR #26 (v0.23.0).

BOTCHA acts as a trust seal issuer for the [Google A2A protocol](https://developers.googleblog.com/en/a2a-a-new-era-of-agent-interoperability/) Agent Cards. Any agent that publishes an A2A Agent Card can submit it to BOTCHA for attestation; BOTCHA produces a tamper-evident trust seal that third parties can verify without contacting BOTCHA again.

This feature is available on BOTCHA. The endpoints below reflect the current API contract.

## What is A2A?

The A2A (Agent-to-Agent) protocol by Google defines a standard JSON `agent.json` card format that describes an agent's capabilities, supported protocols, and identity. Publishing a card at `/.well-known/agent.json` makes an agent auto-discoverable.

## BOTCHA's A2A Agent Card

BOTCHA publishes its own A2A Agent Card at:

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
  "card": {
    "name": "My Commerce Agent",
    "url": "https://myagent.example",
    "version": "1.0.0",
    "capabilities": { "streaming": false },
    "skills": [{ "id": "browse", "name": "Browse" }]
  },
  "duration_seconds": 86400,
  "trust_level": "verified"
}
```

Returns a BOTCHA trust seal (tamper-evident hash of the card + BOTCHA signature):

```json
{
  "success": true,
  "attestation": {
    "attestation_id": "uuid",
    "agent_url": "https://myagent.example",
    "trust_level": "verified",
    "token": "eyJ..."
  },
  "attested_card": {
    "name": "My Commerce Agent",
    "url": "https://myagent.example",
    "extensions": {
      "botcha_attestation": {
        "token": "eyJ...",
        "card_hash": "..."
      }
    }
  }
}
```

## Verifying an Attested Card

```bash
POST /v1/a2a/verify-card
Content-Type: application/json

{
  "card": {
    "...": "...",
    "extensions": {
      "botcha_attestation": {
        "token": "eyJ..."
      }
    }
  }
}
```

Verifies the seal signature and checks that the card hash matches. Returns `valid: true/false`.

```bash
POST /v1/a2a/verify-agent
Content-Type: application/json

{ "agent_url": "https://myagent.example" }
# or
{ "agent_card": { ... } }    # full card with embedded attestation
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

## Known Limitations

- Re-submitting the same `agent_url` creates additional attestations without deduping or revoking prior active records.
- Validation failures on `POST /v1/a2a/attest` still map to `ATTESTATION_FAILED`; should use a dedicated input error code.
- Current trust-level and verify endpoints are public by design; deployers should still apply standard abuse/rate-limit controls.

## References

- [Google A2A protocol announcement](https://developers.googleblog.com/en/a2a-a-new-era-of-agent-interoperability/)
- [A2A spec](https://google.github.io/A2A/)
