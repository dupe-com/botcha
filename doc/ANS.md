# ANS (Agent Name Service) Integration

> **Status:** ✅ Merged to main (PR #27, v0.22.0)

BOTCHA acts as a verification layer for the [Agent Name Service (ANS)](https://www.godaddy.com/engineering/2024/12/16/agent-name-service/) standard, led by GoDaddy. ANS uses DNS TXT records to publish agent identity. BOTCHA provides DNS-based lookup, ownership proof via nonce/signature, and issues BOTCHA identity badges to verified ANS agents.

## What is ANS?

ANS is a DNS-based naming system for AI agents. An agent owner publishes a TXT record at `_ans.<domain>` containing a JSON identity object. Any party can look up and resolve agent identity without a centralized registry.

**Example DNS record:**
```
_ans.myagent.ai TXT "{ \"v\": \"v1.0.0\", \"name\": \"MyAgent\", \"operator\": \"Acme Corp\", ... }"
```

## BOTCHA's ANS Identity

```bash
GET /v1/ans/botcha
```

Returns BOTCHA's own ANS identity record — useful as a reference implementation.

## Public Endpoints

### Resolve an ANS Name

Two equivalent forms:

```bash
GET /v1/ans/resolve/myagent.ai
GET /v1/ans/resolve/lookup?name=myagent.ai
```

Performs a DNS TXT lookup for `_ans.myagent.ai` and returns the parsed ANS identity object.

**Response:**
```json
{
  "name": "myagent.ai",
  "identity": {
    "v": "v1.0.0",
    "name": "MyAgent",
    "operator": "Acme Corp"
  },
  "verified": false
}
```

`"verified": true` if the name has a BOTCHA ownership badge on record.

### Discover Verified ANS Agents

```bash
GET /v1/ans/discover
```

Returns the list of ANS agents that have completed BOTCHA ownership verification.

## Ownership Proof Flow (Auth Required)

Proving you own an ANS name is a two-step nonce/signature flow. Both steps require a valid BOTCHA Bearer token.

### 1. Get Nonce

```bash
GET /v1/ans/nonce/myagent.ai
Authorization: Bearer <botcha-token>
```

Returns a short-lived nonce tied to your agent session.

### 2. Verify Ownership

```bash
POST /v1/ans/verify
Authorization: Bearer <botcha-token>
Content-Type: application/json

{
  "name": "myagent.ai",
  "nonce": "<nonce-from-step-1>",
  "proof": "<signature-over-nonce>"
}
```

BOTCHA:
1. Resolves `_ans.myagent.ai` to get the agent's public key
2. Verifies the signature over the nonce
3. Issues a BOTCHA identity badge stored against the name

**Response on success:**
```json
{
  "verified": true,
  "badge": "eyJ...",
  "name": "myagent.ai"
}
```

## Known Limitations

- Auth check on `POST /v1/ans/verify` happens before DNS lookup (correct behavior; previously it was possible to trigger DNS lookup without auth).
- Ownership badges are stored per-name — transferring a domain name does not automatically revoke the badge.

## References

- [GoDaddy ANS announcement](https://www.godaddy.com/engineering/2024/12/16/agent-name-service/)
- DNS TXT record format: `_ans.<domain>`
