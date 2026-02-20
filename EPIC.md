# Epic: RFC 9421 HTTP Message Signature Enforcement

## Why This Matters
TAP's entire value proposition is **cryptographic agent identity** — an agent proves who it is by signing requests with its private key. Without signature verification, any caller that knows an agent_id can impersonate that agent and create TAP sessions. This is identity theater.

Enforcing RFC 9421 closes the loop: only the holder of the registered private key can create a session for that agent.

## Scope
Enforce RFC 9421 HTTP Message Signatures on `POST /v1/sessions/tap`. When a TAP agent is registered with a public key, all TAP session creation requests MUST include valid RFC 9421 signature headers, and the server MUST verify them.

## What's Already Built
- `packages/cloudflare-workers/src/tap-routes.ts` — TAP session creation (no sig check currently)
- `packages/cloudflare-workers/src/tap-agents.ts` — agent storage, `isValidJWK`, `isValidPublicKey`
- RFC 9421 parsing utilities likely already exist — **search for them before writing anything new**

Search for: `Signature-Input`, `sig1`, `@method`, `@authority`, `verifySignature`, `messageSignature`

## Implementation Plan

### 1. Understand existing RFC 9421 code
```bash
grep -rn "Signature-Input\|RFC 9421\|messageSignature\|verifySignature\|sig1\|@method\|@authority" packages/ --include="*.ts" | grep -v test | head -40
```

### 2. Signature verification flow for `POST /v1/sessions/tap`
When `tap_enabled = true` on the agent:
1. Extract `Signature` and `Signature-Input` headers from request
2. Reconstruct the signature base string from specified components (`@method`, `@path`, `@authority`, request body digest, etc.)
3. Verify signature using agent's stored public key (PEM or JWK)
4. Reject with 401 if signature missing, malformed, expired, or invalid
5. Check nonce for replay protection (KV-backed, 8-minute TTL per ROADMAP)

### 3. Make it opt-in initially (safe rollout)
- If agent has no public key (`tap_enabled = false`): skip signature check (backward compat)
- If agent has public key (`tap_enabled = true`): **require** valid signature

### 4. Supported algorithms
- `ecdsa-p256-sha256` → ES256
- `ed25519` → EdDSA
- `rsa-pss-sha256` → PS256

### 5. Error responses
- `401 SIGNATURE_REQUIRED` — TAP agent requires signatures but none provided
- `401 SIGNATURE_INVALID` — signature present but fails verification
- `401 SIGNATURE_EXPIRED` — signature's `expires` param is in the past
- `401 NONCE_REPLAYED` — nonce already seen (replay attack)

### 6. Tests
- Happy path: valid signature accepted
- Missing signature: 401 SIGNATURE_REQUIRED
- Invalid signature: 401 SIGNATURE_INVALID
- Expired signature: 401 SIGNATURE_EXPIRED
- Replayed nonce: 401 NONCE_REPLAYED
- Agent without key: no sig required (backward compat)

### 7. Update OpenAPI spec and docs
Update the TAP session endpoint docs in `packages/cloudflare-workers/src/index.tsx`

## Tasks
- [ ] Read existing RFC 9421 code thoroughly
- [ ] Implement `verifyRFC9421Signature(req, publicKey, algorithm)` (or wire up existing)
- [ ] Gate TAP session creation on signature verification
- [ ] Add nonce replay protection
- [ ] Write unit tests (≥6 cases)
- [ ] Update OpenAPI docs
- [ ] Deploy check: `npx tsc --noEmit` passes
- [ ] All tests pass
- [ ] Commit with checkpoint messages
- [ ] Push branch + create PR
- [ ] Solve BOTCHA challenge on PR

## GitHub
- Branch: `epic/rfc9421-enforcement`
- Worktree: `/home/node/.openclaw/workspace/botcha-rfc9421`
- Token: `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`
- Repo: `dupe-com/botcha`

## BOTCHA Challenge (solve on every PR)
```python
import hashlib
numbers = [...]  # from challenge comment
answers = [hashlib.sha256(str(n).encode()).hexdigest()[:8] for n in numbers]
```
Hidden data in comment: `<!-- BOTCHA_DATA:<id>:<answers>:<timestamp> -->`
Reply format: `BOTCHA:<id>:\n["a1","a2","a3","a4","a5"]`
