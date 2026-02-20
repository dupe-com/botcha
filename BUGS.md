# BOTCHA — Known Bugs & Future Work

*Last updated: 2026-02-20 by Codex*

---

## ✅ MERGED (PRs #25, #27, #29 — all in main)

### PR #25 — x402 Payment Gating
- ✅ `POST /v1/x402/verify-payment` now requires Bearer auth (was open)
- ✅ JSON 404 handler for unknown routes (was plain-text or 401)
- ✅ Preview env `JWT_SECRET` added so token flow works in preview workers

### PR #27 — ANS Integration
- ✅ `POST /v1/ans/verify` now checks auth BEFORE DNS lookup (was 422 without auth)
- ✅ 2-part domain names (e.g. `botcha.ai`) correctly resolve to `_ans.botcha.ai` (was `_ans.ai`)
- ✅ Version prefix bug fixed (`v1.0.x` now correctly parsed; was matching `v1`)
- ✅ All 37 unit tests passing

### PR #29 — DID/VC Issuer
- ✅ Preview env gets static EC key (`JWT_SIGNING_KEY`) so JWKS and DID doc aren't empty
- ✅ `/.well-known/jwks.json` alias added (some resolvers append `.json`)
- ✅ `POST /v1/credentials/verify` returns 503 (not 200) when server not configured
- ✅ JSON 404 handler for unknown routes
- ✅ Both `JWT_SECRET` + `JWT_SIGNING_KEY` in preview env vars

---

## 🔄 IN PROGRESS (PRs #26, #28 — open, fixes pushed, not yet merged)

### PR #26 — A2A Agent Card Attestation
**Pushed commits `caedb07` + `f27912d` with fixes.**

- ✅ `GET /v1/a2a/agent-card` alias added (no longer 404)
- ✅ `POST /v1/a2a/verify-agent` implemented
- ✅ `GET /v1/a2a/trust-level/:agent_url` implemented
- ✅ Type-safe/compiling `verify-agent` flow and corrected `verifyCard(...)` invocation

**Remaining known issues (🟡 lower priority):**
- 🟡 Re-attesting same `agent_url` creates duplicate attestations — no deduplication or revocation of prior attestations for the same URL
- 🟡 Validation errors on `POST /v1/a2a/attest` use `ATTESTATION_FAILED` for missing fields — should be `INVALID_CARD` or `MISSING_REQUIRED_FIELD`

**TODO to merge:**
1. Wait for preview to redeploy (CI still queued as of 16:47 UTC)
2. Verify the 3 new routes work in preview
3. Rebase onto main (will conflict with #25/#27/#29 squash-merges) and merge

### PR #28 — OIDC-A Attestation
**Pushed commit `1e2ea84` with security + tests.**

**Fixed:**
- ✅ `GET /v1/auth/agent-grant/:id/status` now requires bearer auth and enforces same-app ownership
- ✅ `POST /v1/auth/agent-grant/:id/resolve` now requires bearer auth and enforces same-app ownership
- ✅ `POST /v1/attestation/eat` now validates `ttl_seconds` as a positive finite number
- ✅ OIDC docs/metadata now use `/.well-known/jwks` (not `/v1/jwks`)
- ✅ Added focused OIDC-A tests (`tests/unit/agents/tap-oidca.test.ts`)

**Known issue:**
- 🟡 OIDCA routes are NOT documented in OpenAPI spec (`static.ts`) — spec only covers pre-existing TAP routes

**TODO to merge:**
1. Add OIDC-A routes to OpenAPI spec in `static.ts`
2. Decide on stricter admin policy for grant resolve (currently app-owner scoped)
3. Rebase onto main and merge

### TAP Route Test Stability (cross-branch)
- ✅ `tests/unit/agents/tap-routes.test.ts` now passes on current branch (`41/41`)
- ✅ Replaced `vi.mocked(...)` usage with Bun-compatible explicit mocks
- ✅ Added missing auth stubs in rotate-key tests

---

## 🔮 TECHNICAL DEBT (post-merge, existing in main)

These were identified during TAP feature testing but deprioritized in favor of the 5 epics:

### 1. KV Read-Modify-Write Race Condition
**Location:** `last_verified_at` updates on TAP session creation
**Risk:** Two simultaneous requests updating agent metadata can silently lose one update
**Fix:** Implement compare-and-swap or use `put` with `putOptions.ifMatch` (Cloudflare KV doesn't support CAS natively — workaround: use Durable Objects or pessimistic locking)
**Priority:** 🟠 MAJOR — affects correctness of reputation/trust tracking under load

### 2. RFC 9421 HTTP Message Signatures (Dead Code)
**Location:** `packages/cloudflare-workers/src/tap-routes.ts`
**Issue:** Implementation exists but is not enforced on any route — dead code
**Fix:** Either enforce on a specific route (e.g., `POST /v1/sessions/tap`) or remove until ready
**Priority:** 🟡 MINOR — security feature that's off, not a regression

### 3. Payment/Invoice Flow Untested
**Endpoints:** `/v1/invoices/*`, Consumer/Payment Container verification
**Issue:** Requires `card_acceptor_id` to test — not available in our test environment
**Priority:** 🟡 MINOR — feature exists, just untested

### 4. x402 X-Payment Header Path Hangs
**Location:** `GET /v1/x402/challenge` with `X-Payment` header
**Issue:** Well-formed fake payments pass structural validation and reach the nonce KV step — if KV is slow/unavailable this can hang
**Fix:** Add explicit timeout around `noncesKV.get()` calls; return 504 on timeout
**Priority:** 🟡 MINOR — degrades gracefully in practice

---

## 📋 SESSION NOTES (2026-02-20)

**What was done this session:**
- Full TAP feature test on prod (21 endpoints)
- 5 epic PRs created and tested (x402, ANS, A2A, OIDCA, DID/VC)
- Preview infrastructure added (per-PR workers at `botcha-pr-N.carrot-cart.workers.dev`)
- Preview env fixes: `JWT_SECRET` + `JWT_SIGNING_KEY` in `[env.preview.vars]` for all 5 PRs
- RTT-aware speed challenge (`?ts=` param) — was already in code, agents just needed to use it
- PRs #25, #27, #29 merged to main

**Blockers resolved:**
- 500 on `/v1/token/verify` in preview → root cause: `JWT_SECRET` not set → fixed
- Speed challenge failing from sandbox → root cause: agents not passing `?ts=` → fixed in test agent instructions
- Merge conflicts between epic branches → resolved manually for all squash-merges
