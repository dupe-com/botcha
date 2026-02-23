# BOTCHA — Active Issues Tracker

*Last updated: 2026-02-23 by Choco*

---

Closed/merged work is tracked in `CHANGELOG.md`. This file tracks only open issues and active follow-ups.

---

## ✅ FIXED (2026-02-23 by Choco)

### Issue #33 — OAuth device flow: use verification_uri_complete
**URL:** https://github.com/dupe-com/botcha/issues/33
**PR:** https://github.com/dupe-com/botcha/pull/35 (merged)
**Fix:** `message` uses pre-filled URL; countdown only fires after successful lookup

### Issue #34 — Device approval page requires login (wrong UX)
**URL:** https://github.com/dupe-com/botcha/issues/34
**Commit:** b6f0c98
**Fix:** Removed `requireDashboardAuth` from `GET /device`; device code is now the sole trust anchor (RFC 8628 §6.1)

---

## 🔄 IN PROGRESS (PR #28 — open)

### PR #28 — OIDC-A Attestation
**Landed on this branch:**
- ✅ `GET /v1/auth/agent-grant/:id/status` now requires bearer auth and enforces same-app ownership
- ✅ `POST /v1/auth/agent-grant/:id/resolve` now requires bearer auth and enforces same-app ownership
- ✅ `POST /v1/attestation/eat` now validates `ttl_seconds` as a positive finite number
- ✅ OIDC docs/metadata now use `/.well-known/jwks` (not `/v1/jwks`)
- ✅ Added focused OIDC-A tests (`tests/unit/agents/tap-oidca.test.ts`)
- ✅ Rebased with main and resolved route conflicts (`index.tsx`)
- ✅ OIDC-A routes documented in OpenAPI/static docs (`packages/cloudflare-workers/src/static.ts`)

**Open issue:**
- 🟡 Grant resolve policy is app-owner scoped; stricter enterprise admin model may still be needed

**Remaining before merge:**
1. Decide on stricter admin policy for grant resolve (currently app-owner scoped)
2. Final PR review + merge

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
