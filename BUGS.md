# BOTCHA — Active Issues Tracker

*Last updated: 2026-04-20 by Choco*

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

### PR #28 — OIDC-A Attestation (MERGED)
Full OIDC-A attestation endpoint — EAT tokens, agent grants, OAuth AS metadata. Merged.

### PR #26 — A2A Agent Card (MERGED)
A2A trust oracle with agent cards. Merged.

### PR #41 — TAP UX Improvements (MERGED v0.24.0)
**Bugs fixed:** agents/me 404 fix, INVALID_TTL validation, time_remaining_seconds, ACTION_CATEGORY_MISMATCH hint, reputation alias route.

### Issue #37 / PR #40 — CJS Support (MERGED v0.24.0)
Dual ESM/CJS build via tsconfig.cjs.json + verify-cjs.cjs CI check.

---

## 🔄 IN PROGRESS

### PR — Three TAP UX bugs (2026-04-20 sprint, Choco)
**Branch:** `fix/agent-me-reputation-delegation-ux`
**Bugs confirmed on live API 2026-04-20:**

1. **`GET /v1/agents/me` rejects agent-identity tokens** — `verifyToken` called with `undefined` options (defaults to `botcha-verified` only). OAuth-refresh tokens are blocked even though they ARE valid agent-identity tokens.
   - **Fix:** Pass `{ allowedTypes: ['botcha-verified', 'botcha-agent-identity'] }` (same pattern as all TAP routes)

2. **`GET /v1/agents/:id/reputation` → 400 MISSING_AGENT_ID** — Alias route registered with `:id` param but `getReputationRoute` reads `c.req.param('agent_id')`.
   - **Fix:** Try `c.req.param('agent_id') || c.req.param('id')` in handler

3. **`POST /v1/delegations` — string capabilities give misleading error** — Passing `["browse", "search"]` returns "Invalid capability action. Valid: browse, compare, purchase, audit, search" — implying the value is wrong when the actual issue is the format.
   - **Fix:** Normalize strings to `{action: string}` objects before validation; clearer error message naming the bad action and accepted formats

---

## 🔮 TECHNICAL DEBT (existing in main, deprioritized)

### 1. KV Read-Modify-Write Race Condition
**Location:** `last_verified_at` updates on TAP session creation
**Risk:** Two simultaneous requests updating agent metadata can silently lose one update
**Fix:** Implement compare-and-swap or use Durable Objects for pessimistic locking
**Priority:** 🟠 MAJOR — affects correctness of reputation/trust tracking under load

### 2. RFC 9421 HTTP Message Signatures (Dead Code)
**Location:** `packages/cloudflare-workers/src/tap-routes.ts`
**Issue:** Implementation exists but is not enforced on any route — dead code
**Fix:** Either enforce on a specific route (e.g., `POST /v1/sessions/tap`) or remove until ready
**Priority:** 🟡 MINOR — security feature that's off, not a regression

### 3. Payment/Invoice Flow Untested
**Endpoints:** `/v1/invoices/*`, Consumer/Payment Container verification
**Issue:** Requires `card_acceptor_id` to test — not available in test environment
**Priority:** 🟡 MINOR — feature exists, just untested

### 4. x402 X-Payment Header Path Hangs
**Location:** `GET /v1/x402/challenge` with `X-Payment` header
**Issue:** Well-formed fake payments pass structural validation and reach the nonce KV step — if KV is slow/unavailable this can hang
**Fix:** Add explicit timeout around `noncesKV.get()` calls; return 504 on timeout
**Priority:** 🟡 MINOR — degrades gracefully in practice

### 5. Delegation field naming inconsistency (docs vs API)
**Location:** `POST /v1/delegations`
**Issue:** Natural field names are `delegator_agent_id`/`delegate_agent_id` but API uses `grantor_id`/`grantee_id`. AI agents consistently use the wrong names (tested 2026-04-13).
**Fix:** Accept both field names (alias) or update docs/OpenAPI to be clearer
**Priority:** 🟡 MINOR — docs confusion
