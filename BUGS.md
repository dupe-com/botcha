# BOTCHA — Active Issues Tracker

*Last updated: 2026-06-22 by Choco*

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

### PR #56 — TAP session auth + totalTimeMs fix (2026-06-29 sprint, Choco)
**Branch:** `fix/tap-session-auth-and-timing`
**PR:** https://github.com/dupe-com/botcha/pull/56

**Bug A (2026-06-29): POST /v1/sessions/tap has no authentication — CRITICAL**
Any caller could create TAP sessions for arbitrary agents by supplying their agent_id in the body.
The tap_enabled gate was enforced but there was nothing stopping unauthenticated access.
- **Root cause:** `createTAPSessionRoute` never called `validateTAPAppAccess` unlike every other TAP route
- **Fix:** Add `validateTAPAppAccess(c, true)` at the top; verify app_id and agent_id match JWT claims
- **Tests:** 5 new auth enforcement tests (401, 403 cross-app, 403 agent_id mismatch, app-level token)

**Bug B (2026-06-29): totalTimeMs < speed.solveTimeMs in hybrid verify response**
`hybrid.issuedAt` was captured after two async KV writes, making totalTimeMs appear smaller than sub-challenge times — impossible math visible to every agent caller.
- **Root cause:** `issuedAt = Date.now()` placed after `await generateSpeedChallenge()` + `await generateReasoningChallenge()`
- **Fix:** Capture `issuedAt` before async operations; use it in both `issuedAt` and `expiresAt`
- **Tests:** 2 new timing invariant tests (totalTimeMs >= speed.solveTimeMs, >= reasoning.solveTimeMs)

---

## 🔮 TECHNICAL DEBT (existing in main, deprioritized)

### ✅ 7. POST /v1/sessions/tap requires agent_id in body (no JWT binding) — FIXED in PR #56
**Location:** `tap-routes.ts` → `createTAPSessionRoute`
**Fix:** `validateTAPAppAccess` added; app_id and agent_id cross-checked against JWT claims.
**PR:** https://github.com/dupe-com/botcha/pull/56

### 8. Capability format inconsistency across API surfaces
**Location:** `POST /v1/sessions/tap` vs `POST /v1/attestations` vs `POST /v1/delegations`
**Issue:** Three different capability formats: `{action: "browse"}` objects (sessions), `"browse:*"` strings (attestations), `{action: "browse"}` objects (delegations). Agents consistently pass the wrong format.
**Fix:** Normalize all inputs to a single canonical format, or document clearly in each endpoint's error message what format is expected.
**Priority:** 🟡 MINOR — developer experience

### 9. Hybrid challenge solver patterns needed (reasoning question coverage)
**Location:** `challenges.ts` → REASONING_QUESTIONS bank
**Issue:** During agent sprint, ~30% of reasoning questions were unmatched by any solver pattern. New question types discovered: LIFO → stack, "neck but no head" → bottle, string length questions, "occurs once in a minute..." → letter M, "remove letter from startling" → starling, "what connects: river, money, blood" → bank, etc.
**Note:** Not a blocking bug but shows the question bank has grown past common patterns. Adding these to the Python solver library for future sprints.
**Priority:** 🟡 MINOR — agent usability

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
**Issue:** Natural field names are `delegator_agent_id`/`delegate_agent_id` but API uses `grantor_id`/`grantee_id`. AI agents consistently use the wrong names (tested 2026-04-13 and 2026-04-27).
**Fix:** Accept both field names (alias) or update docs/OpenAPI to be clearer
**Priority:** 🟡 MINOR — docs confusion

### 6. No session listing endpoint
**Issue:** Agents cannot list their own active sessions (e.g., `GET /v1/sessions?agent_id=...`). Must manually track session IDs.
**Priority:** 🟡 MINOR — convenience feature, not a correctness bug
