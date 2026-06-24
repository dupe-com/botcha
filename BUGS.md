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

### PR #55 — Hybrid challenge missing access_token (2026-06-22 sprint, Choco)
**Branch:** `fix/hybrid-challenge-missing-token`
**PR:** https://github.com/dupe-com/botcha/pull/55

**Bug (2026-06-22): Hybrid challenge returns badge but no access_token**
The hybrid challenge is now the default (`GET /v1/challenges` returns hybrid by default).
On success it returned only a `badge` JWT — not a `botcha-verified` access_token + refresh_token.
The speed-only path correctly called `generateToken()`. All three hybrid handlers did not.
- **Root cause:** `verifyHybridChallenge` didn't propagate `app_id`; handlers never called `generateToken()`
- **Fix:** Propagate `app_id` in return value; add `generateToken()` to all 3 hybrid verify handlers
- **Tests:** `tests/unit/challenges/hybrid-token-issuance.test.ts` (3 tests, all passing)

---

## 🔮 TECHNICAL DEBT (existing in main, deprioritized)

### 7. POST /v1/sessions/tap requires agent_id in body (no JWT binding)
**Location:** `tap-routes.ts` → `createTAPSessionRoute`
**Issue:** Handler requires `agent_id` in body but never validates it matches the authenticated agent's JWT claim. An agent with a valid token could theoretically pass a different agent_id — no access control check.
**Fix:** Extract `agent_id` from JWT payload (`c.get('tokenPayload')?.agent_id`); use it instead of / in addition to body `agent_id`. If both present, verify they match.
**Priority:** 🟠 MAJOR — authentication gap

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
