# BOTCHA — Active Issues Tracker

*Last updated: 2026-04-13 by Choco*

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

---

## 🔄 IN PROGRESS

### PR #41 — TAP UX Improvements (open, needs BOTCHA verify + CI)
**URL:** https://github.com/dupe-com/botcha/pull/41
**Bugs fixed (all confirmed on live API 2026-04-13):**
1. `GET /v1/agents/me` → 404 (now resolves from Bearer token)
2. `ttl_seconds: -100` on `POST /v1/sessions/tap` → silently accepted (now 400 INVALID_TTL)
3. `GET /v1/sessions/:id/tap` returns `time_remaining` in ms (renamed to `time_remaining_seconds`, now integer seconds)
4. `ACTION_CATEGORY_MISMATCH` error gives no hint about valid actions (now includes `valid_actions` array)
5. `GET /v1/agents/:id/reputation` → 404 (alias route added, must come before generic `:id`)

### Issue #37 — CJS Support
**URL:** https://github.com/dupe-com/botcha/issues/37
**PRs:** #39 (Copilot, uses tsup), #40 (chocothebot, uses tsc + tsconfig.cjs.json)
**Recommendation:** Merge PR #39 — more comprehensive, covers langchain + verify packages, uses tsup for better bundler compatibility. Supersedes #40.

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
