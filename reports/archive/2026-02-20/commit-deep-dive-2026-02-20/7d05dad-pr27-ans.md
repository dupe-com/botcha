# Commit `7d05dad` Deep Dive (PR #27 ANS)

## Summary
ANS integration is broad and thoughtfully scoped, but there are ownership and accessibility gaps that block safe rollout.

## What Was Added
- ANS core module (`tap-ans.ts`) and routes (`tap-ans-routes.ts`).
- New ANS endpoints wired in `index.tsx`.
- ANS fields added to TAP agent model and registration response.
- ANS unit tests (`tests/unit/agents/tap-ans.test.ts`).

## Findings

### Critical
1. `tap-routes.ts` registration validator has unclosed brace from ANS + DID edits, contributing to workers build failure.
- Evidence: `packages/cloudflare-workers/src/tap-routes.ts:173`.
- This is one root cause of `src/tap-routes.ts(925,1): error TS1005: '}' expected`.

### High
1. Public ANS endpoints are still gated by app middleware.
- Code comments mark ANS resolve/discover/botcha as public.
- But `APP_GATE_OPEN_PATHS` does not include these routes.
- Evidence: `packages/cloudflare-workers/src/index.tsx:158`, `packages/cloudflare-workers/src/index.tsx:2390`.

2. Cross-tenant agent mutation risk in ANS verify route.
- Any caller with valid token can supply any `agent_id` and update that agent’s ANS fields.
- No check that `agent.app_id` matches caller token’s `app_id`.
- Evidence: `packages/cloudflare-workers/src/tap-ans-routes.ts:360`, `packages/cloudflare-workers/src/tap-ans-routes.ts:403`.

### Medium
1. Nonce keying is raw-name sensitive and not canonicalized.
- Equivalent ANS forms can fail nonce consumption unexpectedly.
- Evidence: `packages/cloudflare-workers/src/tap-ans.ts:597`, `packages/cloudflare-workers/src/tap-ans.ts:613`.

2. Coverage gap on route-level app-gate behavior.
- Current ANS tests target core module, not `index.tsx` middleware routing.

## Completion Assessment
- Feature completeness: **partial**.
- Core ANS logic is present, but tenancy and middleware correctness are not complete.

## Recommended Fixes
1. Enforce `agent.app_id === token.app_id` before linking/updating ANS data.
2. Decide and implement true public-path behavior for ANS public endpoints.
3. Canonicalize `ans_name` before nonce store/consume.
4. Add integration tests for ANS routes through global middleware.
