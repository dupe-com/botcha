# Commit `87ef39f` Deep Dive (PR #29 DID/VC)

## Summary
DID/VC feature scope is ambitious and valuable, but this commit currently introduces release-blocking syntax regressions and several auth/tenancy inconsistencies.

## What Was Added
- DID utilities (`tap-did.ts`).
- VC issuance/verification core (`tap-vc.ts`).
- DID/VC route handlers (`tap-vc-routes.ts`).
- Route wiring + JWKS alias in `index.tsx`.
- DID/VC tests (`tap-did.test.ts`, `tap-vc.test.ts`).

## Findings

### Critical
1. Syntax error in workers entrypoint import block.
- Malformed import line breaks workers TypeScript build.
- Evidence: `packages/cloudflare-workers/src/index.tsx:95`, `packages/cloudflare-workers/src/index.tsx:99`.

2. Syntax/brace corruption in TAP registration validation after DID field insertion.
- Contributes to workers build failure.
- Evidence: `packages/cloudflare-workers/src/tap-routes.ts:173`, `packages/cloudflare-workers/src/tap-routes.ts:191`.

### High
1. Endpoints labeled public are still behind app-gate middleware.
- DID resolve and VC verify are documented as public, but not exempted in open-path list.
- Evidence: `packages/cloudflare-workers/src/index.tsx:158`, `packages/cloudflare-workers/src/index.tsx:2419`, `packages/cloudflare-workers/src/index.tsx:2422`.

2. VC issuance can attach claims from arbitrary `agent_id` across tenants.
- No ownership check against caller’s `app_id`.
- Route also silently continues when lookup fails, still issuing VC.
- Evidence: `packages/cloudflare-workers/src/tap-vc-routes.ts:158`, `packages/cloudflare-workers/src/tap-vc-routes.ts:183`.

### Medium
1. DID/VC endpoints are not documented in `static.ts` API docs.
- x402 is present, ANS and DID/VC endpoint documentation is missing.
- Evidence: x402-only section starts at `packages/cloudflare-workers/src/static.ts:117`.

2. Integration coverage gap.
- Unit tests are strong for modules, but routing + app-gate behavior is not exercised.

## Completion Assessment
- Feature completeness: **partial**.
- Current state is **not deployable** in workers package due syntax errors.

## Recommended Fixes
1. Repair syntax regressions first and gate on workers build in CI.
2. Enforce tenant ownership checks when `agent_id` is provided.
3. Explicitly exempt intended public DID/VC routes from app gate (or update docs/behavior consistently).
4. Add route integration tests for DID/VC endpoints.
