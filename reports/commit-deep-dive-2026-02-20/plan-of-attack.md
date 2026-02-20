# Plan Of Attack

## Goal
Stabilize merged epics (#25, #27, #29) to production-safe quality with clear sequencing.

## Phase 0: Restore Build Integrity (Blocker)
1. Fix malformed imports in `packages/cloudflare-workers/src/index.tsx`.
2. Fix broken brace structure in `packages/cloudflare-workers/src/tap-routes.ts`.
3. Add CI step: `cd packages/cloudflare-workers && bun run build`.

## Phase 1: Security Hotfixes
1. x402:
- Enforce webhook signature when `BOTCHA_WEBHOOK_SECRET` is configured.
- Disable token issuance unless payment proof is cryptographically/facilitator verified.
2. Multi-tenant checks:
- In ANS verify and VC issue routes, require `agent.app_id === caller_token.app_id`.

## Phase 2: Product Correctness
1. Decide intended public surface for ANS and DID/VC endpoints.
2. If public, add path exemptions in app gate; if gated, update docs and route comments.
3. Add integration tests that run through `index.tsx` middleware.

## Phase 3: CI/Preview Hardening
1. Remove hardcoded app secret from workflow comments.
2. Remove committed preview JWT secrets/private key from `wrangler.toml`; use secret manager.
3. Isolate preview data from production KV namespaces.

## Phase 4: Documentation Completion
1. Add ANS and DID/VC endpoints to `packages/cloudflare-workers/src/static.ts`.
2. Update `BUGS.md` with verified command outputs and status dates.

## Suggested Execution Order
1. Phase 0
2. Phase 1
3. Phase 2
4. Phase 3
5. Phase 4
