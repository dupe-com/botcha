# Commit Deep Dive Report (2026-02-20)

## Scope
Reviewed these commits in depth:
- `1b6a3d0` docs: add `BUGS.md`
- `87ef39f` feat: PR #29 merged (DID/VC)
- `7d05dad` feat: PR #27 merged (ANS)
- `f72e0eb` feat: PR #25 merged (x402)
- `1d89702` fix(ci): clear routes in preview env
- `bbe8b7e` ci: PR preview environments
- `4c00504` fix: `/v1/token/validate` open path + JWK support

## Validation Run
- `bun run build` (repo root): passes.
- `bun test tests/unit/agents/tap-x402.test.ts tests/unit/agents/tap-ans.test.ts tests/unit/agents/tap-did.test.ts tests/unit/agents/tap-vc.test.ts`: `148` passing.
- `cd packages/cloudflare-workers && bun run build`: **fails**.

Build failure output:
```txt
src/index.tsx(99,1): error TS1109: Expression expected.
src/index.tsx(99,3): error TS1434: Unexpected keyword or identifier.
src/tap-routes.ts(925,1): error TS1005: '}' expected.
```

## Top Findings (Across Epics)
1. **Critical**: Workers package is currently non-buildable due syntax regressions from PR #29 and PR #27 (`packages/cloudflare-workers/src/index.tsx:95`, `packages/cloudflare-workers/src/index.tsx:99`, `packages/cloudflare-workers/src/tap-routes.ts:173`).
2. **Critical**: x402 verification is structural-only (no cryptographic EIP-712 verification), so fake payments can pass (`packages/cloudflare-workers/src/tap-x402.ts:385`, `packages/cloudflare-workers/src/tap-x402.ts:389`).
3. **High**: x402 webhook signature is optional even when a secret exists; unsigned requests are accepted (`packages/cloudflare-workers/src/tap-x402-routes.ts:534`).
4. **High**: Cross-tenant agent linking risk in ANS verify and VC issue routes (no app ownership check on `agent_id`) (`packages/cloudflare-workers/src/tap-ans-routes.ts:360`, `packages/cloudflare-workers/src/tap-vc-routes.ts:158`).
5. **High**: Endpoints documented as public for ANS and DID/VC still sit behind `/v1/*` app gate because open path list was not updated (`packages/cloudflare-workers/src/index.tsx:158`, `packages/cloudflare-workers/src/index.tsx:2390`, `packages/cloudflare-workers/src/index.tsx:2419`).
6. **High**: Preview workflow exposes app secret in PR comments and preview env includes committed JWT secrets/private key (`.github/workflows/preview.yml:90`, `packages/cloudflare-workers/wrangler.toml:93`, `packages/cloudflare-workers/wrangler.toml:95`).

## Per-Commit Reports
- `reports/commit-deep-dive-2026-02-20/f72e0eb-pr25-x402.md`
- `reports/commit-deep-dive-2026-02-20/7d05dad-pr27-ans.md`
- `reports/commit-deep-dive-2026-02-20/87ef39f-pr29-did-vc.md`
- `reports/commit-deep-dive-2026-02-20/bbe8b7e-1d89702-preview-ci.md`
- `reports/commit-deep-dive-2026-02-20/4c00504-token-validate-jwk.md`
- `reports/commit-deep-dive-2026-02-20/1b6a3d0-bugs-doc.md`

## Recommended Plan Of Attack
### Phase 0 (Immediate, block release)
1. Fix syntax/build regressions in workers entrypoints.
2. Add workers build to CI required checks (`cd packages/cloudflare-workers && bun run build`).

### Phase 1 (Security hotfixes)
1. Enforce webhook signature when `BOTCHA_WEBHOOK_SECRET` is configured.
2. Disable token issuance on structural-only x402 checks unless facilitator/on-chain verification is present.
3. Enforce app ownership checks before accepting `agent_id` in ANS and VC routes.

### Phase 2 (Product correctness)
1. Align app-gate behavior with "public route" intent for ANS and DID/VC endpoints.
2. Add integration tests around middleware + route wiring (`index.tsx`) for these new endpoints.
3. Update API docs (`static.ts`) to include ANS and DID/VC endpoints.

### Phase 3 (Operational hardening)
1. Remove hardcoded app secrets from workflow comments.
2. Move preview-only secrets and signing key out of committed `wrangler.toml`.
3. Stop sharing production KV in preview, or isolate by namespace/prefix + cleanup policy.
