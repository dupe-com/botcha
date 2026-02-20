# Commits `bbe8b7e` + `1d89702` Deep Dive (Preview CI)

## Summary
Preview environment automation is useful and `routes = []` fix is correct, but current implementation introduces security and data-isolation risks.

## What Was Added
- PR preview deploy workflow.
- PR preview cleanup workflow.
- `env.preview` config in workers `wrangler.toml`.
- Follow-up route override fix (`routes = []`) to prevent route conflicts.

## Findings

### High
1. Hardcoded app secret is posted into PR comments.
- Workflow comment body includes `APP_SECRET=...` literal.
- Evidence: `.github/workflows/preview.yml:90`.

2. Preview environment uses production KV namespaces.
- This allows preview traffic to mutate production data.
- Evidence: `.github/workflows/preview.yml:97`, `packages/cloudflare-workers/wrangler.toml:97`.

3. Preview private signing key is committed in repo.
- `JWT_SIGNING_KEY` includes private `d` parameter in plaintext.
- Evidence: `packages/cloudflare-workers/wrangler.toml:95`.

### Medium
1. Static preview JWT secret committed in config.
- Even if preview-only, this normalizes secret-in-repo behavior.
- Evidence: `packages/cloudflare-workers/wrangler.toml:93`.

2. Main CI does not compile workers package.
- Regressions can merge without workers build check.
- Evidence: `.github/workflows/ci.yml:37`, root `tsconfig.json` excludes workers sources.

## Positives
- `routes = []` preview override fix is appropriate and prevents accidental botcha.ai route binding.
- Evidence: `packages/cloudflare-workers/wrangler.toml:86`.

## Recommended Fixes
1. Remove hardcoded app secrets from workflow comment templates.
2. Move preview signing secrets to runtime secret store (`wrangler secret put`), not repo config.
3. Isolate preview KV from production KV.
4. Add workers build as required CI check.
