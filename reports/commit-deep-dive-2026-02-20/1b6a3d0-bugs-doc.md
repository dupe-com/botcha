# Commit `1b6a3d0` Deep Dive (`BUGS.md`)

## Summary
`BUGS.md` is useful context and captures active threads across epics, but some status statements are now stale/inaccurate versus current code reality.

## Findings

### Medium
1. Documentation claims merged epics are fully fixed, but workers package currently fails build.
- `BUGS.md` marks PR #29 merged/fixed.
- Current workers build fails on syntax errors in files touched by PR #29/#27.
- Evidence: `BUGS.md`, `packages/cloudflare-workers/src/index.tsx:99`, `packages/cloudflare-workers/src/tap-routes.ts:173`.

2. "Public endpoint" intent and middleware reality diverge.
- The doc messaging suggests polished merged status, but app-gate/public-path mismatches remain.

### Low
1. File is valuable as operational memory; issue is mostly staleness, not structure.

## Recommended Follow-up
1. Add a short "Verified on" checklist in `BUGS.md` with command outputs (`workers build`, route smoke tests).
2. Track confidence level per claim (e.g., `implemented`, `tested in preview`, `tested in prod`).
3. Link back to concrete CI checks to keep status self-correcting.
