# Open PR Merge Plan (2026-02-20)

This plan covers the four open epic PRs:
- #23 `epic/go-sdk`
- #24 `epic/webhooks`
- #26 `epic/a2a-agent-cards`
- #28 `epic/oidc-a-attestation`

## Recommended Merge Order

1. PR #23 (Go SDK)
2. PR #24 (Webhooks)
3. PR #26 (A2A Agent Cards)
4. PR #28 (OIDC-A Attestation)

Rationale:
- #23 is isolated to `packages/go` and has low blast radius.
- #24 is infra/runtime hardening and improves reliability ahead of protocol additions.
- #26 introduces new public trust endpoints but is narrower than OIDC-A auth chains.
- #28 has the highest auth/enterprise risk and should merge last after stricter verification.

## Risk Gates (must pass before merge)

### Gate A — Build & Tests
- `bun run build` passes at repo root.
- `cd packages/cloudflare-workers && bun run build` passes.
- Targeted suites pass:
  - `bun test tap-routes`
  - `bun test tap-oidca`
  - `bun test tap-a2a`
  - `bun test webhooks`

### Gate B — Security Paths
- No open unauthenticated access on grant/status/resolve routes.
- App ownership checks enforced where resource is app-scoped.
- Public endpoints are explicitly intended public routes.

### Gate C — API/Docs Alignment
- Route docs match implemented request/response contracts.
- `doc/A2A.md` and `doc/OIDCA.md` match current route shapes.
- OpenAPI (`static.ts`) includes newly added OIDC-A and A2A routes before final release tag.

### Gate D — Preview Smoke
- For each PR preview:
  - Core route health check returns expected status code.
  - Auth-required route fails without token and succeeds with valid token.
  - One end-to-end happy path validated per epic.

## PR-Specific Checklists

### PR #23 — Go SDK
- [ ] `go vet ./...` passes in `packages/go`
- [ ] Compile-level tests pass (`go test -exec /usr/bin/true ./...`)
- [ ] Endpoint path mapping matches worker routes
- [ ] Auth flow verified (`WithAccessToken`/`SetAccessToken`)

### PR #24 — Webhooks
- [ ] URL validation blocks unsafe targets (localhost/private IP)
- [ ] Retry behavior fits Worker `waitUntil` constraints
- [ ] Per-app webhook limit enforced
- [ ] Webhook unit tests pass

### PR #26 — A2A
- [ ] `verify-agent` works with `{ agent_card }` and `{ agent_url }`
- [ ] `trust-level` returns `unverified` instead of 404 for unknown agent URL
- [ ] A2A unit tests pass (`tap-a2a`)
- [ ] Follow-up issue created for duplicate attestation dedupe

### PR #28 — OIDC-A
- [ ] Grant status/resolve require bearer auth
- [ ] Grant status/resolve enforce same-app ownership
- [ ] EAT TTL input validation enforced
- [ ] OIDC-A tests pass (`tap-oidca`)
- [ ] Follow-up issue created for stricter admin/oversight policy

## Follow-up Work (post-merge)

1. Add OIDC-A/A2A endpoints to OpenAPI output in `packages/cloudflare-workers/src/static.ts`.
2. Decide and implement stricter admin policy for `agent-grant/:id/resolve`.
3. Add dedupe/revocation strategy for repeated A2A attestations by `agent_url`.
