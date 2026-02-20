# Implementation Progress (Started)

## Completed In This Pass
- Fixed app-gate/public-path mismatch for ANS resolve/discover/botcha and DID resolve + VC verify in `packages/cloudflare-workers/src/index.tsx`.
- Added tenant ownership checks:
  - ANS verify route now requires token `app_id` and enforces agent app ownership in `packages/cloudflare-workers/src/tap-ans-routes.ts`.
  - VC issue route now enforces `agent_id` exists and belongs to caller app in `packages/cloudflare-workers/src/tap-vc-routes.ts`.
- Hardened x402 route behavior:
  - Enforced webhook signature presence when webhook secret is configured in `packages/cloudflare-workers/src/tap-x402-routes.ts`.
  - Disabled structural-only payment acceptance by default; explicit unsafe opt-in via `BOTCHA_X402_ALLOW_STRUCTURAL=true` in `packages/cloudflare-workers/src/tap-x402-routes.ts`.
- Added ANS nonce key canonicalization in `packages/cloudflare-workers/src/tap-ans.ts`.
- Added workers package build checks to CI in `.github/workflows/ci.yml`.
- Removed hardcoded app secret from preview PR comment template in `.github/workflows/preview.yml`.
- Removed committed preview JWT secret/private key from `packages/cloudflare-workers/wrangler.toml` and replaced with secret-manager instructions.
- Extended docs to include ANS and DID/VC endpoints and x402 secure-mode note in `packages/cloudflare-workers/src/static.ts`.

## Validation
- `bun run build`: pass
- `cd packages/cloudflare-workers && bun run build`: pass
- `bun test tests/unit/agents/tap-x402.test.ts tests/unit/agents/tap-ans.test.ts`: pass

## Remaining Follow-Ups
- Add integration tests for middleware + route behavior (`index.tsx` public vs gated paths).
- Implement full cryptographic/facilitator x402 verification (replace structural-only path entirely).
- Optionally automate preview secret provisioning in workflow (currently documented via wrangler secret commands).
