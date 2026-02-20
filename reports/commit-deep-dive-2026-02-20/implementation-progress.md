# Implementation Progress (Started)

## Completed In This Pass
- Fixed app-gate/public-path mismatch for ANS resolve/discover/botcha and DID resolve + VC verify in `packages/cloudflare-workers/src/index.tsx`.
- Extracted `/v1/*` app-gate bypass logic into `packages/cloudflare-workers/src/app-gate.ts` and added unit coverage in `tests/unit/agents/app-gate.test.ts`.
- Added tenant ownership checks:
  - ANS verify route now requires token `app_id` and enforces agent app ownership in `packages/cloudflare-workers/src/tap-ans-routes.ts`.
  - VC issue route now enforces `agent_id` exists and belongs to caller app in `packages/cloudflare-workers/src/tap-vc-routes.ts`.
- Hardened x402 route behavior:
  - Enforced webhook signature presence when webhook secret is configured in `packages/cloudflare-workers/src/tap-x402-routes.ts`.
  - Replaced structural signature checks with cryptographic ERC-3009 EIP-712 verification (secp256k1 pubkey recovery) in `packages/cloudflare-workers/src/tap-x402.ts`.
  - Removed 503 route gating on “verification backend unavailable” so valid cryptographic proofs can issue tokens/access in `packages/cloudflare-workers/src/tap-x402-routes.ts`.
- Added ANS nonce key canonicalization in `packages/cloudflare-workers/src/tap-ans.ts`.
- Added workers package build checks to CI in `.github/workflows/ci.yml`.
- Removed hardcoded app secret from preview PR comment template in `.github/workflows/preview.yml`.
- Removed committed preview JWT secret/private key from `packages/cloudflare-workers/wrangler.toml` and replaced with secret-manager instructions.
- Added preview CI secret sync step for per-PR workers (`JWT_SECRET` + optional `JWT_SIGNING_KEY`) in `.github/workflows/preview.yml`.
- Extended docs to include ANS and DID/VC endpoints and x402 secure-mode note in `packages/cloudflare-workers/src/static.ts`.

## Validation
- `bun run build`: pass
- `cd packages/cloudflare-workers && bun run build`: pass
- `bun test tests/unit/agents/app-gate.test.ts tests/unit/agents/tap-ans.test.ts tests/unit/agents/tap-did.test.ts tests/unit/agents/tap-vc.test.ts`: pass
- `bun test tests/unit/agents/tap-x402.test.ts tests/unit/agents/app-gate.test.ts`: pass

## Remaining Follow-Ups
- Add full request/response integration tests for the `/v1/*` middleware chain using a Workers-compatible test harness.
- Add optional facilitator settlement verification hook (external verifier endpoint) for production-grade on-chain confirmation.
- Isolate preview data from production KV namespaces (requires dedicated preview namespace IDs).
