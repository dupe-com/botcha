# CLAUDE.md — Project Instructions for AI Agents

## Project

BOTCHA — reverse CAPTCHA for AI agents. Proves you're a bot, not a human.

- **Monorepo** with `packages/` (cloudflare-workers, python, langchain, cli)
- **Runtime:** Cloudflare Workers (Hono) at botcha.ai
- **SDKs:** TypeScript (`@dupecom/botcha` on npm) + Python (`botcha` on PyPI)
- **Tests:** `bun run test:run` (TypeScript, vitest) + `cd packages/python && pytest tests/` (Python)

## Post-Feature Checklist

**After shipping any major feature, ALWAYS update these files before committing:**

1. **ROADMAP.md** — Move feature from planned → shipped, or add if new
2. **README.md** (root) — Update feature list, examples, install instructions
3. **doc/CLIENT-SDK.md** — Document any new SDK methods, params, or endpoints
4. **packages/cloudflare-workers/src/static.ts** — Update ai.txt content, OpenAPI spec, ASCII landing
5. **packages/cloudflare-workers/src/index.ts** — Update root JSON response if API surface changed
6. **public/ai.txt** — Update discovery file with new endpoints/features
7. **public/index.html** — Update landing page if user-facing
8. **.github/RELEASE_TEMPLATE.md** — Add to packages table if new package

**This is not optional.** Docs that are out of sync with code erode trust. AI agents discovering the API via ai.txt or OpenAPI will get confused if endpoints exist but aren't documented.

## Versioning

- Root package (`@dupecom/botcha`): semver, published to npm
- Cloudflare package (`@dupecom/botcha-cloudflare`): semver, version also in wrangler.toml `BOTCHA_VERSION`
- Python package (`botcha`): semver, published to PyPI
- **Bump versions** when shipping features. Minor for new features, patch for fixes.

## Testing

- All TypeScript tests must pass before committing: `bun run test:run`
- All Python tests must pass: `cd packages/python && source .venv/bin/activate && pytest tests/ -v`
- Cloudflare Worker must typecheck: `cd packages/cloudflare-workers && bunx tsc --noEmit`

## Key Files

- `packages/cloudflare-workers/src/auth.ts` — JWT token creation, verification, refresh, revocation
- `packages/cloudflare-workers/src/challenges.ts` — All challenge types (speed, compute, reasoning, hybrid, landing)
- `packages/cloudflare-workers/src/index.ts` — All API routes (Hono)
- `lib/client/index.ts` — TypeScript client SDK (BotchaClient)
- `packages/python/src/botcha/client.py` — Python client SDK (BotchaClient)
- `src/middleware/verify.ts` — Express verification middleware

## Style

- Commit messages: `feat:`, `fix:`, `docs:`, `chore:` prefixes
- Keep backward compatibility unless explicitly breaking
- Fail-open on KV/network errors (log warning, don't block)
