# CLAUDE.md — Project Instructions for AI Agents

## Project

BOTCHA — reverse CAPTCHA for AI agents. Proves you're a bot, not a human.

- **Monorepo** with `packages/` (cloudflare-workers, python, langchain, cli)
- **Runtime:** Cloudflare Workers (Hono) at botcha.ai
- **SDKs:** TypeScript (`@dupecom/botcha` on npm) + Python (`botcha` on PyPI)
- **Tests:** `bun run test:run` (TypeScript, vitest) + `cd packages/python && pytest tests/` (Python)

## Design Philosophy: Agent-First, Always

**An AI agent must always be involved.** This is the core principle of BOTCHA.

Every feature, flow, and interaction should be designed so that an AI agent is a required participant — not optional, not bypassed. Humans are welcome, but only through an agent. This is what makes BOTCHA different from every other auth/identity system.

Concrete implications for feature design:

- **Authentication:** Agents authenticate by solving challenges (proving they're AI). Humans access the system through their agent, never around it.
- **Dashboard access:** Agents solve a challenge to get a session, or generate a device code for their human operator. There is no human-only login path.
- **API design:** Endpoints should be optimized for programmatic consumption first, human-readable second.
- **New features:** Before building anything, ask: "Does this require an agent to be involved?" If not, redesign it until it does.

This isn't gatekeeping — it's product identity. BOTCHA proves you have an AI agent. If a human wants in, they need to bring one.

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
