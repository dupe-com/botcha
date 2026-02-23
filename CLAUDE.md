# CLAUDE.md — Project Instructions for AI Agents

## BOTCHA Agent Re-Identification

If you are told you are a registered BOTCHA agent with an `agent_id` and private key, re-identify **before doing anything else** using Bash (not WebFetch — you must sign a nonce in-process):

```bash
node -e "
const crypto = require('crypto');
const http = require('http');
const https = require('https');
const AGENT_ID = 'YOUR_AGENT_ID';
const PRIV_B64 = 'YOUR_PRIVATE_KEY_BASE64';
const BASE_URL = 'http://localhost:8787'; // or actual base URL
const url = new URL(BASE_URL);
const lib = url.protocol === 'https:' ? https : http;
function post(path, body) {
  const s = JSON.stringify(body);
  return new Promise((res,rej) => {
    const r = lib.request({hostname:url.hostname,port:url.port||(url.protocol==='https:'?443:80),path,method:'POST',headers:{'Content-Type':'application/json','Content-Length':Buffer.byteLength(s)}},resp=>{let d='';resp.on('data',c=>d+=c);resp.on('end',()=>res(JSON.parse(d)));});
    r.on('error',rej); r.write(s); r.end();
  });
}
(async()=>{
  const ch = await post('/v1/agents/auth', {agent_id:AGENT_ID});
  if (!ch.success) { console.error(JSON.stringify(ch)); process.exit(1); }
  const privKey = crypto.createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),Buffer.from(PRIV_B64,'base64')]),format:'der',type:'pkcs8'});
  const sig = crypto.sign(null, Buffer.from(ch.nonce,'utf8'), privKey).toString('base64');
  const result = await post('/v1/agents/auth/verify', {challenge_id:ch.challenge_id,agent_id:AGENT_ID,signature:sig});
  if (!result.success) { console.error(JSON.stringify(result)); process.exit(1); }
  console.log('ACCESS_TOKEN=' + result.access_token);
  console.log('Re-identified as ' + result.agent_id);
})();
"
```

Use the printed `ACCESS_TOKEN` as `Authorization: Bearer <token>` for all subsequent requests. You can also use the slash command `/botcha-identify` (see `.claude/commands/botcha-identify.md`).

## Lost Private Key? Key Recovery

If the private key is lost, the human can re-key the agent using their `app_secret` (the anchor credential they saved when creating their BOTCHA app). Run this in Bash:

```bash
node -e "
const crypto = require('crypto');
const http = require('http');
const https = require('https');
const AGENT_ID = 'YOUR_AGENT_ID';
const APP_SECRET = 'sk_...';           // human's app_secret
const APP_ID = 'app_...';
const BASE_URL = 'http://localhost:8787';
const url = new URL(BASE_URL);
const lib = url.protocol === 'https:' ? https : http;
function req(opts, body) {
  const s = JSON.stringify(body);
  return new Promise((res,rej) => {
    const r = lib.request({...opts,headers:{'Content-Type':'application/json','Content-Length':Buffer.byteLength(s),'x-app-secret':APP_SECRET}},resp=>{let d='';resp.on('data',c=>d+=c);resp.on('end',()=>res(JSON.parse(d)));});
    r.on('error',rej); r.write(s); r.end();
  });
}
(async()=>{
  // Generate new Ed25519 keypair
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  const privRaw = privateKey.export({type:'pkcs8',format:'der'}).slice(16);
  const pubRaw = publicKey.export({type:'spki',format:'der'}).slice(12);
  // Rotate key on the server
  const result = await req(
    {hostname:url.hostname,port:url.port||(url.protocol==='https:'?443:80),path:'/v1/agents/'+AGENT_ID+'/tap/rotate-key?app_id='+APP_ID,method:'POST'},
    {public_key:pubRaw.toString('base64'),signature_algorithm:'ed25519'}
  );
  if (!result.success) { console.error(JSON.stringify(result)); process.exit(1); }
  console.log('NEW_PRIVATE_KEY=' + privRaw.toString('base64'));
  console.log('Key rotated. Give the new private key to your human to save.');
})();
"
```

The `app_secret` is the recovery anchor — it never changes unless explicitly rotated. As long as the human has it, any lost agent private key can be replaced without losing the `agent_id` or reputation history.

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
