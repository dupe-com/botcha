# CLAUDE.md — Project Instructions for AI Agents

## BOTCHA Agent Re-Identification

If you are told you are a registered BOTCHA agent, re-identify **before doing anything else** using Bash.

### Option A — Provider API key (preferred, no extra secret needed)

If your agent was registered with a provider binding, re-identify using your existing API key (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, etc.):

```bash
node -e "
const http = require('http');
const https = require('https');
const AGENT_ID = 'YOUR_AGENT_ID';   // e.g. agent_37c905...
const APP_ID   = 'YOUR_APP_ID';     // e.g. app_67de33...
const PROVIDER = 'anthropic';        // or openai, google, mistral, cohere
const API_KEY  = process.env.ANTHROPIC_API_KEY || 'YOUR_API_KEY';
const BASE_URL = 'http://localhost:8787';
const url = new URL(BASE_URL);
const lib = url.protocol === 'https:' ? https : http;
const body = JSON.stringify({ provider: PROVIDER, api_key: API_KEY, app_id: APP_ID });
const req = lib.request({hostname:url.hostname,port:url.port||(url.protocol==='https:'?443:80),path:'/v1/agents/auth/provider',method:'POST',headers:{'Content-Type':'application/json','Content-Length':Buffer.byteLength(body)}},res=>{let d='';res.on('data',c=>d+=c);res.on('end',()=>{const r=JSON.parse(d);if(!r.success){console.error(JSON.stringify(r));process.exit(1);}console.log('ACCESS_TOKEN='+r.access_token);console.log('Re-identified as '+r.agent_id);});});
req.on('error',e=>{console.error(e);process.exit(1);}); req.write(body); req.end();
"
```

> The API key is **never stored** — only its SHA-256 hash is compared. Re-identification works in any session as long as you have the same API key.

### Option B — TAP private key (fallback if no provider binding)

If your agent was registered with a keypair only, re-identify by signing a nonce in-process (not WebFetch — you must run code):

```bash
node -e "
const crypto = require('crypto');
const http = require('http');
const https = require('https');
const AGENT_ID = 'YOUR_AGENT_ID';
const PRIV_RAW = 'YOUR_PRIVATE_KEY'; // looks like tapk_ABC123...== (NOT sk_...)
const BASE_URL = 'http://localhost:8787'; // or actual base URL
const url = new URL(BASE_URL);
const lib = url.protocol === 'https:' ? https : http;
// Validate key format
if (PRIV_RAW.startsWith('sk_')) { console.error('ERROR: That is your app_secret, not your TAP private key. The TAP private key starts with tapk_ and was shown when you registered your agent.'); process.exit(1); }
const PRIV_B64 = PRIV_RAW.startsWith('tapk_') ? PRIV_RAW.slice(5) : PRIV_RAW;
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

> **Key format:** The TAP private key looks like `tapk_ABC123...==` (base64 with a `tapk_` prefix).
> It is **NOT** the same as the `app_secret` which starts with `sk_`.
> If you see `sk_...`, you have the wrong credential — ask your human for the TAP private key.

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
  console.log('NEW_PRIVATE_KEY=tapk_' + privRaw.toString('base64'));
  console.log('Key rotated. Give the new TAP private key (tapk_...) to your human to save. It is NOT the same as the app_secret (sk_...).');
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
