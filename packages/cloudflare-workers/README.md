# @dupecom/botcha-cloudflare

> 🤖 **BOTCHA** - Prove you're a bot. Humans need not apply.
> 
> Cloudflare Workers Edition

Reverse CAPTCHA that verifies AI agents and blocks humans. Running at the edge.

## Features

- ⚡ **Speed Challenge** - 5 SHA256 hashes in 500ms (impossible for humans to copy-paste)
- 🧮 **Standard Challenge** - Configurable difficulty prime calculations
- 🌍 **Edge-native** - Runs on Cloudflare's global network
- 🔐 **Multiple verification methods** - Headers, challenges, Web Bot Auth
- 📦 **Zero dependencies at runtime** - Just Hono for routing

## Quick Deploy

```bash
# Clone the repo
git clone https://github.com/i8ramin/botcha
cd botcha/packages/cloudflare-workers

# Install dependencies
npm install

# Deploy to Cloudflare
npm run deploy
```

## Local Development

```bash
npm run dev
# Worker running at http://localhost:8787
```

## API Endpoints

### `GET /`
Returns API info and available endpoints.

### `GET /api/speed-challenge`
Get a speed challenge (5 problems, 500ms time limit).

```json
{
  "challenge": {
    "id": "abc-123",
    "problems": [
      { "num": 123456, "operation": "sha256_first8" },
      ...
    ],
    "timeLimit": "500ms"
  }
}
```

### `POST /api/speed-challenge`
Submit speed challenge answers.

```json
{
  "id": "abc-123",
  "answers": ["a1b2c3d4", "e5f6g7h8", ...]
}
```

### `GET /api/challenge?difficulty=medium`
Get a standard challenge (easy/medium/hard).

### `POST /api/challenge`
Submit standard challenge answer.

### `GET /agent-only`
Protected endpoint. Returns challenge if not authenticated.

**Authentication methods:**
- `X-Agent-Identity: your-agent-name` (testing)
- `X-Botcha-Challenge-Id` + `X-Botcha-Solution` (challenge response)
- `X-Botcha-Landing-Token` (from landing page challenge)
- Known agent User-Agent patterns

## Solving Challenges (for AI Agents)

```typescript
// Speed challenge
const challenge = await fetch('https://your-worker.workers.dev/api/speed-challenge').then(r => r.json());

const answers = await Promise.all(
  challenge.challenge.problems.map(async (p) => {
    const hash = await crypto.subtle.digest(
      'SHA-256',
      new TextEncoder().encode(p.num.toString())
    );
    return Array.from(new Uint8Array(hash))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('')
      .substring(0, 8);
  })
);

const result = await fetch('https://your-worker.workers.dev/api/speed-challenge', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ id: challenge.challenge.id, answers }),
}).then(r => r.json());

console.log(result.verdict); // "🤖 VERIFIED AI AGENT"
```

## Production Considerations

The default implementation uses in-memory Maps for challenge storage. This works for:
- Development
- Low-traffic deployments
- Single-isolate scenarios

For high-traffic production, consider:
- **Cloudflare KV** for distributed challenge storage
- **Durable Objects** for stateful challenge management
- **D1** for persistent audit logs

Uncomment the KV binding in `wrangler.toml` and modify `challenges.ts` to use it.

## License

MIT
