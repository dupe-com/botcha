# Migration: Express → Cloudflare Workers (Local Dev)

## What Changed (Feb 2026)

We've simplified the development workflow by **removing the Express.js development server** and using **Wrangler (Cloudflare Workers)** for both local development and production.

## Why?

1. **Single codebase** - No more keeping Express and CF Workers in sync
2. **Production parity** - Local dev behaves exactly like production
3. **Better DX** - Hot reload, local KV, built-in debugging
4. **SSE support** - Full SSE streaming works locally

## What Still Uses Express?

**The Express middleware (`botchaVerify`) is still available and maintained.**

Users of the SDK can still do:

```typescript
import express from 'express';
import { botcha } from '@dupecom/botcha';

const app = express();
app.get('/agent-only', botcha.verify(), (req, res) => {
  res.json({ message: 'Hello bot!' });
});
```

This middleware is part of the SDK and is **not going away**.

## Migration Guide

### Old (Express Dev Server)

```bash
# Before
bun run dev       # Ran Express server at localhost:3000
```

### New (Wrangler Dev)

```bash
# After
bun run dev       # Runs Wrangler at localhost:8787
```

### Configuration

**Before:**
- Environment variables in `.env` or set manually
- Express config in `src/index.ts`

**After:**
- Local secrets in `packages/cloudflare-workers/.dev.vars`
- Wrangler config in `packages/cloudflare-workers/wrangler.toml`

### File Changes

- ❌ **Deleted**: `src/index.ts` (Express dev server)
  - Backed up to `src/index.ts.backup` if you need it
- ✅ **Kept**: `src/middleware/verify.ts` (Express middleware for SDK)
- ✅ **Kept**: `lib/index.ts` (SDK exports)
- ✅ **Added**: `packages/cloudflare-workers/.dev.vars` (local secrets)

### Wrangler Commands

```bash
# Local development
cd packages/cloudflare-workers
wrangler dev                    # Start local server
wrangler dev --remote          # Use remote resources (not recommended for dev)

# Production deployment
wrangler deploy                 # Deploy to Cloudflare

# Secrets management
wrangler secret put JWT_SECRET  # Set production secret
wrangler kv:namespace list      # List KV namespaces
```

### Local KV Emulation

Wrangler automatically emulates KV storage locally:
- No setup needed
- Data stored in `.wrangler/state/`
- Cleared on restart

### Testing SSE Locally

```bash
# Start dev server
bun run dev

# In another terminal
curl -N http://localhost:8787/v1/challenge/stream
```

## Benefits

| Aspect | Express (Old) | Wrangler (New) |
|--------|---------------|----------------|
| Hot reload | ✅ (via tsx) | ✅ (built-in) |
| KV storage | ❌ (in-memory Map) | ✅ (local emulation) |
| SSE support | ⚠️ (basic) | ✅ (full support) |
| Prod parity | ❌ (different code) | ✅ (same code) |
| Maintenance | 2 codebases | 1 codebase |

## Rollback (if needed)

If you need the old Express dev server:

```bash
# Restore backed up file
mv src/index.ts.backup src/index.ts

# Update package.json
"dev": "tsx watch src/index.ts"

# Run old dev server
bun run dev
```

## Questions?

Open an issue: https://github.com/dupe-com/botcha/issues
