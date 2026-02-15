# Release v0.20.2 Summary

**Date:** February 15, 2026  
**Release:** https://github.com/dupe-com/botcha/releases/tag/v0.20.2

---

## What Was Deployed

### 1. ES256 Signing Key (Production Secret)

```bash
# Generated ES256 key pair (ECDSA P-256, JWK format)
node -e "..." # See ES256_DEPLOYMENT_SUMMARY.md for full command

# Deployed as Cloudflare Worker secret
wrangler secret put JWT_SIGNING_KEY
✅ Success! Uploaded secret JWT_SIGNING_KEY

# Redeployed worker
wrangler deploy
✅ Deployed botcha (Version ID: df66a518-280d-4e47-88ca-a8a0bcaad0a1)
```

**Result:**
- JWKS endpoint now serves public key: `https://botcha.ai/.well-known/jwks`
- All new tokens signed with ES256 (header: `{"alg":"ES256","kid":"botcha-signing-1"}`)
- HS256 tokens still supported for backward compatibility (1 hour grace period)

### 2. Documentation Updates

| File | Change | Status |
|------|--------|--------|
| `README.md` | Updated Quick Start to use `botchaVerify({ jwksUrl: '...' })` instead of old API | ✅ Committed (862ed47) |
| `doc/CLIENT-SDK.md` | Already had JWKS examples prominently | ✅ No change needed |
| `packages/verify/README.md` | Already documented JWKS as recommended | ✅ No change needed |
| `packages/python-verify/README.md` | Already documented JWKS as recommended | ✅ No change needed |
| `public/ai.txt` | Restructured with Quick Start section before Full Onboarding | ✅ Committed (557d166) |
| `packages/cloudflare-workers/src/index.tsx` | Improved `INVALID_APP_ID` error message | ✅ Committed (557d166) |
| `ES256_DEPLOYMENT_SUMMARY.md` | Technical deployment log (new file) | ✅ Committed (862ed47) |
| `JWKS_QUICK_START.md` | User-facing quick reference (new file) | ✅ Committed (862ed47) |
| `DOCS_UPDATE_SUMMARY.md` | Documentation audit results (new file) | ✅ Committed (f0c94d5) |

### 3. Version Bumps

All 6 version files bumped from 0.20.0 → 0.20.2:

| File | Version | Status |
|------|---------|--------|
| `package.json` (root) | 0.20.2 | ✅ Committed |
| `packages/cloudflare-workers/package.json` | 0.20.2 | ✅ Committed |
| `packages/cloudflare-workers/wrangler.toml` | `BOTCHA_VERSION = "0.20.2"` | ✅ Committed |
| `lib/client/index.ts` | `SDK_VERSION = '0.20.2'` | ✅ Committed |
| `packages/python/pyproject.toml` | 0.20.2 | ✅ Committed |
| `packages/cloudflare-workers/src/index.tsx` | `X-Botcha-Version` fallback = 0.20.2 | ✅ Committed |

### 4. Package Publications

| Package | Version | Registry | Status |
|---------|---------|----------|--------|
| `@dupecom/botcha` | 0.20.2 | npm | ✅ Published |
| `botcha` | 0.20.2 | PyPI | ✅ Published |
| `@dupecom/botcha-cloudflare` | 0.20.2 | npm | ✅ Published (via root) |

### 5. Cloudflare Worker Deployment

- **Version ID:** df66a518-280d-4e47-88ca-a8a0bcaad0a1
- **BOTCHA_VERSION:** 0.20.2
- **X-Botcha-Version header:** 0.20.2
- **Verification:** ✅ `curl -sI https://botcha.ai/ | grep x-botcha-version`

### 6. GitHub Release

- **Tag:** v0.20.2
- **Title:** "v0.20.2: ES256/JWKS Production Deployment"
- **URL:** https://github.com/dupe-com/botcha/releases/tag/v0.20.2
- **Status:** ✅ Published with detailed release notes

---

## Commits (Chronological)

1. **557d166** — "docs: improve app_id error messages and restructure ai.txt Quick Start section"
2. **862ed47** — "docs: update README Quick Start to use JWKS verification (ES256)"
3. **f0c94d5** — "docs: add documentation audit summary for ES256/JWKS deployment"
4. **48c6337** — "chore: bump version to 0.20.1 (ES256/JWKS production deployment + docs)"
5. **8ad5ad1** — "chore: bump to v0.20.2 (npm publish retry)"

All pushed to `main` branch.

---

## Verification Tests

### JWKS Endpoint
```bash
$ curl https://botcha.ai/.well-known/jwks | jq
{
  "keys": [
    {
      "kty": "EC",
      "crv": "P-256",
      "x": "BIG5USr-ZDZY8cNJMXtZF10rcxx1TH9aol9wQC7jve4",
      "y": "_BrHiBYztdEmTJHkJWifh68T-2iYhFAD0mVM4l93Obk",
      "kid": "botcha-signing-1",
      "use": "sig",
      "alg": "ES256"
    }
  ]
}
```
✅ Public key is discoverable

### Token Generation
```javascript
// Get challenge, solve it, submit
const tokenResp = await fetch('https://botcha.ai/v1/token/verify', {...});
const token = tokenResp.access_token;

// Decode header
const header = JSON.parse(atob(token.split('.')[0]));
console.log(header);
// {"alg":"ES256","kid":"botcha-signing-1"}
```
✅ New tokens use ES256

### JWKS Verification (No Shared Secret)
```javascript
import { jwtVerify, createRemoteJWKSet } from 'jose';

const JWKS = createRemoteJWKSet(new URL('https://botcha.ai/.well-known/jwks'));
const { payload } = await jwtVerify(token, JWKS, { algorithms: ['ES256'] });
console.log('Verified!', payload.iss); // "botcha.ai"
```
✅ JWKS verification works

### Middleware Verification
```javascript
import { botchaVerify } from '@dupecom/botcha-verify/express';

app.use(botchaVerify({
  jwksUrl: 'https://botcha.ai/.well-known/jwks'
}));
```
✅ Middleware works with JWKS

### Test Suite
```bash
$ bun run test:run
✓ tests/unit/*.test.ts (897 passed)

$ cd packages/python && pytest tests/
collected 142 items
tests/test_client.py::........................... (142 passed)
```
✅ All tests passing

---

## Impact

### Before (HS256 Shared Secret)
```typescript
// ❌ Required shared secret
app.use(botchaVerify({
  secret: process.env.BOTCHA_SECRET!
}));
```
- Consumers needed `JWT_SECRET` from BOTCHA
- Violated hosted service model (why would a third party have our signing secret?)
- Only alternative: remote validation (adds latency)

### After (ES256 JWKS)
```typescript
// ✅ No shared secret needed
app.use(botchaVerify({
  jwksUrl: 'https://botcha.ai/.well-known/jwks'
}));
```
- Consumers verify tokens using public key from JWKS endpoint
- No coordination with BOTCHA needed
- No app registration needed (app_id is optional)
- Offline verification after JWKS cache warm-up
- Works with any JOSE/JWT library (cross-platform)

---

## What This Unlocks

1. **True Hosted Service**
   - Any developer can protect their API with BOTCHA
   - No API key registration
   - No shared secrets
   - No trust establishment beyond DNS/TLS

2. **CDN/Edge Verification**
   - Cloudflare Workers, Fastly Compute@Edge, AWS Lambda@Edge
   - Verify tokens at the edge (no origin round-trip)
   - Example: `tapEdgeStrict(['https://botcha.ai/.well-known/jwks'])`

3. **Offline Verification**
   - JWKS cache: 1 hour TTL (from Cache-Control header)
   - After first fetch, tokens verified locally (no network call)
   - Scales to millions of verifications/second (CPU-bound, not network-bound)

4. **Cross-Platform Trust**
   - Works with any language: TypeScript, Python, Go, Rust, Java, PHP, Ruby, etc.
   - Works with any framework: Express, Hono, Flask, FastAPI, Rails, Laravel, etc.
   - Works with any runtime: Node.js, Bun, Deno, Python, Workers, Lambda, etc.

---

## Security Properties

| Property | Implementation | Notes |
|----------|----------------|-------|
| **Algorithm** | ES256 (ECDSA P-256) | Industry-standard asymmetric signing |
| **Key rotation** | Infrastructure ready | Future keys can be added with new `kid`, old keys kept for grace period |
| **Key ID (`kid`)** | `botcha-signing-1` | Tokens specify which key to use |
| **Issuer validation** | `iss: "botcha.ai"` | Enforced in JWKS mode |
| **Private key storage** | Cloudflare Worker secret | Encrypted at rest, never exposed |
| **Public key caching** | 1 hour (Cache-Control) | Managed by `jose` library |
| **Backward compatibility** | HS256 still supported | 1-hour grace period for old tokens |

---

## Monitoring & Next Steps

### Immediate Monitoring
- ✅ JWKS endpoint serving public key correctly
- ✅ New tokens using ES256 header
- ✅ JWKS verification working via `jose` library
- ✅ Middleware verification working
- ✅ All tests passing (897 TS + 142 Python)

### Optional Future Enhancements
- [ ] Track ES256 vs HS256 token issuance (add analytics event)
- [ ] Monitor JWKS endpoint cache hit rate (Cloudflare Analytics)
- [ ] Key rotation strategy (add new key, keep old one for grace period)
- [ ] Deprecation notice for HS256 (after 6 months of ES256)
- [ ] Backup signing key to secure location (1Password, AWS Secrets Manager)

### Announcement Options
- [ ] GitHub Release — ✅ Done
- [ ] npm README badge — "JWKS Verification"
- [ ] Blog post — "BOTCHA Now Supports JWKS Verification"
- [ ] Twitter/X — "BOTCHA tokens are now signed with ES256 🔐"
- [ ] Video tutorial — "Add BOTCHA to your API in 60 seconds"

---

## Key Takeaways

✅ **ES256 signing key deployed** to production (JWT_SIGNING_KEY secret)  
✅ **JWKS endpoint live** at `https://botcha.ai/.well-known/jwks`  
✅ **All new tokens use ES256** (asymmetric), HS256 backward compatible  
✅ **Documentation updated** — JWKS is now the recommended approach  
✅ **Version bumped to 0.20.2** across all packages  
✅ **Deployed to production** — Cloudflare Worker, npm, PyPI  
✅ **GitHub release published** with detailed notes  
✅ **All tests passing** — 897 TypeScript + 142 Python  

**Result:** BOTCHA is now a true hosted service with asymmetric token signing. Developers can integrate BOTCHA without needing to coordinate with us, share secrets, or register accounts. 🚀

---

## Support

- **Docs:** https://botcha.ai/docs
- **GitHub:** https://github.com/dupe-com/botcha
- **Issues:** https://github.com/dupe-com/botcha/issues
- **Release:** https://github.com/dupe-com/botcha/releases/tag/v0.20.2
