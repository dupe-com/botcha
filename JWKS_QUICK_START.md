# BOTCHA JWKS Quick Start

**TL;DR:** BOTCHA now signs tokens with ES256. Verify them using the public JWKS endpoint — **no shared secret needed**.

---

## Install

```bash
npm install @dupecom/botcha-verify
# or
pip install botcha-verify
```

---

## Verify Tokens (3 Lines)

### TypeScript/Node.js (Express)

```typescript
import { botchaVerify } from '@dupecom/botcha-verify';

app.use(botchaVerify({
  jwksUrl: 'https://botcha.ai/.well-known/jwks'
}));
```

### TypeScript/Node.js (Hono)

```typescript
import { botchaVerify } from '@dupecom/botcha-verify/hono';

app.use('/*', botchaVerify({
  jwksUrl: 'https://botcha.ai/.well-known/jwks'
}));
```

### Python (Flask)

```python
from botcha_verify import verify_botcha_token

@app.before_request
def verify():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    result = verify_botcha_token(token, {
        'jwks_url': 'https://botcha.ai/.well-known/jwks'
    })
    if not result['valid']:
        return {'error': result['error']}, 401
```

### Manual (Any Language with JOSE/JWT Support)

```typescript
import { jwtVerify, createRemoteJWKSet } from 'jose';

const JWKS = createRemoteJWKSet(
  new URL('https://botcha.ai/.well-known/jwks')
);

const { payload } = await jwtVerify(token, JWKS, {
  algorithms: ['ES256'],
  issuer: 'botcha.ai'
});

console.log('Token verified!', payload);
```

---

## Get a Token (Test)

```bash
# 1. Get challenge
curl https://botcha.ai/v1/token

# 2. Solve it (5 SHA-256 hashes in <500ms)
# Use the TypeScript/Python SDK or solve manually

# 3. Submit
curl -X POST https://botcha.ai/v1/token/verify \
  -H 'Content-Type: application/json' \
  -d '{"id":"<challenge-id>","answers":["hash1","hash2","hash3","hash4","hash5"]}'

# Returns: { "access_token": "eyJ...", ... }
```

---

## Using the SDK

### TypeScript

```typescript
import { BotchaClient } from '@dupecom/botcha';

const client = new BotchaClient({ baseUrl: 'https://botcha.ai' });

// Get a token (solves challenge automatically)
const { access_token } = await client.getToken();

// Use it
const response = await fetch('https://api.example.com/protected', {
  headers: { 'Authorization': `Bearer ${access_token}` }
});
```

### Python

```python
from botcha import BotchaClient

client = BotchaClient(base_url='https://botcha.ai')

# Get a token (solves challenge automatically)
token = client.get_token()

# Use it
import requests
response = requests.get('https://api.example.com/protected', headers={
    'Authorization': f'Bearer {token.access_token}'
})
```

---

## Verification Options

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `jwksUrl` | `string` | Yes* | JWKS endpoint URL (https://botcha.ai/.well-known/jwks) |
| `secret` | `string` | No | Shared secret (legacy, not recommended) |
| `audience` | `string` | No | Expected `aud` claim (your API URL) |
| `requireIp` | `boolean` | No | Enforce client IP binding (default: false) |
| `clientIp` | `string` | No | Client IP for validation (auto-detected in middleware) |
| `checkRevocation` | `function` | No | Callback to check if token is revoked |

\* Either `jwksUrl` or `secret` must be provided. `jwksUrl` is recommended.

---

## Token Structure

**Header:**
```json
{
  "alg": "ES256",
  "kid": "botcha-signing-1"
}
```

**Payload:**
```json
{
  "type": "botcha-verified",
  "sub": "challenge-id",
  "iss": "botcha.ai",
  "iat": 1771175953,
  "exp": 1771179553,
  "jti": "unique-token-id",
  "solveTime": 324,
  "aud": "https://api.example.com",  // if requested
  "client_ip": "203.0.113.42"         // if bind_ip=true
}
```

**Lifetime:** 1 hour (3600 seconds)

---

## Public Key Discovery

```bash
curl https://botcha.ai/.well-known/jwks
```

**Returns:**
```json
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

**Cache-Control:** `public, max-age=3600` (1 hour)

---

## Common Patterns

### Audience Validation (Recommended)

Ensure tokens are issued for YOUR API:

```typescript
app.use(botchaVerify({
  jwksUrl: 'https://botcha.ai/.well-known/jwks',
  audience: 'https://api.example.com'  // YOUR API URL
}));
```

When getting tokens, request the audience:

```bash
curl -X POST https://botcha.ai/v1/token/verify \
  -d '{"id":"...","answers":[...],"audience":"https://api.example.com"}'
```

### Client IP Binding (High Security)

Bind tokens to the client's IP address:

```bash
curl -X POST https://botcha.ai/v1/token/verify \
  -d '{"id":"...","answers":[...],"bind_ip":true}'
```

Then enforce it:

```typescript
app.use(botchaVerify({
  jwksUrl: 'https://botcha.ai/.well-known/jwks',
  requireIp: true  // Enforces client_ip claim
}));
```

### Token Revocation (Optional)

Check if a token has been revoked:

```typescript
app.use(botchaVerify({
  jwksUrl: 'https://botcha.ai/.well-known/jwks',
  checkRevocation: async (jti: string) => {
    // Query your revocation list (Redis, database, etc.)
    return await redis.sismember('revoked_tokens', jti);
  }
}));
```

---

## Performance

- **JWKS caching:** The `jose` library caches public keys automatically (1 hour TTL)
- **Offline verification:** After the first fetch, tokens are verified locally (no network call to botcha.ai)
- **Throughput:** Limited only by CPU (ECDSA P-256 verification ~10-20k ops/sec per core)
- **Latency:** <1ms per verification (after JWKS cache warm-up)

---

## Troubleshooting

### "Invalid signature"
- Make sure you're using the latest public key from JWKS
- Check that the token hasn't expired (`exp` claim)
- Verify the token was issued by botcha.ai (`iss` claim)

### "Invalid issuer claim"
- Tokens must have `iss: "botcha.ai"`
- This is enforced when using JWKS mode
- If using shared secret mode, issuer is not validated

### "Invalid audience claim"
- Your middleware expects `aud: "https://api.example.com"` but token has different audience
- Make sure clients request the correct audience when getting tokens

### "JWKS fetch failed"
- Check that https://botcha.ai/.well-known/jwks is accessible
- Verify your firewall allows outbound HTTPS to botcha.ai
- The JWKS endpoint has a 1-hour cache, so occasional failures are tolerated

---

## Migration from HS256 (Shared Secret)

**Old way (shared secret):**
```typescript
app.use(botchaVerify({
  secret: 'your-shared-secret'  // ❌ Not recommended
}));
```

**New way (JWKS):**
```typescript
app.use(botchaVerify({
  jwksUrl: 'https://botcha.ai/.well-known/jwks'  // ✅ Recommended
}));
```

**Transition period (both supported):**
```typescript
app.use(botchaVerify({
  jwksUrl: 'https://botcha.ai/.well-known/jwks',  // Try JWKS first
  secret: 'your-shared-secret'                     // Fall back to shared secret
}));
```

Tokens issued after Feb 15, 2026 use ES256 and can be verified with JWKS.  
Tokens issued before Feb 15, 2026 use HS256 and require the shared secret (or remote validation).

---

## Security Best Practices

1. **Always use HTTPS** for your API (tokens in `Authorization` header are bearer tokens)
2. **Validate audience** to prevent token reuse across different APIs
3. **Check token expiry** (handled automatically by `jose` library)
4. **Consider IP binding** for high-security endpoints
5. **Implement rate limiting** on verification failures (protect against token guessing)
6. **Log verification failures** for security monitoring
7. **Rotate JWKS cache** if you suspect key compromise (wait for new key rotation)

---

## Support

- **Docs:** https://botcha.ai/docs
- **GitHub:** https://github.com/dupe-com/botcha
- **Issues:** https://github.com/dupe-com/botcha/issues
- **Discord:** https://discord.gg/botcha (coming soon)

---

## License

MIT — see [LICENSE](LICENSE) for details.
