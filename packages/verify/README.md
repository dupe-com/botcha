# @dupecom/botcha-verify

Server-side verification middleware for BOTCHA JWT tokens.

## Installation

```bash
npm install @dupecom/botcha-verify
# or
yarn add @dupecom/botcha-verify
# or
bun add @dupecom/botcha-verify
```

## Features

- **JWKS verification (ES256)** — no shared secret needed, keys rotate automatically
- HS256 shared-secret verification (legacy, still supported)
- Automatic expiry checking
- Audience claim validation
- Issuer validation (`botcha.ai`) in JWKS mode
- Client IP binding support
- Token revocation checking (optional)
- Express & Hono middleware
- TypeScript support with full type definitions
- Custom error handlers

## Usage

### JWKS Verification (Recommended)

The recommended approach fetches BOTCHA's public key from the JWKS endpoint.
No shared secret to manage — key rotation is handled automatically.

```typescript
import { verifyBotchaToken } from '@dupecom/botcha-verify';

const result = await verifyBotchaToken(token, {
  jwksUrl: 'https://botcha.ai/.well-known/jwks',
  audience: 'https://api.example.com',
});

if (result.valid) {
  console.log('Token valid! Challenge:', result.payload.sub);
  console.log('Solve time:', result.payload.solveTime, 'ms');
} else {
  console.error('Token invalid:', result.error);
}
```

### Legacy: Shared Secret Verification

Still supported for existing integrations using HS256 tokens.

```typescript
import { verifyBotchaToken } from '@dupecom/botcha-verify';

const result = await verifyBotchaToken(token, {
  secret: process.env.BOTCHA_SECRET!,
  audience: 'https://api.example.com',
  requireIp: true,
});
```

### Express Middleware

```typescript
import express from 'express';
import { botchaVerify } from '@dupecom/botcha-verify/express';

const app = express();

// RECOMMENDED: JWKS verification
app.use('/api', botchaVerify({
  jwksUrl: 'https://botcha.ai/.well-known/jwks',
  audience: 'https://api.example.com',
}));

// LEGACY: Shared secret
app.use('/api', botchaVerify({
  secret: process.env.BOTCHA_SECRET!,
  audience: 'https://api.example.com',
  requireIp: true,
}));

app.get('/api/protected', (req, res) => {
  console.log('Challenge ID:', req.botcha?.sub);
  console.log('Solve time:', req.botcha?.solveTime);
  res.json({ message: 'Success' });
});
```

### Hono Middleware

```typescript
import { Hono } from 'hono';
import { botchaVerify } from '@dupecom/botcha-verify/hono';
import type { BotchaTokenPayload } from '@dupecom/botcha-verify';

const app = new Hono<{ Variables: { botcha: BotchaTokenPayload } }>();

// RECOMMENDED: JWKS verification
app.use('/api/*', botchaVerify({
  jwksUrl: 'https://botcha.ai/.well-known/jwks',
  audience: 'https://api.example.com',
}));

// LEGACY: Shared secret
app.use('/api/*', botchaVerify({
  secret: env.BOTCHA_SECRET,
  audience: 'https://api.example.com',
  requireIp: true,
}));

app.get('/api/protected', (c) => {
  const botcha = c.get('botcha');
  console.log('Challenge ID:', botcha.sub);
  console.log('Solve time:', botcha.solveTime);
  return c.json({ message: 'Success' });
});
```

## API

### `verifyBotchaToken(token, options, clientIp?)`

Verify a BOTCHA JWT token.

**Parameters:**
- `token` (string): JWT token to verify
- `options` (BotchaVerifyOptions): Verification options (at least one of `secret` or `jwksUrl` required)
- `clientIp` (string, optional): Client IP for validation

**Returns:** `Promise<VerificationResult>`

```typescript
interface VerificationResult {
  valid: boolean;
  payload?: BotchaTokenPayload;
  error?: string;
}
```

### `BotchaVerifyOptions`

```typescript
interface BotchaVerifyOptions {
  // JWKS URL for ES256 verification (recommended)
  jwksUrl?: string;

  // Cache JWKS keys for this many seconds (default: 3600)
  jwksCacheTtl?: number;

  // JWT secret for HS256 verification (legacy)
  secret?: string;

  // At least one of `secret` or `jwksUrl` must be provided.
  // If both are provided, JWKS is tried first, falling back to secret.

  // Optional: Expected audience claim
  audience?: string;

  // Optional: Validate client IP claim
  requireIp?: boolean;

  // Optional: Custom error handler
  onError?: (error: string, context: VerificationContext) => void | Promise<void>;

  // Optional: Token revocation check
  checkRevocation?: (jti: string) => Promise<boolean>;
}
```

### `BotchaTokenPayload`

```typescript
interface BotchaTokenPayload {
  sub: string;        // Challenge ID
  iat: number;        // Issued at
  exp: number;        // Expires at
  jti: string;        // JWT ID
  type: 'botcha-verified';
  solveTime: number;  // Solve time in ms
  aud?: string;       // Optional audience
  client_ip?: string; // Optional client IP
}
```

## Token Validation

The verifier checks:

1. **Signature**: ES256 via JWKS (recommended) or HS256 via shared secret (legacy)
2. **Expiry**: Token must not be expired
3. **Type**: Token must be `botcha-verified` (not `botcha-refresh`)
4. **Issuer** (JWKS mode): Token `iss` must be `botcha.ai`
5. **Audience** (optional): Token `aud` must match expected audience
6. **Client IP** (optional): Token `client_ip` must match request IP
7. **Revocation** (optional): Token JTI must not be revoked

## Migration from Shared Secret to JWKS

Replace `secret` with `jwksUrl` in your configuration. During the transition
period you can provide both — JWKS is tried first with a fallback to the secret:

```typescript
// Transition: both methods supported
app.use('/api', botchaVerify({
  jwksUrl: 'https://botcha.ai/.well-known/jwks',
  secret: process.env.BOTCHA_SECRET!, // fallback during migration
  audience: 'https://api.example.com',
}));

// After migration: JWKS only
app.use('/api', botchaVerify({
  jwksUrl: 'https://botcha.ai/.well-known/jwks',
  audience: 'https://api.example.com',
}));
```

## Custom Error Handling

```typescript
app.use('/api', botchaVerify({
  jwksUrl: 'https://botcha.ai/.well-known/jwks',
  onError: (error, context) => {
    console.error('Token verification failed:', error);
    console.error('Context:', context);
  },
}));
```

## Token Revocation

Implement custom revocation checking:

```typescript
import { verifyBotchaToken } from '@dupecom/botcha-verify';

const result = await verifyBotchaToken(token, {
  jwksUrl: 'https://botcha.ai/.well-known/jwks',
  checkRevocation: async (jti) => {
    const isRevoked = await db.revokedTokens.exists(jti);
    return isRevoked;
  },
});
```

## Client IP Extraction

The middleware automatically extracts client IP from:

- **Cloudflare**: `CF-Connecting-IP` header
- **Proxies**: `X-Forwarded-For` header (first IP)
- **Load Balancers**: `X-Real-IP` header
- **Direct**: `req.ip` (Express) or fallback (Hono)

## Security Notes

- **JWKS**: Public keys are cached and rotated automatically by the `jose` library
- **Fail-open**: Revocation checks fail-open if the check throws an error
- **IP validation**: Only enabled if `requireIp: true` is set
- **Audience**: Strongly recommended for multi-API deployments
- **Issuer**: Automatically validated as `botcha.ai` in JWKS mode

## License

MIT

## Links

- [Documentation](https://botcha.ai)
- [GitHub](https://github.com/dupe-com/botcha)
- [NPM](https://www.npmjs.com/package/@dupecom/botcha-verify)
