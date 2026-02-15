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

- 🔐 JWT token verification with HS256 signature
- ⏰ Automatic expiry checking
- 🎯 Audience claim validation
- 🌐 Client IP binding support
- 🚫 Token revocation checking (optional)
- 🎨 Express & Hono middleware
- 📦 TypeScript support with full type definitions
- 🔄 Custom error handlers

## Usage

### Standalone Verification

```typescript
import { verifyBotchaToken } from '@dupecom/botcha-verify';

const result = await verifyBotchaToken(token, {
  secret: process.env.BOTCHA_SECRET!,
  audience: 'https://api.example.com',
  requireIp: true,
});

if (result.valid) {
  console.log('Token valid! Challenge:', result.payload.sub);
  console.log('Solve time:', result.payload.solveTime, 'ms');
} else {
  console.error('Token invalid:', result.error);
}
```

### Express Middleware

```typescript
import express from 'express';
import { botchaVerify } from '@dupecom/botcha-verify/express';

const app = express();

// Protect all /api routes
app.use('/api', botchaVerify({
  secret: process.env.BOTCHA_SECRET!,
  audience: 'https://api.example.com',
  requireIp: true,
}));

app.get('/api/protected', (req, res) => {
  // Access verified token payload
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

// Protect all /api routes
app.use('/api/*', botchaVerify({
  secret: env.BOTCHA_SECRET,
  audience: 'https://api.example.com',
  requireIp: true,
}));

app.get('/api/protected', (c) => {
  // Access verified token payload
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
- `options` (BotchaVerifyOptions): Verification options
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
  // Required: JWT secret (HS256)
  secret: string;

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

1. **Signature**: HS256 signature using the provided secret
2. **Expiry**: Token must not be expired
3. **Type**: Token must be `botcha-verified` (not `botcha-refresh`)
4. **Audience** (optional): Token `aud` must match expected audience
5. **Client IP** (optional): Token `client_ip` must match request IP
6. **Revocation** (optional): Token JTI must not be revoked

## Custom Error Handling

```typescript
app.use('/api', botchaVerify({
  secret: process.env.BOTCHA_SECRET!,
  onError: (error, context) => {
    console.error('Token verification failed:', error);
    console.error('Context:', context);
    // Custom response logic here
  },
}));
```

## Token Revocation

Implement custom revocation checking:

```typescript
import { verifyBotchaToken } from '@dupecom/botcha-verify';

const result = await verifyBotchaToken(token, {
  secret: process.env.BOTCHA_SECRET!,
  checkRevocation: async (jti) => {
    // Check your database/cache if token is revoked
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

- **Fail-open**: Revocation checks fail-open if the check throws an error
- **IP validation**: Only enabled if `requireIp: true` is set
- **Audience**: Strongly recommended for multi-API deployments
- **Secret**: Keep your JWT secret secure and rotate periodically

## License

MIT

## Links

- [Documentation](https://botcha.ai)
- [GitHub](https://github.com/dupe-com/botcha)
- [NPM](https://www.npmjs.com/package/@dupecom/botcha-verify)
