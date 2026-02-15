import { describe, test, expect, vi, beforeAll, beforeEach } from 'vitest';
import { generateKeyPair, exportJWK, SignJWT, decodeProtectedHeader, decodeJwt } from 'jose';
import {
  generateToken,
  verifyToken,
  refreshAccessToken,
  getSigningPublicKeyJWK,
  type ES256SigningKeyJWK,
  type KVNamespace,
} from '../../../packages/cloudflare-workers/src/auth.js';

// ── Shared test fixtures ──────────────────────────────────────────────

let es256PrivateJwk: ES256SigningKeyJWK;
let es256PublicJwk: { kty: string; crv: string; x: string; y: string };
let wrongPrivateJwk: ES256SigningKeyJWK;
let wrongPublicJwk: { kty: string; crv: string; x: string; y: string };

const TEST_SECRET = 'test-secret-at-least-32-chars-long!!';
const TEST_CHALLENGE_ID = 'challenge-abc-123';
const TEST_SOLVE_TIME = 42;

function createMockKV(): KVNamespace & { _store: Map<string, string> } {
  const store = new Map<string, string>();
  return {
    _store: store,
    get: vi.fn(async (key: string) => store.get(key) ?? null),
    put: vi.fn(async (key: string, value: string, _opts?: any) => {
      store.set(key, value);
    }),
    delete: vi.fn(async (key: string) => {
      store.delete(key);
    }),
  };
}

beforeAll(async () => {
  // Generate primary ES256 key pair
  const { privateKey, publicKey } = await generateKeyPair('ES256');
  const privJwk = await exportJWK(privateKey);
  const pubJwk = await exportJWK(publicKey);
  es256PrivateJwk = { ...privJwk, kid: 'botcha-signing-1' } as ES256SigningKeyJWK;
  es256PublicJwk = pubJwk as { kty: string; crv: string; x: string; y: string };

  // Generate a second (wrong) ES256 key pair for negative tests
  const wrong = await generateKeyPair('ES256');
  const wrongPriv = await exportJWK(wrong.privateKey);
  const wrongPub = await exportJWK(wrong.publicKey);
  wrongPrivateJwk = { ...wrongPriv, kid: 'wrong-key' } as ES256SigningKeyJWK;
  wrongPublicJwk = wrongPub as { kty: string; crv: string; x: string; y: string };
});

// =====================================================================
// 1. ES256 Token Generation
// =====================================================================

describe('ES256 Token Generation', () => {
  test('generateToken() with signingKey produces ES256 tokens', async () => {
    const result = await generateToken(
      TEST_CHALLENGE_ID, TEST_SOLVE_TIME, TEST_SECRET,
      undefined, undefined, es256PrivateJwk,
    );

    const header = decodeProtectedHeader(result.access_token);
    expect(header.alg).toBe('ES256');

    const refreshHeader = decodeProtectedHeader(result.refresh_token);
    expect(refreshHeader.alg).toBe('ES256');
  });

  test('generateToken() without signingKey falls back to HS256', async () => {
    const result = await generateToken(
      TEST_CHALLENGE_ID, TEST_SOLVE_TIME, TEST_SECRET,
    );

    const header = decodeProtectedHeader(result.access_token);
    expect(header.alg).toBe('HS256');

    const refreshHeader = decodeProtectedHeader(result.refresh_token);
    expect(refreshHeader.alg).toBe('HS256');
  });

  test('ES256 tokens include kid: "botcha-signing-1" in header', async () => {
    const result = await generateToken(
      TEST_CHALLENGE_ID, TEST_SOLVE_TIME, TEST_SECRET,
      undefined, undefined, es256PrivateJwk,
    );

    const header = decodeProtectedHeader(result.access_token);
    expect(header.kid).toBe('botcha-signing-1');
  });

  test('ES256 tokens include iss: "botcha.ai" in payload', async () => {
    const result = await generateToken(
      TEST_CHALLENGE_ID, TEST_SOLVE_TIME, TEST_SECRET,
      undefined, undefined, es256PrivateJwk,
    );

    const payload = decodeJwt(result.access_token);
    expect(payload.iss).toBe('botcha.ai');
  });

  test('all existing claims still present in ES256 tokens', async () => {
    const kv = createMockKV();
    const result = await generateToken(
      TEST_CHALLENGE_ID, TEST_SOLVE_TIME, TEST_SECRET,
      { CHALLENGES: kv }, {
        aud: 'api.example.com',
        clientIp: '1.2.3.4',
        app_id: 'app_test',
      },
      es256PrivateJwk,
    );

    const payload = decodeJwt(result.access_token);
    expect(payload.type).toBe('botcha-verified');
    expect(payload.solveTime).toBe(TEST_SOLVE_TIME);
    expect(payload.jti).toBeDefined();
    expect(payload.sub).toBe(TEST_CHALLENGE_ID);
    expect(payload.aud).toBe('api.example.com');
    expect(payload.app_id).toBe('app_test');
    expect(payload.client_ip).toBe('1.2.3.4');
    expect(payload.iat).toBeDefined();
    expect(payload.exp).toBeDefined();
  });

  test('HS256 tokens do NOT include kid in header', async () => {
    const result = await generateToken(
      TEST_CHALLENGE_ID, TEST_SOLVE_TIME, TEST_SECRET,
    );

    const header = decodeProtectedHeader(result.access_token);
    expect(header.kid).toBeUndefined();
  });

  test('generateToken returns correct expiry metadata', async () => {
    const result = await generateToken(
      TEST_CHALLENGE_ID, TEST_SOLVE_TIME, TEST_SECRET,
      undefined, undefined, es256PrivateJwk,
    );

    expect(result.expires_in).toBe(3600);
    expect(result.refresh_expires_in).toBe(3600);
  });
});

// =====================================================================
// 2. ES256 Token Verification
// =====================================================================

describe('ES256 Token Verification', () => {
  test('verifyToken() successfully verifies ES256 tokens with public key', async () => {
    const result = await generateToken(
      TEST_CHALLENGE_ID, TEST_SOLVE_TIME, TEST_SECRET,
      undefined, undefined, es256PrivateJwk,
    );

    const verification = await verifyToken(
      result.access_token, TEST_SECRET,
      undefined, undefined, es256PublicJwk,
    );

    expect(verification.valid).toBe(true);
    expect(verification.payload).toBeDefined();
    expect(verification.payload!.sub).toBe(TEST_CHALLENGE_ID);
    expect(verification.payload!.type).toBe('botcha-verified');
    expect(verification.payload!.solveTime).toBe(TEST_SOLVE_TIME);
  });

  test('verifyToken() still verifies HS256 tokens with secret (backward compat)', async () => {
    const result = await generateToken(
      TEST_CHALLENGE_ID, TEST_SOLVE_TIME, TEST_SECRET,
    );

    const verification = await verifyToken(
      result.access_token, TEST_SECRET,
    );

    expect(verification.valid).toBe(true);
    expect(verification.payload).toBeDefined();
    expect(verification.payload!.sub).toBe(TEST_CHALLENGE_ID);
  });

  test('verifyToken() rejects expired ES256 tokens', async () => {
    // Create a token that already expired by manually signing with -1s expiry
    const { importJWK } = await import('jose');
    const key = await importJWK(es256PrivateJwk, 'ES256');

    const expiredToken = await new SignJWT({
      type: 'botcha-verified',
      solveTime: TEST_SOLVE_TIME,
      jti: crypto.randomUUID(),
    })
      .setProtectedHeader({ alg: 'ES256', kid: 'botcha-signing-1' })
      .setSubject(TEST_CHALLENGE_ID)
      .setIssuer('botcha.ai')
      .setIssuedAt(Math.floor(Date.now() / 1000) - 600) // issued 10 min ago
      .setExpirationTime(Math.floor(Date.now() / 1000) - 300) // expired 5 min ago
      .sign(key);

    const verification = await verifyToken(
      expiredToken, TEST_SECRET,
      undefined, undefined, es256PublicJwk,
    );

    expect(verification.valid).toBe(false);
    expect(verification.error).toBeDefined();
  });

  test('verifyToken() rejects ES256 tokens with wrong key', async () => {
    // Sign with the primary key, verify with the wrong public key
    const result = await generateToken(
      TEST_CHALLENGE_ID, TEST_SOLVE_TIME, TEST_SECRET,
      undefined, undefined, es256PrivateJwk,
    );

    const verification = await verifyToken(
      result.access_token, TEST_SECRET,
      undefined, undefined, wrongPublicJwk,
    );

    expect(verification.valid).toBe(false);
    expect(verification.error).toBeDefined();
  });

  test('verifyToken() checks revocation for ES256 tokens', async () => {
    const kv = createMockKV();
    const result = await generateToken(
      TEST_CHALLENGE_ID, TEST_SOLVE_TIME, TEST_SECRET,
      { CHALLENGES: kv }, undefined, es256PrivateJwk,
    );

    // Extract the JTI from the access token
    const payload = decodeJwt(result.access_token);
    const jti = payload.jti as string;

    // Mark it as revoked in KV
    kv._store.set(`revoked:${jti}`, JSON.stringify({ revokedAt: Date.now() }));

    const verification = await verifyToken(
      result.access_token, TEST_SECRET,
      { CHALLENGES: kv }, undefined, es256PublicJwk,
    );

    expect(verification.valid).toBe(false);
    expect(verification.error).toBe('Token has been revoked');
  });

  test('verifyToken() validates audience claims for ES256 tokens', async () => {
    const result = await generateToken(
      TEST_CHALLENGE_ID, TEST_SOLVE_TIME, TEST_SECRET,
      undefined, { aud: 'api.myapp.com' }, es256PrivateJwk,
    );

    // Correct audience
    const ok = await verifyToken(
      result.access_token, TEST_SECRET,
      undefined, { requiredAud: 'api.myapp.com' }, es256PublicJwk,
    );
    expect(ok.valid).toBe(true);

    // Wrong audience
    const bad = await verifyToken(
      result.access_token, TEST_SECRET,
      undefined, { requiredAud: 'api.other.com' }, es256PublicJwk,
    );
    expect(bad.valid).toBe(false);
    expect(bad.error).toBe('Invalid audience claim');
  });

  test('verifyToken() validates client IP for ES256 tokens', async () => {
    const result = await generateToken(
      TEST_CHALLENGE_ID, TEST_SOLVE_TIME, TEST_SECRET,
      undefined, { clientIp: '10.0.0.1' }, es256PrivateJwk,
    );

    // Correct IP
    const ok = await verifyToken(
      result.access_token, TEST_SECRET,
      undefined, { clientIp: '10.0.0.1' }, es256PublicJwk,
    );
    expect(ok.valid).toBe(true);

    // Wrong IP
    const bad = await verifyToken(
      result.access_token, TEST_SECRET,
      undefined, { clientIp: '192.168.1.1' }, es256PublicJwk,
    );
    expect(bad.valid).toBe(false);
    expect(bad.error).toBe('Client IP mismatch');
  });

  test('verifyToken() rejects refresh tokens (type check)', async () => {
    const result = await generateToken(
      TEST_CHALLENGE_ID, TEST_SOLVE_TIME, TEST_SECRET,
      undefined, undefined, es256PrivateJwk,
    );

    // Attempt to verify the refresh token as an access token
    const verification = await verifyToken(
      result.refresh_token, TEST_SECRET,
      undefined, undefined, es256PublicJwk,
    );

    expect(verification.valid).toBe(false);
    expect(verification.error).toBe('Invalid token type');
  });
});

// =====================================================================
// 3. Key Management
// =====================================================================

describe('Key Management — getSigningPublicKeyJWK()', () => {
  test('strips the d parameter from private key JWK', () => {
    const publicJwk = getSigningPublicKeyJWK(es256PrivateJwk);
    expect((publicJwk as any).d).toBeUndefined();
  });

  test('adds kid, use, alg to the public key JWK', () => {
    const publicJwk = getSigningPublicKeyJWK(es256PrivateJwk);
    expect(publicJwk.kid).toBe('botcha-signing-1');
    expect(publicJwk.use).toBe('sig');
    expect(publicJwk.alg).toBe('ES256');
  });

  test('public key JWK has correct format (kty: EC, crv: P-256, x, y)', () => {
    const publicJwk = getSigningPublicKeyJWK(es256PrivateJwk);
    expect(publicJwk.kty).toBe('EC');
    expect(publicJwk.crv).toBe('P-256');
    expect(publicJwk.x).toBeDefined();
    expect(typeof publicJwk.x).toBe('string');
    expect(publicJwk.y).toBeDefined();
    expect(typeof publicJwk.y).toBe('string');
  });

  test('uses kid from private key if present', () => {
    const withKid = { ...es256PrivateJwk, kid: 'custom-kid-99' };
    const publicJwk = getSigningPublicKeyJWK(withKid);
    expect(publicJwk.kid).toBe('custom-kid-99');
  });

  test('defaults kid to botcha-signing-1 when not set', () => {
    const { kid: _kid, ...noKid } = es256PrivateJwk;
    const publicJwk = getSigningPublicKeyJWK(noKid as ES256SigningKeyJWK);
    expect(publicJwk.kid).toBe('botcha-signing-1');
  });

  test('preserves x and y values from the private key', () => {
    const publicJwk = getSigningPublicKeyJWK(es256PrivateJwk);
    expect(publicJwk.x).toBe(es256PrivateJwk.x);
    expect(publicJwk.y).toBe(es256PrivateJwk.y);
  });
});

// =====================================================================
// 4. Token Refresh with ES256
// =====================================================================

describe('Token Refresh with ES256', () => {
  test('refreshAccessToken() verifies ES256 refresh token and issues ES256 access token', async () => {
    const kv = createMockKV();
    const result = await generateToken(
      TEST_CHALLENGE_ID, TEST_SOLVE_TIME, TEST_SECRET,
      { CHALLENGES: kv }, undefined, es256PrivateJwk,
    );

    const publicJwk = getSigningPublicKeyJWK(es256PrivateJwk);
    const refreshResult = await refreshAccessToken(
      result.refresh_token,
      { CHALLENGES: kv },
      TEST_SECRET,
      undefined,
      es256PrivateJwk,
      publicJwk,
    );

    expect(refreshResult.success).toBe(true);
    expect(refreshResult.tokens).toBeDefined();
    expect(refreshResult.tokens!.access_token).toBeDefined();
    expect(refreshResult.tokens!.expires_in).toBe(3600);

    // Verify the new access token is ES256
    const header = decodeProtectedHeader(refreshResult.tokens!.access_token);
    expect(header.alg).toBe('ES256');
    expect(header.kid).toBe('botcha-signing-1');

    // Verify the new access token is valid
    const verification = await verifyToken(
      refreshResult.tokens!.access_token, TEST_SECRET,
      undefined, undefined, es256PublicJwk,
    );
    expect(verification.valid).toBe(true);
    expect(verification.payload!.type).toBe('botcha-verified');
  });

  test('refreshAccessToken() still works with HS256 (backward compat)', async () => {
    const kv = createMockKV();
    const result = await generateToken(
      TEST_CHALLENGE_ID, TEST_SOLVE_TIME, TEST_SECRET,
      { CHALLENGES: kv },
    );

    const refreshResult = await refreshAccessToken(
      result.refresh_token,
      { CHALLENGES: kv },
      TEST_SECRET,
    );

    expect(refreshResult.success).toBe(true);
    expect(refreshResult.tokens).toBeDefined();

    const header = decodeProtectedHeader(refreshResult.tokens!.access_token);
    expect(header.alg).toBe('HS256');

    // Verify the refreshed HS256 token
    const verification = await verifyToken(
      refreshResult.tokens!.access_token, TEST_SECRET,
    );
    expect(verification.valid).toBe(true);
  });

  test('refreshAccessToken() rejects non-refresh tokens', async () => {
    const kv = createMockKV();
    const result = await generateToken(
      TEST_CHALLENGE_ID, TEST_SOLVE_TIME, TEST_SECRET,
      { CHALLENGES: kv }, undefined, es256PrivateJwk,
    );

    const publicJwk = getSigningPublicKeyJWK(es256PrivateJwk);
    const refreshResult = await refreshAccessToken(
      result.access_token, // access token, not refresh
      { CHALLENGES: kv },
      TEST_SECRET,
      undefined,
      es256PrivateJwk,
      publicJwk,
    );

    expect(refreshResult.success).toBe(false);
    expect(refreshResult.error).toContain('Invalid token type');
  });

  test('refreshAccessToken() rejects revoked ES256 refresh tokens', async () => {
    const kv = createMockKV();
    const result = await generateToken(
      TEST_CHALLENGE_ID, TEST_SOLVE_TIME, TEST_SECRET,
      { CHALLENGES: kv }, undefined, es256PrivateJwk,
    );

    // Revoke the refresh token
    const refreshPayload = decodeJwt(result.refresh_token);
    const jti = refreshPayload.jti as string;
    kv._store.set(`revoked:${jti}`, JSON.stringify({ revokedAt: Date.now() }));

    const publicJwk = getSigningPublicKeyJWK(es256PrivateJwk);
    const refreshResult = await refreshAccessToken(
      result.refresh_token,
      { CHALLENGES: kv },
      TEST_SECRET,
      undefined,
      es256PrivateJwk,
      publicJwk,
    );

    expect(refreshResult.success).toBe(false);
    expect(refreshResult.error).toBe('Refresh token has been revoked');
  });

  test('refreshAccessToken() carries over claims from KV', async () => {
    const kv = createMockKV();
    const result = await generateToken(
      TEST_CHALLENGE_ID, TEST_SOLVE_TIME, TEST_SECRET,
      { CHALLENGES: kv }, {
        aud: 'api.example.com',
        clientIp: '1.2.3.4',
        app_id: 'app_42',
      },
      es256PrivateJwk,
    );

    const publicJwk = getSigningPublicKeyJWK(es256PrivateJwk);
    const refreshResult = await refreshAccessToken(
      result.refresh_token,
      { CHALLENGES: kv },
      TEST_SECRET,
      undefined, // no explicit options — should come from KV
      es256PrivateJwk,
      publicJwk,
    );

    expect(refreshResult.success).toBe(true);
    const newPayload = decodeJwt(refreshResult.tokens!.access_token);
    expect(newPayload.aud).toBe('api.example.com');
    expect(newPayload.client_ip).toBe('1.2.3.4');
    expect(newPayload.app_id).toBe('app_42');
  });
});

// =====================================================================
// 5. Remote Validation Simulation (verifyToken as /v1/token/validate)
// =====================================================================

describe('Remote Validation (simulating POST /v1/token/validate)', () => {
  test('valid HS256 token returns valid=true with payload', async () => {
    const result = await generateToken(
      TEST_CHALLENGE_ID, TEST_SOLVE_TIME, TEST_SECRET,
    );

    const verification = await verifyToken(
      result.access_token, TEST_SECRET,
    );

    expect(verification.valid).toBe(true);
    expect(verification.payload).toBeDefined();
    expect(verification.payload!.sub).toBe(TEST_CHALLENGE_ID);
    expect(verification.payload!.solveTime).toBe(TEST_SOLVE_TIME);
    expect(verification.payload!.type).toBe('botcha-verified');
  });

  test('valid ES256 token returns valid=true with payload', async () => {
    const result = await generateToken(
      TEST_CHALLENGE_ID, TEST_SOLVE_TIME, TEST_SECRET,
      undefined, { app_id: 'app_99' }, es256PrivateJwk,
    );

    const verification = await verifyToken(
      result.access_token, TEST_SECRET,
      undefined, undefined, es256PublicJwk,
    );

    expect(verification.valid).toBe(true);
    expect(verification.payload).toBeDefined();
    expect(verification.payload!.sub).toBe(TEST_CHALLENGE_ID);
    expect(verification.payload!.app_id).toBe('app_99');
  });

  test('expired token returns valid=false', async () => {
    const { importJWK } = await import('jose');
    const key = await importJWK(es256PrivateJwk, 'ES256');

    const expiredToken = await new SignJWT({
      type: 'botcha-verified',
      solveTime: TEST_SOLVE_TIME,
      jti: crypto.randomUUID(),
    })
      .setProtectedHeader({ alg: 'ES256', kid: 'botcha-signing-1' })
      .setSubject(TEST_CHALLENGE_ID)
      .setIssuer('botcha.ai')
      .setIssuedAt(Math.floor(Date.now() / 1000) - 600)
      .setExpirationTime(Math.floor(Date.now() / 1000) - 300)
      .sign(key);

    const verification = await verifyToken(
      expiredToken, TEST_SECRET,
      undefined, undefined, es256PublicJwk,
    );

    expect(verification.valid).toBe(false);
    expect(verification.error).toBeDefined();
  });

  test('wrong signature returns valid=false', async () => {
    // Sign with primary key, verify with wrong key
    const result = await generateToken(
      TEST_CHALLENGE_ID, TEST_SOLVE_TIME, TEST_SECRET,
      undefined, undefined, es256PrivateJwk,
    );

    const verification = await verifyToken(
      result.access_token, TEST_SECRET,
      undefined, undefined, wrongPublicJwk,
    );

    expect(verification.valid).toBe(false);
    expect(verification.error).toBeDefined();
  });

  test('revoked token (mock KV) returns valid=false', async () => {
    const kv = createMockKV();
    const result = await generateToken(
      TEST_CHALLENGE_ID, TEST_SOLVE_TIME, TEST_SECRET,
      { CHALLENGES: kv }, undefined, es256PrivateJwk,
    );

    // Revoke it
    const payload = decodeJwt(result.access_token);
    kv._store.set(`revoked:${payload.jti}`, JSON.stringify({ revokedAt: Date.now() }));

    const verification = await verifyToken(
      result.access_token, TEST_SECRET,
      { CHALLENGES: kv }, undefined, es256PublicJwk,
    );

    expect(verification.valid).toBe(false);
    expect(verification.error).toBe('Token has been revoked');
  });

  test('refresh token type returns valid=false (rejects non-access tokens)', async () => {
    const result = await generateToken(
      TEST_CHALLENGE_ID, TEST_SOLVE_TIME, TEST_SECRET,
      undefined, undefined, es256PrivateJwk,
    );

    const verification = await verifyToken(
      result.refresh_token, TEST_SECRET,
      undefined, undefined, es256PublicJwk,
    );

    expect(verification.valid).toBe(false);
    expect(verification.error).toBe('Invalid token type');
  });

  test('completely garbled token returns valid=false', async () => {
    const verification = await verifyToken(
      'not.a.valid.jwt.at.all', TEST_SECRET,
      undefined, undefined, es256PublicJwk,
    );

    expect(verification.valid).toBe(false);
    expect(verification.error).toBeDefined();
  });

  test('HS256 token verified without publicKey still works', async () => {
    const result = await generateToken(
      TEST_CHALLENGE_ID, TEST_SOLVE_TIME, TEST_SECRET,
    );

    // No publicKey argument — should fall back to HS256 verification
    const verification = await verifyToken(
      result.access_token, TEST_SECRET,
    );

    expect(verification.valid).toBe(true);
    expect(verification.payload!.type).toBe('botcha-verified');
  });
});
