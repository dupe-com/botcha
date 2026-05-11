/**
 * Regression tests for POST /v1/token/validate accepting all BOTCHA token types.
 *
 * Bug: The public /v1/token/validate endpoint called verifyToken with undefined options,
 * defaulting allowedTypes to ['botcha-verified']. This caused all non-challenge tokens
 * (agent-identity, attestation, ans-badge, vc) to fail with "Invalid token type".
 *
 * Fix: Pass { allowedTypes: [...ALL_BOTCHA_ACCESS_TOKEN_TYPES] } so any valid
 * BOTCHA access token can be validated via the public endpoint.
 *
 * Intentional exclusion: botcha-refresh tokens are bearer credentials and must
 * NOT be validated by third parties (they authenticate the agent, not the action).
 */

import { describe, test, expect } from 'vitest';
import { SignJWT } from 'jose';
import {
  verifyToken,
  ALL_BOTCHA_ACCESS_TOKEN_TYPES,
} from '../../../packages/cloudflare-workers/src/auth.js';

const TEST_SECRET = 'test-secret-for-token-validate-tests-32bytes!!';

/** Sign a minimal HS256 JWT with the given type. */
async function signToken(type: string, extra?: Record<string, unknown>): Promise<string> {
  return new SignJWT({
    type,
    jti: crypto.randomUUID(),
    sub: 'test-subject',
    ...extra,
  })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime('1h')
    .sign(new TextEncoder().encode(TEST_SECRET));
}

// ─── ALL_BOTCHA_ACCESS_TOKEN_TYPES constant ───────────────────────────────────

describe('ALL_BOTCHA_ACCESS_TOKEN_TYPES', () => {
  test('includes botcha-verified', () => {
    expect(ALL_BOTCHA_ACCESS_TOKEN_TYPES).toContain('botcha-verified');
  });

  test('includes botcha-agent-identity', () => {
    expect(ALL_BOTCHA_ACCESS_TOKEN_TYPES).toContain('botcha-agent-identity');
  });

  test('includes botcha-attestation', () => {
    expect(ALL_BOTCHA_ACCESS_TOKEN_TYPES).toContain('botcha-attestation');
  });

  test('includes botcha-ans-badge', () => {
    expect(ALL_BOTCHA_ACCESS_TOKEN_TYPES).toContain('botcha-ans-badge');
  });

  test('includes botcha-vc', () => {
    expect(ALL_BOTCHA_ACCESS_TOKEN_TYPES).toContain('botcha-vc');
  });

  test('does NOT include botcha-refresh (refresh tokens are bearer credentials)', () => {
    expect(ALL_BOTCHA_ACCESS_TOKEN_TYPES).not.toContain('botcha-refresh');
  });
});

// ─── verifyToken with all allowed types (simulating /v1/token/validate fix) ──

describe('verifyToken with ALL_BOTCHA_ACCESS_TOKEN_TYPES (POST /v1/token/validate behavior)', () => {
  const opts = { allowedTypes: [...ALL_BOTCHA_ACCESS_TOKEN_TYPES] };

  test('accepts botcha-verified token', async () => {
    const token = await signToken('botcha-verified', { solveTime: 42 });
    const result = await verifyToken(token, TEST_SECRET, undefined, opts);
    expect(result.valid).toBe(true);
    expect(result.payload?.type).toBe('botcha-verified');
  });

  test('accepts botcha-agent-identity token', async () => {
    const token = await signToken('botcha-agent-identity', {
      agent_id: 'agent_abc123',
      app_id: 'app_xyz',
    });
    const result = await verifyToken(token, TEST_SECRET, undefined, opts);
    expect(result.valid).toBe(true);
    expect(result.payload?.type).toBe('botcha-agent-identity');
  });

  test('accepts botcha-attestation token', async () => {
    const token = await signToken('botcha-attestation', {
      can: ['browse:*'],
      cannot: [],
    });
    const result = await verifyToken(token, TEST_SECRET, undefined, opts);
    expect(result.valid).toBe(true);
    expect(result.payload?.type).toBe('botcha-attestation');
  });

  test('accepts botcha-ans-badge token', async () => {
    const token = await signToken('botcha-ans-badge', { name: 'my-agent.botcha' });
    const result = await verifyToken(token, TEST_SECRET, undefined, opts);
    expect(result.valid).toBe(true);
    expect(result.payload?.type).toBe('botcha-ans-badge');
  });

  test('accepts botcha-vc token', async () => {
    const token = await signToken('botcha-vc', { vc: { type: ['VerifiableCredential'] } });
    const result = await verifyToken(token, TEST_SECRET, undefined, opts);
    expect(result.valid).toBe(true);
    expect(result.payload?.type).toBe('botcha-vc');
  });

  test('rejects botcha-refresh token (intentionally excluded)', async () => {
    const token = await signToken('botcha-refresh', { solveTime: 42 });
    const result = await verifyToken(token, TEST_SECRET, undefined, opts);
    expect(result.valid).toBe(false);
    expect(result.error).toBe('Invalid token type');
  });

  test('rejects unknown token type', async () => {
    const token = await signToken('botcha-unknown-type');
    const result = await verifyToken(token, TEST_SECRET, undefined, opts);
    expect(result.valid).toBe(false);
    expect(result.error).toBe('Invalid token type');
  });
});

// ─── Regression: old behavior caused failures ─────────────────────────────────

describe('Regression: old default allowedTypes = ["botcha-verified"] caused failures', () => {
  test('OLD behavior: agent-identity token fails with default allowedTypes', async () => {
    const token = await signToken('botcha-agent-identity', { agent_id: 'agent_abc' });
    // Simulate old behavior: no allowedTypes option passed
    const result = await verifyToken(token, TEST_SECRET);
    expect(result.valid).toBe(false);
    expect(result.error).toBe('Invalid token type');
  });

  test('OLD behavior: attestation token fails with default allowedTypes', async () => {
    const token = await signToken('botcha-attestation', { can: ['browse:*'] });
    const result = await verifyToken(token, TEST_SECRET);
    expect(result.valid).toBe(false);
    expect(result.error).toBe('Invalid token type');
  });

  test('NEW behavior: agent-identity token passes with ALL_BOTCHA_ACCESS_TOKEN_TYPES', async () => {
    const token = await signToken('botcha-agent-identity', { agent_id: 'agent_abc' });
    const result = await verifyToken(token, TEST_SECRET, undefined, {
      allowedTypes: [...ALL_BOTCHA_ACCESS_TOKEN_TYPES],
    });
    expect(result.valid).toBe(true);
  });

  test('NEW behavior: attestation token passes with ALL_BOTCHA_ACCESS_TOKEN_TYPES', async () => {
    const token = await signToken('botcha-attestation', { can: ['browse:*'] });
    const result = await verifyToken(token, TEST_SECRET, undefined, {
      allowedTypes: [...ALL_BOTCHA_ACCESS_TOKEN_TYPES],
    });
    expect(result.valid).toBe(true);
  });
});
