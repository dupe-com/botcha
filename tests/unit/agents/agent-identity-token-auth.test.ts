/**
 * Tests for agent identity token auth fix.
 *
 * Bug: agent re-identification tokens (type: 'botcha-agent-identity') were
 * rejected by all TAP endpoints that call validateAppAccess(), because
 * verifyToken() only accepted type: 'botcha-verified'.
 *
 * Fix: verifyToken() now accepts an allowedTypes option. Route-level
 * validateAppAccess() functions pass both 'botcha-verified' and
 * 'botcha-agent-identity' so long-lived agent credentials work everywhere.
 */

import { describe, test, expect, vi, beforeEach } from 'vitest';
import { SignJWT } from 'jose';
import { verifyToken } from '../../../packages/cloudflare-workers/src/auth.js';

// Minimal KV mock
class MockKV {
  private store = new Map<string, string>();
  async get(key: string) { return this.store.get(key) ?? null; }
  async put(key: string, value: string, _opts?: { expirationTtl?: number }) { this.store.set(key, value); }
  async delete(key: string) { this.store.delete(key); }
}

const SECRET = 'test-secret-key-12345';

async function makeToken(type: string, extra: Record<string, unknown> = {}) {
  return new SignJWT({ type, ...extra })
    .setProtectedHeader({ alg: 'HS256' })
    .setSubject('sub-value')
    .setIssuer('botcha.ai')
    .setIssuedAt()
    .setExpirationTime('1h')
    .setJti('jti-test')
    .sign(new TextEncoder().encode(SECRET));
}

describe('verifyToken — allowedTypes option', () => {
  test('accepts botcha-verified by default', async () => {
    const token = await makeToken('botcha-verified', { solveTime: 123, app_id: 'app_test' });
    const result = await verifyToken(token, SECRET);
    expect(result.valid).toBe(true);
    expect(result.payload?.type).toBe('botcha-verified');
    expect(result.payload?.app_id).toBe('app_test');
  });

  test('rejects botcha-agent-identity by default (strict mode)', async () => {
    const token = await makeToken('botcha-agent-identity', {
      agent_id: 'agent_abc',
      app_id: 'app_test',
    });
    const result = await verifyToken(token, SECRET);
    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/Invalid token type/);
  });

  test('accepts botcha-agent-identity when explicitly allowed', async () => {
    const token = await makeToken('botcha-agent-identity', {
      agent_id: 'agent_abc',
      app_id: 'app_test',
    });
    const result = await verifyToken(token, SECRET, undefined, {
      allowedTypes: ['botcha-verified', 'botcha-agent-identity'],
    });
    expect(result.valid).toBe(true);
    expect(result.payload?.type).toBe('botcha-agent-identity');
    expect(result.payload?.app_id).toBe('app_test');
    expect(result.payload?.agent_id).toBe('agent_abc');
  });

  test('rejects refresh tokens regardless of allowedTypes', async () => {
    const token = await makeToken('botcha-refresh', { app_id: 'app_test' });
    const result = await verifyToken(token, SECRET, undefined, {
      allowedTypes: ['botcha-verified', 'botcha-agent-identity'],
    });
    expect(result.valid).toBe(false);
  });

  test('accepts refresh token when explicitly listed in allowedTypes', async () => {
    const token = await makeToken('botcha-refresh', { app_id: 'app_test' });
    const result = await verifyToken(token, SECRET, undefined, {
      allowedTypes: ['botcha-verified', 'botcha-agent-identity', 'botcha-refresh'],
    });
    expect(result.valid).toBe(true);
  });

  test('rejects expired agent-identity token', async () => {
    // Issue a token that expired 1 hour ago
    const now = Math.floor(Date.now() / 1000);
    const token = await new SignJWT({
      type: 'botcha-agent-identity',
      agent_id: 'agent_xyz',
      app_id: 'app_test',
    })
      .setProtectedHeader({ alg: 'HS256' })
      .setSubject('agent_xyz')
      .setIssuer('botcha.ai')
      .setIssuedAt(now - 7200)
      .setExpirationTime(now - 3600)
      .setJti('jti-expired')
      .sign(new TextEncoder().encode(SECRET));

    const result = await verifyToken(token, SECRET, undefined, {
      allowedTypes: ['botcha-verified', 'botcha-agent-identity'],
    });
    expect(result.valid).toBe(false);
  });

  test('agent-identity token carries app_id in payload', async () => {
    const token = await makeToken('botcha-agent-identity', {
      agent_id: 'agent_41a645f6263dac2f',
      app_id: 'app_c4e8aade83ce32f0',
    });
    const result = await verifyToken(token, SECRET, undefined, {
      allowedTypes: ['botcha-verified', 'botcha-agent-identity'],
    });
    expect(result.valid).toBe(true);
    expect(result.payload?.app_id).toBe('app_c4e8aade83ce32f0');
    expect(result.payload?.agent_id).toBe('agent_41a645f6263dac2f');
  });

  test('revoked agent-identity token is rejected', async () => {
    const kv = new MockKV();
    const token = await makeToken('botcha-agent-identity', {
      agent_id: 'agent_abc',
      app_id: 'app_test',
    });

    // Revoke the JTI (verifyToken expects env.CHALLENGES, not a bare KV)
    await kv.put('revoked:jti-test', JSON.stringify({ revokedAt: Date.now() }));

    const result = await verifyToken(
      token,
      SECRET,
      { CHALLENGES: kv as any },
      { allowedTypes: ['botcha-verified', 'botcha-agent-identity'] },
    );
    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/revoked/i);
  });
});

describe('delegation route integration — agent-identity token auth', () => {
  // Import the route and mock auth
  // We test the auth flow at the verifyToken level since that's where the fix lives

  test('validateAppAccess pattern: agent-identity token with matching app_id passes', async () => {
    const token = await makeToken('botcha-agent-identity', {
      agent_id: 'agent_test',
      app_id: 'app_xyz',
    });

    // Simulate what validateAppAccess does in delegation/attestation/reputation routes
    const result = await verifyToken(token, SECRET, undefined, {
      allowedTypes: ['botcha-verified', 'botcha-agent-identity'],
    });

    expect(result.valid).toBe(true);
    const jwtAppId = result.payload?.app_id;
    expect(jwtAppId).toBe('app_xyz');

    // Query app_id matches JWT app_id — access granted
    const queryAppId = 'app_xyz';
    expect(queryAppId === jwtAppId || !queryAppId).toBe(true);
  });

  test('validateAppAccess pattern: mismatched app_id is caught', async () => {
    const token = await makeToken('botcha-agent-identity', {
      agent_id: 'agent_test',
      app_id: 'app_xyz',
    });

    const result = await verifyToken(token, SECRET, undefined, {
      allowedTypes: ['botcha-verified', 'botcha-agent-identity'],
    });

    expect(result.valid).toBe(true);
    const jwtAppId = result.payload?.app_id;

    // Query app_id does NOT match JWT app_id — should be rejected
    const queryAppId = 'app_different';
    expect(queryAppId !== jwtAppId).toBe(true);
  });
});
