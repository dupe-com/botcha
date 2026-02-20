import { beforeAll, describe, expect, test } from 'vitest';
import { Hono } from 'hono';
import { generateToken, type ES256SigningKeyJWK } from '../../../packages/cloudflare-workers/src/auth.js';
import {
  buildOAuthASMetadata,
  buildOIDCAgentClaims,
  getGrantStatus,
  issueAgentGrant,
  issueEAT,
  resolveGrant,
  verifyEAT,
} from '../../../packages/cloudflare-workers/src/tap-oidca.js';
import {
  agentGrantResolveRoute,
  agentGrantStatusRoute,
} from '../../../packages/cloudflare-workers/src/tap-oidca-routes.js';

const TEST_SECRET = 'test-jwt-secret-for-oidca-tests-minimum-32chars!!';

class MockKV {
  private store = new Map<string, string>();

  async get(key: string): Promise<string | null> {
    return this.store.get(key) ?? null;
  }

  async put(key: string, value: string): Promise<void> {
    this.store.set(key, value);
  }

  async delete(key: string): Promise<void> {
    this.store.delete(key);
  }

  keys(prefix: string): string[] {
    return [...this.store.keys()].filter(k => k.startsWith(prefix));
  }
}

let signingKey: ES256SigningKeyJWK;
let publicJwk: Record<string, unknown>;

const BOTCHA_PAYLOAD = {
  sub: 'challenge_test_123',
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + 3600,
  jti: 'jti_test_123',
  type: 'botcha-verified' as const,
  solveTime: 138,
  app_id: 'app_test_001',
};

beforeAll(async () => {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  );
  const privateJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
  const pubJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);

  signingKey = {
    kty: privateJwk.kty!,
    crv: privateJwk.crv!,
    x: privateJwk.x!,
    y: privateJwk.y!,
    d: privateJwk.d!,
    kid: 'test-oidca-signing-key',
  };

  publicJwk = {
    kty: pubJwk.kty,
    crv: pubJwk.crv,
    x: pubJwk.x,
    y: pubJwk.y,
    kid: 'test-oidca-signing-key',
  };
});

async function makeAccessToken(appId: string): Promise<string> {
  const tokenResult = await generateToken(
    'challenge_runtime_123',
    120,
    TEST_SECRET,
    undefined,
    { app_id: appId },
    signingKey,
  );
  return tokenResult.access_token;
}

describe('tap-oidca core', () => {
  test('buildOAuthASMetadata publishes well-known JWKS URI', () => {
    const metadata = buildOAuthASMetadata('https://botcha.ai') as { jwks_uri: string };
    expect(metadata.jwks_uri).toBe('https://botcha.ai/.well-known/jwks');
  });

  test('issueEAT + verifyEAT roundtrip', async () => {
    const eat = await issueEAT(BOTCHA_PAYLOAD, signingKey, { ttlSeconds: 300 });
    const decoded = await verifyEAT(eat, publicJwk);
    expect(decoded).not.toBeNull();
    expect(decoded!.botcha_verified).toBe(true);
    expect(decoded!.botcha_app_id).toBe(BOTCHA_PAYLOAD.app_id);
    expect(decoded!.eat_profile).toContain('botcha.ai/eat-profile');
  });

  test('issueAgentGrant stores pending grants when oversight required', async () => {
    const kv = new MockKV();
    const eat = await issueEAT(BOTCHA_PAYLOAD, signingKey);
    const { claims } = await buildOIDCAgentClaims(BOTCHA_PAYLOAD, eat, signingKey);

    const grant = await issueAgentGrant(
      BOTCHA_PAYLOAD,
      eat,
      claims,
      signingKey,
      kv,
      'https://botcha.ai',
      { humanOversightRequired: true },
    );

    expect(grant.human_oversight_required).toBe(true);
    expect(grant.oversight_status).toBe('pending');
    expect(grant.oversight_polling_url).toContain('/v1/auth/agent-grant/');

    const key = kv.keys('agent_grant:')[0];
    expect(key).toBeTruthy();
    const grantId = key.replace('agent_grant:', '');
    const pending = await getGrantStatus(grantId, kv);
    expect(pending?.status).toBe('pending');

    const approved = await resolveGrant(grantId, 'approved', undefined, kv);
    expect(approved.success).toBe(true);
    expect(approved.grant?.status).toBe('approved');

    const secondResolve = await resolveGrant(grantId, 'denied', 'late deny', kv);
    expect(secondResolve.success).toBe(false);
  });
});

describe('tap-oidca routes', () => {
  test('agentGrantStatusRoute requires bearer auth', async () => {
    const kv = new MockKV();
    const app = new Hono();
    app.get('/v1/auth/agent-grant/:id/status', agentGrantStatusRoute);

    const res = await app.fetch(
      new Request('https://botcha.ai/v1/auth/agent-grant/grant_1/status'),
      {
        JWT_SECRET: TEST_SECRET,
        JWT_SIGNING_KEY: JSON.stringify(signingKey),
        SESSIONS: kv,
        CHALLENGES: kv,
      },
    );

    expect(res.status).toBe(401);
  });

  test('agentGrantStatusRoute blocks cross-app grant access', async () => {
    const kv = new MockKV();
    await kv.put(
      'agent_grant:grant_cross',
      JSON.stringify({
        grant_id: 'grant_cross',
        agent_id: 'app_owner:challenge_1',
        app_id: 'app_owner',
        scope: 'agent:read',
        requested_at: Date.now(),
        status: 'pending',
      }),
    );

    const token = await makeAccessToken('app_other');
    const app = new Hono();
    app.get('/v1/auth/agent-grant/:id/status', agentGrantStatusRoute);

    const res = await app.fetch(
      new Request('https://botcha.ai/v1/auth/agent-grant/grant_cross/status', {
        headers: { authorization: `Bearer ${token}` },
      }),
      {
        JWT_SECRET: TEST_SECRET,
        JWT_SIGNING_KEY: JSON.stringify(signingKey),
        SESSIONS: kv,
        CHALLENGES: kv,
      },
    );

    expect(res.status).toBe(403);
  });

  test('agentGrantResolveRoute requires bearer auth', async () => {
    const kv = new MockKV();
    const app = new Hono();
    app.post('/v1/auth/agent-grant/:id/resolve', agentGrantResolveRoute);

    const res = await app.fetch(
      new Request('https://botcha.ai/v1/auth/agent-grant/grant_1/resolve', {
        method: 'POST',
        body: JSON.stringify({ decision: 'approved' }),
      }),
      {
        JWT_SECRET: TEST_SECRET,
        JWT_SIGNING_KEY: JSON.stringify(signingKey),
        SESSIONS: kv,
        CHALLENGES: kv,
      },
    );

    expect(res.status).toBe(401);
  });
});
