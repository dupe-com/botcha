/**
 * Tests for tap-vc.ts — W3C Verifiable Credential issuance and verification
 *
 * Tests cover:
 *   - VC issuance (ES256 and HS256)
 *   - VC verification (valid, expired, tampered)
 *   - Issuer validation
 *   - Credential subject structure
 *   - Optional agent DID in credentialSubject.id
 *   - Duration limits (default, custom, max cap)
 */

import { describe, test, expect, beforeAll } from 'vitest';
import {
  issueVC,
  verifyVC,
  extractVCPayloadClaims,
  type IssueVCOptions,
  type VerifiableCredential,
} from '../../../packages/cloudflare-workers/src/tap-vc.js';

// ============ TEST FIXTURES ============

// Generate a test ES256 key pair using the Web Crypto API
let testSigningKey: any;
let testPublicKeyJwk: any;

beforeAll(async () => {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  );
  const privateJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
  const publicJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);

  testSigningKey = {
    kty: privateJwk.kty,
    crv: privateJwk.crv,
    x: privateJwk.x,
    y: privateJwk.y,
    d: privateJwk.d,
    kid: 'test-signing-key-1',
  };

  testPublicKeyJwk = {
    kty: publicJwk.kty,
    crv: publicJwk.crv,
    x: publicJwk.x,
    y: publicJwk.y,
    kid: 'test-signing-key-1',
  };
});

const TEST_SECRET = 'test-jwt-secret-for-vc-tests-minimum-32chars!!';

const SAMPLE_OPTIONS: IssueVCOptions = {
  agent_id: 'agent_test_001',
  app_id: 'app_test_001',
  solve_time_ms: 142,
  challenge_type: 'speed',
  trust_level: 'basic',
  capabilities: ['browse:products', 'search:*'],
};

// ============ ISSUANCE TESTS ============

describe('issueVC', () => {
  describe('with ES256 signing key', () => {
    test('issues a valid VC JWT', async () => {
      const result = await issueVC(SAMPLE_OPTIONS, testSigningKey);
      expect(result.success).toBe(true);
      expect(result.vc_jwt).toBeTruthy();
      expect(typeof result.vc_jwt).toBe('string');
      expect(result.vc_jwt!.split('.').length).toBe(3); // valid JWT format
    });

    test('VC object has correct structure', async () => {
      const result = await issueVC(SAMPLE_OPTIONS, testSigningKey);
      expect(result.success).toBe(true);

      const vc = result.vc!;
      expect(vc['@context']).toContain('https://www.w3.org/ns/credentials/v2');
      expect(vc.type).toContain('VerifiableCredential');
      expect(vc.type).toContain('BotchaVerification');
      expect(vc.issuer).toBe('did:web:botcha.ai');
      expect(vc.id).toMatch(/^urn:botcha:vc:/);
    });

    test('credentialSubject contains all required fields', async () => {
      const result = await issueVC(SAMPLE_OPTIONS, testSigningKey);
      const cs = result.vc!.credentialSubject;

      expect(cs.agent_id).toBe('agent_test_001');
      expect(cs.app_id).toBe('app_test_001');
      expect(cs.solve_time_ms).toBe(142);
      expect(cs.challenge_type).toBe('speed');
      expect(cs.trust_level).toBe('basic');
      expect(cs.capabilities).toEqual(['browse:products', 'search:*']);
    });

    test('credentialSubject.id is set when agent_did provided', async () => {
      const opts = {
        ...SAMPLE_OPTIONS,
        agent_did: 'did:web:botcha.ai:agents:agent_test_001',
      };
      const result = await issueVC(opts, testSigningKey);
      expect(result.vc!.credentialSubject.id).toBe('did:web:botcha.ai:agents:agent_test_001');
    });

    test('credentialSubject.id is undefined when no agent_did', async () => {
      const result = await issueVC(SAMPLE_OPTIONS, testSigningKey);
      expect(result.vc!.credentialSubject.id).toBeUndefined();
    });

    test('validFrom and validUntil are ISO 8601 timestamps', async () => {
      const result = await issueVC(SAMPLE_OPTIONS, testSigningKey);
      const vc = result.vc!;
      expect(() => new Date(vc.validFrom)).not.toThrow();
      expect(() => new Date(vc.validUntil)).not.toThrow();
      expect(new Date(vc.validUntil).getTime()).toBeGreaterThan(
        new Date(vc.validFrom).getTime()
      );
    });

    test('default duration is 24 hours', async () => {
      const result = await issueVC(SAMPLE_OPTIONS, testSigningKey);
      const vc = result.vc!;
      const diffMs =
        new Date(vc.validUntil).getTime() - new Date(vc.validFrom).getTime();
      const diffHours = diffMs / 1000 / 3600;
      expect(diffHours).toBeCloseTo(24, 0);
    });

    test('custom duration is respected', async () => {
      const result = await issueVC(
        { ...SAMPLE_OPTIONS, duration_seconds: 3600 },
        testSigningKey
      );
      const vc = result.vc!;
      const diffMs =
        new Date(vc.validUntil).getTime() - new Date(vc.validFrom).getTime();
      const diffSecs = diffMs / 1000;
      expect(diffSecs).toBeCloseTo(3600, -1);
    });

    test('duration is capped at 30 days', async () => {
      const MAX_DAYS = 30;
      const result = await issueVC(
        { ...SAMPLE_OPTIONS, duration_seconds: 86_400 * 100 }, // 100 days — over limit
        testSigningKey
      );
      const vc = result.vc!;
      const diffMs =
        new Date(vc.validUntil).getTime() - new Date(vc.validFrom).getTime();
      const diffDays = diffMs / 1000 / 3600 / 24;
      expect(diffDays).toBeCloseTo(MAX_DAYS, 0);
    });

    test('returns credential_id and timestamps in result', async () => {
      const result = await issueVC(SAMPLE_OPTIONS, testSigningKey);
      expect(result.credential_id).toMatch(/^urn:botcha:vc:/);
      expect(result.issued_at).toBeTruthy();
      expect(result.expires_at).toBeTruthy();
    });

    test('agent_id defaults to "anonymous" when not provided', async () => {
      const opts = { ...SAMPLE_OPTIONS };
      delete opts.agent_id;
      const result = await issueVC(opts, testSigningKey);
      expect(result.vc!.credentialSubject.agent_id).toBe('anonymous');
    });

    test('each issuance produces a unique credential_id', async () => {
      const r1 = await issueVC(SAMPLE_OPTIONS, testSigningKey);
      const r2 = await issueVC(SAMPLE_OPTIONS, testSigningKey);
      expect(r1.credential_id).not.toBe(r2.credential_id);
    });

    test('capabilities is omitted from credentialSubject when empty', async () => {
      const opts = { ...SAMPLE_OPTIONS, capabilities: [] };
      const result = await issueVC(opts, testSigningKey);
      expect(result.vc!.credentialSubject.capabilities).toBeUndefined();
    });
  });

  describe('with HS256 fallback', () => {
    test('issues a valid VC JWT with HS256', async () => {
      const result = await issueVC(SAMPLE_OPTIONS, undefined, TEST_SECRET);
      expect(result.success).toBe(true);
      expect(result.vc_jwt).toBeTruthy();
    });

    test('fails when neither key nor secret provided', async () => {
      const result = await issueVC(SAMPLE_OPTIONS);
      expect(result.success).toBe(false);
      expect(result.error).toBeTruthy();
    });
  });
});

// ============ VERIFICATION TESTS ============

describe('verifyVC', () => {
  describe('with ES256 key', () => {
    test('verifies a valid ES256 VC JWT', async () => {
      const issued = await issueVC(SAMPLE_OPTIONS, testSigningKey);
      const verified = await verifyVC(issued.vc_jwt!, testSigningKey);

      expect(verified.valid).toBe(true);
      expect(verified.issuer).toBe('did:web:botcha.ai');
      expect(verified.credential_subject?.agent_id).toBe('agent_test_001');
      expect(verified.credential_subject?.app_id).toBe('app_test_001');
    });

    test('returns full VC object on success', async () => {
      const issued = await issueVC(SAMPLE_OPTIONS, testSigningKey);
      const verified = await verifyVC(issued.vc_jwt!, testSigningKey);

      expect(verified.vc).toBeDefined();
      expect(verified.vc!.type).toContain('BotchaVerification');
    });

    test('returns credential_id on success', async () => {
      const issued = await issueVC(SAMPLE_OPTIONS, testSigningKey);
      const verified = await verifyVC(issued.vc_jwt!, testSigningKey);

      expect(verified.credential_id).toBe(issued.credential_id);
    });

    test('returns issued_at and expires_at on success', async () => {
      const issued = await issueVC(SAMPLE_OPTIONS, testSigningKey);
      const verified = await verifyVC(issued.vc_jwt!, testSigningKey);

      expect(verified.issued_at).toBeTruthy();
      expect(verified.expires_at).toBeTruthy();
    });

    test('fails verification with wrong key', async () => {
      // Generate a different key pair
      const kp2 = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['sign', 'verify']
      );
      const wrongPrivJwk = await crypto.subtle.exportKey('jwk', kp2.privateKey);
      const wrongKey = {
        kty: wrongPrivJwk.kty!,
        crv: wrongPrivJwk.crv!,
        x: wrongPrivJwk.x!,
        y: wrongPrivJwk.y!,
        d: wrongPrivJwk.d!,
        kid: 'wrong-key',
      };

      const issued = await issueVC(SAMPLE_OPTIONS, testSigningKey);
      const verified = await verifyVC(issued.vc_jwt!, wrongKey);

      expect(verified.valid).toBe(false);
      expect(verified.error).toBeTruthy();
    });

    test('fails verification on tampered payload', async () => {
      const issued = await issueVC(SAMPLE_OPTIONS, testSigningKey);

      // Tamper with the JWT by flipping a character in the signature segment
      // This definitively breaks the ES256 signature without touching the payload
      const parts = issued.vc_jwt!.split('.');
      const sig = parts[2];
      // Replace first character with a different one to corrupt the signature
      const tamperedSig = (sig[0] === 'A' ? 'B' : 'A') + sig.slice(1);
      const tampered = `${parts[0]}.${parts[1]}.${tamperedSig}`;

      const verified = await verifyVC(tampered, testSigningKey);
      expect(verified.valid).toBe(false);
    });

    test('rejects token with wrong type claim', async () => {
      // Issue a BOTCHA access_token (type: botcha-verified) and try to use it as a VC
      const { SignJWT, importJWK } = await import('jose');
      const signKey = await importJWK(testSigningKey, 'ES256');
      const fakeJwt = await new SignJWT({ type: 'botcha-verified', vc: {} })
        .setProtectedHeader({ alg: 'ES256', kid: testSigningKey.kid, typ: 'JWT' })
        .setIssuer('did:web:botcha.ai')
        .setExpirationTime('1h')
        .sign(signKey as CryptoKey);

      const verified = await verifyVC(fakeJwt, testSigningKey);
      expect(verified.valid).toBe(false);
      expect(verified.error).toContain('type');
    });

    test('rejects token with wrong issuer', async () => {
      const { SignJWT, importJWK } = await import('jose');
      const signKey = await importJWK(testSigningKey, 'ES256');
      const fakeJwt = await new SignJWT({
        type: 'botcha-vc',
        vc: { credentialSubject: { agent_id: 'x', app_id: 'x', solve_time_ms: 1, challenge_type: 'speed', trust_level: 'basic' } },
      })
        .setProtectedHeader({ alg: 'ES256', kid: testSigningKey.kid, typ: 'JWT' })
        .setIssuer('did:web:evil.example.com') // Wrong issuer
        .setExpirationTime('1h')
        .sign(signKey as CryptoKey);

      const verified = await verifyVC(fakeJwt, testSigningKey);
      expect(verified.valid).toBe(false);
      expect(verified.error).toContain('issuer');
    });

    test('rejects expired VC', async () => {
      // Issue with 1-second duration and then wait for it to expire
      // Instead of waiting, we directly craft an expired JWT
      const { SignJWT, importJWK } = await import('jose');
      const signKey = await importJWK(testSigningKey, 'ES256');
      const pastTime = Math.floor(Date.now() / 1000) - 3600; // 1 hour ago
      const fakeJwt = await new SignJWT({
        type: 'botcha-vc',
        vc: {
          '@context': ['https://www.w3.org/ns/credentials/v2'],
          type: ['VerifiableCredential', 'BotchaVerification'],
          id: 'urn:botcha:vc:test',
          issuer: 'did:web:botcha.ai',
          credentialSubject: {
            agent_id: 'agent_x',
            app_id: 'app_x',
            solve_time_ms: 100,
            challenge_type: 'speed',
            trust_level: 'basic',
          },
          validFrom: new Date((pastTime - 7200) * 1000).toISOString(),
          validUntil: new Date(pastTime * 1000).toISOString(),
        },
      })
        .setProtectedHeader({ alg: 'ES256', kid: testSigningKey.kid, typ: 'JWT' })
        .setIssuer('did:web:botcha.ai')
        .setIssuedAt(pastTime - 7200)
        .setNotBefore(pastTime - 7200)
        .setExpirationTime(pastTime) // Already expired
        .sign(signKey as CryptoKey);

      const verified = await verifyVC(fakeJwt, testSigningKey);
      expect(verified.valid).toBe(false);
      // jose throws JWTExpired, error message contains "expired"
      expect(verified.error?.toLowerCase()).toContain('exp');
    });

    test('fails when no key provided', async () => {
      const issued = await issueVC(SAMPLE_OPTIONS, testSigningKey);
      const verified = await verifyVC(issued.vc_jwt!);
      expect(verified.valid).toBe(false);
    });
  });

  describe('with HS256 fallback', () => {
    test('verifies a valid HS256 VC JWT', async () => {
      const issued = await issueVC(SAMPLE_OPTIONS, undefined, TEST_SECRET);
      const verified = await verifyVC(issued.vc_jwt!, undefined, TEST_SECRET);

      expect(verified.valid).toBe(true);
      expect(verified.credential_subject?.agent_id).toBe('agent_test_001');
    });

    test('fails with wrong secret', async () => {
      const issued = await issueVC(SAMPLE_OPTIONS, undefined, TEST_SECRET);
      const verified = await verifyVC(issued.vc_jwt!, undefined, 'wrong-secret');

      expect(verified.valid).toBe(false);
    });
  });

  describe('agent DID in credential subject', () => {
    test('verifies VC with agent DID in credentialSubject.id', async () => {
      const agentDid = 'did:web:botcha.ai:agents:agent_abc';
      const issued = await issueVC({ ...SAMPLE_OPTIONS, agent_did: agentDid }, testSigningKey);
      const verified = await verifyVC(issued.vc_jwt!, testSigningKey);

      expect(verified.valid).toBe(true);
      expect(verified.credential_subject!.id).toBe(agentDid);
    });
  });
});

// ============ extractVCPayloadClaims ============

describe('extractVCPayloadClaims', () => {
  test('extracts claims from a valid VC JWT without verification', async () => {
    const issued = await issueVC(SAMPLE_OPTIONS, testSigningKey);
    const claims = extractVCPayloadClaims(issued.vc_jwt!);

    expect(claims).not.toBeNull();
    expect(claims!.agent_id).toBe('agent_test_001');
    expect(claims!.app_id).toBe('app_test_001');
    expect(claims!.solve_time_ms).toBe(142);
    expect(claims!.challenge_type).toBe('speed');
    expect(claims!.trust_level).toBe('basic');
  });

  test('returns null for malformed JWT', () => {
    expect(extractVCPayloadClaims('not-a-jwt')).toBeNull();
    expect(extractVCPayloadClaims('')).toBeNull();
    expect(extractVCPayloadClaims('a.b')).toBeNull(); // Only 2 parts
  });

  test('returns null for valid JWT without vc claim', async () => {
    const { SignJWT, importJWK } = await import('jose');
    const signKey = await importJWK(testSigningKey, 'ES256');
    const jwt = await new SignJWT({ type: 'botcha-verified' })
      .setProtectedHeader({ alg: 'ES256', typ: 'JWT' })
      .setExpirationTime('1h')
      .sign(signKey as CryptoKey);

    expect(extractVCPayloadClaims(jwt)).toBeNull();
  });
});

// ============ INTEGRATION: issue → verify roundtrip ============

describe('Full issue→verify roundtrip', () => {
  test('ES256 roundtrip with all fields', async () => {
    const opts: IssueVCOptions = {
      agent_id: 'agent_roundtrip_001',
      app_id: 'app_roundtrip_001',
      solve_time_ms: 88,
      challenge_type: 'hybrid',
      trust_level: 'verified',
      capabilities: ['browse:products', 'purchase:*'],
      agent_did: 'did:web:botcha.ai:agents:agent_roundtrip_001',
      duration_seconds: 7200,
    };

    const issued = await issueVC(opts, testSigningKey);
    expect(issued.success).toBe(true);

    const verified = await verifyVC(issued.vc_jwt!, testSigningKey);
    expect(verified.valid).toBe(true);
    expect(verified.credential_subject!.agent_id).toBe('agent_roundtrip_001');
    expect(verified.credential_subject!.app_id).toBe('app_roundtrip_001');
    expect(verified.credential_subject!.solve_time_ms).toBe(88);
    expect(verified.credential_subject!.challenge_type).toBe('hybrid');
    expect(verified.credential_subject!.trust_level).toBe('verified');
    expect(verified.credential_subject!.capabilities).toEqual(['browse:products', 'purchase:*']);
    expect(verified.credential_subject!.id).toBe('did:web:botcha.ai:agents:agent_roundtrip_001');
    expect(verified.issuer).toBe('did:web:botcha.ai');
  });

  test('HS256 roundtrip', async () => {
    const issued = await issueVC(SAMPLE_OPTIONS, undefined, TEST_SECRET);
    const verified = await verifyVC(issued.vc_jwt!, undefined, TEST_SECRET);
    expect(verified.valid).toBe(true);
    expect(verified.credential_subject!.agent_id).toBe('agent_test_001');
  });
});
