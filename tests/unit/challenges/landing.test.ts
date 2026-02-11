import { describe, test, expect } from 'vitest';
import { verifyLandingChallenge } from '../../../packages/cloudflare-workers/src/challenges.js';
import { sha256 } from '../../../packages/cloudflare-workers/src/crypto.js';

describe('Landing Challenge (CF Workers)', () => {
  describe('verifyLandingChallenge() - timestamp validation', () => {
    test('rejects timestamps older than 2 minutes', async () => {
      const oldTimestamp = new Date(Date.now() - 3 * 60 * 1000).toISOString(); // 3 min ago
      const result = await verifyLandingChallenge('anything', oldTimestamp);

      expect(result.valid).toBe(false);
      expect(result.error).toContain('expired');
    });

    test('rejects timestamps in the future beyond 2 minutes', async () => {
      const futureTimestamp = new Date(Date.now() + 3 * 60 * 1000).toISOString(); // 3 min in future
      const result = await verifyLandingChallenge('anything', futureTimestamp);

      expect(result.valid).toBe(false);
      expect(result.error).toContain('expired');
    });

    test('rejects invalid timestamp format', async () => {
      const result = await verifyLandingChallenge('anything', 'not-a-timestamp');

      expect(result.valid).toBe(false);
      expect(result.error).toContain('expired');
    });
  });

  describe('verifyLandingChallenge() - per-request nonce', () => {
    test('accepts correct answer for current timestamp', async () => {
      const timestamp = new Date().toISOString();
      const today = new Date().toISOString().split('T')[0];
      const expectedHash = (await sha256(`BOTCHA-LANDING-${today}-${timestamp}`)).substring(0, 16);

      const result = await verifyLandingChallenge(expectedHash, timestamp);

      expect(result.valid).toBe(true);
      expect(result.token).toBeDefined();
      expect(typeof result.token).toBe('string');
      expect(result.token!.length).toBe(64); // 32 bytes = 64 hex chars
    });

    test('rejects wrong answer', async () => {
      const timestamp = new Date().toISOString();
      const result = await verifyLandingChallenge('0000000000000000', timestamp);

      expect(result.valid).toBe(false);
      expect(result.error).toBe('Incorrect answer');
    });

    test('different timestamps produce different expected answers (nonce)', async () => {
      const today = new Date().toISOString().split('T')[0];

      const timestamp1 = new Date(Date.now() - 1000).toISOString(); // 1s ago
      const timestamp2 = new Date(Date.now() - 2000).toISOString(); // 2s ago

      const hash1 = (await sha256(`BOTCHA-LANDING-${today}-${timestamp1}`)).substring(0, 16);
      const hash2 = (await sha256(`BOTCHA-LANDING-${today}-${timestamp2}`)).substring(0, 16);

      // Different timestamps → different answers (prevents sharing)
      expect(hash1).not.toBe(hash2);
    });

    test('answer from timestamp1 does NOT work for timestamp2 (anti-sharing)', async () => {
      const today = new Date().toISOString().split('T')[0];

      const timestamp1 = new Date(Date.now() - 1000).toISOString();
      const timestamp2 = new Date(Date.now() - 500).toISOString();

      // Compute answer for timestamp1
      const answer1 = (await sha256(`BOTCHA-LANDING-${today}-${timestamp1}`)).substring(0, 16);

      // Try to use it with timestamp2 — should fail
      const result = await verifyLandingChallenge(answer1, timestamp2);
      expect(result.valid).toBe(false);
    });

    test('error hint does NOT leak the formula', async () => {
      const timestamp = new Date().toISOString();
      const result = await verifyLandingChallenge('wrong', timestamp);

      expect(result.valid).toBe(false);
      expect(result.hint).toBeDefined();
      // Should NOT contain the actual computation details
      expect(result.hint).not.toContain('BOTCHA-LANDING');
      expect(result.hint).not.toContain('SHA256');
    });
  });
});
