import { describe, test, expect, beforeEach } from 'vitest';
import crypto from 'crypto';
import { generateSpeedChallenge, verifySpeedChallenge } from '../../../src/challenges/speed.js';

describe('Speed Challenge', () => {
  describe('generateSpeedChallenge', () => {
    test('returns valid structure with id, challenges, timeLimit', () => {
      const challenge = generateSpeedChallenge();
      
      expect(challenge).toHaveProperty('id');
      expect(challenge).toHaveProperty('challenges');
      expect(challenge).toHaveProperty('timeLimit');
      expect(challenge).toHaveProperty('instructions');
      
      expect(typeof challenge.id).toBe('string');
      expect(Array.isArray(challenge.challenges)).toBe(true);
      expect(challenge.timeLimit).toBe(500);
      expect(typeof challenge.instructions).toBe('string');
    });

    test('adjusts timeout based on RTT when client timestamp provided', () => {
      const clientTimestamp = Date.now() - 100; // Simulate 100ms RTT
      const challenge = generateSpeedChallenge(clientTimestamp);
      
      expect(challenge.timeLimit).toBeGreaterThan(500); // Should be adjusted
      expect(challenge).toHaveProperty('rttInfo');
      expect(challenge.rttInfo?.measuredRtt).toBe(100);
      expect(challenge.rttInfo?.adjustedTimeout).toBeGreaterThan(500);
    });

    test('uses default timeout when no client timestamp provided', () => {
      const challenge = generateSpeedChallenge();
      
      expect(challenge.timeLimit).toBe(500);
      expect(challenge.rttInfo).toBeUndefined();
    });

    test('caps RTT adjustment at 5 seconds max (anti-spoofing)', () => {
      // Simulate a spoofed timestamp from the distant past (e.g., epoch 0)
      const challenge = generateSpeedChallenge(1);
      
      // Should NOT get an enormous timeout — RTT should be capped at 5000ms
      // Max possible: 500 + (2 * 5000) + 100 = 10600ms
      // But actually, timestamps >30s old are rejected entirely, so we get base timeout
      expect(challenge.timeLimit).toBe(500);
      expect(challenge.rttInfo).toBeUndefined();
    });

    test('rejects future timestamps (anti-spoofing)', () => {
      // Timestamp 10 seconds in the future
      const futureTimestamp = Date.now() + 10000;
      const challenge = generateSpeedChallenge(futureTimestamp);
      
      // Future timestamps should be silently ignored — use base timeout
      expect(challenge.timeLimit).toBe(500);
      expect(challenge.rttInfo).toBeUndefined();
    });

    test('rejects timestamps older than 30 seconds (anti-spoofing)', () => {
      // Timestamp 60 seconds ago — should be rejected
      const oldTimestamp = Date.now() - 60000;
      const challenge = generateSpeedChallenge(oldTimestamp);
      
      expect(challenge.timeLimit).toBe(500);
      expect(challenge.rttInfo).toBeUndefined();
    });

    test('accepts valid timestamp within 30s window and caps RTT', () => {
      // Simulate 200ms RTT (within valid range)
      const validTimestamp = Date.now() - 200;
      const challenge = generateSpeedChallenge(validTimestamp);
      
      expect(challenge.timeLimit).toBeGreaterThan(500);
      expect(challenge.rttInfo).toBeDefined();
      // RTT should be approximately 200ms (within margin for test execution time)
      expect(challenge.rttInfo!.measuredRtt).toBeGreaterThanOrEqual(200);
      expect(challenge.rttInfo!.measuredRtt).toBeLessThan(5000);
    });

    test('RTT cap limits maximum adjusted timeout', () => {
      // Simulate a 25 second RTT — within 30s window but above 5s cap
      const slowTimestamp = Date.now() - 25000;
      const challenge = generateSpeedChallenge(slowTimestamp);
      
      // RTT should be capped at 5000ms, so adjusted timeout = 500 + (2*5000) + 100 = 10600
      expect(challenge.timeLimit).toBe(10600);
      expect(challenge.rttInfo).toBeDefined();
      expect(challenge.rttInfo!.measuredRtt).toBe(5000); // Capped, not 25000
    });

    test('generated challenge has exactly 5 problems', () => {
      const challenge = generateSpeedChallenge();
      
      expect(challenge.challenges).toHaveLength(5);
    });

    test('each problem has correct structure with num and operation', () => {
      const challenge = generateSpeedChallenge();
      
      challenge.challenges.forEach((problem) => {
        expect(problem).toHaveProperty('num');
        expect(problem).toHaveProperty('operation');
        expect(typeof problem.num).toBe('number');
        expect(problem.operation).toBe('sha256_first8');
        expect(problem.num).toBeGreaterThanOrEqual(100000);
        expect(problem.num).toBeLessThan(1100000);
      });
    });

    test('expected answers are correct SHA256 first-8 hashes', () => {
      const challenge = generateSpeedChallenge();
      
      // Compute the expected answers ourselves and verify against the challenge
      const computedAnswers = challenge.challenges.map((problem) => {
        const hash = crypto.createHash('sha256')
          .update(problem.num.toString())
          .digest('hex');
        return hash.substring(0, 8);
      });
      
      // We can't directly access expectedAnswers, but we can verify by solving the challenge
      const result = verifySpeedChallenge(challenge.id, computedAnswers);
      expect(result.valid).toBe(true);
    });
  });

  describe('verifySpeedChallenge', () => {
    test('passes with correct answers', () => {
      const challenge = generateSpeedChallenge();
      
      // Solve the challenge correctly
      const answers = challenge.challenges.map((problem) => {
        const hash = crypto.createHash('sha256')
          .update(problem.num.toString())
          .digest('hex');
        return hash.substring(0, 8);
      });
      
      const result = verifySpeedChallenge(challenge.id, answers);
      
      expect(result.valid).toBe(true);
      expect(result.reason).toBeUndefined();
    });

    test('fails with incorrect answers', () => {
      const challenge = generateSpeedChallenge();
      
      // Provide wrong answers
      const wrongAnswers = ['00000000', '11111111', '22222222', '33333333', '44444444'];
      
      const result = verifySpeedChallenge(challenge.id, wrongAnswers);
      
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('Wrong answer');
    });

    test('fails with expired challenge', async () => {
      const challenge = generateSpeedChallenge();
      
      // Compute correct answers
      const answers = challenge.challenges.map((problem) => {
        const hash = crypto.createHash('sha256')
          .update(problem.num.toString())
          .digest('hex');
        return hash.substring(0, 8);
      });
      
      // Wait for the challenge to expire (500ms + 100ms grace period)
      await new Promise((resolve) => setTimeout(resolve, 650));
      
      const result = verifySpeedChallenge(challenge.id, answers);
      
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('Too slow');
    });

    test('fails with wrong answer count', () => {
      const challenge = generateSpeedChallenge();
      
      // Provide only 3 answers instead of 5
      const answers = ['12345678', '23456789', '34567890'];
      
      const result = verifySpeedChallenge(challenge.id, answers);
      
      expect(result.valid).toBe(false);
      expect(result.reason).toBe('Must provide exactly 5 answers as array');
    });

    test('returns solveTimeMs on success', () => {
      const challenge = generateSpeedChallenge();
      
      // Solve the challenge correctly
      const answers = challenge.challenges.map((problem) => {
        const hash = crypto.createHash('sha256')
          .update(problem.num.toString())
          .digest('hex');
        return hash.substring(0, 8);
      });
      
      const result = verifySpeedChallenge(challenge.id, answers);
      
      expect(result.valid).toBe(true);
      expect(result.solveTimeMs).toBeDefined();
      expect(typeof result.solveTimeMs).toBe('number');
      expect(result.solveTimeMs).toBeGreaterThanOrEqual(0);
      expect(result.solveTimeMs).toBeLessThan(500); // Should be fast in tests
    });

    test('challenge is deleted after verification (cannot use same ID twice)', () => {
      const challenge = generateSpeedChallenge();
      
      // Solve the challenge correctly
      const answers = challenge.challenges.map((problem) => {
        const hash = crypto.createHash('sha256')
          .update(problem.num.toString())
          .digest('hex');
        return hash.substring(0, 8);
      });
      
      // First verification should succeed
      const firstResult = verifySpeedChallenge(challenge.id, answers);
      expect(firstResult.valid).toBe(true);
      
      // Second verification with same ID should fail (challenge deleted)
      const secondResult = verifySpeedChallenge(challenge.id, answers);
      expect(secondResult.valid).toBe(false);
      expect(secondResult.reason).toBe('Challenge not found or expired');
    });
  });
});
