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
