import { describe, it, expect, beforeEach } from 'vitest';
import crypto from 'crypto';
import {
  generateChallenge,
  verifyChallenge,
  isPrime,
  generatePrimes,
} from '../../../src/challenges/compute.js';

describe('Compute Challenge', () => {
  describe('isPrime()', () => {
    it('correctly identifies primes', () => {
      const primes = [2, 3, 5, 7, 11, 13, 17, 19];
      
      for (const num of primes) {
        expect(isPrime(num)).toBe(true);
      }
    });

    it('correctly rejects non-primes', () => {
      const nonPrimes = [0, 1, 4, 6, 8, 9, 10, 15];
      
      for (const num of nonPrimes) {
        expect(isPrime(num)).toBe(false);
      }
    });
  });

  describe('generatePrimes()', () => {
    it('returns exactly n primes', () => {
      const testCases = [5, 10, 20, 50];
      
      for (const n of testCases) {
        const primes = generatePrimes(n);
        expect(primes).toHaveLength(n);
        
        // Verify all returned values are actually prime
        for (const prime of primes) {
          expect(isPrime(prime)).toBe(true);
        }
      }
    });

    it('returns correct first 10 primes', () => {
      const expected = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29];
      const actual = generatePrimes(10);
      
      expect(actual).toEqual(expected);
    });
  });

  describe('generateChallenge()', () => {
    it('easy difficulty has timeLimit 10000', () => {
      const challenge = generateChallenge('easy');
      
      expect(challenge.timeLimit).toBe(10000);
    });

    it('medium difficulty has timeLimit 5000', () => {
      const challenge = generateChallenge('medium');
      
      expect(challenge.timeLimit).toBe(5000);
    });

    it('hard difficulty has timeLimit 3000', () => {
      const challenge = generateChallenge('hard');
      
      expect(challenge.timeLimit).toBe(3000);
    });

    it('generated challenge includes id, puzzle, timeLimit, hint', () => {
      const challenge = generateChallenge('medium');
      
      expect(challenge).toHaveProperty('id');
      expect(challenge).toHaveProperty('puzzle');
      expect(challenge).toHaveProperty('timeLimit');
      expect(challenge).toHaveProperty('hint');
      
      expect(typeof challenge.id).toBe('string');
      expect(typeof challenge.puzzle).toBe('string');
      expect(typeof challenge.timeLimit).toBe('number');
      expect(typeof challenge.hint).toBe('string');
      
      expect(challenge.id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i);
    });
  });

  describe('verifyChallenge()', () => {
    it('passes with correct answer', () => {
      // Generate challenge
      const challenge = generateChallenge('easy');
      
      // Compute the correct answer
      const primes = generatePrimes(100); // Easy difficulty uses 100 primes
      const concatenated = primes.join('');
      const hash = crypto.createHash('sha256').update(concatenated).digest('hex');
      const answer = hash.substring(0, 16);
      
      // Verify
      const result = verifyChallenge(challenge.id, answer);
      
      expect(result.valid).toBe(true);
      expect(result.reason).toBeUndefined();
    });

    it('fails with incorrect answer', () => {
      const challenge = generateChallenge('medium');
      const wrongAnswer = '0000000000000000';
      
      const result = verifyChallenge(challenge.id, wrongAnswer);
      
      expect(result.valid).toBe(false);
      expect(result.reason).toBe('Incorrect answer');
    });

    it('fails with unknown challenge ID', () => {
      const fakeId = '00000000-0000-0000-0000-000000000000';
      const answer = '1234567890abcdef';
      
      const result = verifyChallenge(fakeId, answer);
      
      expect(result.valid).toBe(false);
      expect(result.reason).toBe('Challenge not found or expired');
    });

    it('challenge is single-use (deleted after verify, second verify fails)', () => {
      // Generate challenge
      const challenge = generateChallenge('easy');
      
      // Compute correct answer
      const primes = generatePrimes(100);
      const concatenated = primes.join('');
      const hash = crypto.createHash('sha256').update(concatenated).digest('hex');
      const answer = hash.substring(0, 16);
      
      // First verification should succeed
      const firstResult = verifyChallenge(challenge.id, answer);
      expect(firstResult.valid).toBe(true);
      
      // Second verification with same ID should fail (challenge deleted)
      const secondResult = verifyChallenge(challenge.id, answer);
      expect(secondResult.valid).toBe(false);
      expect(secondResult.reason).toBe('Challenge not found or expired');
    });
  });
});
