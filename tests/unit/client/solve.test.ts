import { describe, test, expect } from 'vitest';
import crypto from 'crypto';
import { BotchaClient, solveBotcha } from '../../../lib/client/index.js';

describe('Client SDK - Solve Functions', () => {
  describe('BotchaClient.solve()', () => {
    test('computes SHA256 first-8 hex chars correctly for single number', () => {
      const client = new BotchaClient();
      const result = client.solve([123456]);
      
      // Compute expected hash independently
      const expected = crypto.createHash('sha256')
        .update('123456')
        .digest('hex')
        .substring(0, 8);
      
      expect(result).toHaveLength(1);
      expect(result[0]).toBe(expected);
      expect(result[0]).toBe('8d969eef');
    });

    test('handles multiple numbers correctly', () => {
      const client = new BotchaClient();
      const result = client.solve([123456, 789012]);
      
      // Compute expected hashes independently
      const expected1 = crypto.createHash('sha256')
        .update('123456')
        .digest('hex')
        .substring(0, 8);
      const expected2 = crypto.createHash('sha256')
        .update('789012')
        .digest('hex')
        .substring(0, 8);
      
      expect(result).toHaveLength(2);
      expect(result[0]).toBe(expected1);
      expect(result[1]).toBe(expected2);
    });

    test('handles empty array correctly', () => {
      const client = new BotchaClient();
      const result = client.solve([]);
      
      expect(result).toEqual([]);
      expect(result).toHaveLength(0);
    });

    test('results are lowercase hex strings', () => {
      const client = new BotchaClient();
      const result = client.solve([123456, 789012, 999999999]);
      
      result.forEach((hash) => {
        // Should only contain lowercase hex characters (0-9, a-f)
        expect(hash).toMatch(/^[0-9a-f]+$/);
        // Should not contain any uppercase characters
        expect(hash).toBe(hash.toLowerCase());
      });
    });

    test('results are exactly 8 characters each', () => {
      const client = new BotchaClient();
      const result = client.solve([1, 123456, 789012, 999999999]);
      
      result.forEach((hash) => {
        expect(hash).toHaveLength(8);
      });
    });

    test('known test vector: solve([645234]) matches expected hash', () => {
      const client = new BotchaClient();
      const result = client.solve([645234]);
      
      // Known test vector
      const expected = crypto.createHash('sha256')
        .update('645234')
        .digest('hex')
        .substring(0, 8);
      
      expect(result[0]).toBe(expected);
      expect(result[0]).toBe('20ac4997');
    });

    test('handles large numbers correctly', () => {
      const client = new BotchaClient();
      const result = client.solve([999999999]);
      
      // Compute expected hash independently
      const expected = crypto.createHash('sha256')
        .update('999999999')
        .digest('hex')
        .substring(0, 8);
      
      expect(result).toHaveLength(1);
      expect(result[0]).toBe(expected);
      expect(result[0]).toBe('bb421fa3');
    });
  });

  describe('solveBotcha() standalone function', () => {
    test('produces same results as BotchaClient.solve()', () => {
      const client = new BotchaClient();
      const testCases = [
        [123456],
        [789012],
        [123456, 789012],
        [645234],
        [999999999],
        [1, 2, 3, 4, 5],
        []
      ];
      
      testCases.forEach((problems) => {
        const clientResult = client.solve(problems);
        const standaloneResult = solveBotcha(problems);
        
        expect(standaloneResult).toEqual(clientResult);
      });
    });

    test('computes SHA256 first-8 hex chars correctly', () => {
      const result = solveBotcha([123456]);
      
      // Compute expected hash independently
      const expected = crypto.createHash('sha256')
        .update('123456')
        .digest('hex')
        .substring(0, 8);
      
      expect(result).toHaveLength(1);
      expect(result[0]).toBe(expected);
      expect(result[0]).toBe('8d969eef');
    });

    test('handles multiple numbers correctly', () => {
      const result = solveBotcha([123456, 789012]);
      
      // Compute expected hashes independently
      const expected1 = crypto.createHash('sha256')
        .update('123456')
        .digest('hex')
        .substring(0, 8);
      const expected2 = crypto.createHash('sha256')
        .update('789012')
        .digest('hex')
        .substring(0, 8);
      
      expect(result).toHaveLength(2);
      expect(result[0]).toBe(expected1);
      expect(result[1]).toBe(expected2);
    });

    test('handles empty array correctly', () => {
      const result = solveBotcha([]);
      
      expect(result).toEqual([]);
      expect(result).toHaveLength(0);
    });
  });

  describe('Edge cases and consistency', () => {
    test('handles single-digit numbers', () => {
      const client = new BotchaClient();
      const result = client.solve([0, 1, 9]);
      
      expect(result).toHaveLength(3);
      result.forEach((hash) => {
        expect(hash).toHaveLength(8);
        expect(hash).toMatch(/^[0-9a-f]+$/);
      });
    });

    test('results are deterministic', () => {
      const client = new BotchaClient();
      const problems = [123456, 789012, 999999999];
      
      const result1 = client.solve(problems);
      const result2 = client.solve(problems);
      const result3 = solveBotcha(problems);
      
      expect(result1).toEqual(result2);
      expect(result2).toEqual(result3);
    });

    test('each number produces unique hash', () => {
      const client = new BotchaClient();
      const result = client.solve([123456, 123457, 123458]);
      
      // All hashes should be unique
      const uniqueHashes = new Set(result);
      expect(uniqueHashes.size).toBe(result.length);
    });
  });
});
