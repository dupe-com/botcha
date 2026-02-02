import { describe, test, expect, vi, beforeEach } from 'vitest';
import { BotchaClient } from '../../../lib/client/index.js';

describe('BotchaClient', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  describe('Constructor', () => {
    test('uses default baseUrl', () => {
      const client = new BotchaClient();
      // Access private property for testing via bracket notation
      expect((client as any).baseUrl).toBe('https://botcha.ai');
    });

    test('uses default agentIdentity with SDK version', () => {
      const client = new BotchaClient();
      expect((client as any).agentIdentity).toMatch(/^BotchaClient\/\d+\.\d+\.\d+$/);
    });

    test('accepts custom options', () => {
      const client = new BotchaClient({
        baseUrl: 'https://custom.botcha.ai',
        agentIdentity: 'CustomAgent/1.0.0',
        maxRetries: 5,
      });
      
      expect((client as any).baseUrl).toBe('https://custom.botcha.ai');
      expect((client as any).agentIdentity).toBe('CustomAgent/1.0.0');
      expect((client as any).maxRetries).toBe(5);
    });
  });

  describe('solveChallenge()', () => {
    test('throws on non-200 response', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        status: 500,
        ok: false,
        statusText: 'Internal Server Error',
      });

      const client = new BotchaClient();
      await expect(client.solveChallenge()).rejects.toThrow(
        'Challenge request failed with status 500 Internal Server Error'
      );
    });

    test('throws on non-JSON response (text/html)', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        status: 200,
        ok: true,
        headers: {
          get: vi.fn().mockReturnValue('text/html'),
        },
      });

      const client = new BotchaClient();
      await expect(client.solveChallenge()).rejects.toThrow(
        'Expected JSON response for challenge request'
      );
    });

    test('throws when success=false in response', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        status: 200,
        ok: true,
        headers: {
          get: vi.fn().mockReturnValue('application/json'),
        },
        json: vi.fn().mockResolvedValue({
          success: false,
        }),
      });

      const client = new BotchaClient();
      await expect(client.solveChallenge()).rejects.toThrow(
        'Failed to get challenge'
      );
    });

    test('successfully solves challenge when response is valid', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        status: 200,
        ok: true,
        headers: {
          get: vi.fn().mockReturnValue('application/json'),
        },
        json: vi.fn().mockResolvedValue({
          success: true,
          challenge: {
            id: 'test-challenge-id',
            problems: [
              { num: 123456, operation: 'sha256_first8' },
              { num: 789012, operation: 'sha256_first8' },
            ],
            timeLimit: 10000,
            instructions: 'Solve these problems',
          },
        }),
      });

      const client = new BotchaClient();
      const result = await client.solveChallenge();
      
      expect(result.id).toBe('test-challenge-id');
      expect(result.answers).toHaveLength(2);
      expect(result.answers[0]).toHaveLength(8);
      expect(result.answers[1]).toHaveLength(8);
    });
  });

  describe('verify()', () => {
    test('throws on non-200 response', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        status: 400,
        ok: false,
        statusText: 'Bad Request',
      });

      const client = new BotchaClient();
      await expect(client.verify('test-id', ['answer1'])).rejects.toThrow(
        'Verification request failed with status 400 Bad Request'
      );
    });

    test('throws on non-JSON response', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        status: 200,
        ok: true,
        headers: {
          get: vi.fn().mockReturnValue('text/plain'),
        },
      });

      const client = new BotchaClient();
      await expect(client.verify('test-id', ['answer1'])).rejects.toThrow(
        'Expected JSON response for verification request'
      );
    });

    test('successfully verifies with valid response', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        status: 200,
        ok: true,
        headers: {
          get: vi.fn().mockReturnValue('application/json'),
        },
        json: vi.fn().mockResolvedValue({
          success: true,
          message: 'Verification successful',
          solveTimeMs: 123,
          verdict: 'PASS',
        }),
      });

      const client = new BotchaClient();
      const result = await client.verify('test-id', ['answer1']);
      
      expect(result.success).toBe(true);
      expect(result.message).toBe('Verification successful');
    });
  });

  describe('fetch()', () => {
    const createClient = (options: ConstructorParameters<typeof BotchaClient>[0] = {}) =>
      new BotchaClient({ autoToken: false, ...options });

    test('returns response on 200 status', async () => {
      const mockResponse = {
        status: 200,
        ok: true,
        json: vi.fn().mockResolvedValue({ data: 'test' }),
      };

      global.fetch = vi.fn().mockResolvedValue(mockResponse);

      const client = createClient();
      const response = await client.fetch('https://example.com');
      
      expect(response.status).toBe(200);
      expect(response.ok).toBe(true);
    });

    test('clones response before reading body (response.json() should still work for caller)', async () => {
      const mockJson = vi.fn().mockResolvedValue({ data: 'test' });
      const mockClone = vi.fn().mockReturnValue({
        json: vi.fn().mockResolvedValue({ data: 'test' }),
      });

      global.fetch = vi.fn().mockResolvedValue({
        status: 200,
        ok: true,
        json: mockJson,
        clone: mockClone,
      });

      const client = createClient();
      const response = await client.fetch('https://example.com');
      
      // Ensure response body is still usable by caller
      const data = await response.json();
      expect(data).toEqual({ data: 'test' });
      expect(mockJson).toHaveBeenCalled();
    });

    test('retries on BOTCHA challenge (403 with challenge in body)', async () => {
      const challengeResponse = {
        status: 403,
        ok: false,
        clone: vi.fn().mockReturnValue({
          json: vi.fn().mockResolvedValue({
            challenge: {
              id: 'challenge-123',
              problems: [{ num: 123456, operation: 'sha256_first8' }],
            },
          }),
        }),
      };

      const successResponse = {
        status: 200,
        ok: true,
        json: vi.fn().mockResolvedValue({ data: 'success' }),
      };

      global.fetch = vi.fn()
        .mockResolvedValueOnce(challengeResponse)
        .mockResolvedValueOnce(successResponse);

      const client = createClient();
      const response = await client.fetch('https://example.com');
      
      expect(response.status).toBe(200);
      expect(global.fetch).toHaveBeenCalledTimes(2);
    });

    test('respects maxRetries limit (stops after max attempts)', async () => {
      const challengeResponse = {
        status: 403,
        ok: false,
        clone: vi.fn().mockReturnValue({
          json: vi.fn().mockResolvedValue({
            challenge: {
              id: 'challenge-123',
              problems: [{ num: 123456, operation: 'sha256_first8' }],
            },
          }),
        }),
      };

      global.fetch = vi.fn().mockResolvedValue(challengeResponse);

      const client = createClient({ maxRetries: 2 });
      const response = await client.fetch('https://example.com');
      
      // Initial request + 2 retries = 3 total calls
      expect(global.fetch).toHaveBeenCalledTimes(3);
      expect(response.status).toBe(403);
    });

    test('breaks loop on non-BOTCHA 403 (no challenge in body)', async () => {
      const non403Response = {
        status: 403,
        ok: false,
        clone: vi.fn().mockReturnValue({
          json: vi.fn().mockResolvedValue({
            error: 'Forbidden',
            message: 'Access denied',
          }),
        }),
      };

      global.fetch = vi.fn().mockResolvedValue(non403Response);

      const client = createClient({ maxRetries: 3 });
      const response = await client.fetch('https://example.com');
      
      // Should only call fetch once since it's not a BOTCHA challenge
      expect(global.fetch).toHaveBeenCalledTimes(1);
      expect(response.status).toBe(403);
    });

    test('handles challenge with problems array directly', async () => {
      const challengeResponse = {
        status: 403,
        ok: false,
        clone: vi.fn().mockReturnValue({
          json: vi.fn().mockResolvedValue({
            challenge: {
              id: 'challenge-456',
              problems: [789012, 345678],
            },
          }),
        }),
      };

      const successResponse = {
        status: 200,
        ok: true,
        json: vi.fn().mockResolvedValue({ data: 'success' }),
      };

      global.fetch = vi.fn()
        .mockResolvedValueOnce(challengeResponse)
        .mockResolvedValueOnce(successResponse);

      const client = createClient();
      const response = await client.fetch('https://example.com');
      
      expect(response.status).toBe(200);
      expect(global.fetch).toHaveBeenCalledTimes(2);
    });

    test('solves standard challenge puzzle and retries with X-Botcha-Solution', async () => {
      const puzzle = 'Compute SHA256 of the first 10 prime numbers concatenated (no separators). Return the first 16 hex characters.';
      const challengeResponse = {
        status: 403,
        ok: false,
        clone: vi.fn().mockReturnValue({
          json: vi.fn().mockResolvedValue({
            challenge: {
              id: 'challenge-standard-1',
              puzzle,
            },
          }),
        }),
      };

      const successResponse = {
        status: 200,
        ok: true,
        json: vi.fn().mockResolvedValue({ data: 'success' }),
      };

      const fetchMock = vi.fn()
        .mockResolvedValueOnce(challengeResponse)
        .mockResolvedValueOnce(successResponse);

      global.fetch = fetchMock;

      const client = createClient();
      const response = await client.fetch('https://example.com');

      expect(response.status).toBe(200);
      expect(fetchMock).toHaveBeenCalledTimes(2);

      const secondCallArgs = fetchMock.mock.calls[1];
      const secondInit = secondCallArgs[1] as RequestInit;
      const headers = new Headers(secondInit.headers);
      const solution = headers.get('X-Botcha-Solution');
      expect(solution).toBeTruthy();
      expect(headers.get('X-Botcha-Challenge-Id')).toBe('challenge-standard-1');
    });
  });

  describe('createHeaders()', () => {
    test('returns correct header structure', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        status: 200,
        ok: true,
        headers: {
          get: vi.fn().mockReturnValue('application/json'),
        },
        json: vi.fn().mockResolvedValue({
          success: true,
          challenge: {
            id: 'test-challenge-id',
            problems: [{ num: 123456, operation: 'sha256_first8' }],
            timeLimit: 10000,
            instructions: 'Solve this',
          },
        }),
      });

      const client = new BotchaClient();
      const headers = await client.createHeaders();
      
      expect(headers).toHaveProperty('X-Botcha-Id');
      expect(headers).toHaveProperty('X-Botcha-Challenge-Id');
      expect(headers).toHaveProperty('X-Botcha-Answers');
      expect(headers).toHaveProperty('User-Agent');
      expect(headers['X-Botcha-Id']).toBe('test-challenge-id');
      expect(headers['User-Agent']).toMatch(/^BotchaClient\/\d+\.\d+\.\d+$/);
      
      // Verify answers is a JSON string
      const answers = JSON.parse(headers['X-Botcha-Answers']);
      expect(Array.isArray(answers)).toBe(true);
      expect(answers).toHaveLength(1);
    });
  });
});
