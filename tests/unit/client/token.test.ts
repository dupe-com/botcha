import { describe, test, expect, vi, beforeEach } from 'vitest';
import { BotchaClient } from '../../../lib/client/index.js';

describe('BotchaClient - Token Flow', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  describe('getToken()', () => {
    test('successfully acquires token through challenge flow', async () => {
      // Mock GET /v1/token - returns challenge
      const challengeResponse = {
        success: true,
        token: null,
        challenge: {
          id: 'token-challenge-123',
          problems: [
            { num: 123456, operation: 'sha256_first8' },
            { num: 789012, operation: 'sha256_first8' },
          ],
          timeLimit: 10000,
          instructions: 'Solve to get token',
        },
        nextStep: 'POST /v1/token/verify',
      };

      // Mock POST /v1/token/verify - returns JWT
      const verifyResponse = {
        success: true,
        token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.token',
        expiresIn: '1h',
      };

      global.fetch = vi.fn()
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: vi.fn().mockResolvedValue(challengeResponse),
        })
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: vi.fn().mockResolvedValue(verifyResponse),
        });

      const client = new BotchaClient();
      const token = await client.getToken();

      expect(token).toBe('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.token');
      expect(global.fetch).toHaveBeenCalledTimes(2);
      
      // Verify first call was GET /v1/token
      const firstCall = (global.fetch as any).mock.calls[0];
      expect(firstCall[0]).toContain('/v1/token');
      expect(firstCall[1]?.method).toBeUndefined(); // GET is default
      
      // Verify second call was POST /v1/token/verify with solution
      const secondCall = (global.fetch as any).mock.calls[1];
      expect(secondCall[0]).toContain('/v1/token/verify');
      expect(secondCall[1]?.method).toBe('POST');
      
      const body = JSON.parse(secondCall[1]?.body);
      expect(body.id).toBe('token-challenge-123');
      expect(body.answers).toHaveLength(2);
      expect(body.answers[0]).toHaveLength(8);
    });

    test('caches token and reuses it within validity period', async () => {
      const verifyResponse = {
        success: true,
        token: 'cached.jwt.token',
        expiresIn: '1h',
      };

      global.fetch = vi.fn()
        .mockResolvedValueOnce({
          ok: true,
          json: vi.fn().mockResolvedValue({
            success: true,
            token: null,
            challenge: {
              id: 'challenge-1',
              problems: [123456],
              timeLimit: 10000,
              instructions: 'Solve',
            },
          }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: vi.fn().mockResolvedValue(verifyResponse),
        });

      const client = new BotchaClient();
      
      // First call - should fetch token
      const token1 = await client.getToken();
      expect(token1).toBe('cached.jwt.token');
      expect(global.fetch).toHaveBeenCalledTimes(2);
      
      // Second call - should use cached token
      const token2 = await client.getToken();
      expect(token2).toBe('cached.jwt.token');
      expect(global.fetch).toHaveBeenCalledTimes(2); // No additional calls
    });

    test('refreshes token when near expiry (within 5 minutes)', async () => {
      const firstToken = 'first.jwt.token';
      const secondToken = 'refreshed.jwt.token';

      global.fetch = vi.fn()
        // First token acquisition
        .mockResolvedValueOnce({
          ok: true,
          json: vi.fn().mockResolvedValue({
            success: true,
            token: null,
            challenge: { id: 'c1', problems: [123], timeLimit: 10000, instructions: 'Solve' },
          }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: vi.fn().mockResolvedValue({ success: true, token: firstToken, expiresIn: '1h' }),
        })
        // Second token acquisition (after manipulating expiry)
        .mockResolvedValueOnce({
          ok: true,
          json: vi.fn().mockResolvedValue({
            success: true,
            token: null,
            challenge: { id: 'c2', problems: [456], timeLimit: 10000, instructions: 'Solve' },
          }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: vi.fn().mockResolvedValue({ success: true, token: secondToken, expiresIn: '1h' }),
        });

      const client = new BotchaClient();
      
      // Get first token
      const token1 = await client.getToken();
      expect(token1).toBe(firstToken);
      
      // Manually set token to expire in 4 minutes (within refresh threshold)
      (client as any).tokenExpiresAt = Date.now() + 4 * 60 * 1000;
      
      // Should trigger refresh
      const token2 = await client.getToken();
      expect(token2).toBe(secondToken);
      expect(global.fetch).toHaveBeenCalledTimes(4);
    });

    test('throws error when challenge request fails', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 500,
        statusText: 'Internal Server Error',
      });

      const client = new BotchaClient();
      await expect(client.getToken()).rejects.toThrow(
        'Token request failed with status 500 Internal Server Error'
      );
    });

    test('throws error when no challenge provided', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: vi.fn().mockResolvedValue({
          success: true,
          token: null,
          // Missing challenge field
        }),
      });

      const client = new BotchaClient();
      await expect(client.getToken()).rejects.toThrow(
        'No challenge provided in token response'
      );
    });

    test('throws error when verification fails', async () => {
      global.fetch = vi.fn()
        .mockResolvedValueOnce({
          ok: true,
          json: vi.fn().mockResolvedValue({
            success: true,
            token: null,
            challenge: {
              id: 'challenge-1',
              problems: [123456],
              timeLimit: 10000,
              instructions: 'Solve',
            },
          }),
        })
        .mockResolvedValueOnce({
          ok: false,
          status: 400,
          statusText: 'Bad Request',
        });

      const client = new BotchaClient();
      await expect(client.getToken()).rejects.toThrow(
        'Token verification failed with status 400 Bad Request'
      );
    });

    test('throws error when verification returns no token', async () => {
      global.fetch = vi.fn()
        .mockResolvedValueOnce({
          ok: true,
          json: vi.fn().mockResolvedValue({
            success: true,
            token: null,
            challenge: {
              id: 'challenge-1',
              problems: [123456],
              timeLimit: 10000,
              instructions: 'Solve',
            },
          }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: vi.fn().mockResolvedValue({
            success: false,
            token: null,
          }),
        });

      const client = new BotchaClient();
      await expect(client.getToken()).rejects.toThrow(
        'Failed to obtain token from verification'
      );
    });

    test('handles invalid problems format', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: vi.fn().mockResolvedValue({
          success: true,
          token: null,
          challenge: {
            id: 'challenge-1',
            problems: ['invalid', 'format'], // Invalid format
            timeLimit: 10000,
            instructions: 'Solve',
          },
        }),
      });

      const client = new BotchaClient();
      await expect(client.getToken()).rejects.toThrow(
        'Invalid challenge problems format'
      );
    });
  });

  describe('clearToken()', () => {
    test('clears cached token and forces refresh', async () => {
      global.fetch = vi.fn()
        // First acquisition
        .mockResolvedValueOnce({
          ok: true,
          json: vi.fn().mockResolvedValue({
            success: true,
            token: null,
            challenge: { id: 'c1', problems: [123], timeLimit: 10000, instructions: 'Solve' },
          }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: vi.fn().mockResolvedValue({ success: true, token: 'first.token', expiresIn: '1h' }),
        })
        // Second acquisition after clear
        .mockResolvedValueOnce({
          ok: true,
          json: vi.fn().mockResolvedValue({
            success: true,
            token: null,
            challenge: { id: 'c2', problems: [456], timeLimit: 10000, instructions: 'Solve' },
          }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: vi.fn().mockResolvedValue({ success: true, token: 'second.token', expiresIn: '1h' }),
        });

      const client = new BotchaClient();
      
      // Get first token
      await client.getToken();
      expect(global.fetch).toHaveBeenCalledTimes(2);
      
      // Clear token
      client.clearToken();
      
      // Get token again - should fetch new one
      await client.getToken();
      expect(global.fetch).toHaveBeenCalledTimes(4);
    });
  });

  describe('fetch() with autoToken', () => {
    test('automatically adds Bearer token to requests when autoToken is enabled', async () => {
      const token = 'auto.jwt.token';
      
      global.fetch = vi.fn()
        // Token acquisition
        .mockResolvedValueOnce({
          ok: true,
          json: vi.fn().mockResolvedValue({
            success: true,
            token: null,
            challenge: { id: 'c1', problems: [123], timeLimit: 10000, instructions: 'Solve' },
          }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: vi.fn().mockResolvedValue({ success: true, token, expiresIn: '1h' }),
        })
        // Actual API request
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: vi.fn().mockResolvedValue({ data: 'success' }),
        });

      const client = new BotchaClient({ autoToken: true });
      const response = await client.fetch('https://api.example.com/protected');

      expect(response.status).toBe(200);
      expect(global.fetch).toHaveBeenCalledTimes(3);
      
      // Check that Bearer token was added
      const apiCall = (global.fetch as any).mock.calls[2];
      const headers = apiCall[1]?.headers;
      expect(headers.get('Authorization')).toBe(`Bearer ${token}`);
    });

    test('handles 401 by refreshing token and retrying', async () => {
      const firstToken = 'expired.token';
      const secondToken = 'fresh.token';
      
      global.fetch = vi.fn()
        // First token acquisition
        .mockResolvedValueOnce({
          ok: true,
          json: vi.fn().mockResolvedValue({
            success: true,
            token: null,
            challenge: { id: 'c1', problems: [123], timeLimit: 10000, instructions: 'Solve' },
          }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: vi.fn().mockResolvedValue({ success: true, token: firstToken, expiresIn: '1h' }),
        })
        // API request with expired token - returns 401
        .mockResolvedValueOnce({
          ok: false,
          status: 401,
        })
        // Token refresh
        .mockResolvedValueOnce({
          ok: true,
          json: vi.fn().mockResolvedValue({
            success: true,
            token: null,
            challenge: { id: 'c2', problems: [456], timeLimit: 10000, instructions: 'Solve' },
          }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: vi.fn().mockResolvedValue({ success: true, token: secondToken, expiresIn: '1h' }),
        })
        // Retry API request with fresh token
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: vi.fn().mockResolvedValue({ data: 'success after refresh' }),
        });

      const client = new BotchaClient({ autoToken: true });
      const response = await client.fetch('https://api.example.com/protected');

      expect(response.status).toBe(200);
      
      // Should have: 2 calls for first token + 1 failed API call + 2 calls for refresh + 1 retry = 6 total
      expect(global.fetch).toHaveBeenCalledTimes(6);
    });

    test('can disable autoToken via options', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: vi.fn().mockResolvedValue({ data: 'success' }),
      });

      const client = new BotchaClient({ autoToken: false });
      await client.fetch('https://api.example.com/public');

      // Should only make the API call, not acquire token
      expect(global.fetch).toHaveBeenCalledTimes(1);
      
      // Check that no Authorization header was added
      const apiCall = (global.fetch as any).mock.calls[0];
      const headers = apiCall[1]?.headers;
      expect(headers.get('Authorization')).toBeNull();
    });

    test('falls back to challenge headers when token acquisition fails', async () => {
      global.fetch = vi.fn()
        // Token acquisition fails
        .mockResolvedValueOnce({
          ok: false,
          status: 500,
          statusText: 'Internal Server Error',
        })
        // API request returns 403 with challenge
        .mockResolvedValueOnce({
          ok: false,
          status: 403,
          clone: vi.fn().mockReturnValue({
            json: vi.fn().mockResolvedValue({
              challenge: {
                id: 'fallback-challenge',
                problems: [{ num: 123456, operation: 'sha256_first8' }],
              },
            }),
          }),
        })
        // Retry with challenge headers succeeds
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: vi.fn().mockResolvedValue({ data: 'success via headers' }),
        });

      // Mock console.warn to suppress warning output in tests
      const consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

      const client = new BotchaClient({ autoToken: true });
      const response = await client.fetch('https://api.example.com/protected');

      expect(response.status).toBe(200);
      expect(consoleWarnSpy).toHaveBeenCalledWith(
        expect.stringContaining('Failed to acquire token'),
        expect.anything()
      );
      
      consoleWarnSpy.mockRestore();
    });

    test('uses custom baseUrl for token endpoints', async () => {
      const customBaseUrl = 'https://custom.botcha.ai';
      const token = 'custom.jwt.token';
      
      global.fetch = vi.fn()
        .mockResolvedValueOnce({
          ok: true,
          json: vi.fn().mockResolvedValue({
            success: true,
            token: null,
            challenge: { id: 'c1', problems: [123], timeLimit: 10000, instructions: 'Solve' },
          }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: vi.fn().mockResolvedValue({ success: true, token, expiresIn: '1h' }),
        });

      const client = new BotchaClient({ baseUrl: customBaseUrl });
      await client.getToken();

      // Verify custom baseUrl was used
      const firstCall = (global.fetch as any).mock.calls[0];
      expect(firstCall[0]).toBe(`${customBaseUrl}/v1/token`);
      
      const secondCall = (global.fetch as any).mock.calls[1];
      expect(secondCall[0]).toBe(`${customBaseUrl}/v1/token/verify`);
    });

    test('maintains backward compatibility with challenge header flow', async () => {
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
        // Token acquisition
        .mockResolvedValueOnce({
          ok: true,
          json: vi.fn().mockResolvedValue({
            success: true,
            token: null,
            challenge: { id: 'token-c', problems: [999], timeLimit: 10000, instructions: 'Solve' },
          }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: vi.fn().mockResolvedValue({ success: true, token: 'jwt.token', expiresIn: '1h' }),
        })
        // API returns 403 with challenge (token didn't work)
        .mockResolvedValueOnce(challengeResponse)
        // Retry with challenge headers
        .mockResolvedValueOnce(successResponse);

      const client = new BotchaClient({ autoToken: true });
      const response = await client.fetch('https://example.com');
      
      expect(response.status).toBe(200);
      expect(global.fetch).toHaveBeenCalledTimes(4);
    });
  });
});
