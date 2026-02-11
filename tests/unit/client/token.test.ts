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

      // Mock POST /v1/token/verify - returns JWT with new fields
      const verifyResponse = {
        verified: true,
        success: true,
        token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.token',
        access_token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.token',
        refresh_token: 'refresh.token.here',
        expires_in: 300,
        refresh_expires_in: 3600,
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
      
      // Verify refresh token is stored
      expect((client as any)._refreshToken).toBe('refresh.token.here');
      
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

    test('sends audience in verify request when configured', async () => {
      const challengeResponse = {
        success: true,
        token: null,
        challenge: {
          id: 'token-challenge-123',
          problems: [{ num: 123456, operation: 'sha256_first8' }],
          timeLimit: 10000,
          instructions: 'Solve to get token',
        },
      };

      const verifyResponse = {
        verified: true,
        access_token: 'token.with.audience',
        refresh_token: 'refresh.token',
        expires_in: 300,
      };

      global.fetch = vi.fn()
        .mockResolvedValueOnce({
          ok: true,
          json: vi.fn().mockResolvedValue(challengeResponse),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: vi.fn().mockResolvedValue(verifyResponse),
        });

      const client = new BotchaClient({ audience: 'api.example.com' });
      await client.getToken();

      // Verify audience was sent in verify request
      const verifyCall = (global.fetch as any).mock.calls[1];
      const body = JSON.parse(verifyCall[1]?.body);
      expect(body.audience).toBe('api.example.com');
    });

    test('does not send audience when not configured', async () => {
      const challengeResponse = {
        success: true,
        token: null,
        challenge: {
          id: 'token-challenge-123',
          problems: [{ num: 123456, operation: 'sha256_first8' }],
          timeLimit: 10000,
          instructions: 'Solve to get token',
        },
      };

      const verifyResponse = {
        verified: true,
        access_token: 'token.without.audience',
        expires_in: 300,
      };

      global.fetch = vi.fn()
        .mockResolvedValueOnce({
          ok: true,
          json: vi.fn().mockResolvedValue(challengeResponse),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: vi.fn().mockResolvedValue(verifyResponse),
        });

      const client = new BotchaClient();
      await client.getToken();

      // Verify audience was NOT sent in verify request
      const verifyCall = (global.fetch as any).mock.calls[1];
      const body = JSON.parse(verifyCall[1]?.body);
      expect(body.audience).toBeUndefined();
    });

    test('caches token and reuses it within validity period', async () => {
      const verifyResponse = {
        verified: true,
        access_token: 'cached.jwt.token',
        refresh_token: 'refresh.token',
        expires_in: 300,
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

    test('refreshes token when near expiry (within 1 minute)', async () => {
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
          json: vi.fn().mockResolvedValue({ 
            verified: true,
            access_token: firstToken, 
            refresh_token: 'refresh.token',
            expires_in: 300
          }),
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
          json: vi.fn().mockResolvedValue({ 
            verified: true,
            access_token: secondToken,
            refresh_token: 'refresh.token.2',
            expires_in: 300
          }),
        });

      const client = new BotchaClient();
      
      // Get first token
      const token1 = await client.getToken();
      expect(token1).toBe(firstToken);
      
      // Manually set token to expire in 30 seconds (within refresh threshold of 1 minute)
      (client as any).tokenExpiresAt = Date.now() + 30 * 1000;
      
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

  describe('refreshToken()', () => {
    test('successfully refreshes token using refresh token', async () => {
      // First, get initial token with refresh token
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
          json: vi.fn().mockResolvedValue({
            verified: true,
            access_token: 'initial.access.token',
            refresh_token: 'valid.refresh.token',
            expires_in: 300,
          }),
        })
        // Mock refresh endpoint
        .mockResolvedValueOnce({
          ok: true,
          json: vi.fn().mockResolvedValue({
            access_token: 'new.access.token',
            expires_in: 300,
          }),
        });

      const client = new BotchaClient();
      
      // Get initial token
      await client.getToken();
      
      // Refresh token
      const newToken = await client.refreshToken();
      
      expect(newToken).toBe('new.access.token');
      expect(global.fetch).toHaveBeenCalledTimes(3);
      
      // Verify refresh endpoint was called correctly
      const refreshCall = (global.fetch as any).mock.calls[2];
      expect(refreshCall[0]).toContain('/v1/token/refresh');
      expect(refreshCall[1]?.method).toBe('POST');
      
      const body = JSON.parse(refreshCall[1]?.body);
      expect(body.refresh_token).toBe('valid.refresh.token');
    });

    test('throws error when no refresh token available', async () => {
      const client = new BotchaClient();
      
      await expect(client.refreshToken()).rejects.toThrow(
        'No refresh token available. Call getToken() first.'
      );
    });

    test('throws error when refresh endpoint returns error', async () => {
      // First, get initial token with refresh token
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
          json: vi.fn().mockResolvedValue({
            verified: true,
            access_token: 'initial.access.token',
            refresh_token: 'invalid.refresh.token',
            expires_in: 300,
          }),
        })
        // Mock refresh endpoint failing
        .mockResolvedValueOnce({
          ok: false,
          status: 401,
          statusText: 'Unauthorized',
        });

      const client = new BotchaClient();
      
      // Get initial token
      await client.getToken();
      
      // Try to refresh - should fail
      await expect(client.refreshToken()).rejects.toThrow(
        'Token refresh failed with status 401 Unauthorized'
      );
    });

    test('updates cached token after successful refresh', async () => {
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
          json: vi.fn().mockResolvedValue({
            verified: true,
            access_token: 'initial.token',
            refresh_token: 'refresh.token',
            expires_in: 300,
          }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: vi.fn().mockResolvedValue({
            access_token: 'refreshed.token',
            expires_in: 300,
          }),
        });

      const client = new BotchaClient();
      
      const token1 = await client.getToken();
      expect(token1).toBe('initial.token');
      
      await client.refreshToken();
      
      // Verify cached token was updated
      expect((client as any).cachedToken).toBe('refreshed.token');
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
          json: vi.fn().mockResolvedValue({ 
            verified: true,
            access_token: 'first.token',
            refresh_token: 'first.refresh',
            expires_in: 300
          }),
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
          json: vi.fn().mockResolvedValue({ 
            verified: true,
            access_token: 'second.token',
            refresh_token: 'second.refresh',
            expires_in: 300
          }),
        });

      const client = new BotchaClient();
      
      // Get first token
      await client.getToken();
      expect(global.fetch).toHaveBeenCalledTimes(2);
      expect((client as any)._refreshToken).toBe('first.refresh');
      
      // Clear token
      client.clearToken();
      
      // Verify both tokens are cleared
      expect((client as any).cachedToken).toBeNull();
      expect((client as any)._refreshToken).toBeNull();
      expect((client as any).tokenExpiresAt).toBeNull();
      
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
          json: vi.fn().mockResolvedValue({ 
            verified: true,
            access_token: token,
            refresh_token: 'refresh.token',
            expires_in: 300
          }),
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

    test('handles 401 by using refresh token first, then retrying', async () => {
      const firstToken = 'expired.token';
      const refreshedToken = 'refreshed.token';
      
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
          json: vi.fn().mockResolvedValue({ 
            verified: true,
            access_token: firstToken,
            refresh_token: 'valid.refresh.token',
            expires_in: 300
          }),
        })
        // API request with expired token - returns 401
        .mockResolvedValueOnce({
          ok: false,
          status: 401,
        })
        // Token refresh using refresh token
        .mockResolvedValueOnce({
          ok: true,
          json: vi.fn().mockResolvedValue({
            access_token: refreshedToken,
            expires_in: 300,
          }),
        })
        // Retry API request with refreshed token
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: vi.fn().mockResolvedValue({ data: 'success after refresh' }),
        });

      const client = new BotchaClient({ autoToken: true });
      const response = await client.fetch('https://api.example.com/protected');

      expect(response.status).toBe(200);
      
      // Should have: 2 calls for initial token + 1 failed API call + 1 refresh call + 1 retry = 5 total
      expect(global.fetch).toHaveBeenCalledTimes(5);
      
      // Verify refresh endpoint was used (not full re-verify)
      const refreshCall = (global.fetch as any).mock.calls[3];
      expect(refreshCall[0]).toContain('/v1/token/refresh');
    });

    test('handles 401 by doing full re-verify when refresh token fails', async () => {
      const firstToken = 'expired.token';
      const newToken = 'new.token';
      
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
          json: vi.fn().mockResolvedValue({ 
            verified: true,
            access_token: firstToken,
            refresh_token: 'invalid.refresh.token',
            expires_in: 300
          }),
        })
        // API request with expired token - returns 401
        .mockResolvedValueOnce({
          ok: false,
          status: 401,
        })
        // Token refresh fails
        .mockResolvedValueOnce({
          ok: false,
          status: 401,
          statusText: 'Unauthorized',
        })
        // Full re-verify flow
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
          json: vi.fn().mockResolvedValue({ 
            verified: true,
            access_token: newToken,
            refresh_token: 'new.refresh.token',
            expires_in: 300
          }),
        })
        // Retry API request with new token
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: vi.fn().mockResolvedValue({ data: 'success after full re-verify' }),
        });

      const client = new BotchaClient({ autoToken: true });
      const response = await client.fetch('https://api.example.com/protected');

      expect(response.status).toBe(200);
      
      // Should have: 2 calls for initial token + 1 failed API call + 1 failed refresh + 2 calls for re-verify + 1 retry = 7 total
      expect(global.fetch).toHaveBeenCalledTimes(7);
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
          json: vi.fn().mockResolvedValue({ 
            verified: true,
            access_token: token,
            refresh_token: 'refresh.token',
            expires_in: 300
          }),
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
          json: vi.fn().mockResolvedValue({ 
            verified: true,
            access_token: 'jwt.token',
            refresh_token: 'refresh.token',
            expires_in: 300
          }),
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
