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

    test('accepts appId option', () => {
      const client = new BotchaClient({
        appId: 'test-app-123',
      });
      
      expect((client as any).appId).toBe('test-app-123');
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

    test('includes X-Botcha-App-Id header when appId is set', async () => {
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

      const client = new BotchaClient({ appId: 'test-app-123' });
      const headers = await client.createHeaders();
      
      expect(headers).toHaveProperty('X-Botcha-App-Id');
      expect(headers['X-Botcha-App-Id']).toBe('test-app-123');
    });

    test('does not include X-Botcha-App-Id header when appId is not set', async () => {
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
      
      expect(headers).not.toHaveProperty('X-Botcha-App-Id');
    });
  });

  describe('appId support', () => {
    test('appId is passed as query param in getToken()', async () => {
      const fetchMock = vi.fn()
        .mockResolvedValueOnce({
          status: 200,
          ok: true,
          json: vi.fn().mockResolvedValue({
            challenge: {
              id: 'test-challenge-id',
              problems: [{ num: 123456, operation: 'sha256_first8' }],
              timeLimit: 10000,
            },
          }),
        })
        .mockResolvedValueOnce({
          status: 200,
          ok: true,
          json: vi.fn().mockResolvedValue({
            success: true,
            verified: true,
            access_token: 'test-token',
            expires_in: 300,
          }),
        });

      global.fetch = fetchMock;

      const client = new BotchaClient({ appId: 'test-app-123' });
      await client.getToken();

      // Check first call (GET /v1/token)
      expect(fetchMock.mock.calls[0][0]).toContain('app_id=test-app-123');
    });

    test('appId is passed in POST /v1/token/verify body', async () => {
      const fetchMock = vi.fn()
        .mockResolvedValueOnce({
          status: 200,
          ok: true,
          json: vi.fn().mockResolvedValue({
            challenge: {
              id: 'test-challenge-id',
              problems: [{ num: 123456, operation: 'sha256_first8' }],
              timeLimit: 10000,
            },
          }),
        })
        .mockResolvedValueOnce({
          status: 200,
          ok: true,
          json: vi.fn().mockResolvedValue({
            success: true,
            verified: true,
            access_token: 'test-token',
            expires_in: 300,
          }),
        });

      global.fetch = fetchMock;

      const client = new BotchaClient({ appId: 'test-app-123' });
      await client.getToken();

      // Check second call (POST /v1/token/verify)
      const verifyCall = fetchMock.mock.calls[1];
      const body = JSON.parse(verifyCall[1].body);
      expect(body.app_id).toBe('test-app-123');
    });

    test('appId is passed as query param in solveChallenge()', async () => {
      const fetchMock = vi.fn().mockResolvedValue({
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

      global.fetch = fetchMock;

      const client = new BotchaClient({ appId: 'test-app-123' });
      await client.solveChallenge();

      expect(fetchMock.mock.calls[0][0]).toContain('app_id=test-app-123');
    });

    test('backward compatibility: no appId means no query param', async () => {
      const fetchMock = vi.fn()
        .mockResolvedValueOnce({
          status: 200,
          ok: true,
          json: vi.fn().mockResolvedValue({
            challenge: {
              id: 'test-challenge-id',
              problems: [{ num: 123456, operation: 'sha256_first8' }],
              timeLimit: 10000,
            },
          }),
        })
        .mockResolvedValueOnce({
          status: 200,
          ok: true,
          json: vi.fn().mockResolvedValue({
            success: true,
            verified: true,
            access_token: 'test-token',
            expires_in: 300,
          }),
        });

      global.fetch = fetchMock;

      const client = new BotchaClient();
      await client.getToken();

      // Check first call - should NOT contain app_id
      expect(fetchMock.mock.calls[0][0]).not.toContain('app_id');
      
      // Check second call - body should NOT contain app_id
      const verifyCall = fetchMock.mock.calls[1];
      const body = JSON.parse(verifyCall[1].body);
      expect(body.app_id).toBeUndefined();
    });
  });

  describe('createApp()', () => {
    test('creates app and auto-sets appId', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        status: 201,
        ok: true,
        json: vi.fn().mockResolvedValue({
          success: true,
          app_id: 'app_test123',
          app_secret: 'sk_secret',
          email: 'agent@example.com',
          email_verified: false,
          verification_required: true,
          warning: 'Save your secret!',
          credential_advice: 'Store securely.',
          created_at: '2026-01-01T00:00:00Z',
          rate_limit: 100,
          next_step: 'POST /v1/apps/app_test123/verify-email',
        }),
      });

      const client = new BotchaClient();
      const result = await client.createApp('agent@example.com');

      expect(result.success).toBe(true);
      expect(result.app_id).toBe('app_test123');
      expect(result.app_secret).toBe('sk_secret');
      expect(result.email).toBe('agent@example.com');
      expect(result.email_verified).toBe(false);
      // appId should be auto-set
      expect((client as any).appId).toBe('app_test123');

      // Verify POST body
      const call = (global.fetch as any).mock.calls[0];
      expect(call[0]).toContain('/v1/apps');
      expect(call[1].method).toBe('POST');
      const body = JSON.parse(call[1].body);
      expect(body.email).toBe('agent@example.com');
    });

    test('throws on missing email (400)', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        status: 400,
        ok: false,
        json: vi.fn().mockResolvedValue({
          success: false,
          error: 'MISSING_EMAIL',
          message: 'Email is required',
        }),
      });

      const client = new BotchaClient();
      await expect(client.createApp('')).rejects.toThrow('Email is required');
    });
  });

  describe('verifyEmail()', () => {
    test('verifies email with code', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        status: 200,
        ok: true,
        json: vi.fn().mockResolvedValue({
          success: true,
          email_verified: true,
        }),
      });

      const client = new BotchaClient({ appId: 'app_test123' });
      const result = await client.verifyEmail('123456');

      expect(result.success).toBe(true);
      expect(result.email_verified).toBe(true);

      const call = (global.fetch as any).mock.calls[0];
      expect(call[0]).toContain('/v1/apps/app_test123/verify-email');
      const body = JSON.parse(call[1].body);
      expect(body.code).toBe('123456');
    });

    test('throws when no appId set', async () => {
      const client = new BotchaClient();
      await expect(client.verifyEmail('123456')).rejects.toThrow('No app ID');
    });

    test('accepts explicit appId override', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        status: 200,
        ok: true,
        json: vi.fn().mockResolvedValue({ success: true, email_verified: true }),
      });

      const client = new BotchaClient({ appId: 'app_default' });
      await client.verifyEmail('123456', 'app_override');

      const call = (global.fetch as any).mock.calls[0];
      expect(call[0]).toContain('/v1/apps/app_override/verify-email');
    });
  });

  describe('resendVerification()', () => {
    test('resends verification email', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        status: 200,
        ok: true,
        json: vi.fn().mockResolvedValue({
          success: true,
          message: 'Verification code sent',
        }),
      });

      const client = new BotchaClient({ appId: 'app_test123' });
      const result = await client.resendVerification();

      expect(result.success).toBe(true);

      const call = (global.fetch as any).mock.calls[0];
      expect(call[0]).toContain('/v1/apps/app_test123/resend-verification');
      expect(call[1].method).toBe('POST');
    });

    test('throws when no appId set', async () => {
      const client = new BotchaClient();
      await expect(client.resendVerification()).rejects.toThrow('No app ID');
    });
  });

  describe('recoverAccount()', () => {
    test('sends recovery request', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        status: 200,
        ok: true,
        json: vi.fn().mockResolvedValue({
          success: true,
          message: 'If this email is registered, a recovery code has been sent.',
        }),
      });

      const client = new BotchaClient();
      const result = await client.recoverAccount('agent@example.com');

      expect(result.success).toBe(true);
      expect(result.message).toContain('recovery code');

      const call = (global.fetch as any).mock.calls[0];
      expect(call[0]).toContain('/v1/auth/recover');
      const body = JSON.parse(call[1].body);
      expect(body.email).toBe('agent@example.com');
    });
  });

  describe('rotateSecret()', () => {
    test('rotates secret with Bearer token', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        status: 200,
        ok: true,
        json: vi.fn().mockResolvedValue({
          success: true,
          app_id: 'app_test123',
          app_secret: 'sk_new_secret',
          warning: 'Save your new secret!',
          rotated_at: '2026-01-01T00:00:00Z',
        }),
      });

      const client = new BotchaClient({ appId: 'app_test123' });
      // Simulate having a cached token
      (client as any).cachedToken = 'session-token-xyz';

      const result = await client.rotateSecret();

      expect(result.success).toBe(true);
      expect(result.app_secret).toBe('sk_new_secret');

      const call = (global.fetch as any).mock.calls[0];
      expect(call[0]).toContain('/v1/apps/app_test123/rotate-secret');
      expect(call[1].headers['Authorization']).toBe('Bearer session-token-xyz');
    });

    test('throws when no appId set', async () => {
      const client = new BotchaClient();
      await expect(client.rotateSecret()).rejects.toThrow('No app ID');
    });

    test('throws on auth failure (401)', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        status: 401,
        ok: false,
        json: vi.fn().mockResolvedValue({
          success: false,
          message: 'Authentication required',
        }),
      });

      const client = new BotchaClient({ appId: 'app_test123' });
      await expect(client.rotateSecret()).rejects.toThrow('Authentication required');
    });
  });

  // ============ JWKS & KEY MANAGEMENT ============

  describe('getJWKS()', () => {
    test('fetches JWKS from well-known endpoint', async () => {
      const mockJWKS = {
        keys: [
          { kty: 'EC', kid: 'agent_abc123', alg: 'ES256', crv: 'P-256', x: 'x-val', y: 'y-val' },
          { kty: 'OKP', kid: 'agent_def456', alg: 'EdDSA', crv: 'Ed25519', x: 'x-val' },
        ],
      };

      global.fetch = vi.fn().mockResolvedValue({
        status: 200,
        ok: true,
        json: vi.fn().mockResolvedValue(mockJWKS),
      });

      const client = new BotchaClient();
      const result = await client.getJWKS();

      expect(result.keys).toHaveLength(2);
      expect(result.keys[0].kid).toBe('agent_abc123');
      expect(result.keys[1].alg).toBe('EdDSA');

      const call = (global.fetch as any).mock.calls[0];
      expect(call[0]).toContain('/.well-known/jwks');
    });

    test('includes app_id query param when set', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        status: 200,
        ok: true,
        json: vi.fn().mockResolvedValue({ keys: [] }),
      });

      const client = new BotchaClient({ appId: 'app_test123' });
      await client.getJWKS();

      const call = (global.fetch as any).mock.calls[0];
      expect(call[0]).toContain('app_id=app_test123');
    });

    test('explicit appId overrides client appId', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        status: 200,
        ok: true,
        json: vi.fn().mockResolvedValue({ keys: [] }),
      });

      const client = new BotchaClient({ appId: 'app_default' });
      await client.getJWKS('app_override');

      const call = (global.fetch as any).mock.calls[0];
      expect(call[0]).toContain('app_id=app_override');
      expect(call[0]).not.toContain('app_default');
    });

    test('throws on server error', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        status: 500,
        ok: false,
        json: vi.fn().mockResolvedValue({ message: 'Internal error' }),
      });

      const client = new BotchaClient();
      await expect(client.getJWKS()).rejects.toThrow('Internal error');
    });
  });

  describe('getKeyById()', () => {
    test('fetches a specific key by ID', async () => {
      const mockKey = {
        kty: 'EC', kid: 'agent_abc123', alg: 'ES256', crv: 'P-256', x: 'x-val', y: 'y-val',
      };

      global.fetch = vi.fn().mockResolvedValue({
        status: 200,
        ok: true,
        json: vi.fn().mockResolvedValue(mockKey),
      });

      const client = new BotchaClient();
      const result = await client.getKeyById('agent_abc123');

      expect(result.kid).toBe('agent_abc123');
      expect(result.alg).toBe('ES256');

      const call = (global.fetch as any).mock.calls[0];
      expect(call[0]).toContain('/v1/keys/agent_abc123');
    });

    test('URL-encodes key IDs with special characters', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        status: 200,
        ok: true,
        json: vi.fn().mockResolvedValue({ kty: 'EC', kid: 'agent/special' }),
      });

      const client = new BotchaClient();
      await client.getKeyById('agent/special');

      const call = (global.fetch as any).mock.calls[0];
      expect(call[0]).toContain('/v1/keys/agent%2Fspecial');
    });

    test('throws on 404', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        status: 404,
        ok: false,
        json: vi.fn().mockResolvedValue({ message: 'Key not found' }),
      });

      const client = new BotchaClient();
      await expect(client.getKeyById('nonexistent')).rejects.toThrow('Key not found');
    });
  });

  describe('rotateAgentKey()', () => {
    test('posts key rotation request with Bearer token', async () => {
      const mockAgent = {
        success: true,
        agent_id: 'agent_abc123',
        public_key: '-----BEGIN PUBLIC KEY-----\nNEWKEY\n-----END PUBLIC KEY-----',
        signature_algorithm: 'ecdsa-p256-sha256',
      };

      global.fetch = vi.fn().mockResolvedValue({
        status: 200,
        ok: true,
        json: vi.fn().mockResolvedValue(mockAgent),
      });

      const client = new BotchaClient();
      (client as any).cachedToken = 'bearer-token-xyz';

      const result = await client.rotateAgentKey('agent_abc123', {
        public_key: '-----BEGIN PUBLIC KEY-----\nNEWKEY\n-----END PUBLIC KEY-----',
        signature_algorithm: 'ecdsa-p256-sha256',
        key_expires_at: '2027-01-01T00:00:00Z',
      });

      expect(result.success).toBe(true);
      expect(result.agent_id).toBe('agent_abc123');

      const call = (global.fetch as any).mock.calls[0];
      expect(call[0]).toContain('/v1/agents/agent_abc123/tap/rotate-key');
      expect(call[1].headers['Authorization']).toBe('Bearer bearer-token-xyz');

      const body = JSON.parse(call[1].body);
      expect(body.public_key).toContain('NEWKEY');
      expect(body.signature_algorithm).toBe('ecdsa-p256-sha256');
      expect(body.key_expires_at).toBe('2027-01-01T00:00:00Z');
    });

    test('works with Ed25519 algorithm', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        status: 200,
        ok: true,
        json: vi.fn().mockResolvedValue({
          success: true,
          agent_id: 'agent_ed25519',
          signature_algorithm: 'ed25519',
        }),
      });

      const client = new BotchaClient();
      const result = await client.rotateAgentKey('agent_ed25519', {
        public_key: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo=',
        signature_algorithm: 'ed25519',
      });

      expect(result.signature_algorithm).toBe('ed25519');
    });

    test('throws on 403', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        status: 403,
        ok: false,
        json: vi.fn().mockResolvedValue({ message: 'Not authorized to rotate this key' }),
      });

      const client = new BotchaClient();
      await expect(
        client.rotateAgentKey('agent_other', {
          public_key: 'key',
          signature_algorithm: 'ecdsa-p256-sha256',
        })
      ).rejects.toThrow('Not authorized');
    });
  });

  // ============ INVOICE & PAYMENT (402 Flow) ============

  describe('createInvoice()', () => {
    test('creates invoice with all required fields', async () => {
      const mockInvoice = {
        success: true,
        invoice_id: 'inv_abc123',
        resource_uri: 'https://example.com/premium',
        amount: '500',
        currency: 'USD',
        card_acceptor_id: 'CAID_ABC',
        status: 'pending',
        expires_at: '2026-02-14T22:00:00Z',
      };

      global.fetch = vi.fn().mockResolvedValue({
        status: 200,
        ok: true,
        json: vi.fn().mockResolvedValue(mockInvoice),
      });

      const client = new BotchaClient();
      const result = await client.createInvoice({
        resource_uri: 'https://example.com/premium',
        amount: '500',
        currency: 'USD',
        card_acceptor_id: 'CAID_ABC',
        description: 'Premium article',
        ttl_seconds: 3600,
      });

      expect(result.invoice_id).toBe('inv_abc123');
      expect(result.amount).toBe('500');
      expect(result.status).toBe('pending');

      const call = (global.fetch as any).mock.calls[0];
      expect(call[0]).toContain('/v1/invoices');
      expect(call[1].method).toBe('POST');

      const body = JSON.parse(call[1].body);
      expect(body.resource_uri).toBe('https://example.com/premium');
      expect(body.card_acceptor_id).toBe('CAID_ABC');
      expect(body.description).toBe('Premium article');
      expect(body.ttl_seconds).toBe(3600);
    });

    test('attaches Bearer token when authenticated', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        status: 200,
        ok: true,
        json: vi.fn().mockResolvedValue({ success: true, invoice_id: 'inv_auth' }),
      });

      const client = new BotchaClient();
      (client as any).cachedToken = 'my-token';

      await client.createInvoice({
        resource_uri: 'https://example.com/gated',
        amount: '100',
        currency: 'USD',
        card_acceptor_id: 'CAID_XYZ',
      });

      const call = (global.fetch as any).mock.calls[0];
      expect(call[1].headers['Authorization']).toBe('Bearer my-token');
    });

    test('throws on 400', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        status: 400,
        ok: false,
        json: vi.fn().mockResolvedValue({ message: 'Missing required field: amount' }),
      });

      const client = new BotchaClient();
      await expect(
        client.createInvoice({
          resource_uri: 'https://example.com',
          amount: '',
          currency: 'USD',
          card_acceptor_id: 'CAID',
        })
      ).rejects.toThrow('Missing required field');
    });
  });

  describe('getInvoice()', () => {
    test('fetches invoice by ID', async () => {
      const mockInvoice = {
        invoice_id: 'inv_abc123',
        status: 'pending',
        amount: '500',
        currency: 'USD',
        resource_uri: 'https://example.com/premium',
        expires_at: '2026-02-14T22:00:00Z',
      };

      global.fetch = vi.fn().mockResolvedValue({
        status: 200,
        ok: true,
        json: vi.fn().mockResolvedValue(mockInvoice),
      });

      const client = new BotchaClient();
      const result = await client.getInvoice('inv_abc123');

      expect(result.invoice_id).toBe('inv_abc123');
      expect(result.status).toBe('pending');

      const call = (global.fetch as any).mock.calls[0];
      expect(call[0]).toContain('/v1/invoices/inv_abc123');
    });

    test('URL-encodes invoice IDs', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        status: 200,
        ok: true,
        json: vi.fn().mockResolvedValue({ invoice_id: 'inv/special' }),
      });

      const client = new BotchaClient();
      await client.getInvoice('inv/special');

      const call = (global.fetch as any).mock.calls[0];
      expect(call[0]).toContain('/v1/invoices/inv%2Fspecial');
    });

    test('throws on 404', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        status: 404,
        ok: false,
        json: vi.fn().mockResolvedValue({ message: 'Invoice not found' }),
      });

      const client = new BotchaClient();
      await expect(client.getInvoice('nonexistent')).rejects.toThrow('Invoice not found');
    });
  });

  describe('verifyBrowsingIOU()', () => {
    test('verifies valid IOU and returns access token', async () => {
      const mockResult = {
        verified: true,
        access_token: 'access_token_xyz',
        expires_in: 3600,
      };

      global.fetch = vi.fn().mockResolvedValue({
        status: 200,
        ok: true,
        json: vi.fn().mockResolvedValue(mockResult),
      });

      const client = new BotchaClient();
      const iou = {
        invoiceId: 'inv_abc123',
        amount: '500',
        cardAcceptorId: 'CAID_ABC',
        acquirerId: 'ACQ_XYZ',
        uri: 'https://example.com/premium',
        sequenceCounter: '1',
        paymentService: 'agent-pay',
        kid: 'agent_def456',
        alg: 'ES256',
        signature: 'base64-signature-here',
      };

      const result = await client.verifyBrowsingIOU('inv_abc123', iou);

      expect(result.verified).toBe(true);
      expect(result.access_token).toBe('access_token_xyz');

      const call = (global.fetch as any).mock.calls[0];
      expect(call[0]).toContain('/v1/invoices/inv_abc123/verify-iou');
      expect(call[1].method).toBe('POST');

      const body = JSON.parse(call[1].body);
      expect(body.invoiceId).toBe('inv_abc123');
      expect(body.amount).toBe('500');
      expect(body.signature).toBe('base64-signature-here');
    });

    test('handles rejected IOU', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        status: 200,
        ok: true,
        json: vi.fn().mockResolvedValue({
          verified: false,
          error: 'Amount mismatch',
        }),
      });

      const client = new BotchaClient();
      const result = await client.verifyBrowsingIOU('inv_abc123', {
        invoiceId: 'inv_abc123',
        amount: '999',
        cardAcceptorId: 'CAID_ABC',
        acquirerId: 'ACQ_XYZ',
        uri: 'https://example.com',
        sequenceCounter: '1',
        paymentService: 'agent-pay',
        kid: 'agent_def456',
        alg: 'ES256',
        signature: 'bad-sig',
      });

      expect(result.verified).toBe(false);
      expect(result.error).toBe('Amount mismatch');
    });

    test('throws on server error', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        status: 500,
        ok: false,
        json: vi.fn().mockResolvedValue({ message: 'Internal server error' }),
      });

      const client = new BotchaClient();
      await expect(
        client.verifyBrowsingIOU('inv_abc123', {
          invoiceId: 'inv_abc123',
          amount: '500',
          cardAcceptorId: 'CAID',
          acquirerId: 'ACQ',
          uri: 'https://example.com',
          sequenceCounter: '1',
          paymentService: 'agent-pay',
          kid: 'agent_x',
          alg: 'ES256',
          signature: 'sig',
        })
      ).rejects.toThrow('Internal server error');
    });
  });
});
