/**
 * Tests for BOTCHA Express middleware
 */

import { describe, it, expect, vi } from 'vitest';
import { SignJWT } from 'jose';
import { botchaVerify } from '../src/middleware/express.js';
import type { Request, Response, NextFunction } from 'express';

const TEST_SECRET = 'test-secret-key-min-32-chars-long-for-hs256';
const TEST_AUDIENCE = 'https://api.example.com';
const TEST_CLIENT_IP = '192.168.1.1';

/**
 * Helper to create test tokens using jose
 */
async function createTestToken(
  payload: Record<string, any>,
  secret: string = TEST_SECRET,
  expiresIn: string = '5m'
): Promise<string> {
  const encoder = new TextEncoder();
  const secretKey = encoder.encode(secret);

  const jwt = new SignJWT(payload)
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime(expiresIn);

  if (payload.sub) {
    jwt.setSubject(payload.sub);
  }

  return await jwt.sign(secretKey);
}

/**
 * Create mock Express request/response/next
 */
function createMocks() {
  const req = {
    headers: {} as Record<string, string | string[]>,
    ip: '127.0.0.1',
    botcha: undefined,
  } as Request;

  const res = {
    status: vi.fn().mockReturnThis(),
    json: vi.fn().mockReturnThis(),
  } as unknown as Response;

  const next = vi.fn() as NextFunction;

  return { req, res, next };
}

describe('Express botchaVerify middleware', () => {
  describe('Valid tokens', () => {
    it('should verify valid token and call next()', async () => {
      const token = await createTestToken({
        sub: 'challenge-123',
        type: 'botcha-verified',
        jti: 'token-id-123',
        solveTime: 1500,
      });

      const { req, res, next } = createMocks();
      req.headers.authorization = `Bearer ${token}`;

      const middleware = botchaVerify({ secret: TEST_SECRET });
      await middleware(req, res, next);

      expect(next).toHaveBeenCalledOnce();
      expect(req.botcha).toBeDefined();
      expect(req.botcha?.sub).toBe('challenge-123');
      expect(req.botcha?.solveTime).toBe(1500);
      expect(res.status).not.toHaveBeenCalled();
    });

    it('should verify token with audience claim', async () => {
      const token = await createTestToken({
        sub: 'challenge-123',
        type: 'botcha-verified',
        jti: 'token-id-123',
        solveTime: 1500,
        aud: TEST_AUDIENCE,
      });

      const { req, res, next } = createMocks();
      req.headers.authorization = `Bearer ${token}`;

      const middleware = botchaVerify({
        secret: TEST_SECRET,
        audience: TEST_AUDIENCE,
      });
      await middleware(req, res, next);

      expect(next).toHaveBeenCalledOnce();
      expect(req.botcha?.aud).toBe(TEST_AUDIENCE);
    });

    it('should verify token with client IP', async () => {
      const token = await createTestToken({
        sub: 'challenge-123',
        type: 'botcha-verified',
        jti: 'token-id-123',
        solveTime: 1500,
        client_ip: TEST_CLIENT_IP,
      });

      const { req, res, next } = createMocks();
      req.headers.authorization = `Bearer ${token}`;
      Object.defineProperty(req, 'ip', { value: TEST_CLIENT_IP, writable: true });

      const middleware = botchaVerify({
        secret: TEST_SECRET,
        requireIp: true,
      });
      await middleware(req, res, next);

      expect(next).toHaveBeenCalledOnce();
      expect(req.botcha?.client_ip).toBe(TEST_CLIENT_IP);
    });

    it('should extract IP from X-Forwarded-For header', async () => {
      const token = await createTestToken({
        sub: 'challenge-123',
        type: 'botcha-verified',
        jti: 'token-id-123',
        solveTime: 1500,
        client_ip: '203.0.113.1',
      });

      const { req, res, next } = createMocks();
      req.headers.authorization = `Bearer ${token}`;
      req.headers['x-forwarded-for'] = '203.0.113.1, 198.51.100.1';

      const middleware = botchaVerify({
        secret: TEST_SECRET,
        requireIp: true,
      });
      await middleware(req, res, next);

      expect(next).toHaveBeenCalledOnce();
    });

    it('should extract IP from X-Real-IP header', async () => {
      const token = await createTestToken({
        sub: 'challenge-123',
        type: 'botcha-verified',
        jti: 'token-id-123',
        solveTime: 1500,
        client_ip: '203.0.113.1',
      });

      const { req, res, next } = createMocks();
      req.headers.authorization = `Bearer ${token}`;
      req.headers['x-real-ip'] = '203.0.113.1';

      const middleware = botchaVerify({
        secret: TEST_SECRET,
        requireIp: true,
      });
      await middleware(req, res, next);

      expect(next).toHaveBeenCalledOnce();
    });
  });

  describe('Invalid tokens', () => {
    it('should return 401 for missing Authorization header', async () => {
      const { req, res, next } = createMocks();
      // No authorization header

      const middleware = botchaVerify({ secret: TEST_SECRET });
      await middleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({
        error: 'Unauthorized',
        message: 'Missing Authorization header with Bearer token',
      });
      expect(next).not.toHaveBeenCalled();
    });

    it('should return 401 for malformed Authorization header', async () => {
      const { req, res, next } = createMocks();
      req.headers.authorization = 'Basic abc123';

      const middleware = botchaVerify({ secret: TEST_SECRET });
      await middleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({
        error: 'Unauthorized',
        message: 'Missing Authorization header with Bearer token',
      });
      expect(next).not.toHaveBeenCalled();
    });

    it('should return 401 for invalid token', async () => {
      const { req, res, next } = createMocks();
      req.headers.authorization = 'Bearer invalid-token';

      const middleware = botchaVerify({ secret: TEST_SECRET });
      await middleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalled();
      expect(next).not.toHaveBeenCalled();
    });

    it('should return 401 for expired token', async () => {
      const token = await createTestToken(
        {
          sub: 'challenge-123',
          type: 'botcha-verified',
          jti: 'token-id-123',
          solveTime: 1500,
        },
        TEST_SECRET,
        '0s'
      );

      await new Promise((resolve) => setTimeout(resolve, 100));

      const { req, res, next } = createMocks();
      req.headers.authorization = `Bearer ${token}`;

      const middleware = botchaVerify({ secret: TEST_SECRET });
      await middleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(next).not.toHaveBeenCalled();
    });

    it('should return 401 for wrong token type', async () => {
      const token = await createTestToken({
        sub: 'challenge-123',
        type: 'botcha-refresh',
        jti: 'token-id-123',
        solveTime: 1500,
      });

      const { req, res, next } = createMocks();
      req.headers.authorization = `Bearer ${token}`;

      const middleware = botchaVerify({ secret: TEST_SECRET });
      await middleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({
        error: 'Unauthorized',
        message: 'Invalid token type. Expected botcha-verified token.',
      });
      expect(next).not.toHaveBeenCalled();
    });

    it('should return 401 for wrong audience', async () => {
      const token = await createTestToken({
        sub: 'challenge-123',
        type: 'botcha-verified',
        jti: 'token-id-123',
        solveTime: 1500,
        aud: 'https://different.example.com',
      });

      const { req, res, next } = createMocks();
      req.headers.authorization = `Bearer ${token}`;

      const middleware = botchaVerify({
        secret: TEST_SECRET,
        audience: TEST_AUDIENCE,
      });
      await middleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(next).not.toHaveBeenCalled();
    });

    it('should return 401 for IP mismatch', async () => {
      const token = await createTestToken({
        sub: 'challenge-123',
        type: 'botcha-verified',
        jti: 'token-id-123',
        solveTime: 1500,
        client_ip: '10.0.0.1',
      });

      const { req, res, next } = createMocks();
      req.headers.authorization = `Bearer ${token}`;
      Object.defineProperty(req, 'ip', { value: TEST_CLIENT_IP, writable: true }); // Different IP

      const middleware = botchaVerify({
        secret: TEST_SECRET,
        requireIp: true,
      });
      await middleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({
        error: 'Unauthorized',
        message: 'Client IP mismatch',
      });
      expect(next).not.toHaveBeenCalled();
    });
  });

  describe('Custom error handler', () => {
    it('should call custom onError handler for missing token', async () => {
      const onError = vi.fn();
      const { req, res, next } = createMocks();

      const middleware = botchaVerify({
        secret: TEST_SECRET,
        onError,
      });
      await middleware(req, res, next);

      expect(onError).toHaveBeenCalledOnce();
      expect(onError).toHaveBeenCalledWith(
        'Missing Authorization header with Bearer token',
        expect.objectContaining({
          error: 'Missing Authorization header with Bearer token',
        })
      );
      expect(res.status).toHaveBeenCalledWith(401);
      expect(next).not.toHaveBeenCalled();
    });

    it('should call custom onError handler for invalid token', async () => {
      const onError = vi.fn();
      const { req, res, next } = createMocks();
      req.headers.authorization = 'Bearer invalid-token';

      const middleware = botchaVerify({
        secret: TEST_SECRET,
        onError,
      });
      await middleware(req, res, next);

      expect(onError).toHaveBeenCalledOnce();
      expect(onError.mock.calls[0][1]).toMatchObject({
        token: 'invalid-token',
        error: expect.any(String),
      });
      expect(res.status).toHaveBeenCalledWith(401);
    });

    it('should call custom onError handler with client IP context', async () => {
      const onError = vi.fn();
      const { req, res, next } = createMocks();
      req.headers['x-forwarded-for'] = '203.0.113.1';

      const middleware = botchaVerify({
        secret: TEST_SECRET,
        onError,
      });
      await middleware(req, res, next);

      expect(onError).toHaveBeenCalledOnce();
      expect(onError.mock.calls[0][1].clientIp).toBe('203.0.113.1');
      expect(res.status).toHaveBeenCalledWith(401);
    });
  });

  describe('Token revocation', () => {
    it('should reject revoked token', async () => {
      const token = await createTestToken({
        sub: 'challenge-123',
        type: 'botcha-verified',
        jti: 'revoked-token',
        solveTime: 1500,
      });

      const { req, res, next } = createMocks();
      req.headers.authorization = `Bearer ${token}`;

      const middleware = botchaVerify({
        secret: TEST_SECRET,
        checkRevocation: async (jti) => jti === 'revoked-token',
      });
      await middleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({
        error: 'Unauthorized',
        message: 'Token has been revoked',
      });
      expect(next).not.toHaveBeenCalled();
    });

    it('should accept non-revoked token', async () => {
      const token = await createTestToken({
        sub: 'challenge-123',
        type: 'botcha-verified',
        jti: 'active-token',
        solveTime: 1500,
      });

      const { req, res, next } = createMocks();
      req.headers.authorization = `Bearer ${token}`;

      const middleware = botchaVerify({
        secret: TEST_SECRET,
        checkRevocation: async (jti) => jti === 'revoked-token',
      });
      await middleware(req, res, next);

      expect(next).toHaveBeenCalledOnce();
      expect(res.status).not.toHaveBeenCalled();
    });
  });
});
