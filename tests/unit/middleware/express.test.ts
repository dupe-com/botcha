import { describe, test, expect, vi, beforeEach } from 'vitest';
import { verify, solve, BotchaOptions } from '../../../lib/index.js';
import { Request, Response, NextFunction } from 'express';

describe('Express middleware - verify() (lib/index.ts)', () => {
  let mockReq: Partial<Request>;
  let mockRes: Partial<Response>;
  let mockNext: NextFunction;
  let jsonResponse: any;

  beforeEach(() => {
    vi.resetAllMocks();
    jsonResponse = null;

    mockReq = {
      headers: {},
    };

    mockRes = {
      status: vi.fn().mockReturnThis(),
      json: vi.fn().mockImplementation((data) => {
        jsonResponse = data;
        return mockRes;
      }),
    };

    mockNext = vi.fn();
  });

  describe('allowTestHeader default', () => {
    test('defaults to false — X-Agent-Identity does NOT bypass', async () => {
      mockReq.headers = { 'x-agent-identity': 'SneakyHuman/1.0' };

      const middleware = verify(); // no options — uses defaults
      await middleware(mockReq as Request, mockRes as Response, mockNext);

      // Should NOT call next — must solve a challenge instead
      expect(mockNext).not.toHaveBeenCalled();
      expect(mockRes.status).toHaveBeenCalledWith(403);
      expect(jsonResponse.error).toBe('BOTCHA_CHALLENGE');
    });

    test('allowTestHeader: true explicitly enables X-Agent-Identity bypass', async () => {
      mockReq.headers = { 'x-agent-identity': 'TrustedDevBot/1.0' };

      const middleware = verify({ allowTestHeader: true });
      await middleware(mockReq as Request, mockRes as Response, mockNext);

      // Should call next — opt-in bypass is enabled
      expect(mockNext).toHaveBeenCalled();
      expect((mockReq as any).botcha).toBeDefined();
      expect((mockReq as any).botcha.verified).toBe(true);
      expect((mockReq as any).botcha.agent).toBe('TrustedDevBot/1.0');
      expect((mockReq as any).botcha.method).toBe('header');
    });

    test('allowTestHeader: false explicitly disables X-Agent-Identity bypass', async () => {
      mockReq.headers = { 'x-agent-identity': 'SneakyHuman/1.0' };

      const middleware = verify({ allowTestHeader: false });
      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockNext).not.toHaveBeenCalled();
      expect(mockRes.status).toHaveBeenCalledWith(403);
    });
  });

  describe('challenge-response flow', () => {
    test('returns BOTCHA challenge on unauthenticated request', async () => {
      mockReq.headers = {};

      const middleware = verify();
      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockNext).not.toHaveBeenCalled();
      expect(mockRes.status).toHaveBeenCalledWith(403);
      expect(jsonResponse.error).toBe('BOTCHA_CHALLENGE');
      expect(jsonResponse.challenge).toBeDefined();
      expect(jsonResponse.challenge.id).toBeDefined();
      expect(jsonResponse.challenge.problems).toBeDefined();
      expect(Array.isArray(jsonResponse.challenge.problems)).toBe(true);
      expect(jsonResponse.challenge.problems).toHaveLength(5);
    });

    test('accepts correct challenge solution via headers', async () => {
      // Step 1: Get challenge
      const middleware = verify();
      await middleware(mockReq as Request, mockRes as Response, mockNext);

      const challengeId = jsonResponse.challenge.id;
      const problems = jsonResponse.challenge.problems;

      // Step 2: Solve it
      const answers = solve(problems);

      // Step 3: Submit solution
      mockReq = {
        headers: {
          'x-botcha-id': challengeId,
          'x-botcha-answers': JSON.stringify(answers),
        },
      };
      mockRes = {
        status: vi.fn().mockReturnThis(),
        json: vi.fn().mockReturnThis(),
      };
      mockNext = vi.fn();

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockNext).toHaveBeenCalled();
      expect((mockReq as any).botcha).toBeDefined();
      expect((mockReq as any).botcha.verified).toBe(true);
      expect((mockReq as any).botcha.method).toBe('challenge');
    });

    test('rejects wrong challenge answers', async () => {
      // Step 1: Get challenge
      const middleware = verify();
      await middleware(mockReq as Request, mockRes as Response, mockNext);

      const challengeId = jsonResponse.challenge.id;

      // Step 2: Submit wrong answers
      mockReq = {
        headers: {
          'x-botcha-id': challengeId,
          'x-botcha-answers': JSON.stringify(['wrong', 'wrong', 'wrong', 'wrong', 'wrong']),
        },
      };
      mockRes = {
        status: vi.fn().mockReturnThis(),
        json: vi.fn().mockImplementation((data) => { jsonResponse = data; return mockRes; }),
      };
      mockNext = vi.fn();

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      // Should fail and issue a new challenge
      expect(mockNext).not.toHaveBeenCalled();
      expect(mockRes.status).toHaveBeenCalledWith(403);
    });
  });
});
