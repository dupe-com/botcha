import { describe, test, expect, vi, beforeEach } from 'vitest';
import { botchaVerify } from '../../../src/middleware/verify.js';
import { generateChallenge, verifyChallenge } from '../../../src/challenges/compute.js';
import crypto from 'crypto';
import { Request, Response, NextFunction } from 'express';

describe('Middleware - botchaVerify', () => {
  let mockReq: Partial<Request>;
  let mockRes: Partial<Response>;
  let mockNext: NextFunction;

  beforeEach(() => {
    vi.resetAllMocks();
    
    mockReq = {
      headers: {},
      method: 'GET',
      path: '/test',
    };
    
    mockRes = {
      status: vi.fn().mockReturnThis(),
      json: vi.fn().mockReturnThis(),
      header: vi.fn().mockReturnThis(),
    };
    
    mockNext = vi.fn();
  });

  // Test 1: Passes request with X-Agent-Identity header
  test('passes with X-Agent-Identity header', async () => {
    mockReq.headers = { 'x-agent-identity': 'TestAgent/1.0' };
    
    const middleware = botchaVerify();
    await middleware(mockReq as Request, mockRes as Response, mockNext);
    
    expect(mockNext).toHaveBeenCalled();
    expect((mockReq as any).agent).toBe('TestAgent/1.0');
    expect((mockReq as any).verificationMethod).toBe('header');
    expect(mockRes.status).not.toHaveBeenCalled();
  });

  // Test 2: Passes request with valid challenge solution
  test('passes with valid challenge solution', async () => {
    // First, generate a challenge
    const challenge = generateChallenge('easy');
    
    // Solve it manually: generate the first 100 primes, concatenate, hash
    const primes: number[] = [];
    let num = 2;
    while (primes.length < 100) {
      if (isPrime(num)) {
        primes.push(num);
      }
      num++;
    }
    const concatenated = primes.join('');
    const hash = crypto.createHash('sha256').update(concatenated).digest('hex');
    const solution = hash.substring(0, 16);
    
    // Now make the request with the challenge ID and solution
    mockReq.headers = {
      'x-botcha-challenge-id': challenge.id,
      'x-botcha-solution': solution,
    };
    
    const middleware = botchaVerify();
    await middleware(mockReq as Request, mockRes as Response, mockNext);
    
    expect(mockNext).toHaveBeenCalled();
    expect((mockReq as any).verificationMethod).toBe('challenge');
    expect((mockReq as any).agent).toContain('challenge-verified');
    expect(mockRes.status).not.toHaveBeenCalled();
  });

  // Test 3: Passes request with known User-Agent pattern: OpenClaw/1.0
  test('passes with User-Agent: OpenClaw/1.0', async () => {
    mockReq.headers = { 'user-agent': 'OpenClaw/1.0' };
    
    const middleware = botchaVerify();
    await middleware(mockReq as Request, mockRes as Response, mockNext);
    
    expect(mockNext).toHaveBeenCalled();
    expect((mockReq as any).agent).toBe('OpenClaw/1.0');
    expect((mockReq as any).verificationMethod).toBe('header');
  });

  // Test 4: Passes request with known User-Agent pattern: Claude-Agent/2.0
  test('passes with User-Agent: Claude-Agent/2.0', async () => {
    mockReq.headers = { 'user-agent': 'Claude-Agent/2.0' };
    
    const middleware = botchaVerify();
    await middleware(mockReq as Request, mockRes as Response, mockNext);
    
    expect(mockNext).toHaveBeenCalled();
    expect((mockReq as any).agent).toBe('Claude-Agent/2.0');
    expect((mockReq as any).verificationMethod).toBe('header');
  });

  // Test 5: Returns 403 with challenge when not verified
  test('returns 403 with challenge when not verified', async () => {
    mockReq.headers = { 'user-agent': 'Mozilla/5.0 (regular browser)' };
    
    const middleware = botchaVerify();
    await middleware(mockReq as Request, mockRes as Response, mockNext);
    
    expect(mockNext).not.toHaveBeenCalled();
    expect(mockRes.status).toHaveBeenCalledWith(403);
    expect(mockRes.json).toHaveBeenCalled();
    
    const jsonCall = (mockRes.json as any).mock.calls[0][0];
    expect(jsonCall.success).toBe(false);
    expect(jsonCall.error).toBe('BOTCHA_VERIFICATION_FAILED');
    expect(jsonCall.message).toContain('Access denied');
  });

  // Test 6: Response includes challenge.id and challenge.puzzle
  test('response includes challenge.id and challenge.puzzle', async () => {
    mockReq.headers = { 'user-agent': 'Mozilla/5.0 (regular browser)' };
    
    const middleware = botchaVerify();
    await middleware(mockReq as Request, mockRes as Response, mockNext);
    
    expect(mockRes.json).toHaveBeenCalled();
    
    const jsonCall = (mockRes.json as any).mock.calls[0][0];
    expect(jsonCall.challenge).toBeDefined();
    expect(jsonCall.challenge.id).toBeDefined();
    expect(jsonCall.challenge.puzzle).toBeDefined();
    expect(typeof jsonCall.challenge.id).toBe('string');
    expect(typeof jsonCall.challenge.puzzle).toBe('string');
    expect(jsonCall.challenge.puzzle).toContain('SHA256');
    expect(jsonCall.challenge.puzzle).toContain('prime');
  });

  // Test 7: Sets X-Botcha-Challenge-Id header on 403
  test('sets X-Botcha-Challenge-Id header on 403', async () => {
    mockReq.headers = { 'user-agent': 'Mozilla/5.0 (regular browser)' };
    
    const middleware = botchaVerify();
    await middleware(mockReq as Request, mockRes as Response, mockNext);
    
    expect(mockRes.header).toHaveBeenCalledWith('X-Botcha-Challenge-Id', expect.any(String));
    expect(mockRes.header).toHaveBeenCalledWith('X-Botcha-Challenge-Type', 'compute');
    expect(mockRes.header).toHaveBeenCalledWith('X-Botcha-Time-Limit', expect.any(String));
  });

  // Test 8: Sets req.agent on successful verification
  test('sets req.agent on successful verification', async () => {
    mockReq.headers = { 'x-agent-identity': 'MyCustomAgent/3.0' };
    
    const middleware = botchaVerify();
    await middleware(mockReq as Request, mockRes as Response, mockNext);
    
    expect((mockReq as any).agent).toBe('MyCustomAgent/3.0');
    expect(mockNext).toHaveBeenCalled();
  });

  // Test 9: Sets req.verificationMethod correctly
  test('sets req.verificationMethod correctly for different methods', async () => {
    // Test with header method
    mockReq.headers = { 'x-agent-identity': 'TestAgent/1.0' };
    let middleware = botchaVerify();
    await middleware(mockReq as Request, mockRes as Response, mockNext);
    expect((mockReq as any).verificationMethod).toBe('header');

    // Reset and test with User-Agent pattern
    mockReq = { headers: { 'user-agent': 'GPT-Agent/1.0' }, method: 'GET', path: '/test' };
    mockNext = vi.fn();
    middleware = botchaVerify();
    await middleware(mockReq as Request, mockRes as Response, mockNext);
    expect((mockReq as any).verificationMethod).toBe('header');

    // Note: Challenge method is tested in test 2
  });

  // Test 10: Allows challenge to be verified correctly (full flow)
  test('full challenge flow: generate -> solve -> verify', async () => {
    // Step 1: First request without credentials - should get challenge
    mockReq.headers = { 'user-agent': 'TestBot/1.0' };
    
    let middleware = botchaVerify();
    await middleware(mockReq as Request, mockRes as Response, mockNext);
    
    expect(mockRes.status).toHaveBeenCalledWith(403);
    expect(mockRes.json).toHaveBeenCalled();
    
    const firstResponse = (mockRes.json as any).mock.calls[0][0];
    const challengeId = firstResponse.challenge.id;
    const challengePuzzle = firstResponse.challenge.puzzle;
    
    expect(challengeId).toBeDefined();
    expect(challengePuzzle).toContain('SHA256');
    
    // Step 2: Solve the challenge
    // Parse the puzzle to get the number of primes (default is 500 for medium difficulty)
    const primeMatch = challengePuzzle.match(/first (\d+) prime/i);
    const primeCount = primeMatch ? parseInt(primeMatch[1]) : 500;
    
    const primes: number[] = [];
    let num = 2;
    while (primes.length < primeCount) {
      if (isPrime(num)) {
        primes.push(num);
      }
      num++;
    }
    const concatenated = primes.join('');
    const hash = crypto.createHash('sha256').update(concatenated).digest('hex');
    const solution = hash.substring(0, 16);
    
    // Step 3: Make second request with solution
    mockReq = {
      headers: {
        'x-botcha-challenge-id': challengeId,
        'x-botcha-solution': solution,
      },
      method: 'GET',
      path: '/test',
    };
    mockRes = {
      status: vi.fn().mockReturnThis(),
      json: vi.fn().mockReturnThis(),
      header: vi.fn().mockReturnThis(),
    };
    mockNext = vi.fn();
    
    middleware = botchaVerify();
    await middleware(mockReq as Request, mockRes as Response, mockNext);
    
    // Should now be verified
    expect(mockNext).toHaveBeenCalled();
    expect((mockReq as any).verificationMethod).toBe('challenge');
    expect((mockReq as any).agent).toContain('challenge-verified');
    expect(mockRes.status).not.toHaveBeenCalled();
  });

  // Test with allowChallenge: false option
  test('returns 403 without challenge when allowChallenge is false', async () => {
    mockReq.headers = { 'user-agent': 'Mozilla/5.0 (regular browser)' };
    
    const middleware = botchaVerify({ allowChallenge: false });
    await middleware(mockReq as Request, mockRes as Response, mockNext);
    
    expect(mockRes.status).toHaveBeenCalledWith(403);
    expect(mockRes.json).toHaveBeenCalled();
    
    const jsonCall = (mockRes.json as any).mock.calls[0][0];
    expect(jsonCall.challenge).toBeUndefined();
    expect(mockRes.header).not.toHaveBeenCalledWith('X-Botcha-Challenge-Id', expect.any(String));
  });

  // Test with different difficulty levels
  test('respects challengeDifficulty option', async () => {
    mockReq.headers = { 'user-agent': 'Mozilla/5.0' };
    
    const middleware = botchaVerify({ challengeDifficulty: 'easy' });
    await middleware(mockReq as Request, mockRes as Response, mockNext);
    
    const jsonCall = (mockRes.json as any).mock.calls[0][0];
    expect(jsonCall.challenge.puzzle).toContain('100 prime'); // Easy = 100 primes
  });

  // Test that User-Agent matching is case-insensitive
  test('User-Agent matching is case-insensitive', async () => {
    mockReq.headers = { 'user-agent': 'openclaw/2.5' };
    
    const middleware = botchaVerify();
    await middleware(mockReq as Request, mockRes as Response, mockNext);
    
    expect(mockNext).toHaveBeenCalled();
    expect((mockReq as any).agent).toBe('openclaw/2.5');
  });

  // Test with invalid challenge solution
  test('rejects invalid challenge solution', async () => {
    const challenge = generateChallenge('easy');
    
    mockReq.headers = {
      'x-botcha-challenge-id': challenge.id,
      'x-botcha-solution': 'wrong-answer-123',
    };
    
    const middleware = botchaVerify();
    await middleware(mockReq as Request, mockRes as Response, mockNext);
    
    expect(mockNext).not.toHaveBeenCalled();
    expect(mockRes.status).toHaveBeenCalledWith(403);
    
    const jsonCall = (mockRes.json as any).mock.calls[0][0];
    expect(jsonCall.hint).toBeDefined();
  });

  // Test with expired challenge
  test('rejects expired challenge', async () => {
    const challenge = generateChallenge('easy');
    
    // Wait for challenge to expire (in real scenario)
    // For testing, we'll just use an old/non-existent challenge ID
    mockReq.headers = {
      'x-botcha-challenge-id': 'expired-challenge-id',
      'x-botcha-solution': 'some-solution',
    };
    
    const middleware = botchaVerify();
    await middleware(mockReq as Request, mockRes as Response, mockNext);
    
    expect(mockNext).not.toHaveBeenCalled();
    expect(mockRes.status).toHaveBeenCalledWith(403);
    
    const jsonCall = (mockRes.json as any).mock.calls[0][0];
    expect(jsonCall.hint).toContain('not found');
  });
});

// Helper function for prime checking (used in tests)
function isPrime(n: number): boolean {
  if (n < 2) return false;
  if (n === 2) return true;
  if (n % 2 === 0) return false;
  
  for (let i = 3; i <= Math.sqrt(n); i += 2) {
    if (n % i === 0) return false;
  }
  
  return true;
}
