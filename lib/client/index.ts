import crypto from 'crypto';

// SDK version - hardcoded since npm_package_version is unreliable when used as a library
const SDK_VERSION = '0.4.0';

// Export types
export type {
  SpeedProblem,
  BotchaClientOptions,
  ChallengeResponse,
  StandardChallengeResponse,
  VerifyResponse,
  TokenResponse,
  StreamSession,
  StreamEvent,
  Problem,
  VerifyResult,
  StreamChallengeOptions,
} from './types.js';

import type {
  SpeedProblem,
  BotchaClientOptions,
  ChallengeResponse,
  StandardChallengeResponse,
  VerifyResponse,
  TokenResponse,
} from './types.js';

// Export stream client
export { BotchaStreamClient } from './stream.js';

/**
 * BOTCHA Client SDK for AI Agents
 * 
 * Automatically handles BOTCHA challenges when accessing protected endpoints.
 * 
 * @example
 * ```typescript
 * import { BotchaClient } from '@dupecom/botcha/client';
 * 
 * const client = new BotchaClient();
 * 
 * // Automatically solves challenges and retries
 * const response = await client.fetch('https://api.example.com/agent-only');
 * ```
 */
export class BotchaClient {
  private baseUrl: string;
  private agentIdentity: string;
  private maxRetries: number;
  private autoToken: boolean;
  private opts: BotchaClientOptions;
  private cachedToken: string | null = null;
  private _refreshToken: string | null = null;
  private tokenExpiresAt: number | null = null;

  constructor(options: BotchaClientOptions = {}) {
    this.opts = options;
    this.baseUrl = options.baseUrl || 'https://botcha.ai';
    this.agentIdentity = options.agentIdentity || `BotchaClient/${SDK_VERSION}`;
    this.maxRetries = options.maxRetries || 3;
    this.autoToken = options.autoToken !== undefined ? options.autoToken : true;
  }

  /**
   * Solve a BOTCHA speed challenge
   * 
   * @param problems - Array of numbers to hash
   * @returns Array of SHA256 first 8 hex chars for each number
   */
  solve(problems: number[]): string[] {
    return problems.map(num =>
      crypto.createHash('sha256').update(num.toString()).digest('hex').substring(0, 8)
    );
  }

  /**
   * Get a JWT token from the BOTCHA service using the token flow.
   * Automatically solves the challenge and verifies to obtain a token.
   * Token is cached until near expiry (refreshed at 4 minutes).
   * 
   * @returns JWT token string
   * @throws Error if token acquisition fails
   */
  async getToken(): Promise<string> {
    // Check if we have a valid cached token (refresh at 1 minute before expiry)
    if (this.cachedToken && this.tokenExpiresAt) {
      const now = Date.now();
      const timeUntilExpiry = this.tokenExpiresAt - now;
      const refreshThreshold = 1 * 60 * 1000; // 1 minute before expiry
      
      if (timeUntilExpiry > refreshThreshold) {
        return this.cachedToken;
      }
    }

    // Step 1: Get challenge from GET /v1/token
    const challengeRes = await fetch(`${this.baseUrl}/v1/token`, {
      headers: { 'User-Agent': this.agentIdentity },
    });

    if (!challengeRes.ok) {
      throw new Error(`Token request failed with status ${challengeRes.status} ${challengeRes.statusText}`);
    }

    const challengeData = await challengeRes.json() as TokenResponse;
    
    if (!challengeData.challenge) {
      throw new Error('No challenge provided in token response');
    }

    // Step 2: Solve the challenge
    const problems = normalizeProblems(challengeData.challenge.problems);
    if (!problems) {
      throw new Error('Invalid challenge problems format');
    }
    const answers = this.solve(problems);

    // Step 3: Submit solution to POST /v1/token/verify
    const verifyBody: any = {
      id: challengeData.challenge.id,
      answers,
    };
    
    // Include audience if specified
    if (this.opts.audience) {
      verifyBody.audience = this.opts.audience;
    }

    const verifyRes = await fetch(`${this.baseUrl}/v1/token/verify`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': this.agentIdentity,
      },
      body: JSON.stringify(verifyBody),
    });

    if (!verifyRes.ok) {
      throw new Error(`Token verification failed with status ${verifyRes.status} ${verifyRes.statusText}`);
    }

    const verifyData = await verifyRes.json() as TokenResponse;

    if (!verifyData.success && !verifyData.verified) {
      throw new Error('Failed to obtain token from verification');
    }

    // Extract access token (prefer access_token field, fall back to token for backward compat)
    const accessToken = verifyData.access_token || verifyData.token;
    if (!accessToken) {
      throw new Error('Failed to obtain token from verification');
    }

    // Store refresh token if provided
    if (verifyData.refresh_token) {
      this._refreshToken = verifyData.refresh_token;
    }

    // Cache the token - use expires_in from response (in seconds), default to 5 minutes
    const expiresInSeconds = verifyData.expires_in || 300; // Default to 5 minutes
    this.cachedToken = accessToken;
    this.tokenExpiresAt = Date.now() + expiresInSeconds * 1000;

    return this.cachedToken;
  }

  /**
   * Refresh the access token using the refresh token.
   * Only works if a refresh token was obtained from a previous getToken() call.
   * 
   * @returns New JWT access token string
   * @throws Error if refresh fails or no refresh token available
   */
  async refreshToken(): Promise<string> {
    if (!this._refreshToken) {
      throw new Error('No refresh token available. Call getToken() first.');
    }

    const refreshRes = await fetch(`${this.baseUrl}/v1/token/refresh`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': this.agentIdentity,
      },
      body: JSON.stringify({
        refresh_token: this._refreshToken,
      }),
    });

    if (!refreshRes.ok) {
      throw new Error(`Token refresh failed with status ${refreshRes.status} ${refreshRes.statusText}`);
    }

    const refreshData = await refreshRes.json() as TokenResponse;

    if (!refreshData.access_token) {
      throw new Error('Failed to obtain access token from refresh');
    }

    // Update cached token with new access token
    this.cachedToken = refreshData.access_token;
    const expiresInSeconds = refreshData.expires_in || 300; // Default to 5 minutes
    this.tokenExpiresAt = Date.now() + expiresInSeconds * 1000;

    return this.cachedToken;
  }

  /**
   * Clear the cached token, forcing a refresh on the next request
   */
  clearToken(): void {
    this.cachedToken = null;
    this._refreshToken = null;
    this.tokenExpiresAt = null;
  }

  /**
   * Get and solve a challenge from BOTCHA service
   */
  async solveChallenge(): Promise<{ id: string; answers: string[] }> {
    const res = await fetch(`${this.baseUrl}/api/speed-challenge`, {
      headers: { 'User-Agent': this.agentIdentity },
    });

    if (!res.ok) {
      throw new Error(`Challenge request failed with status ${res.status} ${res.statusText}`);
    }

    const contentType = res.headers.get('content-type') || '';
    if (!contentType.toLowerCase().includes('application/json')) {
      throw new Error('Expected JSON response for challenge request');
    }
    
    const data = await res.json() as ChallengeResponse;
    
    if (!data.success || !data.challenge) {
      throw new Error('Failed to get challenge');
    }

    const problems = normalizeProblems(data.challenge.problems);
    if (!problems) {
      throw new Error('Invalid challenge problems format');
    }
    const answers = this.solve(problems);
    return { id: data.challenge.id, answers };
  }

  /**
   * Verify a solved challenge
   */
  async verify(id: string, answers: string[]): Promise<VerifyResponse> {
    const res = await fetch(`${this.baseUrl}/api/speed-challenge`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': this.agentIdentity,
      },
      body: JSON.stringify({ id, answers }),
    });

    if (!res.ok) {
      throw new Error(`Verification request failed with status ${res.status} ${res.statusText}`);
    }

    const contentType = res.headers.get('content-type') || '';
    if (!contentType.toLowerCase().includes('application/json')) {
      throw new Error('Expected JSON response for verification request');
    }

    return await res.json() as VerifyResponse;
  }

  /**
   * Fetch a URL, automatically solving BOTCHA challenges if encountered.
   * If autoToken is enabled (default), automatically acquires and uses JWT tokens.
   * 
   * @example
   * ```typescript
   * const response = await client.fetch('https://api.example.com/agent-only');
   * const data = await response.json();
   * ```
   */
  async fetch(url: string, init?: RequestInit): Promise<Response> {
    const headers = new Headers(init?.headers);
    headers.set('User-Agent', this.agentIdentity);

    // If autoToken is enabled, try to use token-based auth
    if (this.autoToken) {
      try {
        const token = await this.getToken();
        headers.set('Authorization', `Bearer ${token}`);
      } catch (error) {
        // If token acquisition fails, fall back to challenge header method
        console.warn('Failed to acquire token, falling back to challenge headers:', error);
      }
    }

    let response = await fetch(url, {
      ...init,
      headers,
    });
    
    // Handle 401 by trying refresh first, then full re-verify if refresh fails
    if (response.status === 401 && this.autoToken) {
      try {
        // Try refresh token first if available
        let token: string;
        if (this._refreshToken) {
          try {
            token = await this.refreshToken();
          } catch (refreshError) {
            // Refresh failed, clear tokens and do full re-verify
            this.clearToken();
            token = await this.getToken();
          }
        } else {
          // No refresh token, clear and do full re-verify
          this.clearToken();
          token = await this.getToken();
        }
        headers.set('Authorization', `Bearer ${token}`);
        response = await fetch(url, { ...init, headers });
      } catch (error) {
        // Token refresh/acquisition failed, return the 401 response
      }
    }

    let retries = 0;

    // Fall back to challenge header method for 403 responses
    while (response.status === 403 && retries < this.maxRetries) {
      // Clone response before reading body to preserve it for the caller
      const clonedResponse = response.clone();
      const body = await clonedResponse.json().catch(() => null);
      
      // Check if this is a BOTCHA challenge
      const challenge = body?.challenge;
      if (!challenge) {
        break;
      }

      if (!canRetryBody(init?.body)) {
        break;
      }

      const retryHeaders = new Headers(init?.headers);
      retryHeaders.set('User-Agent', this.agentIdentity);

      if (challenge?.problems && Array.isArray(challenge.problems)) {
        const problems = normalizeProblems(challenge.problems);
        if (!problems) {
          break;
        }
        const answers = this.solve(problems);
        retryHeaders.set('X-Botcha-Id', challenge.id);
        retryHeaders.set('X-Botcha-Challenge-Id', challenge.id);
        retryHeaders.set('X-Botcha-Answers', JSON.stringify(answers));
        retryHeaders.set('X-Botcha-Solution', JSON.stringify(answers));
      } else if (challenge?.puzzle && typeof challenge.puzzle === 'string') {
        const solution = solveStandardPuzzle(challenge.puzzle);
        retryHeaders.set('X-Botcha-Challenge-Id', challenge.id);
        retryHeaders.set('X-Botcha-Solution', solution);
      } else {
        break;
      }

      response = await fetch(url, { ...init, headers: retryHeaders });
      retries++;
    }

    return response;
  }

  /**
   * Create headers with pre-solved challenge for manual use
   * 
   * @example
   * ```typescript
   * const headers = await client.createHeaders();
   * const response = await fetch('https://api.example.com/agent-only', { headers });
   * ```
   */
  async createHeaders(): Promise<Record<string, string>> {
    const { id, answers } = await this.solveChallenge();
    
    return {
      'X-Botcha-Id': id,
      'X-Botcha-Challenge-Id': id,
      'X-Botcha-Answers': JSON.stringify(answers),
      'User-Agent': this.agentIdentity,
    };
  }
}

/**
 * Convenience function for one-off solves
 * 
 * @example
 * ```typescript
 * const answers = solveBotcha([123456, 789012]);
 * // Returns: ['a1b2c3d4', 'e5f6g7h8']
 * ```
 */
export function solveBotcha(problems: number[]): string[] {
  return problems.map(num =>
    crypto.createHash('sha256').update(num.toString()).digest('hex').substring(0, 8)
  );
}

export default BotchaClient;

function normalizeProblems(problems: SpeedProblem[]): number[] | null {
  if (!Array.isArray(problems)) return null;
  const numbers: number[] = [];
  for (const problem of problems) {
    if (typeof problem === 'number') {
      numbers.push(problem);
      continue;
    }
    if (typeof problem === 'object' && problem !== null && typeof problem.num === 'number') {
      numbers.push(problem.num);
      continue;
    }
    return null;
  }
  return numbers;
}

function solveStandardPuzzle(puzzle: string): string {
  const primeMatch = puzzle.match(/first\s+(\d+)\s+prime/i);
  if (!primeMatch) {
    throw new Error('Unsupported standard challenge puzzle format');
  }
  const primeCount = Number.parseInt(primeMatch[1], 10);
  if (!Number.isFinite(primeCount) || primeCount <= 0) {
    throw new Error('Invalid prime count in puzzle');
  }
  const primes = generatePrimes(primeCount);
  const concatenated = primes.join('');
  const hash = crypto.createHash('sha256').update(concatenated).digest('hex');
  return hash.substring(0, 16);
}

function generatePrimes(count: number): number[] {
  const primes: number[] = [];
  let num = 2;

  while (primes.length < count) {
    if (isPrime(num)) {
      primes.push(num);
    }
    num++;
  }

  return primes;
}

function isPrime(n: number): boolean {
  if (n < 2) return false;
  if (n === 2) return true;
  if (n % 2 === 0) return false;

  for (let i = 3; i <= Math.sqrt(n); i += 2) {
    if (n % i === 0) return false;
  }

  return true;
}

function canRetryBody(body: RequestInit['body']): boolean {
  if (body == null) return true;
  if (typeof body === 'string') return true;
  if (body instanceof URLSearchParams) return true;
  if (body instanceof ArrayBuffer) return true;
  if (ArrayBuffer.isView(body)) return true;
  if (typeof Blob !== 'undefined' && body instanceof Blob) return true;
  if (typeof FormData !== 'undefined' && body instanceof FormData) return true;
  return false;
}
