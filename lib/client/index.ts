import crypto from 'crypto';

// SDK version - hardcoded since npm_package_version is unreliable when used as a library
const SDK_VERSION = '0.4.0';

export interface BotchaClientOptions {
  /** Base URL of BOTCHA service (default: https://botcha.ai) */
  baseUrl?: string;
  /** Custom identity header value */
  agentIdentity?: string;
  /** Max retries for challenge solving */
  maxRetries?: number;
}

export interface ChallengeResponse {
  success: boolean;
  challenge?: {
    id: string;
    problems: number[];
    timeLimit: number;
    instructions: string;
  };
}

export interface VerifyResponse {
  success: boolean;
  message: string;
  solveTimeMs?: number;
  verdict?: string;
}

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

  constructor(options: BotchaClientOptions = {}) {
    this.baseUrl = options.baseUrl || 'https://botcha.ai';
    this.agentIdentity = options.agentIdentity || `BotchaClient/${SDK_VERSION}`;
    this.maxRetries = options.maxRetries || 3;
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

    const answers = this.solve(data.challenge.problems);
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
   * Fetch a URL, automatically solving BOTCHA challenges if encountered
   * 
   * @example
   * ```typescript
   * const response = await client.fetch('https://api.example.com/agent-only');
   * const data = await response.json();
   * ```
   */
  async fetch(url: string, init?: RequestInit): Promise<Response> {
    let response = await fetch(url, {
      ...init,
      headers: {
        ...Object.fromEntries(new Headers(init?.headers).entries()),
        'User-Agent': this.agentIdentity,
      },
    });
    
    let retries = 0;

    while (response.status === 403 && retries < this.maxRetries) {
      // Clone response before reading body to preserve it for the caller
      const clonedResponse = response.clone();
      const body = await clonedResponse.json().catch(() => null);
      
      // Check if this is a BOTCHA challenge
      if (body?.error === 'BOTCHA_CHALLENGE' || body?.challenge?.problems) {
        const challenge = body.challenge;
        
        if (challenge?.problems && Array.isArray(challenge.problems)) {
          // Solve the challenge
          const answers = this.solve(challenge.problems);
          
          // Create fresh headers for retry to avoid state issues
          const retryHeaders = new Headers(init?.headers);
          retryHeaders.set('User-Agent', this.agentIdentity);
          retryHeaders.set('X-Botcha-Id', challenge.id);
          retryHeaders.set('X-Botcha-Answers', JSON.stringify(answers));
          
          response = await fetch(url, { ...init, headers: retryHeaders });
          retries++;
        } else {
          break;
        }
      } else {
        break;
      }
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
