import { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';

// ============ TYPES ============
export interface BotchaOptions {
  /** Challenge mode: 'speed' (500ms, 5 hashes) or 'standard' (5s, primes) */
  mode?: 'speed' | 'standard';
  /** Difficulty for standard mode */
  difficulty?: 'easy' | 'medium' | 'hard';
  /** Allow X-Agent-Identity header to bypass challenges (for development/testing ONLY).
   *  WARNING: Enabling this in production allows anyone to bypass verification with a single header.
   *  @default false */
  allowTestHeader?: boolean;
  /** Custom failure handler */
  onFailure?: (req: Request, res: Response, reason: string) => void;
}

export interface ChallengeResult {
  valid: boolean;
  reason?: string;
  solveTimeMs?: number;
}

// ============ CHALLENGE STORAGE ============
interface StoredChallenge {
  id: string;
  expectedAnswers: string[];
  issuedAt: number;
  expiresAt: number;
}

const challenges = new Map<string, StoredChallenge>();

// Cleanup expired challenges
setInterval(() => {
  const now = Date.now();
  for (const [id, c] of challenges) {
    if (c.expiresAt < now) challenges.delete(id);
  }
}, 30000);

// ============ CHALLENGE GENERATION ============
function generateSpeedChallenge(): { id: string; problems: number[]; timeLimit: number } {
  const id = crypto.randomUUID();
  const problems: number[] = [];
  const expectedAnswers: string[] = [];

  for (let i = 0; i < 5; i++) {
    const num = Math.floor(Math.random() * 900000) + 100000;
    problems.push(num);
    expectedAnswers.push(crypto.createHash('sha256').update(num.toString()).digest('hex').substring(0, 8));
  }

  challenges.set(id, {
    id,
    expectedAnswers,
    issuedAt: Date.now(),
    expiresAt: Date.now() + 600, // 500ms + 100ms grace
  });

  return { id, problems, timeLimit: 500 };
}

function verifySpeedChallenge(id: string, answers: string[]): ChallengeResult {
  const challenge = challenges.get(id);
  if (!challenge) return { valid: false, reason: 'Challenge expired or not found' };

  const now = Date.now();
  const solveTimeMs = now - challenge.issuedAt;
  challenges.delete(id);

  if (now > challenge.expiresAt) {
    return { valid: false, reason: `Too slow (${solveTimeMs}ms). Limit: 500ms` };
  }

  if (!Array.isArray(answers) || answers.length !== 5) {
    return { valid: false, reason: 'Must provide 5 answers' };
  }

  for (let i = 0; i < 5; i++) {
    if (answers[i]?.toLowerCase() !== challenge.expectedAnswers[i]) {
      return { valid: false, reason: `Wrong answer #${i + 1}` };
    }
  }

  return { valid: true, solveTimeMs };
}

// ============ MIDDLEWARE ============

/**
 * Express middleware to verify AI agents
 * 
 * @example
 * import { botcha } from 'botcha';
 * app.use('/agent-only', botcha.verify());
 */
export function verify(options: BotchaOptions = {}) {
  const opts: BotchaOptions = {
    mode: 'speed',
    allowTestHeader: false,
    ...options,
  };

  return async (req: Request, res: Response, next: NextFunction) => {
    // Check for test header (dev mode ONLY — disabled by default)
    if (opts.allowTestHeader && req.headers['x-agent-identity']) {
      console.warn('[botcha] WARNING: X-Agent-Identity bypass used. Disable allowTestHeader in production!');
      (req as any).botcha = { verified: true, agent: req.headers['x-agent-identity'], method: 'header' };
      return next();
    }

    // Check for challenge solution
    const challengeId = req.headers['x-botcha-id'] as string;
    const answers = req.headers['x-botcha-answers'] as string;

    if (challengeId && answers) {
      try {
        const answerArray = JSON.parse(answers);
        const result = verifySpeedChallenge(challengeId, answerArray);
        if (result.valid) {
          (req as any).botcha = { verified: true, solveTimeMs: result.solveTimeMs, method: 'challenge' };
          return next();
        }
      } catch {}
    }

    // Generate new challenge
    const challenge = generateSpeedChallenge();
    
    const failureResponse = {
      error: 'BOTCHA_CHALLENGE',
      message: '🤖 Prove you are an AI agent',
      challenge: {
        id: challenge.id,
        problems: challenge.problems,
        timeLimit: challenge.timeLimit,
        instructions: 'SHA256 each number, return first 8 hex chars as JSON array',
      },
      headers: {
        'X-Botcha-Id': challenge.id,
        'X-Botcha-Answers': '["abc123...", ...]',
      },
    };

    if (opts.onFailure) {
      opts.onFailure(req, res, 'Challenge required');
    } else {
      res.status(403).json(failureResponse);
    }
  };
}

/**
 * Solve a BOTCHA challenge (for AI agents to use)
 */
export function solve(problems: number[]): string[] {
  return problems.map(n => 
    crypto.createHash('sha256').update(n.toString()).digest('hex').substring(0, 8)
  );
}

// ============ EXPORTS ============
export const botcha = { verify, solve };
export default botcha;
