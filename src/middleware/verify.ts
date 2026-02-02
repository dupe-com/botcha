import { Request, Response, NextFunction } from 'express';
import { generateChallenge, verifyChallenge } from '../challenges/compute.js';
import { generateSpeedChallenge, verifySpeedChallenge } from '../challenges/speed.js';
import { verifyWebBotAuth, isTrustedProvider } from '../utils/signature.js';

interface BotchaOptions {
  requireSignature?: boolean;
  allowChallenge?: boolean;
  challengeType?: 'standard' | 'speed';
  challengeDifficulty?: 'easy' | 'medium' | 'hard';
  trustedProviders?: string[];
  customVerify?: (req: Request) => Promise<boolean>;
}

const defaultOptions: BotchaOptions = {
  requireSignature: false,
  allowChallenge: true,
  challengeType: 'standard',
  challengeDifficulty: 'medium',
};

export function botchaVerify(options: BotchaOptions = {}) {
  const opts = { ...defaultOptions, ...options };

  return async (req: Request, res: Response, next: NextFunction) => {
    const result = await verifyAgent(req, opts);

    if (result.verified) {
      (req as any).agent = result.agent;
      (req as any).verificationMethod = result.method;
      (req as any).provider = result.provider;
      return next();
    }

    // Not verified - return challenge or denial
    const challenge = opts.allowChallenge
      ? (opts.challengeType === 'speed'
        ? generateSpeedChallenge()
        : generateChallenge(opts.challengeDifficulty))
      : undefined;

    // Add challenge-specific headers
    if (challenge) {
      res.header('X-Botcha-Challenge-Id', challenge.id);
      res.header('X-Botcha-Challenge-Type', opts.challengeType === 'speed' ? 'speed' : 'standard');
      res.header('X-Botcha-Time-Limit', challenge.timeLimit.toString());
    }

    res.status(403).json({
      success: false,
      error: 'BOTCHA_VERIFICATION_FAILED',
      code: 'BOTCHA_CHALLENGE',
      message: '🚫 Access denied. This endpoint is for AI agents only.',
      hint: result.hint,
      challenge: challenge ? (
        opts.challengeType === 'speed'
          ? {
              id: challenge.id,
              type: 'speed',
              problems: (challenge as ReturnType<typeof generateSpeedChallenge>).challenges,
              timeLimit: `${challenge.timeLimit}ms`,
              instructions: (challenge as ReturnType<typeof generateSpeedChallenge>).instructions,
              submitHeader: 'X-Botcha-Challenge-Id',
              answerHeader: 'X-Botcha-Answers',
            }
          : {
              id: challenge.id,
              type: 'standard',
              puzzle: (challenge as ReturnType<typeof generateChallenge>).puzzle,
              timeLimit: `${challenge.timeLimit}ms`,
              hint: (challenge as ReturnType<typeof generateChallenge>).hint,
              submitHeader: 'X-Botcha-Challenge-Id',
              answerHeader: 'X-Botcha-Solution',
            }
      ) : undefined,
    });
  };
}

interface VerificationResult {
  verified: boolean;
  method?: 'signature' | 'challenge' | 'header' | 'custom';
  agent?: string;
  provider?: string;
  hint?: string;
}

async function verifyAgent(req: Request, opts: BotchaOptions): Promise<VerificationResult> {
  
  // Method 1: Web Bot Auth cryptographic signature (strongest)
  const signatureAgent = req.headers['signature-agent'] as string;
  if (signatureAgent) {
    // Check if from trusted provider
    if (!isTrustedProvider(signatureAgent)) {
      return { 
        verified: false, 
        hint: `Provider ${signatureAgent} not in trusted list`,
      };
    }
    
    const sigResult = await verifyWebBotAuth(
      req.headers as Record<string, string>,
      req.method,
      req.path,
      typeof req.body === 'string' ? req.body : JSON.stringify(req.body)
    );
    
    if (sigResult.valid) {
      return { 
        verified: true, 
        method: 'signature', 
        agent: sigResult.agent,
        provider: sigResult.provider,
      };
    }
  }

  // Method 2: Challenge-Response (if challenge solution provided)
  const challengeId = (req.headers['x-botcha-challenge-id'] as string)
    || (req.headers['x-botcha-id'] as string);
  const solution = req.headers['x-botcha-solution'] as string | undefined;
  const answersHeader = req.headers['x-botcha-answers'] as string | undefined;
  
  if (challengeId && (solution || answersHeader)) {
    const speedPayload = answersHeader || (solution && looksLikeJsonArray(solution) ? solution : undefined);
    if (speedPayload) {
      const answers = parseJsonArray(speedPayload);
      if (!answers) {
        return { verified: false, hint: 'Invalid speed challenge answers format' };
      }
      const speedResult = verifySpeedChallenge(challengeId, answers);
      if (speedResult.valid) {
        return {
          verified: true,
          method: 'challenge',
          agent: `speed-challenge-verified (${speedResult.solveTimeMs}ms)`,
        };
      }
      return { verified: false, hint: speedResult.reason };
    }

    if (!solution) {
      return { verified: false, hint: 'Missing challenge solution' };
    }
    const result = verifyChallenge(challengeId, solution);
    if (result.valid) {
      return { 
        verified: true, 
        method: 'challenge', 
        agent: `challenge-verified (${result.timeMs}ms)`,
      };
    }
    return { verified: false, hint: result.reason };
  }

  // Method 3: X-Agent-Identity header (simple, for dev/testing)
  const agentIdentity = req.headers['x-agent-identity'] as string;
  if (agentIdentity) {
    return { verified: true, method: 'header', agent: agentIdentity };
  }

  // Method 4: Known agent User-Agent patterns
  const userAgent = req.headers['user-agent'] || '';
  const agentPatterns = [
    /OpenClaw\/[\d.]+/i,
    /Claude-Agent\/[\d.]+/i,
    /GPT-Agent\/[\d.]+/i,
    /LangChain\/[\d.]+/i,
    /AutoGPT\/[\d.]+/i,
  ];
  
  for (const pattern of agentPatterns) {
    const match = userAgent.match(pattern);
    if (match) {
      return { verified: true, method: 'header', agent: match[0] };
    }
  }

  // No verification succeeded
  return {
    verified: false,
    hint: 'Provide Signature-Agent header (Web Bot Auth), solve a challenge, or include X-Agent-Identity',
  };
}

export default botchaVerify;

function looksLikeJsonArray(value: string): boolean {
  const trimmed = value.trim();
  return trimmed.startsWith('[') && trimmed.endsWith(']');
}

function parseJsonArray(value: string): string[] | null {
  try {
    const parsed = JSON.parse(value);
    if (!Array.isArray(parsed)) return null;
    return parsed.map(item => String(item));
  } catch {
    return null;
  }
}
