/**
 * TAP-Enhanced BOTCHA Verification Middleware
 * Extends existing BOTCHA middleware with Trusted Agent Protocol support
 * 
 * Provides multiple verification modes:
 * - TAP (full): Cryptographic signature + computational challenge
 * - Signature-only: Cryptographic verification without challenge
 * - Challenge-only: Existing BOTCHA computational challenge
 * - Flexible: TAP preferred but allows fallback
 */

import { Request, Response, NextFunction } from 'express';
import { generateChallenge, verifyChallenge } from '../challenges/compute';
import { generateSpeedChallenge, verifySpeedChallenge } from '../challenges/speed';
import { 
  verifyHTTPMessageSignature, 
  parseTAPIntent, 
  extractTAPHeaders, 
  getVerificationMode,
  buildTAPChallengeResponse,
  TAPVerificationResult 
} from '../../packages/cloudflare-workers/src/tap-verify';
import { 
  getTAPAgent, 
  updateAgentVerification, 
  createTAPSession, 
  validateCapability,
  TAPAgent 
} from '../../packages/cloudflare-workers/src/tap-agents';

// ============ EXTENDED OPTIONS ============

interface TAPBotchaOptions {
  // Existing BOTCHA options
  requireSignature?: boolean;
  allowChallenge?: boolean;
  challengeType?: 'standard' | 'speed';
  challengeDifficulty?: 'easy' | 'medium' | 'hard';
  customVerify?: (req: Request) => Promise<boolean>;
  
  // TAP-specific options
  requireTAP?: boolean;           // Force TAP authentication (no fallback)
  preferTAP?: boolean;            // Prefer TAP but allow fallback
  tapEnabled?: boolean;           // Enable TAP features
  auditLogging?: boolean;         // Log all verification attempts
  
  // Enterprise options
  trustedIssuers?: string[];      // Trusted agent issuers
  maxSessionDuration?: number;    // Session TTL in seconds
  signatureAlgorithms?: string[]; // Allowed signature algorithms
  requireCapabilities?: string[]; // Required agent capabilities
  
  // Storage (for Cloudflare Workers integration)
  agentsKV?: any;                 // KV namespace for agents
  sessionsKV?: any;               // KV namespace for sessions
}

const defaultTAPOptions: TAPBotchaOptions = {
  // BOTCHA defaults
  requireSignature: false,
  allowChallenge: true,
  challengeType: 'speed',
  challengeDifficulty: 'medium',
  
  // TAP defaults
  requireTAP: false,
  preferTAP: true,
  tapEnabled: true,
  auditLogging: false,
  trustedIssuers: ['openclaw.ai', 'anthropic.com', 'openai.com'],
  maxSessionDuration: 3600,
  signatureAlgorithms: ['ecdsa-p256-sha256', 'rsa-pss-sha256'],
  requireCapabilities: []
};

// ============ MAIN MIDDLEWARE ============

/**
 * Enhanced BOTCHA middleware with TAP support
 */
export function tapEnhancedVerify(options: TAPBotchaOptions = {}) {
  const opts = { ...defaultTAPOptions, ...options };
  
  return async (req: Request, res: Response, next: NextFunction) => {
    const startTime = Date.now();
    
    try {
      // Determine verification approach
      const { mode, hasTAPHeaders, hasChallenge } = getVerificationMode(req.headers as Record<string, string>);
      
      let result: TAPVerificationResult;
      
      // Route to appropriate verification method
      if (mode === 'tap' && opts.tapEnabled) {
        result = await performFullTAPVerification(req, opts);
      } else if (mode === 'signature-only' && opts.tapEnabled) {
        result = await performSignatureOnlyVerification(req, opts);
      } else if (mode === 'challenge-only') {
        result = await performChallengeOnlyVerification(req, opts);
      } else {
        // Fallback or error case
        result = await handleVerificationFallback(req, opts, mode);
      }
      
      // Custom verification hook
      if (opts.customVerify && result.verified) {
        const customResult = await opts.customVerify(req);
        if (!customResult) {
          result.verified = false;
          result.error = 'Custom verification failed';
        }
      }
      
      // Audit logging
      if (opts.auditLogging) {
        logVerificationAttempt(req, result, Date.now() - startTime);
      }
      
      // Handle successful verification
      if (result.verified) {
        // Attach verification context to request
        (req as any).tapAgent = result.agent_id ? await getTAPAgentById(opts.agentsKV, result.agent_id) : null;
        (req as any).verificationMethod = result.verification_method;
        (req as any).tapSession = result.session_id;
        (req as any).challengesPassed = result.challenges_passed;
        (req as any).verificationDuration = Date.now() - startTime;
        
        return next();
      }
      
      // Handle verification failure
      return sendVerificationChallenge(res, result, opts);
      
    } catch (error) {
      console.error('TAP verification error:', error);
      
      if (opts.auditLogging) {
        console.log('TAP_VERIFICATION_ERROR', {
          error: error.message,
          path: req.path,
          method: req.method,
          timestamp: new Date().toISOString()
        });
      }
      
      return res.status(500).json({
        success: false,
        error: 'VERIFICATION_ERROR',
        message: 'Internal verification error'
      });
    }
  };
}

// ============ VERIFICATION METHODS ============

/**
 * Full TAP verification (crypto + computational)
 */
async function performFullTAPVerification(
  req: Request,
  opts: TAPBotchaOptions
): Promise<TAPVerificationResult> {
  const { tapHeaders } = extractTAPHeaders(req.headers as Record<string, string>);
  
  if (!tapHeaders['x-tap-agent-id'] || !opts.agentsKV) {
    return {
      verified: false,
      verification_method: 'tap',
      challenges_passed: { computational: false, cryptographic: false },
      error: 'Missing TAP agent ID or storage not configured'
    };
  }
  
  // Get agent from registry
  const agentResult = await getTAPAgent(opts.agentsKV, tapHeaders['x-tap-agent-id']!);
  if (!agentResult.success || !agentResult.agent) {
    return {
      verified: false,
      verification_method: 'tap',
      challenges_passed: { computational: false, cryptographic: false },
      error: `Agent ${tapHeaders['x-tap-agent-id']} not found`
    };
  }
  
  const agent = agentResult.agent;
  
  // Verify cryptographic signature
  const cryptoResult = await verifyCryptographicSignature(req, agent);
  
  // Verify computational challenge
  const challengeResult = await verifyComputationalChallenge(req);
  
  // Both must pass for full TAP
  const verified = cryptoResult.valid && challengeResult.valid;
  
  // Update agent verification timestamp
  if (opts.agentsKV) {
    await updateAgentVerification(opts.agentsKV, agent.agent_id, verified);
  }
  
  // Create session if successful
  let sessionId: string | undefined;
  if (verified && opts.sessionsKV && tapHeaders['x-tap-intent'] && tapHeaders['x-tap-user-context']) {
    const intentResult = parseTAPIntent(tapHeaders['x-tap-intent']);
    if (intentResult.valid && intentResult.intent) {
      const sessionResult = await createTAPSession(
        opts.sessionsKV,
        agent.agent_id,
        agent.app_id,
        tapHeaders['x-tap-user-context'],
        agent.capabilities || [],
        intentResult.intent
      );
      
      if (sessionResult.success) {
        sessionId = sessionResult.session?.session_id;
      }
    }
  }
  
  return {
    verified,
    agent_id: agent.agent_id,
    verification_method: 'tap',
    challenges_passed: {
      computational: challengeResult.valid,
      cryptographic: cryptoResult.valid
    },
    session_id: sessionId,
    error: verified ? undefined : `Crypto: ${cryptoResult.error || 'OK'}, Challenge: ${challengeResult.error || 'OK'}`,
    metadata: {
      solve_time_ms: challengeResult.solveTimeMs,
      signature_valid: cryptoResult.valid,
      capabilities: agent.capabilities?.map(c => c.action)
    }
  };
}

/**
 * Signature-only verification
 */
async function performSignatureOnlyVerification(
  req: Request,
  opts: TAPBotchaOptions
): Promise<TAPVerificationResult> {
  const { tapHeaders } = extractTAPHeaders(req.headers as Record<string, string>);
  
  if (!tapHeaders['x-tap-agent-id'] || !opts.agentsKV) {
    return {
      verified: false,
      verification_method: 'signature-only',
      challenges_passed: { computational: false, cryptographic: false },
      error: 'Missing TAP agent ID'
    };
  }
  
  // Get agent from registry
  const agentResult = await getTAPAgent(opts.agentsKV, tapHeaders['x-tap-agent-id']!);
  if (!agentResult.success || !agentResult.agent) {
    return {
      verified: false,
      verification_method: 'signature-only',
      challenges_passed: { computational: false, cryptographic: false },
      error: 'Agent not found'
    };
  }
  
  // Verify signature
  const cryptoResult = await verifyCryptographicSignature(req, agentResult.agent);
  
  return {
    verified: cryptoResult.valid,
    agent_id: agentResult.agent.agent_id,
    verification_method: 'signature-only',
    challenges_passed: {
      computational: false,
      cryptographic: cryptoResult.valid
    },
    error: cryptoResult.error,
    metadata: {
      signature_valid: cryptoResult.valid
    }
  };
}

/**
 * Challenge-only verification (existing BOTCHA)
 */
async function performChallengeOnlyVerification(
  req: Request,
  opts: TAPBotchaOptions
): Promise<TAPVerificationResult> {
  const challengeResult = await verifyComputationalChallenge(req);
  
  return {
    verified: challengeResult.valid,
    verification_method: 'challenge',
    challenges_passed: {
      computational: challengeResult.valid,
      cryptographic: false
    },
    error: challengeResult.error,
    metadata: {
      solve_time_ms: challengeResult.solveTimeMs
    }
  };
}

/**
 * Handle verification fallback cases
 */
async function handleVerificationFallback(
  req: Request,
  opts: TAPBotchaOptions,
  mode: string
): Promise<TAPVerificationResult> {
  if (opts.requireTAP) {
    return {
      verified: false,
      verification_method: 'tap',
      challenges_passed: { computational: false, cryptographic: false },
      error: 'TAP authentication required'
    };
  }
  
  // Fallback to challenge-only if allowed
  if (opts.allowChallenge) {
    return await performChallengeOnlyVerification(req, opts);
  }
  
  return {
    verified: false,
    verification_method: 'challenge',
    challenges_passed: { computational: false, cryptographic: false },
    error: 'No valid verification method available'
  };
}

// ============ HELPER FUNCTIONS ============

async function verifyCryptographicSignature(
  req: Request,
  agent: TAPAgent
): Promise<{ valid: boolean; error?: string }> {
  if (!agent.public_key || !agent.signature_algorithm) {
    return { valid: false, error: 'Agent has no cryptographic key configured' };
  }
  
  const verificationRequest = {
    method: req.method,
    path: req.path,
    headers: req.headers as Record<string, string>,
    body: typeof req.body === 'string' ? req.body : JSON.stringify(req.body)
  };
  
  return await verifyHTTPMessageSignature(
    verificationRequest,
    agent.public_key,
    agent.signature_algorithm
  );
}

async function verifyComputationalChallenge(req: Request): Promise<{
  valid: boolean;
  error?: string;
  solveTimeMs?: number;
}> {
  const challengeId = req.headers['x-botcha-challenge-id'] as string;
  const answers = req.headers['x-botcha-answers'] as string;
  
  if (!challengeId || !answers) {
    return { valid: false, error: 'Missing challenge ID or answers' };
  }
  
  try {
    const answersArray = JSON.parse(answers);
    if (!Array.isArray(answersArray)) {
      return { valid: false, error: 'Answers must be an array' };
    }
    
    const result = verifySpeedChallenge(challengeId, answersArray);
    return {
      valid: result.valid,
      error: result.reason,
      solveTimeMs: result.solveTimeMs
    };
  } catch (err) {
    return { valid: false, error: `Challenge verification error: ${err}` };
  }
}

async function getTAPAgentById(agentsKV: any, agentId: string): Promise<TAPAgent | null> {
  if (!agentsKV) return null;
  
  try {
    const result = await getTAPAgent(agentsKV, agentId);
    return result.success ? result.agent! : null;
  } catch {
    return null;
  }
}

function sendVerificationChallenge(
  res: Response,
  result: TAPVerificationResult,
  opts: TAPBotchaOptions
): void {
  // Generate challenge if needed
  let challenge = null;
  if (!result.challenges_passed.computational && opts.allowChallenge) {
    challenge = generateSpeedChallenge();
  }
  
  // Build TAP challenge response
  const response = buildTAPChallengeResponse(result, challenge);
  
  // Add challenge headers
  if (challenge) {
    res.header('X-Botcha-Challenge-Id', challenge.id);
    res.header('X-Botcha-Challenge-Type', 'speed');
    res.header('X-Botcha-Time-Limit', challenge.timeLimit.toString());
  }
  
  const statusCode = result.challenges_passed.cryptographic ? 401 : 403;
  res.status(statusCode).json(response);
}

function logVerificationAttempt(
  req: Request,
  result: TAPVerificationResult,
  durationMs: number
): void {
  const logEntry = {
    timestamp: new Date().toISOString(),
    method: req.method,
    path: req.path,
    userAgent: req.headers['user-agent'],
    clientIP: req.ip || req.connection?.remoteAddress,
    verificationMethod: result.verification_method,
    verified: result.verified,
    challengesPassed: result.challenges_passed,
    agentId: result.agent_id,
    sessionId: result.session_id,
    durationMs,
    error: result.error
  };
  
  console.log('TAP_VERIFICATION_AUDIT', logEntry);
}

// ============ PRE-CONFIGURED MODES ============

export const tapVerifyModes = {
  /**
   * Require full TAP authentication (crypto + challenge)
   */
  strict: (options: Partial<TAPBotchaOptions> = {}) => tapEnhancedVerify({
    requireTAP: true,
    allowChallenge: true,
    auditLogging: true,
    ...options
  }),
  
  /**
   * Prefer TAP but allow computational fallback
   */
  flexible: (options: Partial<TAPBotchaOptions> = {}) => tapEnhancedVerify({
    preferTAP: true,
    allowChallenge: true,
    requireTAP: false,
    ...options
  }),
  
  /**
   * Signature-only verification (no computational challenge)
   */
  signatureOnly: (options: Partial<TAPBotchaOptions> = {}) => tapEnhancedVerify({
    requireTAP: false,
    allowChallenge: false,
    tapEnabled: true,
    ...options
  }),
  
  /**
   * Development mode with relaxed security
   */
  development: (options: Partial<TAPBotchaOptions> = {}) => tapEnhancedVerify({
    requireTAP: false,
    allowChallenge: true,
    auditLogging: true,
    trustedIssuers: ['test-issuer', 'localhost', 'development'],
    ...options
  })
};

export default tapEnhancedVerify;