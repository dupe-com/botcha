import crypto from 'crypto';

interface SpeedChallenge {
  id: string;
  challenges: { num: number; operation: string }[];
  expectedAnswers: string[];
  issuedAt: number;
  expiresAt: number;
  baseTimeLimit: number;
  adjustedTimeLimit: number;
  rttMs?: number;
}

const speedChallenges = new Map<string, SpeedChallenge>();

// Cleanup expired
setInterval(() => {
  const now = Date.now();
  for (const [id, c] of speedChallenges) {
    if (c.expiresAt < now) speedChallenges.delete(id);
  }
}, 30000);

/**
 * Generate a speed challenge: 5 math problems, RTT-aware timeout
 * Trivial for AI, impossible for humans to copy-paste fast enough
 */
export function generateSpeedChallenge(clientTimestamp?: number): {
  id: string;
  challenges: { num: number; operation: string }[];
  timeLimit: number;
  instructions: string;
  rttInfo?: {
    measuredRtt: number;
    adjustedTimeout: number;
    explanation: string;
  };
} {
  const id = crypto.randomUUID();
  const challenges: { num: number; operation: string }[] = [];
  const expectedAnswers: string[] = [];
  
  for (let i = 0; i < 5; i++) {
    const num = Math.floor(Math.random() * 1000000) + 100000;
    const operation = 'sha256_first8';
    challenges.push({ num, operation });
    
    const hash = crypto.createHash('sha256').update(num.toString()).digest('hex');
    expectedAnswers.push(hash.substring(0, 8));
  }
  
  // RTT-aware timeout calculation
  const baseTimeLimit = 500; // Base computation time for AI agents
  const now = Date.now();
  let rttMs = 0;
  let adjustedTimeLimit = baseTimeLimit;
  let rttInfo: any = undefined;
  
  if (clientTimestamp && clientTimestamp > 0) {
    // Calculate RTT from client timestamp
    rttMs = Math.max(0, now - clientTimestamp);
    
    // Adjust timeout: base + (2 * RTT) + 100ms buffer
    // The 2x RTT accounts for request + response network time
    adjustedTimeLimit = Math.max(baseTimeLimit, baseTimeLimit + (2 * rttMs) + 100);
    
    rttInfo = {
      measuredRtt: rttMs,
      adjustedTimeout: adjustedTimeLimit,
      explanation: `RTT: ${rttMs}ms → Timeout: ${baseTimeLimit}ms + (2×${rttMs}ms) + 100ms = ${adjustedTimeLimit}ms`,
    };
  }
  
  speedChallenges.set(id, {
    id,
    challenges,
    expectedAnswers,
    issuedAt: now,
    expiresAt: now + adjustedTimeLimit + 50, // Small server-side grace period
    baseTimeLimit,
    adjustedTimeLimit,
    rttMs,
  });
  
  const instructions = rttMs > 0
    ? `Compute SHA256 of each number, return first 8 hex chars of each. Submit as array. You have ${adjustedTimeLimit}ms (adjusted for your ${rttMs}ms network latency).`
    : 'Compute SHA256 of each number, return first 8 hex chars of each. Submit as array. You have 500ms.';
  
  return {
    id,
    challenges,
    timeLimit: adjustedTimeLimit,
    instructions,
    rttInfo,
  };
}

export function verifySpeedChallenge(id: string, answers: string[]): {
  valid: boolean;
  reason?: string;
  solveTimeMs?: number;
  rttInfo?: {
    measuredRtt: number;
    adjustedTimeout: number;
    actualTime: number;
  };
} {
  const challenge = speedChallenges.get(id);
  
  if (!challenge) {
    return { valid: false, reason: 'Challenge not found or expired' };
  }
  
  const now = Date.now();
  const solveTimeMs = now - challenge.issuedAt;
  
  // Clean up
  speedChallenges.delete(id);
  
  // Use the challenge's adjusted timeout, fallback to base if not available
  const timeLimit = challenge.adjustedTimeLimit || challenge.baseTimeLimit || 500;
  
  if (now > challenge.expiresAt) {
    const rttExplanation = challenge.rttMs 
      ? ` (RTT-adjusted: ${challenge.rttMs}ms network + ${challenge.baseTimeLimit}ms compute = ${timeLimit}ms limit)`
      : '';
    return { 
      valid: false, 
      reason: `Too slow! Took ${solveTimeMs}ms, limit was ${timeLimit}ms${rttExplanation}`,
      rttInfo: challenge.rttMs ? {
        measuredRtt: challenge.rttMs,
        adjustedTimeout: timeLimit,
        actualTime: solveTimeMs,
      } : undefined,
    };
  }
  
  if (!Array.isArray(answers) || answers.length !== 5) {
    return { valid: false, reason: 'Must provide exactly 5 answers as array' };
  }
  
  for (let i = 0; i < 5; i++) {
    if (answers[i]?.toLowerCase() !== challenge.expectedAnswers[i]) {
      return { valid: false, reason: `Wrong answer for challenge ${i + 1}` };
    }
  }
  
  return { 
    valid: true, 
    solveTimeMs,
    rttInfo: challenge.rttMs ? {
      measuredRtt: challenge.rttMs,
      adjustedTimeout: timeLimit,
      actualTime: solveTimeMs,
    } : undefined,
  };
}

export default { generateSpeedChallenge, verifySpeedChallenge };
