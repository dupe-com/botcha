import crypto from 'crypto';
import { generateSpeedChallenge, verifySpeedChallenge } from './speed.js';
import { generateReasoningChallenge, verifyReasoningChallenge } from './reasoning.js';

interface HybridChallenge {
  id: string;
  speedChallengeId: string;
  reasoningChallengeId: string;
  issuedAt: number;
  expiresAt: number;
}

const hybridChallenges = new Map<string, HybridChallenge>();

// Cleanup expired
setInterval(() => {
  const now = Date.now();
  for (const [id, c] of hybridChallenges) {
    if (c.expiresAt < now) hybridChallenges.delete(id);
  }
}, 60000);

/**
 * Generate a hybrid challenge: speed + reasoning combined
 * Must solve SHA256 problems in <500ms AND answer reasoning questions
 */
export function generateHybridChallenge(): {
  id: string;
  speed: {
    problems: { num: number; operation: string }[];
    timeLimit: number;
  };
  reasoning: {
    questions: { id: string; question: string; category: string }[];
    timeLimit: number;
  };
  instructions: string;
} {
  const id = crypto.randomUUID();

  // Generate both sub-challenges
  const speedChallenge = generateSpeedChallenge();
  const reasoningChallenge = generateReasoningChallenge();

  // Store the mapping
  hybridChallenges.set(id, {
    id,
    speedChallengeId: speedChallenge.id,
    reasoningChallengeId: reasoningChallenge.id,
    issuedAt: Date.now(),
    expiresAt: Date.now() + 35000, // 35 seconds total (500ms for speed + 30s for reasoning + buffer)
  });

  return {
    id,
    speed: {
      problems: speedChallenge.challenges,
      timeLimit: speedChallenge.timeLimit,
    },
    reasoning: {
      questions: reasoningChallenge.questions,
      timeLimit: reasoningChallenge.timeLimit,
    },
    instructions: 'Solve ALL speed problems (SHA256) in <500ms AND answer ALL reasoning questions. Submit both together.',
  };
}

export function verifyHybridChallenge(
  id: string,
  speedAnswers: string[],
  reasoningAnswers: Record<string, string>
): {
  valid: boolean;
  reason?: string;
  speed: { passed: boolean; solveTimeMs?: number; reason?: string };
  reasoning: { passed: boolean; score?: string; solveTimeMs?: number; reason?: string };
  totalTimeMs?: number;
} {
  const hybrid = hybridChallenges.get(id);

  if (!hybrid) {
    return {
      valid: false,
      reason: 'Hybrid challenge not found or expired',
      speed: { passed: false, reason: 'Challenge not found' },
      reasoning: { passed: false, reason: 'Challenge not found' },
    };
  }

  const now = Date.now();
  const totalTimeMs = now - hybrid.issuedAt;

  // Don't delete yet - we need to verify both parts

  if (now > hybrid.expiresAt) {
    hybridChallenges.delete(id);
    return {
      valid: false,
      reason: 'Hybrid challenge expired',
      speed: { passed: false, reason: 'Expired' },
      reasoning: { passed: false, reason: 'Expired' },
      totalTimeMs,
    };
  }

  // Verify speed challenge
  const speedResult = verifySpeedChallenge(hybrid.speedChallengeId, speedAnswers);

  // Verify reasoning challenge
  const reasoningResult = verifyReasoningChallenge(hybrid.reasoningChallengeId, reasoningAnswers);

  // Clean up
  hybridChallenges.delete(id);

  const speedPassed = speedResult.valid;
  const reasoningPassed = reasoningResult.valid;
  const bothPassed = speedPassed && reasoningPassed;

  return {
    valid: bothPassed,
    reason: bothPassed
      ? undefined
      : `Failed: ${!speedPassed ? 'speed' : ''}${!speedPassed && !reasoningPassed ? ' + ' : ''}${!reasoningPassed ? 'reasoning' : ''}`,
    speed: {
      passed: speedPassed,
      solveTimeMs: speedResult.solveTimeMs,
      reason: speedResult.reason,
    },
    reasoning: {
      passed: reasoningPassed,
      score: reasoningResult.valid ? `${reasoningResult.correctCount}/${reasoningResult.totalCount}` : undefined,
      solveTimeMs: reasoningResult.solveTimeMs,
      reason: reasoningResult.reason,
    },
    totalTimeMs,
  };
}

export default { generateHybridChallenge, verifyHybridChallenge };
