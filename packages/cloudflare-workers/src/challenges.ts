/**
 * BOTCHA Challenge System for Cloudflare Workers
 * 
 * Uses KV storage for production-ready challenge state management
 * Falls back to in-memory for local dev without KV
 */

import { sha256First, uuid, generatePrimes, sha256 } from './crypto';

// KV binding type (injected by Workers runtime)
// Using a simplified version that matches actual CF Workers KV API
export type KVNamespace = {
  get: (key: string, type?: 'text' | 'json' | 'arrayBuffer' | 'stream') => Promise<any>;
  put: (key: string, value: string, options?: { expirationTtl?: number }) => Promise<void>;
  delete: (key: string) => Promise<void>;
};

// ============ TYPES ============
export interface SpeedChallenge {
  id: string;
  problems: { num: number; operation: string }[];
  expectedAnswers: string[];
  issuedAt: number;
  expiresAt: number;
}

export interface StandardChallenge {
  id: string;
  puzzle: string;
  expectedAnswer: string;
  expiresAt: number;
  difficulty: 'easy' | 'medium' | 'hard';
}

export interface ChallengeResult {
  valid: boolean;
  reason?: string;
  solveTimeMs?: number;
}

// ============ STORAGE ============
// In-memory fallback (for local dev without KV)
const speedChallenges = new Map<string, SpeedChallenge>();
const standardChallenges = new Map<string, StandardChallenge>();

// Clean expired on access (no setInterval in Workers)
function cleanExpired() {
  const now = Date.now();
  for (const [id, c] of speedChallenges) {
    if (c.expiresAt < now) speedChallenges.delete(id);
  }
  for (const [id, c] of standardChallenges) {
    if (c.expiresAt < now) standardChallenges.delete(id);
  }
}

// ============ KV STORAGE HELPERS ============
/**
 * Store challenge in KV (with TTL) or fallback to memory
 */
async function storeChallenge(
  kv: KVNamespace | undefined,
  id: string,
  challenge: SpeedChallenge | StandardChallenge,
  ttlSeconds: number
): Promise<void> {
  if (kv) {
    await kv.put(`challenge:${id}`, JSON.stringify(challenge), {
      expirationTtl: ttlSeconds,
    });
  } else {
    // Fallback to in-memory
    if ('problems' in challenge) {
      speedChallenges.set(id, challenge);
    } else {
      standardChallenges.set(id, challenge);
    }
  }
}

/**
 * Get challenge from KV or fallback to memory
 */
async function getChallenge<T extends SpeedChallenge | StandardChallenge>(
  kv: KVNamespace | undefined,
  id: string,
  isSpeed: boolean
): Promise<T | null> {
  if (kv) {
    const data = await kv.get(`challenge:${id}`);
    return data ? JSON.parse(data) : null;
  } else {
    // Fallback to in-memory
    cleanExpired();
    return (isSpeed ? speedChallenges.get(id) : standardChallenges.get(id)) as T | undefined || null;
  }
}

/**
 * Delete challenge from KV or memory
 */
async function deleteChallenge(
  kv: KVNamespace | undefined,
  id: string
): Promise<void> {
  if (kv) {
    await kv.delete(`challenge:${id}`);
  } else {
    speedChallenges.delete(id);
    standardChallenges.delete(id);
  }
}

// ============ SPEED CHALLENGE ============
/**
 * Generate a speed challenge: 5 SHA256 problems, 500ms to solve ALL
 * Trivial for AI, impossible for humans to copy-paste fast enough
 */
export async function generateSpeedChallenge(kv?: KVNamespace): Promise<{
  id: string;
  problems: { num: number; operation: string }[];
  timeLimit: number;
  instructions: string;
}> {
  cleanExpired();
  
  const id = uuid();
  const problems: { num: number; operation: string }[] = [];
  const expectedAnswers: string[] = [];
  
  for (let i = 0; i < 5; i++) {
    const num = Math.floor(Math.random() * 900000) + 100000;
    problems.push({ num, operation: 'sha256_first8' });
    expectedAnswers.push(await sha256First(num.toString(), 8));
  }
  
  const timeLimit = 500;
  const challenge: SpeedChallenge = {
    id,
    problems,
    expectedAnswers,
    issuedAt: Date.now(),
    expiresAt: Date.now() + timeLimit + 100, // tiny grace
  };
  
  // Store in KV with 5 minute TTL (safety buffer for time checks)
  await storeChallenge(kv, id, challenge, 300);
  
  return {
    id,
    problems,
    timeLimit,
    instructions: 'Compute SHA256 of each number, return first 8 hex chars of each. Submit as array. You have 500ms.',
  };
}

/**
 * Verify a speed challenge response
 */
export async function verifySpeedChallenge(
  id: string,
  answers: string[],
  kv?: KVNamespace
): Promise<ChallengeResult> {
  const challenge = await getChallenge<SpeedChallenge>(kv, id, true);
  
  if (!challenge) {
    return { valid: false, reason: 'Challenge not found or expired' };
  }
  
  const now = Date.now();
  const solveTimeMs = now - challenge.issuedAt;
  
  // Delete challenge immediately to prevent replay attacks
  await deleteChallenge(kv, id);
  
  if (now > challenge.expiresAt) {
    return { valid: false, reason: `Too slow! Took ${solveTimeMs}ms, limit was 500ms` };
  }
  
  if (!Array.isArray(answers) || answers.length !== 5) {
    return { valid: false, reason: 'Must provide exactly 5 answers as array' };
  }
  
  for (let i = 0; i < 5; i++) {
    if (answers[i]?.toLowerCase() !== challenge.expectedAnswers[i]) {
      return { valid: false, reason: `Wrong answer for challenge ${i + 1}` };
    }
  }
  
  return { valid: true, solveTimeMs };
}

// ============ STANDARD CHALLENGE ============
const DIFFICULTY_CONFIG = {
  easy: { primes: 100, timeLimit: 10000 },
  medium: { primes: 500, timeLimit: 5000 },
  hard: { primes: 1000, timeLimit: 3000 },
};

/**
 * Generate a standard challenge: compute SHA256 of concatenated primes
 */
export async function generateStandardChallenge(
  difficulty: 'easy' | 'medium' | 'hard' = 'medium',
  kv?: KVNamespace
): Promise<{
  id: string;
  puzzle: string;
  timeLimit: number;
  hint: string;
}> {
  cleanExpired();
  
  const id = uuid();
  const config = DIFFICULTY_CONFIG[difficulty];
  
  const primes = generatePrimes(config.primes);
  const concatenated = primes.join('');
  const hash = await sha256(concatenated);
  const answer = hash.substring(0, 16);
  
  const challenge: StandardChallenge = {
    id,
    puzzle: `Compute SHA256 of the first ${config.primes} prime numbers concatenated (no separators). Return the first 16 hex characters.`,
    expectedAnswer: answer,
    expiresAt: Date.now() + config.timeLimit + 1000,
    difficulty,
  };
  
  // Store in KV with 5 minute TTL
  await storeChallenge(kv, id, challenge, 300);
  
  return {
    id,
    puzzle: `Compute SHA256 of the first ${config.primes} prime numbers concatenated (no separators). Return the first 16 hex characters.`,
    timeLimit: config.timeLimit,
    hint: `Example: First 5 primes = "235711" → SHA256 → first 16 chars`,
  };
}

/**
 * Verify a standard challenge response
 */
export async function verifyStandardChallenge(
  id: string,
  answer: string,
  kv?: KVNamespace
): Promise<ChallengeResult> {
  const challenge = await getChallenge<StandardChallenge>(kv, id, false);
  
  if (!challenge) {
    return { valid: false, reason: 'Challenge not found or expired' };
  }
  
  const now = Date.now();
  
  // Delete challenge immediately to prevent replay attacks
  await deleteChallenge(kv, id);
  
  if (now > challenge.expiresAt) {
    return { valid: false, reason: 'Challenge expired - too slow!' };
  }
  
  const isValid = answer.toLowerCase() === challenge.expectedAnswer.toLowerCase();
  
  if (!isValid) {
    return { valid: false, reason: 'Incorrect answer' };
  }
  
  const solveTimeMs = now - (challenge.expiresAt - DIFFICULTY_CONFIG[challenge.difficulty].timeLimit - 1000);
  
  return { valid: true, solveTimeMs };
}

// ============ LANDING CHALLENGE ============
const landingTokens = new Map<string, number>();

/**
 * Verify landing page challenge and issue access token
 * @deprecated - Use JWT token flow instead (see auth.ts)
 */
export async function verifyLandingChallenge(
  answer: string,
  timestamp: string,
  kv?: KVNamespace
): Promise<{
  valid: boolean;
  token?: string;
  error?: string;
  hint?: string;
}> {
  cleanExpired();
  
  // Verify timestamp is recent (within 5 minutes)
  const submittedTime = new Date(timestamp).getTime();
  const now = Date.now();
  if (Math.abs(now - submittedTime) > 5 * 60 * 1000) {
    return { valid: false, error: 'Timestamp too old or in future' };
  }
  
  // Calculate expected answer for today
  const today = new Date().toISOString().split('T')[0];
  const expectedHash = (await sha256(`BOTCHA-LANDING-${today}`)).substring(0, 16);
  
  if (answer.toLowerCase() !== expectedHash.toLowerCase()) {
    return { 
      valid: false, 
      error: 'Incorrect answer',
      hint: `Expected SHA256('BOTCHA-LANDING-${today}') first 16 chars`
    };
  }
  
  // Generate token
  const tokenBytes = new Uint8Array(32);
  crypto.getRandomValues(tokenBytes);
  const token = Array.from(tokenBytes).map(b => b.toString(16).padStart(2, '0')).join('');
  
  if (kv) {
    await kv.put(`landing:${token}`, Date.now().toString(), { expirationTtl: 3600 });
  } else {
    landingTokens.set(token, Date.now() + 60 * 60 * 1000);
  }
  
  // Clean expired tokens (memory only)
  for (const [t, expiry] of landingTokens) {
    if (expiry < Date.now()) landingTokens.delete(t);
  }
  
  return { valid: true, token };
}

/**
 * Validate a landing token
 * @deprecated - Use JWT token flow instead (see auth.ts)
 */
export async function validateLandingToken(token: string, kv?: KVNamespace): Promise<boolean> {
  if (kv) {
    const value = await kv.get(`landing:${token}`);
    return value !== null;
  } else {
    const expiry = landingTokens.get(token);
    if (!expiry) return false;
    if (expiry < Date.now()) {
      landingTokens.delete(token);
      return false;
    }
    return true;
  }
}

// ============ SOLVER (for AI agents) ============
/**
 * Solve speed challenge problems (utility for AI agents)
 */
export async function solveSpeedChallenge(problems: number[]): Promise<string[]> {
  return Promise.all(problems.map(n => sha256First(n.toString(), 8)));
}
