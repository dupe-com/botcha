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
  baseTimeLimit: number;
  adjustedTimeLimit: number;
  rttMs?: number;
}

export interface StandardChallenge {
  id: string;
  puzzle: string;
  expectedAnswer: string;
  expiresAt: number;
  difficulty: 'easy' | 'medium' | 'hard';
}

export interface ReasoningQuestion {
  id: string;
  question: string;
  category: 'analogy' | 'logic' | 'wordplay' | 'math' | 'code' | 'common-sense';
  acceptedAnswers: string[];
}

export interface ReasoningChallenge {
  id: string;
  questions: { id: string; question: string; category: string }[];
  expectedAnswers: Record<string, string[]>;
  issuedAt: number;
  expiresAt: number;
}

export interface ChallengeResult {
  valid: boolean;
  reason?: string;
  solveTimeMs?: number;
  correctCount?: number;
  totalCount?: number;
}

export interface HybridChallenge {
  id: string;
  speedChallengeId: string;
  reasoningChallengeId: string;
  issuedAt: number;
  expiresAt: number;
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
 * Generate a speed challenge: 5 SHA256 problems, RTT-aware timeout
 * Trivial for AI, impossible for humans to copy-paste fast enough
 */
export async function generateSpeedChallenge(
  kv?: KVNamespace,
  clientTimestamp?: number
): Promise<{
  id: string;
  problems: { num: number; operation: string }[];
  timeLimit: number;
  instructions: string;
  rttInfo?: {
    measuredRtt: number;
    adjustedTimeout: number;
    explanation: string;
  };
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
  
  // RTT-aware timeout calculation
  const baseTimeLimit = 500; // Base computation time for AI agents
  const MAX_RTT_MS = 5000; // Cap RTT to prevent timestamp spoofing (5s max)
  const MAX_TIMESTAMP_AGE_MS = 30000; // Reject timestamps older than 30s
  const now = Date.now();
  let rttMs = 0;
  let adjustedTimeLimit = baseTimeLimit;
  let rttInfo: any = undefined;
  
  if (clientTimestamp && clientTimestamp > 0) {
    // Reject timestamps in the future or too far in the past (anti-spoofing)
    const age = now - clientTimestamp;
    if (age >= 0 && age <= MAX_TIMESTAMP_AGE_MS) {
      // Calculate RTT from client timestamp, capped to prevent abuse
      rttMs = Math.min(age, MAX_RTT_MS);
      
      // Adjust timeout: base + (2 * RTT) + 100ms buffer
      // The 2x RTT accounts for request + response network time
      adjustedTimeLimit = Math.max(baseTimeLimit, baseTimeLimit + (2 * rttMs) + 100);
      
      rttInfo = {
        measuredRtt: rttMs,
        adjustedTimeout: adjustedTimeLimit,
        explanation: `RTT: ${rttMs}ms → Timeout: ${baseTimeLimit}ms + (2×${rttMs}ms) + 100ms = ${adjustedTimeLimit}ms`,
      };
    }
    // else: invalid timestamp silently ignored, use base timeout
  }
  
  const challenge: SpeedChallenge = {
    id,
    problems,
    expectedAnswers,
    issuedAt: now,
    expiresAt: now + adjustedTimeLimit + 50, // Small server-side grace period
    baseTimeLimit,
    adjustedTimeLimit,
    rttMs,
  };
  
  // Store in KV with 5 minute TTL (safety buffer for time checks)
  await storeChallenge(kv, id, challenge, 300);
  
  const instructions = rttMs > 0
    ? `Compute SHA256 of each number, return first 8 hex chars of each. Submit as array. You have ${adjustedTimeLimit}ms (adjusted for your ${rttMs}ms network latency).`
    : 'Compute SHA256 of each number, return first 8 hex chars of each. Submit as array. You have 500ms.';
  
  return {
    id,
    problems,
    timeLimit: adjustedTimeLimit,
    instructions,
    rttInfo,
  };
}

/**
 * Verify a speed challenge response with RTT-aware timeout
 */
export async function verifySpeedChallenge(
  id: string,
  answers: string[],
  kv?: KVNamespace
): Promise<ChallengeResult & { 
  rttInfo?: { 
    measuredRtt: number; 
    adjustedTimeout: number; 
    actualTime: number;
  } 
}> {
  const challenge = await getChallenge<SpeedChallenge>(kv, id, true);
  
  if (!challenge) {
    return { valid: false, reason: 'Challenge not found or expired' };
  }
  
  const now = Date.now();
  const solveTimeMs = now - challenge.issuedAt;
  
  // Delete challenge immediately to prevent replay attacks
  await deleteChallenge(kv, id);
  
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
  
  // Random salt makes each challenge unique — precomputed lookup tables won't work
  const salt = uuid().replace(/-/g, '').substring(0, 16);
  
  const primes = generatePrimes(config.primes);
  const concatenated = primes.join('') + salt;
  const hash = await sha256(concatenated);
  const answer = hash.substring(0, 16);
  
  const challenge: StandardChallenge = {
    id,
    puzzle: `Compute SHA256 of the first ${config.primes} prime numbers concatenated (no separators) followed by the salt "${salt}". Return the first 16 hex characters.`,
    expectedAnswer: answer,
    expiresAt: Date.now() + config.timeLimit + 1000,
    difficulty,
  };
  
  // Store in KV with 5 minute TTL
  await storeChallenge(kv, id, challenge, 300);
  
  return {
    id,
    puzzle: `Compute SHA256 of the first ${config.primes} prime numbers concatenated (no separators) followed by the salt "${salt}". Return the first 16 hex characters.`,
    timeLimit: config.timeLimit,
    hint: `Example: First 5 primes + salt = "235711${salt}" → SHA256 → first 16 chars`,
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
  
  // Verify timestamp is recent (within 2 minutes — tighter window for security)
  const submittedTime = new Date(timestamp).getTime();
  const now = Date.now();
  if (Number.isNaN(submittedTime) || Math.abs(now - submittedTime) > 2 * 60 * 1000) {
    return { valid: false, error: 'Timestamp expired or invalid. Request a fresh challenge.' };
  }
  
  // Per-request nonce: include the timestamp in the hash input so answers are unique per request
  // This prevents answer sharing — each timestamp produces a different expected answer
  const today = new Date().toISOString().split('T')[0];
  const expectedHash = (await sha256(`BOTCHA-LANDING-${today}-${timestamp}`)).substring(0, 16);
  
  if (answer.toLowerCase() !== expectedHash.toLowerCase()) {
    return { 
      valid: false, 
      error: 'Incorrect answer',
      // Don't leak the formula — only give a generic hint
      hint: 'Parse the challenge from <script type="application/botcha+json"> on the landing page and compute the answer.',
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

// ============ REASONING CHALLENGE ============
// In-memory storage for reasoning challenges
const reasoningChallenges = new Map<string, ReasoningChallenge>();

// ============ PARAMETERIZED QUESTION GENERATORS ============
// These generate unique questions each time, so a static lookup table won't work.

function randInt(min: number, max: number): number {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function pickRandom<T>(arr: T[]): T {
  return arr[Math.floor(Math.random() * arr.length)];
}

type QuestionGenerator = () => ReasoningQuestion;

// --- Math generators (randomized numbers each time) ---
function genMathAdd(): ReasoningQuestion {
  const a = randInt(100, 999);
  const b = randInt(100, 999);
  return {
    id: `math-add-${uuid().substring(0, 8)}`,
    question: `What is ${a} + ${b}?`,
    category: 'math',
    acceptedAnswers: [(a + b).toString()],
  };
}

function genMathMultiply(): ReasoningQuestion {
  const a = randInt(12, 99);
  const b = randInt(12, 99);
  return {
    id: `math-mul-${uuid().substring(0, 8)}`,
    question: `What is ${a} × ${b}?`,
    category: 'math',
    acceptedAnswers: [(a * b).toString()],
  };
}

function genMathModulo(): ReasoningQuestion {
  const a = randInt(50, 999);
  const b = randInt(3, 19);
  return {
    id: `math-mod-${uuid().substring(0, 8)}`,
    question: `What is ${a} % ${b} (modulo)?`,
    category: 'math',
    acceptedAnswers: [(a % b).toString()],
  };
}

function genMathSheep(): ReasoningQuestion {
  const total = randInt(15, 50);
  const remaining = randInt(3, total - 2);
  return {
    id: `math-sheep-${uuid().substring(0, 8)}`,
    question: `A farmer has ${total} sheep. All but ${remaining} run away. How many sheep does he have left? Answer with just the number.`,
    category: 'math',
    acceptedAnswers: [remaining.toString()],
  };
}

function genMathDoubling(): ReasoningQuestion {
  const days = randInt(20, 60);
  return {
    id: `math-double-${uuid().substring(0, 8)}`,
    question: `A patch of lily pads doubles in size every day. If it takes ${days} days to cover the entire lake, how many days to cover half? Answer with just the number.`,
    category: 'math',
    acceptedAnswers: [(days - 1).toString()],
  };
}

function genMathMachines(): ReasoningQuestion {
  const n = pickRandom([5, 7, 8, 10, 12]);
  const m = randInt(50, 200);
  return {
    id: `math-machines-${uuid().substring(0, 8)}`,
    question: `If it takes ${n} machines ${n} minutes to make ${n} widgets, how many minutes would it take ${m} machines to make ${m} widgets? Answer with just the number.`,
    category: 'math',
    acceptedAnswers: [n.toString()],
  };
}

// --- Code generators (randomized values) ---
function genCodeModulo(): ReasoningQuestion {
  const a = randInt(20, 200);
  const b = randInt(3, 15);
  return {
    id: `code-mod-${uuid().substring(0, 8)}`,
    question: `In most programming languages, what does ${a} % ${b} evaluate to?`,
    category: 'code',
    acceptedAnswers: [(a % b).toString()],
  };
}

function genCodeBitwise(): ReasoningQuestion {
  const a = randInt(1, 15);
  const b = randInt(1, 15);
  const op = pickRandom(['&', '|', '^'] as const);
  const opName = op === '&' ? 'AND' : op === '|' ? 'OR' : 'XOR';
  let answer: number;
  if (op === '&') answer = a & b;
  else if (op === '|') answer = a | b;
  else answer = a ^ b;
  return {
    id: `code-bit-${uuid().substring(0, 8)}`,
    question: `What is ${a} ${op} ${b} (bitwise ${opName})? Answer with just the number.`,
    category: 'code',
    acceptedAnswers: [answer.toString()],
  };
}

function genCodeStringLen(): ReasoningQuestion {
  const words = ['hello', 'world', 'banana', 'algorithm', 'quantum', 'symphony', 'cryptography', 'paradigm', 'ephemeral', 'serendipity'];
  const word = pickRandom(words);
  return {
    id: `code-strlen-${uuid().substring(0, 8)}`,
    question: `What is the length of the string "${word}"? Answer with just the number.`,
    category: 'code',
    acceptedAnswers: [word.length.toString()],
  };
}

// --- Logic generators (randomized names/items) ---
function genLogicSyllogism(): ReasoningQuestion {
  const groups = [
    ['Bloops', 'Razzies', 'Lazzies'],
    ['Florps', 'Zinkies', 'Mopples'],
    ['Grunts', 'Tazzles', 'Wibbles'],
    ['Plonks', 'Snazzles', 'Krinkles'],
    ['Dweems', 'Fozzits', 'Glimmers'],
  ];
  const [a, b, c] = pickRandom(groups);
  return {
    id: `logic-syl-${uuid().substring(0, 8)}`,
    question: `If all ${a} are ${b} and all ${b} are ${c}, are all ${a} definitely ${c}? Answer yes or no.`,
    category: 'logic',
    acceptedAnswers: ['yes'],
  };
}

function genLogicNegation(): ReasoningQuestion {
  const total = randInt(20, 100);
  const keep = randInt(3, total - 5);
  return {
    id: `logic-neg-${uuid().substring(0, 8)}`,
    question: `There are ${total} marbles in a bag. You remove all but ${keep}. How many marbles are left in the bag? Answer with just the number.`,
    category: 'logic',
    acceptedAnswers: [keep.toString()],
  };
}

function genLogicSequence(): ReasoningQuestion {
  const start = randInt(2, 20);
  const step = randInt(2, 8);
  const seq = [start, start + step, start + 2 * step, start + 3 * step];
  return {
    id: `logic-seq-${uuid().substring(0, 8)}`,
    question: `What comes next in the sequence: ${seq.join(', ')}, ___? Answer with just the number.`,
    category: 'logic',
    acceptedAnswers: [(start + 4 * step).toString()],
  };
}

// --- Wordplay / static (with randomized IDs so lookup by ID fails) ---
const WORDPLAY_GENERATORS: QuestionGenerator[] = [
  () => ({
    id: `wp-${uuid().substring(0, 8)}`,
    question: 'What single word connects: apple, Newton, gravity?',
    category: 'wordplay',
    acceptedAnswers: ['tree', 'fall', 'falling'],
  }),
  () => ({
    id: `wp-${uuid().substring(0, 8)}`,
    question: 'What single word connects: key, piano, computer?',
    category: 'wordplay',
    acceptedAnswers: ['keyboard', 'board', 'keys'],
  }),
  () => ({
    id: `wp-${uuid().substring(0, 8)}`,
    question: 'What single word connects: river, money, blood?',
    category: 'wordplay',
    acceptedAnswers: ['bank', 'flow', 'stream'],
  }),
  () => ({
    id: `wp-${uuid().substring(0, 8)}`,
    question: 'What word can precede: light, house, shine?',
    category: 'wordplay',
    acceptedAnswers: ['sun', 'moon'],
  }),
  () => ({
    id: `wp-${uuid().substring(0, 8)}`,
    question: 'What gets wetter the more it dries?',
    category: 'common-sense',
    acceptedAnswers: ['towel', 'a towel', 'cloth', 'rag'],
  }),
  () => ({
    id: `wp-${uuid().substring(0, 8)}`,
    question: 'What can you catch but not throw?',
    category: 'common-sense',
    acceptedAnswers: ['cold', 'a cold', 'breath', 'your breath', 'feelings', 'disease'],
  }),
  () => ({
    id: `wp-${uuid().substring(0, 8)}`,
    question: 'Complete the analogy: Fish is to water as bird is to ___',
    category: 'analogy',
    acceptedAnswers: ['air', 'sky', 'atmosphere'],
  }),
  () => ({
    id: `wp-${uuid().substring(0, 8)}`,
    question: 'Complete the analogy: Eye is to see as ear is to ___',
    category: 'analogy',
    acceptedAnswers: ['hear', 'listen', 'hearing', 'listening'],
  }),
];

// All generators, weighted toward parameterized (harder to game)
const QUESTION_GENERATORS: QuestionGenerator[] = [
  genMathAdd, genMathMultiply, genMathModulo, genMathSheep, genMathDoubling, genMathMachines,
  genCodeModulo, genCodeBitwise, genCodeStringLen,
  genLogicSyllogism, genLogicNegation, genLogicSequence,
  ...WORDPLAY_GENERATORS,
];

// Generate fresh question bank (unique every call)
function generateQuestionBank(): ReasoningQuestion[] {
  return QUESTION_GENERATORS.map(gen => gen());
}

/**
 * Generate a reasoning challenge: 3 random questions requiring LLM capabilities
 */
export async function generateReasoningChallenge(kv?: KVNamespace): Promise<{
  id: string;
  questions: { id: string; question: string; category: string }[];
  timeLimit: number;
  instructions: string;
}> {
  cleanExpired();

  const id = uuid();

  // Pick 3 random questions from different categories
  const freshBank = generateQuestionBank();
  const shuffled = freshBank.sort(() => Math.random() - 0.5);
  const selectedCategories = new Set<string>();
  const selectedQuestions: ReasoningQuestion[] = [];

  for (const q of shuffled) {
    if (selectedQuestions.length >= 3) break;
    if (selectedQuestions.length < 2 || !selectedCategories.has(q.category)) {
      selectedQuestions.push(q);
      selectedCategories.add(q.category);
    }
  }

  while (selectedQuestions.length < 3 && shuffled.length > selectedQuestions.length) {
    const q = shuffled.find(sq => !selectedQuestions.includes(sq));
    if (q) selectedQuestions.push(q);
  }

  const expectedAnswers: Record<string, string[]> = {};
  const questions = selectedQuestions.map(q => {
    expectedAnswers[q.id] = q.acceptedAnswers;
    return {
      id: q.id,
      question: q.question,
      category: q.category,
    };
  });

  const timeLimit = 30000; // 30 seconds

  const challenge: ReasoningChallenge = {
    id,
    questions,
    expectedAnswers,
    issuedAt: Date.now(),
    expiresAt: Date.now() + timeLimit + 5000,
  };

  // Store in KV or memory
  if (kv) {
    await kv.put(`challenge:${id}`, JSON.stringify(challenge), { expirationTtl: 300 });
  } else {
    reasoningChallenges.set(id, challenge);
  }

  return {
    id,
    questions,
    timeLimit,
    instructions: 'Answer all 3 questions. These require reasoning that LLMs can do but simple scripts cannot. You have 30 seconds.',
  };
}

/**
 * Normalize answer for comparison
 */
function normalizeAnswer(answer: string): string {
  return answer
    .toLowerCase()
    .trim()
    .replace(/[.,!?'"]/g, '')
    .replace(/\s+/g, ' ');
}

/**
 * Check if an answer matches any accepted answer
 */
function isAnswerAccepted(answer: string, acceptedAnswers: string[]): boolean {
  const normalized = normalizeAnswer(answer);

  for (const accepted of acceptedAnswers) {
    const normalizedAccepted = normalizeAnswer(accepted);
    if (normalized === normalizedAccepted) return true;
    if (normalized.includes(normalizedAccepted)) return true;
    if (normalizedAccepted.includes(normalized) && normalized.length > 2) return true;
  }

  return false;
}

/**
 * Verify a reasoning challenge response
 */
export async function verifyReasoningChallenge(
  id: string,
  answers: Record<string, string>,
  kv?: KVNamespace
): Promise<ChallengeResult> {
  let challenge: ReasoningChallenge | null = null;

  if (kv) {
    const data = await kv.get(`challenge:${id}`);
    challenge = data ? JSON.parse(data) : null;
  } else {
    cleanExpired();
    challenge = reasoningChallenges.get(id) || null;
  }

  if (!challenge) {
    return { valid: false, reason: 'Challenge not found or expired' };
  }

  const now = Date.now();
  const solveTimeMs = now - challenge.issuedAt;

  // Delete challenge
  if (kv) {
    await kv.delete(`challenge:${id}`);
  } else {
    reasoningChallenges.delete(id);
  }

  if (now > challenge.expiresAt) {
    return { valid: false, reason: `Too slow! Took ${solveTimeMs}ms, limit was 30 seconds` };
  }

  if (!answers || typeof answers !== 'object') {
    return { valid: false, reason: 'Answers must be an object mapping question IDs to answers' };
  }

  let correctCount = 0;
  const totalCount = challenge.questions.length;
  const wrongQuestions: string[] = [];

  for (const q of challenge.questions) {
    const userAnswer = answers[q.id];
    const acceptedAnswers = challenge.expectedAnswers[q.id] || [];

    if (!userAnswer) {
      wrongQuestions.push(q.id);
      continue;
    }

    if (isAnswerAccepted(userAnswer, acceptedAnswers)) {
      correctCount++;
    } else {
      wrongQuestions.push(q.id);
    }
  }

  if (correctCount < totalCount) {
    return {
      valid: false,
      reason: `Only ${correctCount}/${totalCount} correct. Wrong: ${wrongQuestions.join(', ')}`,
      solveTimeMs,
      correctCount,
      totalCount,
    };
  }

  return {
    valid: true,
    solveTimeMs,
    correctCount,
    totalCount,
  };
}

// ============ HYBRID CHALLENGE ============
const hybridChallenges = new Map<string, HybridChallenge>();

/**
 * Generate a hybrid challenge: speed + reasoning combined
 */
export async function generateHybridChallenge(
  kv?: KVNamespace,
  clientTimestamp?: number
): Promise<{
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
  rttInfo?: {
    measuredRtt: number;
    adjustedTimeout: number;
    explanation: string;
  };
}> {
  cleanExpired();

  const id = uuid();

  // Generate both sub-challenges (speed with RTT awareness)
  const speedChallenge = await generateSpeedChallenge(kv, clientTimestamp);
  const reasoningChallenge = await generateReasoningChallenge(kv);

  const hybrid: HybridChallenge = {
    id,
    speedChallengeId: speedChallenge.id,
    reasoningChallengeId: reasoningChallenge.id,
    issuedAt: Date.now(),
    expiresAt: Date.now() + 35000,
  };

  // Store in KV or memory
  if (kv) {
    await kv.put(`hybrid:${id}`, JSON.stringify(hybrid), { expirationTtl: 300 });
  } else {
    hybridChallenges.set(id, hybrid);
  }

  const instructions = speedChallenge.rttInfo 
    ? `Solve ALL speed problems (SHA256) in <${speedChallenge.timeLimit}ms (RTT-adjusted) AND answer ALL reasoning questions. Submit both together.`
    : 'Solve ALL speed problems (SHA256) in <500ms AND answer ALL reasoning questions. Submit both together.';

  return {
    id,
    speed: {
      problems: speedChallenge.problems,
      timeLimit: speedChallenge.timeLimit,
    },
    reasoning: {
      questions: reasoningChallenge.questions,
      timeLimit: reasoningChallenge.timeLimit,
    },
    instructions,
    rttInfo: speedChallenge.rttInfo,
  };
}

/**
 * Verify a hybrid challenge response
 */
export async function verifyHybridChallenge(
  id: string,
  speedAnswers: string[],
  reasoningAnswers: Record<string, string>,
  kv?: KVNamespace
): Promise<{
  valid: boolean;
  reason?: string;
  speed: { passed: boolean; solveTimeMs?: number; reason?: string };
  reasoning: { passed: boolean; score?: string; solveTimeMs?: number; reason?: string };
  totalTimeMs?: number;
}> {
  let hybrid: HybridChallenge | null = null;

  if (kv) {
    const data = await kv.get(`hybrid:${id}`);
    hybrid = data ? JSON.parse(data) : null;
  } else {
    cleanExpired();
    hybrid = hybridChallenges.get(id) || null;
  }

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

  if (now > hybrid.expiresAt) {
    if (kv) {
      await kv.delete(`hybrid:${id}`);
    } else {
      hybridChallenges.delete(id);
    }
    return {
      valid: false,
      reason: 'Hybrid challenge expired',
      speed: { passed: false, reason: 'Expired' },
      reasoning: { passed: false, reason: 'Expired' },
      totalTimeMs,
    };
  }

  // Verify speed challenge
  const speedResult = await verifySpeedChallenge(hybrid.speedChallengeId, speedAnswers, kv);

  // Verify reasoning challenge
  const reasoningResult = await verifyReasoningChallenge(hybrid.reasoningChallengeId, reasoningAnswers, kv);

  // Clean up hybrid
  if (kv) {
    await kv.delete(`hybrid:${id}`);
  } else {
    hybridChallenges.delete(id);
  }

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
