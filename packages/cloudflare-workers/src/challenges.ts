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

// ============ REASONING CHALLENGE ============
// In-memory storage for reasoning challenges
const reasoningChallenges = new Map<string, ReasoningChallenge>();

// Question bank - LLMs can answer these, simple scripts cannot
const QUESTION_BANK: ReasoningQuestion[] = [
  // Analogies
  {
    id: 'analogy-1',
    question: 'Complete the analogy: Book is to library as car is to ___',
    category: 'analogy',
    acceptedAnswers: ['garage', 'parking lot', 'dealership', 'parking garage', 'lot'],
  },
  {
    id: 'analogy-2',
    question: 'Complete the analogy: Painter is to brush as writer is to ___',
    category: 'analogy',
    acceptedAnswers: ['pen', 'pencil', 'keyboard', 'typewriter', 'quill'],
  },
  {
    id: 'analogy-3',
    question: 'Complete the analogy: Fish is to water as bird is to ___',
    category: 'analogy',
    acceptedAnswers: ['air', 'sky', 'atmosphere'],
  },
  {
    id: 'analogy-4',
    question: 'Complete the analogy: Eye is to see as ear is to ___',
    category: 'analogy',
    acceptedAnswers: ['hear', 'listen', 'hearing', 'listening'],
  },
  // Wordplay
  {
    id: 'wordplay-1',
    question: 'What single word connects: apple, Newton, gravity?',
    category: 'wordplay',
    acceptedAnswers: ['tree', 'fall', 'falling'],
  },
  {
    id: 'wordplay-2',
    question: 'What single word connects: key, piano, computer?',
    category: 'wordplay',
    acceptedAnswers: ['keyboard', 'board', 'keys'],
  },
  {
    id: 'wordplay-3',
    question: 'What single word connects: river, money, blood?',
    category: 'wordplay',
    acceptedAnswers: ['bank', 'flow', 'stream'],
  },
  {
    id: 'wordplay-4',
    question: 'What word can precede: light, house, shine?',
    category: 'wordplay',
    acceptedAnswers: ['sun', 'moon'],
  },
  // Logic
  {
    id: 'logic-1',
    question: 'If all Bloops are Razzies and all Razzies are Lazzies, are all Bloops definitely Lazzies? Answer yes or no.',
    category: 'logic',
    acceptedAnswers: ['yes'],
  },
  {
    id: 'logic-2',
    question: 'If some Widgets are Gadgets, and all Gadgets are blue, can some Widgets be blue? Answer yes or no.',
    category: 'logic',
    acceptedAnswers: ['yes'],
  },
  {
    id: 'logic-3',
    question: 'I have a bee in my hand. What do I have in my eye? (Think about the saying)',
    category: 'logic',
    acceptedAnswers: ['beauty', 'beholder'],
  },
  {
    id: 'logic-4',
    question: 'A farmer has 17 sheep. All but 9 run away. How many sheep does he have left?',
    category: 'logic',
    acceptedAnswers: ['9', 'nine'],
  },
  // Math
  {
    id: 'math-1',
    question: 'A bat and ball cost $1.10 total. The bat costs $1.00 more than the ball. How much does the ball cost in cents?',
    category: 'math',
    acceptedAnswers: ['5', '5 cents', 'five', 'five cents', '0.05', '$0.05'],
  },
  {
    id: 'math-2',
    question: 'If it takes 5 machines 5 minutes to make 5 widgets, how many minutes would it take 100 machines to make 100 widgets?',
    category: 'math',
    acceptedAnswers: ['5', 'five', '5 minutes', 'five minutes'],
  },
  {
    id: 'math-3',
    question: 'In a lake, there is a patch of lily pads. Every day, the patch doubles in size. If it takes 48 days for the patch to cover the entire lake, how many days would it take for the patch to cover half of the lake?',
    category: 'math',
    acceptedAnswers: ['47', 'forty-seven', 'forty seven', '47 days'],
  },
  // Code
  {
    id: 'code-1',
    question: 'What is wrong with this code: if (x = 5) { doSomething(); }',
    category: 'code',
    acceptedAnswers: ['assignment', 'single equals', '= instead of ==', 'should be ==', 'should be ===', 'equality', 'comparison'],
  },
  {
    id: 'code-2',
    question: 'In most programming languages, what does the modulo operator % return for 17 % 5?',
    category: 'code',
    acceptedAnswers: ['2', 'two'],
  },
  {
    id: 'code-3',
    question: 'What data structure uses LIFO (Last In, First Out)?',
    category: 'code',
    acceptedAnswers: ['stack', 'a stack'],
  },
  // Common sense
  {
    id: 'sense-1',
    question: 'If you are running a race and you pass the person in second place, what place are you in now?',
    category: 'common-sense',
    acceptedAnswers: ['second', '2nd', '2', 'two'],
  },
  {
    id: 'sense-2',
    question: 'What gets wetter the more it dries?',
    category: 'common-sense',
    acceptedAnswers: ['towel', 'a towel', 'cloth', 'rag'],
  },
  {
    id: 'sense-3',
    question: 'What can you catch but not throw?',
    category: 'common-sense',
    acceptedAnswers: ['cold', 'a cold', 'breath', 'your breath', 'feelings', 'disease'],
  },
];

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
  const shuffled = [...QUESTION_BANK].sort(() => Math.random() - 0.5);
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
