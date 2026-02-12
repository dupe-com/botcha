import crypto from 'crypto';

interface ReasoningQuestion {
  id: string;
  question: string;
  category: 'analogy' | 'logic' | 'wordplay' | 'math' | 'code' | 'common-sense';
  acceptedAnswers: string[]; // Multiple valid answers (lowercase, trimmed)
  hint?: string;
}

interface ReasoningChallenge {
  id: string;
  questions: { id: string; question: string; category: string }[];
  expectedAnswers: Map<string, string[]>; // questionId -> acceptedAnswers
  issuedAt: number;
  expiresAt: number;
}

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
  const answer = (a + b).toString();
  return {
    id: `math-add-${crypto.randomUUID().substring(0, 8)}`,
    question: `What is ${a} + ${b}?`,
    category: 'math',
    acceptedAnswers: [answer],
  };
}

function genMathMultiply(): ReasoningQuestion {
  const a = randInt(12, 99);
  const b = randInt(12, 99);
  const answer = (a * b).toString();
  return {
    id: `math-mul-${crypto.randomUUID().substring(0, 8)}`,
    question: `What is ${a} × ${b}?`,
    category: 'math',
    acceptedAnswers: [answer],
  };
}

function genMathModulo(): ReasoningQuestion {
  const a = randInt(50, 999);
  const b = randInt(3, 19);
  const answer = (a % b).toString();
  return {
    id: `math-mod-${crypto.randomUUID().substring(0, 8)}`,
    question: `What is ${a} % ${b} (modulo)?`,
    category: 'math',
    acceptedAnswers: [answer],
  };
}

function genMathSheep(): ReasoningQuestion {
  const total = randInt(15, 50);
  const remaining = randInt(3, total - 2);
  return {
    id: `math-sheep-${crypto.randomUUID().substring(0, 8)}`,
    question: `A farmer has ${total} sheep. All but ${remaining} run away. How many sheep does he have left? Answer with just the number.`,
    category: 'math',
    acceptedAnswers: [remaining.toString()],
  };
}

function genMathDoubling(): ReasoningQuestion {
  // Vary starting value (days: 10-1050) to get 1041 unique answer values
  // Answer is always (days - 1), so days range of 10-1050 gives answers 9-1049
  const days = randInt(10, 1050);
  const items = pickRandom([
    'lily pads',
    'bacteria cells',
    'algae colonies',
    'viral particles',
    'yeast cells',
    'water plants',
    'moss patches',
    'fungal spores',
  ]);
  const answer = (days - 1).toString();
  return {
    id: `math-double-${crypto.randomUUID().substring(0, 8)}`,
    question: `A patch of ${items} doubles in size every day. If it takes ${days} days to cover the entire lake, how many days to cover half? Answer with just the number.`,
    category: 'math',
    acceptedAnswers: [answer],
  };
}

function genMathMachines(): ReasoningQuestion {
  // Parameterized: n (5-1100) to get 1096 unique answer values
  // Answer is always n (the time in minutes)
  const n = randInt(5, 1100);
  const m = randInt(50, 500);
  const items = pickRandom([
    'widgets',
    'parts',
    'components',
    'units',
    'products',
    'items',
    'gadgets',
    'devices',
  ]);
  return {
    id: `math-machines-${crypto.randomUUID().substring(0, 8)}`,
    question: `If it takes ${n} machines ${n} minutes to make ${n} ${items}, how many minutes would it take ${m} machines to make ${m} ${items}? Answer with just the number.`,
    category: 'math',
    acceptedAnswers: [n.toString()],
  };
}

// --- Code generators (randomized values) ---
function genCodeModulo(): ReasoningQuestion {
  const a = randInt(20, 200);
  const b = randInt(3, 15);
  const answer = (a % b).toString();
  return {
    id: `code-mod-${crypto.randomUUID().substring(0, 8)}`,
    question: `In most programming languages, what does ${a} % ${b} evaluate to?`,
    category: 'code',
    acceptedAnswers: [answer],
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
    id: `code-bit-${crypto.randomUUID().substring(0, 8)}`,
    question: `What is ${a} ${op} ${b} (bitwise ${opName})? Answer with just the number.`,
    category: 'code',
    acceptedAnswers: [answer.toString()],
  };
}

function genCodeStringLen(): ReasoningQuestion {
  const words = ['hello', 'world', 'banana', 'algorithm', 'quantum', 'symphony', 'cryptography', 'paradigm', 'ephemeral', 'serendipity'];
  const word = pickRandom(words);
  return {
    id: `code-strlen-${crypto.randomUUID().substring(0, 8)}`,
    question: `What is the length of the string "${word}"? Answer with just the number.`,
    category: 'code',
    acceptedAnswers: [word.length.toString()],
  };
}

// --- Logic generators (randomized names/items) ---
function genLogicSyllogism(): ReasoningQuestion {
  // Generate counting-based syllogism to produce numeric answers with ≥1000 answer space
  // "In a group of N people, if X are teachers and all teachers are kind, how many kind people are there at minimum?"
  // Answer: X (the number in the subset)
  // Range: X from 10 to 1500 = 1491 unique answers
  const total = randInt(50, 2000);
  const count = randInt(10, Math.min(total - 5, 1500));
  
  const groups = [
    { container: 'people', subsetName: 'teachers', property: 'kind' },
    { container: 'animals', subsetName: 'dogs', property: 'friendly' },
    { container: 'students', subsetName: 'seniors', property: 'experienced' },
    { container: 'employees', subsetName: 'managers', property: 'trained' },
    { container: 'books', subsetName: 'novels', property: 'fictional' },
    { container: 'vehicles', subsetName: 'cars', property: 'motorized' },
    { container: 'plants', subsetName: 'trees', property: 'woody' },
    { container: 'items', subsetName: 'tools', property: 'useful' },
  ];
  
  const { container, subsetName, property } = pickRandom(groups);
  
  return {
    id: `logic-syl-${crypto.randomUUID().substring(0, 8)}`,
    question: `In a group of ${total} ${container}, ${count} of them are ${subsetName}. If all ${subsetName} are ${property}, what is the minimum number of ${property} ${container}? Answer with just the number.`,
    category: 'logic',
    acceptedAnswers: [count.toString()],
  };
}

function genLogicNegation(): ReasoningQuestion {
  const total = randInt(20, 100);
  const keep = randInt(3, total - 5);
  return {
    id: `logic-neg-${crypto.randomUUID().substring(0, 8)}`,
    question: `There are ${total} marbles in a bag. You remove all but ${keep}. How many marbles are left in the bag? Answer with just the number.`,
    category: 'logic',
    acceptedAnswers: [keep.toString()],
  };
}

function genLogicSequence(): ReasoningQuestion {
  // Generate a simple arithmetic or geometric sequence
  const start = randInt(2, 20);
  const step = randInt(2, 8);
  const seq = [start, start + step, start + 2 * step, start + 3 * step];
  const answer = (start + 4 * step).toString();
  return {
    id: `logic-seq-${crypto.randomUUID().substring(0, 8)}`,
    question: `What comes next in the sequence: ${seq.join(', ')}, ___? Answer with just the number.`,
    category: 'logic',
    acceptedAnswers: [answer],
  };
}

// --- Wordplay (static but with large pool + randomized IDs so lookup by ID fails) ---
const WORDPLAY_QUESTIONS: (() => ReasoningQuestion)[] = [
  () => ({
    id: `wp-${crypto.randomUUID().substring(0, 8)}`,
    question: 'What single word connects: apple, Newton, gravity?',
    category: 'wordplay',
    acceptedAnswers: ['tree', 'fall', 'falling'],
  }),
  () => ({
    id: `wp-${crypto.randomUUID().substring(0, 8)}`,
    question: 'What single word connects: key, piano, computer?',
    category: 'wordplay',
    acceptedAnswers: ['keyboard', 'board', 'keys'],
  }),
  () => ({
    id: `wp-${crypto.randomUUID().substring(0, 8)}`,
    question: 'What single word connects: river, money, blood?',
    category: 'wordplay',
    acceptedAnswers: ['bank', 'flow', 'stream'],
  }),
  () => ({
    id: `wp-${crypto.randomUUID().substring(0, 8)}`,
    question: 'What word can precede: light, house, shine?',
    category: 'wordplay',
    acceptedAnswers: ['sun', 'moon'],
  }),
  () => ({
    id: `wp-${crypto.randomUUID().substring(0, 8)}`,
    question: 'What gets wetter the more it dries?',
    category: 'common-sense',
    acceptedAnswers: ['towel', 'a towel', 'cloth', 'rag'],
  }),
  () => ({
    id: `wp-${crypto.randomUUID().substring(0, 8)}`,
    question: 'What can you catch but not throw?',
    category: 'common-sense',
    acceptedAnswers: ['cold', 'a cold', 'breath', 'your breath', 'feelings', 'disease'],
  }),
  () => ({
    id: `wp-${crypto.randomUUID().substring(0, 8)}`,
    question: 'What data structure uses LIFO (Last In, First Out)?',
    category: 'code',
    acceptedAnswers: ['stack', 'a stack'],
  }),
  () => ({
    id: `wp-${crypto.randomUUID().substring(0, 8)}`,
    question: 'Complete the analogy: Fish is to water as bird is to ___',
    category: 'analogy',
    acceptedAnswers: ['air', 'sky', 'atmosphere'],
  }),
  () => ({
    id: `wp-${crypto.randomUUID().substring(0, 8)}`,
    question: 'Complete the analogy: Eye is to see as ear is to ___',
    category: 'analogy',
    acceptedAnswers: ['hear', 'listen', 'hearing', 'listening'],
  }),
  () => ({
    id: `wp-${crypto.randomUUID().substring(0, 8)}`,
    question: 'Complete the analogy: Painter is to brush as writer is to ___',
    category: 'analogy',
    acceptedAnswers: ['pen', 'pencil', 'keyboard', 'typewriter', 'quill'],
  }),
];

// All generators, weighted toward parameterized (harder to game)
const QUESTION_GENERATORS: QuestionGenerator[] = [
  // Math (parameterized — unique every time)
  genMathAdd,
  genMathMultiply,
  genMathModulo,
  genMathSheep,
  genMathDoubling,
  genMathMachines,
  // Code (parameterized)
  genCodeModulo,
  genCodeBitwise,
  genCodeStringLen,
  // Logic (parameterized)
  genLogicSyllogism,
  genLogicNegation,
  genLogicSequence,
  // Wordplay / static (but with random IDs)
  ...WORDPLAY_QUESTIONS,
];

// Legacy compatibility: generate a static-looking bank from generators
function generateQuestionBank(): ReasoningQuestion[] {
  return QUESTION_GENERATORS.map(gen => gen());
}

// Cleanup expired challenges
setInterval(() => {
  const now = Date.now();
  for (const [id, c] of reasoningChallenges) {
    if (c.expiresAt < now) reasoningChallenges.delete(id);
  }
}, 60000);

/**
 * Generate a reasoning challenge: 3 random questions requiring LLM capabilities
 * Simple scripts can't answer these, but any LLM can
 */
export function generateReasoningChallenge(): {
  id: string;
  questions: { id: string; question: string; category: string }[];
  timeLimit: number;
  instructions: string;
} {
  const id = crypto.randomUUID();

  // Generate fresh parameterized questions (different every time)
  const freshBank = generateQuestionBank();
  const shuffled = freshBank.sort(() => Math.random() - 0.5);
  const selectedCategories = new Set<string>();
  const selectedQuestions: ReasoningQuestion[] = [];

  for (const q of shuffled) {
    if (selectedQuestions.length >= 3) break;
    // Try to get diverse categories
    if (selectedQuestions.length < 2 || !selectedCategories.has(q.category)) {
      selectedQuestions.push(q);
      selectedCategories.add(q.category);
    }
  }

  // If we didn't get 3, just take any 3
  while (selectedQuestions.length < 3 && shuffled.length > selectedQuestions.length) {
    const q = shuffled.find(sq => !selectedQuestions.includes(sq));
    if (q) selectedQuestions.push(q);
  }

  const expectedAnswers = new Map<string, string[]>();
  const questions = selectedQuestions.map(q => {
    expectedAnswers.set(q.id, q.acceptedAnswers);
    return {
      id: q.id,
      question: q.question,
      category: q.category,
    };
  });

  const timeLimit = 30000; // 30 seconds - plenty of time for an LLM

  reasoningChallenges.set(id, {
    id,
    questions,
    expectedAnswers,
    issuedAt: Date.now(),
    expiresAt: Date.now() + timeLimit + 5000, // 5s grace for network latency
  });

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
    .replace(/[.,!?'"]/g, '') // Remove punctuation
    .replace(/\s+/g, ' '); // Normalize whitespace
}

/**
 * Check if an answer matches any accepted answer
 */
function isAnswerAccepted(answer: string, acceptedAnswers: string[]): boolean {
  const normalized = normalizeAnswer(answer);

  for (const accepted of acceptedAnswers) {
    const normalizedAccepted = normalizeAnswer(accepted);

    // Exact match
    if (normalized === normalizedAccepted) return true;

    // Contains match (for longer answers that include the key word)
    if (normalized.includes(normalizedAccepted)) return true;
    if (normalizedAccepted.includes(normalized) && normalized.length > 2) return true;
  }

  return false;
}

export function verifyReasoningChallenge(
  id: string,
  answers: Record<string, string>
): {
  valid: boolean;
  reason?: string;
  solveTimeMs?: number;
  correctCount?: number;
  totalCount?: number;
} {
  const challenge = reasoningChallenges.get(id);

  if (!challenge) {
    return { valid: false, reason: 'Challenge not found or expired' };
  }

  const now = Date.now();
  const solveTimeMs = now - challenge.issuedAt;

  // Clean up
  reasoningChallenges.delete(id);

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
    const acceptedAnswers = challenge.expectedAnswers.get(q.id) || [];

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

  // Require all 3 correct
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

export function getQuestionCount(): number {
  return QUESTION_GENERATORS.length;
}

export default { generateReasoningChallenge, verifyReasoningChallenge, getQuestionCount };
