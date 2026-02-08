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

  // Wordplay / Connections
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

  // Logic puzzles
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
    hint: 'Beauty is in the eye of the ___',
  },
  {
    id: 'logic-4',
    question: 'A farmer has 17 sheep. All but 9 run away. How many sheep does he have left?',
    category: 'logic',
    acceptedAnswers: ['9', 'nine'],
  },

  // Math word problems (tricky ones)
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

  // Code understanding
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

  // Pick 3 random questions from different categories
  const shuffled = [...QUESTION_BANK].sort(() => Math.random() - 0.5);
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
  return QUESTION_BANK.length;
}

export default { generateReasoningChallenge, verifyReasoningChallenge, getQuestionCount };
