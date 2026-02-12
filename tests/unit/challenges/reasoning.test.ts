import { describe, test, expect } from 'vitest';
import {
  generateReasoningChallenge,
  verifyReasoningChallenge,
  getQuestionCount,
} from '../../../src/challenges/reasoning.js';

describe('Reasoning Challenge', () => {
  describe('generateReasoningChallenge()', () => {
    test('returns valid structure', () => {
      const challenge = generateReasoningChallenge();

      expect(challenge).toHaveProperty('id');
      expect(challenge).toHaveProperty('questions');
      expect(challenge).toHaveProperty('timeLimit');
      expect(challenge).toHaveProperty('instructions');
      expect(challenge.questions).toHaveLength(3);
      expect(challenge.timeLimit).toBe(30000);
    });

    test('each question has id, question text, and category', () => {
      const challenge = generateReasoningChallenge();

      for (const q of challenge.questions) {
        expect(typeof q.id).toBe('string');
        expect(q.id.length).toBeGreaterThan(0);
        expect(typeof q.question).toBe('string');
        expect(q.question.length).toBeGreaterThan(10);
        expect(typeof q.category).toBe('string');
      }
    });

    test('question IDs are non-static and unique per generation (anti-lookup-table)', () => {
      const challenge1 = generateReasoningChallenge();
      const challenge2 = generateReasoningChallenge();

      const ids1 = challenge1.questions.map(q => q.id);
      const ids2 = challenge2.questions.map(q => q.id);

      // IDs should NOT be the same across two generations
      // (with randomized UUIDs in IDs, collision is astronomically unlikely)
      const overlap = ids1.filter(id => ids2.includes(id));
      expect(overlap.length).toBe(0);
    });

    test('questions are not always the same set (randomization works)', () => {
      // Generate 10 challenges and collect all question texts
      const allQuestions = new Set<string>();
      for (let i = 0; i < 10; i++) {
        const challenge = generateReasoningChallenge();
        for (const q of challenge.questions) {
          allQuestions.add(q.question);
        }
      }

      // With 20+ generators and 3 per challenge, 10 runs should produce more than 3 unique questions
      expect(allQuestions.size).toBeGreaterThan(3);
    });

    test('parameterized math questions have different numbers each time', () => {
      // Generate many challenges and look for math questions with numbers
      const mathQuestions: string[] = [];
      for (let i = 0; i < 20; i++) {
        const challenge = generateReasoningChallenge();
        for (const q of challenge.questions) {
          if (q.question.match(/What is \d+ [+×%]/)) {
            mathQuestions.push(q.question);
          }
        }
      }

      // Should have found some math questions
      if (mathQuestions.length >= 2) {
        // At least some should be different (different random numbers)
        const uniqueQuestions = new Set(mathQuestions);
        expect(uniqueQuestions.size).toBeGreaterThan(1);
      }
    });
  });

  describe('verifyReasoningChallenge()', () => {
    test('passes with correct answers to generated questions', () => {
      // We need to "cheat" by solving the questions correctly.
      // Generate a challenge, then solve each question by brute-forcing known patterns.
      const challenge = generateReasoningChallenge();

      const answers: Record<string, string> = {};
      for (const q of challenge.questions) {
        answers[q.id] = solveQuestion(q.question);
      }

      const result = verifyReasoningChallenge(challenge.id, answers);

      expect(result.valid).toBe(true);
      expect(result.correctCount).toBe(3);
      expect(result.totalCount).toBe(3);
    });

    test('fails with wrong answers', () => {
      const challenge = generateReasoningChallenge();

      const wrongAnswers: Record<string, string> = {};
      for (const q of challenge.questions) {
        wrongAnswers[q.id] = 'definitely-wrong-answer-xyz';
      }

      const result = verifyReasoningChallenge(challenge.id, wrongAnswers);

      expect(result.valid).toBe(false);
    });

    test('fails with missing answers', () => {
      const challenge = generateReasoningChallenge();

      const result = verifyReasoningChallenge(challenge.id, {});

      expect(result.valid).toBe(false);
    });

    test('fails with unknown challenge ID', () => {
      const result = verifyReasoningChallenge('nonexistent-id', { q: 'a' });

      expect(result.valid).toBe(false);
      expect(result.reason).toContain('not found');
    });

    test('challenge is single-use (deleted after verify)', () => {
      const challenge = generateReasoningChallenge();
      const answers: Record<string, string> = {};
      for (const q of challenge.questions) {
        answers[q.id] = solveQuestion(q.question);
      }

      const first = verifyReasoningChallenge(challenge.id, answers);
      expect(first.valid).toBe(true);

      const second = verifyReasoningChallenge(challenge.id, answers);
      expect(second.valid).toBe(false);
      expect(second.reason).toContain('not found');
    });
  });

  describe('getQuestionCount()', () => {
    test('returns the number of question generators', () => {
      const count = getQuestionCount();
      expect(count).toBeGreaterThanOrEqual(15); // We added ~20 generators
    });
  });

  describe('answer space diversity (anti-lookup-table)', () => {
    // These tests verify each generator produces sufficient answer diversity (≥1000 unique answers)
    // to prevent lookup table attacks. We sample N times and verify we get enough unique answers.

    test('genMathMachines has answer space ≥1000', () => {
      // genMathMachines: n ranges from 5-1100, answer is always n → 1096 unique answers
      const answers = new Set<string>();
      
      // Each challenge has 3 random questions from ~22 generators
      // So we need many challenges to get enough samples of this specific generator
      for (let i = 0; i < 2000; i++) {
        const challenge = generateReasoningChallenge();
        for (const q of challenge.questions) {
          // Match machine question pattern
          if (q.question.match(/takes (\d+) machines (\d+) minutes to make (\d+)/)) {
            const match = q.question.match(/takes (\d+) machines/);
            if (match) {
              answers.add(match[1]); // The n value (which is also the answer)
            }
          }
        }
      }
      
      // With ~270 samples (2000 challenges × 3 questions × ~4.5% chance) from 1096 possibilities
      // expect ~200-250 unique values
      expect(answers.size).toBeGreaterThan(150);
    });

    test('genLogicSyllogism has answer space ≥1000', () => {
      // genLogicSyllogism: count ranges from 10-1500 → 1491 unique answers
      const answers = new Set<string>();
      
      for (let i = 0; i < 2000; i++) {
        const challenge = generateReasoningChallenge();
        for (const q of challenge.questions) {
          // Match syllogism pattern: "In a group of N container, X of them are..."
          if (q.question.match(/In a group of \d+ \w+, (\d+) of them are/)) {
            const match = q.question.match(/In a group of \d+ \w+, (\d+) of them are/);
            if (match) {
              answers.add(match[1]); // The count (which is the answer)
            }
          }
        }
      }
      
      // With ~270 samples from 1491 possibilities, expect ~200-250 unique
      expect(answers.size).toBeGreaterThan(150);
    });

    test('genMathDoubling has answer space ≥1000', () => {
      // genMathDoubling: days range 10-1050, answers are (days - 1) → 9-1049 = 1041 unique answers
      const answers = new Set<string>();
      
      for (let i = 0; i < 2000; i++) {
        const challenge = generateReasoningChallenge();
        for (const q of challenge.questions) {
          // Match doubling pattern: "takes X days to cover the entire lake"
          if (q.question.match(/takes (\d+) days.*cover the entire lake/)) {
            const match = q.question.match(/takes (\d+) days/);
            if (match) {
              const days = parseInt(match[1]);
              answers.add((days - 1).toString()); // Answer is always (days - 1)
            }
          }
        }
      }
      
      // With ~270 samples from 1041 possibilities, expect ~200-250 unique
      expect(answers.size).toBeGreaterThan(150);
    });

    test('genCodeBitwise has sufficient answer diversity', () => {
      // genCodeBitwise: a (1-15) × b (1-15) × 3 ops = 675 unique combinations
      // Not quite 1000, but still substantial diversity
      const questions = new Set<string>();
      
      for (let i = 0; i < 2000; i++) {
        const challenge = generateReasoningChallenge();
        for (const q of challenge.questions) {
          // Match bitwise pattern: "What is A & B" or "A | B" or "A ^ B"
          if (q.question.match(/What is (\d+) ([&|^]) (\d+)/)) {
            questions.add(q.question); // Track the full question (includes a, b, op)
          }
        }
      }
      
      // With ~270 samples from 675 possibilities, expect ~200-250 unique
      expect(questions.size).toBeGreaterThan(150);
    });

    test('genCodeStringLen produces varied outputs', () => {
      // genCodeStringLen: 10 word pool with different lengths
      // Not parametric enough to reach 1000, but verify diversity exists
      const words = new Set<string>();
      const answers = new Set<string>();
      
      for (let i = 0; i < 100; i++) {
        const challenge = generateReasoningChallenge();
        for (const q of challenge.questions) {
          // Match string length pattern
          const match = q.question.match(/length of the string "(\w+)"/);
          if (match) {
            words.add(match[1]);
            answers.add(match[1].length.toString());
          }
        }
      }
      
      // Should see multiple different words from the pool
      expect(words.size).toBeGreaterThan(3);
      // Should have multiple different lengths
      expect(answers.size).toBeGreaterThan(3);
    });

    test('wordplay pool has sufficient variety', () => {
      // WORDPLAY_QUESTIONS: 10 static questions (each returns fresh with new ID)
      const questionTexts = new Set<string>();
      
      for (let i = 0; i < 50; i++) {
        const challenge = generateReasoningChallenge();
        for (const q of challenge.questions) {
          // Collect all wordplay/analogy/common-sense questions
          if (['wordplay', 'analogy', 'common-sense'].includes(q.category)) {
            questionTexts.add(q.question);
          }
        }
      }
      
      // Should have at least 8-10 unique wordplay questions
      expect(questionTexts.size).toBeGreaterThanOrEqual(8);
    });

    test('overall challenge has high answer diversity', () => {
      // Meta-test: verify that across many challenge generations,
      // we get a large variety of answer combinations
      const answerSets = new Set<string>();
      
      for (let i = 0; i < 200; i++) {
        const challenge = generateReasoningChallenge();
        const answers: string[] = [];
        
        for (const q of challenge.questions) {
          const solved = solveQuestion(q.question);
          answers.push(solved);
        }
        
        // Create a fingerprint of this challenge's answer set
        const fingerprint = answers.sort().join('|');
        answerSets.add(fingerprint);
      }
      
      // With parameterized generators, we should get mostly unique answer combinations
      // (200 samples should yield close to 200 unique sets)
      expect(answerSets.size).toBeGreaterThan(150);
    });

    test('parameter ranges are correct for high-diversity generators', () => {
      // Verify that parameterized generators actually use their full ranges
      const machineValues = new Set<number>();
      const syllogismValues = new Set<number>();
      const doublingValues = new Set<number>();
      
      // Sample many times to verify range boundaries
      for (let i = 0; i < 3000; i++) {
        const challenge = generateReasoningChallenge();
        for (const q of challenge.questions) {
          // Machines: should see values from 5-1100
          let match = q.question.match(/takes (\d+) machines/);
          if (match) {
            machineValues.add(parseInt(match[1]));
          }
          
          // Syllogism: should see values from 10-1500
          match = q.question.match(/In a group of \d+ \w+, (\d+) of them are/);
          if (match) {
            syllogismValues.add(parseInt(match[1]));
          }
          
          // Doubling: should see days from 10-1050
          match = q.question.match(/takes (\d+) days.*cover the entire lake/);
          if (match) {
            doublingValues.add(parseInt(match[1]));
          }
        }
      }
      
      // Verify we're seeing good coverage of the ranges
      if (machineValues.size > 0) {
        expect(Math.min(...machineValues)).toBeGreaterThanOrEqual(5);
        expect(Math.max(...machineValues)).toBeLessThanOrEqual(1100);
        expect(machineValues.size).toBeGreaterThan(80); // Good sampling
      }
      
      if (syllogismValues.size > 0) {
        expect(Math.min(...syllogismValues)).toBeGreaterThanOrEqual(10);
        expect(Math.max(...syllogismValues)).toBeLessThanOrEqual(1500);
        expect(syllogismValues.size).toBeGreaterThan(80);
      }
      
      if (doublingValues.size > 0) {
        expect(Math.min(...doublingValues)).toBeGreaterThanOrEqual(10);
        expect(Math.max(...doublingValues)).toBeLessThanOrEqual(1050);
        expect(doublingValues.size).toBeGreaterThan(80);
      }
    });
  });
});

// ============ TEST HELPER: Solve a generated question ============
// This simulates an LLM solving the question. It needs to handle all our parameterized formats.
function solveQuestion(question: string): string {
  // Math: "What is A + B?"
  let match = question.match(/What is (\d+) \+ (\d+)/);
  if (match) return String(Number(match[1]) + Number(match[2]));

  // Math: "What is A × B?"
  match = question.match(/What is (\d+) × (\d+)/);
  if (match) return String(Number(match[1]) * Number(match[2]));

  // Math: "What is A % B (modulo)?"
  match = question.match(/What is (\d+) % (\d+)/);
  if (match) return String(Number(match[1]) % Number(match[2]));

  // Math: "farmer has X sheep. All but Y run away"
  match = question.match(/All but (\d+) run away/);
  if (match) return match[1];

  // Math: "takes X days to cover the entire lake" (supports various growth patterns and items)
  match = question.match(/takes (\d+) days.*cover the entire lake/);
  if (match) return String(Number(match[1]) - 1);

  // Math: "takes N machines N minutes to make N widgets/items/etc"
  match = question.match(/takes (\d+) machines (\d+) minutes to make (\d+) \w+/);
  if (match) return match[2]; // Answer is always N minutes

  // Code: "A % B evaluate to"
  match = question.match(/(\d+) % (\d+) evaluate/);
  if (match) return String(Number(match[1]) % Number(match[2]));

  // Code: bitwise "A & B", "A | B", "A ^ B"
  match = question.match(/What is (\d+) ([&|^]) (\d+)/);
  if (match) {
    const a = Number(match[1]);
    const b = Number(match[3]);
    const op = match[2];
    if (op === '&') return String(a & b);
    if (op === '|') return String(a | b);
    if (op === '^') return String(a ^ b);
  }

  // Code: string length
  match = question.match(/length of the string "(\w+)"/);
  if (match) return String(match[1].length);

  // Logic: syllogism "are all X definitely Z?" (old format - may not appear anymore)
  if (question.match(/are all .+ definitely .+\? Answer yes or no/)) return 'yes';
  
  // Logic: counting syllogism "In a group of N container, X of them are subset..."
  match = question.match(/In a group of \d+ \w+, (\d+) of them are/);
  if (match) return match[1];

  // Logic: negation "remove all but X"
  match = question.match(/remove all but (\d+)/);
  if (match) return match[1];

  // Logic: sequence "What comes next"
  match = question.match(/sequence: ([\d, ]+), ___/);
  if (match) {
    const nums = match[1].split(', ').map(Number);
    const step = nums[1] - nums[0];
    return String(nums[nums.length - 1] + step);
  }

  // Wordplay/common-sense static answers (best guess from accepted answers)
  if (question.includes('apple, Newton, gravity')) return 'tree';
  if (question.includes('key, piano, computer')) return 'keyboard';
  if (question.includes('river, money, blood')) return 'bank';
  if (question.includes('precede: light, house, shine')) return 'sun';
  if (question.includes('wetter the more it dries')) return 'towel';
  if (question.includes('catch but not throw')) return 'cold';
  if (question.includes('LIFO')) return 'stack';
  if (question.includes('Fish is to water')) return 'air';
  if (question.includes('Eye is to see')) return 'hear';
  if (question.includes('Painter is to brush')) return 'pen';

  // Fallback — should not happen if we cover all generators
  throw new Error(`Test solver cannot handle question: "${question}"`);
}
