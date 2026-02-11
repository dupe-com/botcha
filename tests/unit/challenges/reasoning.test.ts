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

  // Math: "takes X days to cover the entire lake"
  match = question.match(/takes (\d+) days.*cover the entire lake/);
  if (match) return String(Number(match[1]) - 1);

  // Math: "takes N machines N minutes to make N widgets"
  match = question.match(/takes (\d+) machines (\d+) minutes to make (\d+) widgets/);
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

  // Logic: syllogism "are all X definitely Z?"
  if (question.match(/are all .+ definitely .+\? Answer yes or no/)) return 'yes';

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
