import crypto from 'crypto';

interface Challenge {
  id: string;
  puzzle: string;
  expectedAnswer: string;
  expiresAt: number;
  difficulty: 'easy' | 'medium' | 'hard';
}

// In-memory challenge store (use Redis in production)
const challenges = new Map<string, Challenge>();

// Clean up expired challenges periodically
setInterval(() => {
  const now = Date.now();
  for (const [id, challenge] of challenges) {
    if (challenge.expiresAt < now) {
      challenges.delete(id);
    }
  }
}, 60000);

export function generateChallenge(difficulty: 'easy' | 'medium' | 'hard' = 'medium'): {
  id: string;
  puzzle: string;
  timeLimit: number;
  hint: string;
} {
  const id = crypto.randomUUID();
  
  // Different difficulty levels
  const config = {
    easy: { primes: 100, timeLimit: 10000 },
    medium: { primes: 500, timeLimit: 5000 },
    hard: { primes: 1000, timeLimit: 3000 },
  }[difficulty];
  
  // Random salt makes each challenge unique — precomputed lookup tables won't work
  const salt = crypto.randomUUID().replace(/-/g, '').substring(0, 16);
  
  // Generate first N primes, concatenate with salt, hash
  const primes = generatePrimes(config.primes);
  const concatenated = primes.join('') + salt;
  const hash = crypto.createHash('sha256').update(concatenated).digest('hex');
  const answer = hash.substring(0, 16); // First 16 chars
  
  const challenge: Challenge = {
    id,
    puzzle: `Compute SHA256 of the first ${config.primes} prime numbers concatenated (no separators) followed by the salt "${salt}". Return the first 16 hex characters.`,
    expectedAnswer: answer,
    expiresAt: Date.now() + config.timeLimit + 1000, // Small grace period
    difficulty,
  };
  
  challenges.set(id, challenge);
  
  return {
    id,
    puzzle: challenge.puzzle,
    timeLimit: config.timeLimit,
    hint: `Example: First 5 primes + salt = "235711${salt}" → SHA256 → first 16 chars`,
  };
}

export function verifyChallenge(id: string, answer: string): {
  valid: boolean;
  reason?: string;
  timeMs?: number;
} {
  const challenge = challenges.get(id);
  
  if (!challenge) {
    return { valid: false, reason: 'Challenge not found or expired' };
  }
  
  const now = Date.now();
  if (now > challenge.expiresAt) {
    challenges.delete(id);
    return { valid: false, reason: 'Challenge expired - too slow!' };
  }
  
  const isValid = answer.toLowerCase() === challenge.expectedAnswer.toLowerCase();
  
  // Clean up used challenge
  challenges.delete(id);
  
  if (!isValid) {
    return { valid: false, reason: 'Incorrect answer' };
  }
  
  return { 
    valid: true,
    timeMs: challenge.expiresAt - now - 1000, // Approximate solve time
  };
}

export function generatePrimes(count: number): number[] {
  const primes: number[] = [];
  let num = 2;
  
  while (primes.length < count) {
    if (isPrime(num)) {
      primes.push(num);
    }
    num++;
  }
  
  return primes;
}

export function isPrime(n: number): boolean {
  if (n < 2) return false;
  if (n === 2) return true;
  if (n % 2 === 0) return false;
  
  for (let i = 3; i <= Math.sqrt(n); i += 2) {
    if (n % i === 0) return false;
  }
  
  return true;
}

export default { generateChallenge, verifyChallenge };
