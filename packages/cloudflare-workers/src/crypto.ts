/**
 * Web Crypto API utilities for BOTCHA
 * Works in Cloudflare Workers, Deno, and browsers
 */

/**
 * SHA256 hash, returns hex string
 */
export async function sha256(input: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(input);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * SHA256 hash, returns first N hex chars
 */
export async function sha256First(input: string, chars: number): Promise<string> {
  const hash = await sha256(input);
  return hash.substring(0, chars);
}

/**
 * Generate a UUID (crypto.randomUUID is available in Workers)
 */
export function uuid(): string {
  return crypto.randomUUID();
}

/**
 * Generate N first primes
 */
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

function isPrime(n: number): boolean {
  if (n < 2) return false;
  if (n === 2) return true;
  if (n % 2 === 0) return false;
  
  for (let i = 3; i <= Math.sqrt(n); i += 2) {
    if (n % i === 0) return false;
  }
  
  return true;
}
