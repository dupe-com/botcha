/**
 * Test: Hybrid challenge returns access_token after passing
 *
 * Bug: verifyHybridChallenge did not propagate app_id, and the hybrid
 * challenge verify handlers returned only a `badge`, leaving agents with
 * no usable API token after passing the hybrid test.
 *
 * Fix: propagate app_id in verifyHybridChallenge return value; issue
 * generateToken() in all three hybrid verify handlers, mirroring the
 * speed-only challenge flow.
 */

import { describe, it, expect } from 'vitest';
import {
  generateHybridChallenge,
  verifyHybridChallenge,
  HybridChallenge,
} from '../../../packages/cloudflare-workers/src/challenges';

// ---------------------------------------------------------------------------
// Minimal KV mock (in-memory)
// ---------------------------------------------------------------------------
function makeMockKV(): { get: (k: string) => Promise<any>; put: (k: string, v: string, opts?: any) => Promise<void>; delete: (k: string) => Promise<void> } {
  const store = new Map<string, string>();
  return {
    async get(key: string) { return store.get(key) ?? null; },
    async put(key: string, value: string) { store.set(key, value); },
    async delete(key: string) { store.delete(key); },
  };
}

// ---------------------------------------------------------------------------
// Helpers to extract reasoning answers from challenge
// ---------------------------------------------------------------------------
import * as crypto from 'node:crypto';

function solveSpeed(problems: { num: number; operation: string }[]): string[] {
  return problems.map(p => {
    const hash = crypto.createHash('sha256').update(String(p.num)).digest('hex');
    return hash.slice(0, 8);
  });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('verifyHybridChallenge — app_id propagation', () => {
  it('propagates app_id in the return value when challenge was issued with app_id', async () => {
    const kv = makeMockKV();
    const APP_ID = 'app_test123';
    const challenge = await generateHybridChallenge(kv, undefined, APP_ID);

    // Manually solve (we trust reasoning is tested elsewhere; just use known-good answers)
    const speedAnswers = solveSpeed(challenge.speed.problems);

    // Build "correct" reasoning answers from the internal expected answers
    // by reading the stored challenge JSON directly
    const stored = await kv.get(`hybrid:${challenge.id}`);
    const hybridData: HybridChallenge = JSON.parse(stored);

    // Pull reasoning challenge to get expected answers (stored under challenge:<id>)
    const reasoningStored = await kv.get(`challenge:${hybridData.reasoningChallengeId}`);
    const reasoningData = JSON.parse(reasoningStored);
    const reasoningAnswers: Record<string, string> = {};
    for (const [qid, accepted] of Object.entries(reasoningData.expectedAnswers as Record<string, string[]>)) {
      reasoningAnswers[qid] = (accepted as string[])[0];
    }

    // Re-put the challenge (reading deleted it during solve attempt below)
    // Actually we haven't called verify yet, so nothing is deleted.

    const result = await verifyHybridChallenge(challenge.id, speedAnswers, reasoningAnswers, kv);

    expect(result.valid).toBe(true);
    // app_id must be propagated for token generation in the route handler
    expect(result.app_id).toBe(APP_ID);
  });

  it('returns app_id as undefined when challenge was issued without app_id', async () => {
    const kv = makeMockKV();
    const challenge = await generateHybridChallenge(kv); // no app_id

    const speedAnswers = solveSpeed(challenge.speed.problems);

    const stored = await kv.get(`hybrid:${challenge.id}`);
    const hybridData: HybridChallenge = JSON.parse(stored);

    const reasoningStored = await kv.get(`challenge:${hybridData.reasoningChallengeId}`);
    const reasoningData = JSON.parse(reasoningStored);
    const reasoningAnswers: Record<string, string> = {};
    for (const [qid, accepted] of Object.entries(reasoningData.expectedAnswers as Record<string, string[]>)) {
      reasoningAnswers[qid] = (accepted as string[])[0];
    }

    const result = await verifyHybridChallenge(challenge.id, speedAnswers, reasoningAnswers, kv);

    expect(result.valid).toBe(true);
    expect(result.app_id).toBeUndefined();
  });

  it('propagates app_id on failure (not just on success)', async () => {
    const kv = makeMockKV();
    const APP_ID = 'app_fail_test';
    const challenge = await generateHybridChallenge(kv, undefined, APP_ID);

    // Wrong speed answers
    const badSpeedAnswers = challenge.speed.problems.map(() => '00000000');
    const reasoningAnswers = { dummy: 'wrong' };

    const result = await verifyHybridChallenge(challenge.id, badSpeedAnswers, reasoningAnswers, kv);

    expect(result.valid).toBe(false);
    // app_id is still propagated so callers can log/audit which app attempted
    expect(result.app_id).toBe(APP_ID);
  });
});
