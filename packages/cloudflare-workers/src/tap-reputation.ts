/**
 * TAP Agent Reputation Scoring
 * 
 * The "credit score" for AI agents. Persistent identity enables behavioral
 * tracking over time, producing trust scores that unlock higher rate limits,
 * faster verification, and access to sensitive APIs.
 * 
 * Scoring model:
 *   - Base score: 500 (neutral, no history)
 *   - Range: 0..1000
 *   - Events adjust score via weighted deltas
 *   - Decay: scores trend toward 500 over time without activity (mean reversion)
 *   - Tiers: untrusted (0-199), low (200-399), neutral (400-599),
 *            good (600-799), excellent (800-1000)
 * 
 * Event categories:
 *   - verification: challenge solved, auth success/failure
 *   - attestation: issued, verified, revoked
 *   - delegation: granted, received, revoked
 *   - session: created, expired normally, force-terminated
 *   - violation: rate limit exceeded, invalid token, abuse detected
 *   - endorsement: explicit trust signal from another agent or app
 * 
 * KV storage (SESSIONS namespace):
 *   - reputation:{agent_id}          — ReputationScore record
 *   - reputation_events:{agent_id}   — Array of event IDs (index)
 *   - reputation_event:{event_id}    — Individual ReputationEvent (with TTL)
 */

import type { KVNamespace } from './agents.js';
import { getTAPAgent } from './tap-agents.js';

// ============ TYPES ============

export type ReputationTier = 'untrusted' | 'low' | 'neutral' | 'good' | 'excellent';

export type ReputationEventCategory =
  | 'verification'
  | 'attestation'
  | 'delegation'
  | 'session'
  | 'violation'
  | 'endorsement';

export type ReputationEventAction =
  // verification
  | 'challenge_solved'
  | 'challenge_failed'
  | 'auth_success'
  | 'auth_failure'
  // attestation
  | 'attestation_issued'
  | 'attestation_verified'
  | 'attestation_revoked'
  // delegation
  | 'delegation_granted'
  | 'delegation_received'
  | 'delegation_revoked'
  // session
  | 'session_created'
  | 'session_expired'
  | 'session_terminated'
  // violation
  | 'rate_limit_exceeded'
  | 'invalid_token'
  | 'abuse_detected'
  // endorsement
  | 'endorsement_received'
  | 'endorsement_given';

export interface ReputationEvent {
  event_id: string;
  agent_id: string;
  app_id: string;
  category: ReputationEventCategory;
  action: ReputationEventAction;
  delta: number;           // score change applied
  score_before: number;    // score before this event
  score_after: number;     // score after this event
  source_agent_id?: string;  // for endorsements/delegation
  metadata?: Record<string, string>;
  created_at: number;
}

export interface ReputationScore {
  agent_id: string;
  app_id: string;
  score: number;           // 0..1000
  tier: ReputationTier;
  event_count: number;     // total events recorded
  positive_events: number;
  negative_events: number;
  last_event_at: number | null;
  created_at: number;
  updated_at: number;
  // Breakdown by category
  category_scores: {
    verification: number;
    attestation: number;
    delegation: number;
    session: number;
    violation: number;
    endorsement: number;
  };
}

export interface RecordEventOptions {
  agent_id: string;
  category: ReputationEventCategory;
  action: ReputationEventAction;
  source_agent_id?: string;
  metadata?: Record<string, string>;
}

export interface ReputationResult {
  success: boolean;
  score?: ReputationScore;
  error?: string;
}

export interface EventResult {
  success: boolean;
  event?: ReputationEvent;
  score?: ReputationScore;
  error?: string;
}

export interface EventListResult {
  success: boolean;
  events?: ReputationEvent[];
  count?: number;
  error?: string;
}

// ============ CONSTANTS ============

const BASE_SCORE = 500;
const MIN_SCORE = 0;
const MAX_SCORE = 1000;

/** How long individual events are retained in KV (90 days) */
const EVENT_TTL_SECONDS = 90 * 24 * 3600;

/** Max events to keep in the index per agent */
const MAX_EVENT_INDEX = 1000;

/** Score deltas per action — positive values increase score, negative decrease */
const ACTION_DELTAS: Record<ReputationEventAction, number> = {
  // verification (+/-)
  challenge_solved: 5,
  challenge_failed: -3,
  auth_success: 3,
  auth_failure: -5,
  // attestation
  attestation_issued: 8,
  attestation_verified: 4,
  attestation_revoked: -10,
  // delegation
  delegation_granted: 6,
  delegation_received: 10,
  delegation_revoked: -8,
  // session
  session_created: 2,
  session_expired: 1,      // normal expiry is fine
  session_terminated: -5,  // force-terminated is suspicious
  // violation
  rate_limit_exceeded: -15,
  invalid_token: -10,
  abuse_detected: -50,
  // endorsement
  endorsement_received: 20,
  endorsement_given: 3,
};

// ============ TIER LOGIC ============

export function getTier(score: number): ReputationTier {
  if (score < 200) return 'untrusted';
  if (score < 400) return 'low';
  if (score < 600) return 'neutral';
  if (score < 800) return 'good';
  return 'excellent';
}

// ============ SCORE OPERATIONS ============

/**
 * Clamp score to [MIN_SCORE, MAX_SCORE].
 */
function clamp(value: number): number {
  return Math.max(MIN_SCORE, Math.min(MAX_SCORE, value));
}

/**
 * Create a fresh reputation score for a new agent.
 */
function createDefaultScore(agentId: string, appId: string): ReputationScore {
  const now = Date.now();
  return {
    agent_id: agentId,
    app_id: appId,
    score: BASE_SCORE,
    tier: getTier(BASE_SCORE),
    event_count: 0,
    positive_events: 0,
    negative_events: 0,
    last_event_at: null,
    created_at: now,
    updated_at: now,
    category_scores: {
      verification: 0,
      attestation: 0,
      delegation: 0,
      session: 0,
      violation: 0,
      endorsement: 0,
    },
  };
}

/**
 * Apply mean-reversion decay. For every 7 days since last activity,
 * nudge the score 1% toward BASE_SCORE.
 */
export function applyDecay(score: ReputationScore): ReputationScore {
  if (!score.last_event_at) return score;

  const daysSinceActivity = (Date.now() - score.last_event_at) / (1000 * 60 * 60 * 24);
  const decayPeriods = Math.floor(daysSinceActivity / 7);

  if (decayPeriods <= 0) return score;

  const diff = score.score - BASE_SCORE;
  // Each period decays 1% of distance from base
  const decayFactor = Math.pow(0.99, decayPeriods);
  const newScore = clamp(Math.round(BASE_SCORE + diff * decayFactor));

  return {
    ...score,
    score: newScore,
    tier: getTier(newScore),
    updated_at: Date.now(),
  };
}

// ============ CORE FUNCTIONS ============

/**
 * Get the reputation score for an agent. Creates a default score if none exists.
 */
export async function getReputationScore(
  sessions: KVNamespace,
  agents: KVNamespace,
  agentId: string,
  appId: string
): Promise<ReputationResult> {
  try {
    // Verify agent exists
    const agentResult = await getTAPAgent(agents, agentId);
    if (!agentResult.success || !agentResult.agent) {
      return { success: false, error: 'Agent not found' };
    }

    const data = await sessions.get(`reputation:${agentId}`, 'text');
    if (!data) {
      // Return default score (don't persist until first event)
      const defaultScore = createDefaultScore(agentId, appId);
      return { success: true, score: defaultScore };
    }

    let score = JSON.parse(data) as ReputationScore;

    // Apply decay
    score = applyDecay(score);

    return { success: true, score };

  } catch (error) {
    console.error('Failed to get reputation score:', error);
    return { success: false, error: 'Internal server error' };
  }
}

/**
 * Record a reputation event for an agent.
 * Creates the reputation record if it doesn't exist yet.
 */
export async function recordReputationEvent(
  sessions: KVNamespace,
  agents: KVNamespace,
  appId: string,
  options: RecordEventOptions
): Promise<EventResult> {
  try {
    // Validate agent exists and belongs to app
    const agentResult = await getTAPAgent(agents, options.agent_id);
    if (!agentResult.success || !agentResult.agent) {
      return { success: false, error: 'Agent not found' };
    }
    if (agentResult.agent.app_id !== appId) {
      return { success: false, error: 'Agent does not belong to this app' };
    }

    // Validate source agent if provided (for endorsements)
    if (options.source_agent_id) {
      const sourceResult = await getTAPAgent(agents, options.source_agent_id);
      if (!sourceResult.success || !sourceResult.agent) {
        return { success: false, error: 'Source agent not found' };
      }
      if (sourceResult.agent.app_id !== appId) {
        return { success: false, error: 'Source agent does not belong to this app' };
      }
      // Cannot endorse yourself
      if (options.source_agent_id === options.agent_id) {
        return { success: false, error: 'Agent cannot endorse itself' };
      }
    }

    // Validate action belongs to category
    if (!isValidCategoryAction(options.category, options.action)) {
      return { success: false, error: `Action "${options.action}" does not belong to category "${options.category}"` };
    }

    // Get or create score
    const data = await sessions.get(`reputation:${options.agent_id}`, 'text');
    let score: ReputationScore = data
      ? JSON.parse(data) as ReputationScore
      : createDefaultScore(options.agent_id, appId);

    // Apply decay before recording event
    score = applyDecay(score);

    // Calculate delta
    const delta = ACTION_DELTAS[options.action] ?? 0;
    const scoreBefore = score.score;
    const scoreAfter = clamp(scoreBefore + delta);

    // Create event record
    const eventId = crypto.randomUUID();
    const now = Date.now();
    const event: ReputationEvent = {
      event_id: eventId,
      agent_id: options.agent_id,
      app_id: appId,
      category: options.category,
      action: options.action,
      delta,
      score_before: scoreBefore,
      score_after: scoreAfter,
      source_agent_id: options.source_agent_id,
      metadata: options.metadata,
      created_at: now,
    };

    // Update score
    score.score = scoreAfter;
    score.tier = getTier(scoreAfter);
    score.event_count += 1;
    if (delta > 0) score.positive_events += 1;
    if (delta < 0) score.negative_events += 1;
    score.last_event_at = now;
    score.updated_at = now;
    score.category_scores[options.category] += delta;

    // Persist score
    await sessions.put(`reputation:${options.agent_id}`, JSON.stringify(score));

    // Persist event with TTL
    await sessions.put(
      `reputation_event:${eventId}`,
      JSON.stringify(event),
      { expirationTtl: EVENT_TTL_SECONDS }
    );

    // Update event index
    await updateEventIndex(sessions, options.agent_id, eventId);

    return { success: true, event, score };

  } catch (error) {
    console.error('Failed to record reputation event:', error);
    return { success: false, error: 'Internal server error' };
  }
}

/**
 * List reputation events for an agent.
 * Returns the most recent events (up to limit).
 */
export async function listReputationEvents(
  sessions: KVNamespace,
  agentId: string,
  options?: {
    category?: ReputationEventCategory;
    limit?: number;
  }
): Promise<EventListResult> {
  try {
    const limit = Math.min(options?.limit ?? 50, 100);

    const indexKey = `reputation_events:${agentId}`;
    const indexData = await sessions.get(indexKey, 'text');
    const eventIds: string[] = indexData ? JSON.parse(indexData) : [];

    // Most recent first (index is append-order, reverse for recency)
    const recentIds = eventIds.slice(-limit).reverse();

    const events: ReputationEvent[] = [];
    for (const id of recentIds) {
      const data = await sessions.get(`reputation_event:${id}`, 'text');
      if (data) {
        const event = JSON.parse(data) as ReputationEvent;
        if (!options?.category || event.category === options.category) {
          events.push(event);
        }
      }
    }

    return { success: true, events, count: events.length };

  } catch (error) {
    console.error('Failed to list reputation events:', error);
    return { success: false, error: 'Internal server error' };
  }
}

/**
 * Reset an agent's reputation to default. Used by app admins.
 */
export async function resetReputation(
  sessions: KVNamespace,
  agents: KVNamespace,
  agentId: string,
  appId: string
): Promise<ReputationResult> {
  try {
    // Verify agent exists and belongs to app
    const agentResult = await getTAPAgent(agents, agentId);
    if (!agentResult.success || !agentResult.agent) {
      return { success: false, error: 'Agent not found' };
    }
    if (agentResult.agent.app_id !== appId) {
      return { success: false, error: 'Agent does not belong to this app' };
    }

    const score = createDefaultScore(agentId, appId);
    await sessions.put(`reputation:${agentId}`, JSON.stringify(score));

    // Clear event index (events themselves expire via TTL)
    await sessions.put(`reputation_events:${agentId}`, JSON.stringify([]));

    return { success: true, score };

  } catch (error) {
    console.error('Failed to reset reputation:', error);
    return { success: false, error: 'Internal server error' };
  }
}

// ============ VALIDATION ============

const CATEGORY_ACTIONS: Record<ReputationEventCategory, ReputationEventAction[]> = {
  verification: ['challenge_solved', 'challenge_failed', 'auth_success', 'auth_failure'],
  attestation: ['attestation_issued', 'attestation_verified', 'attestation_revoked'],
  delegation: ['delegation_granted', 'delegation_received', 'delegation_revoked'],
  session: ['session_created', 'session_expired', 'session_terminated'],
  violation: ['rate_limit_exceeded', 'invalid_token', 'abuse_detected'],
  endorsement: ['endorsement_received', 'endorsement_given'],
};

export function isValidCategoryAction(
  category: ReputationEventCategory,
  action: ReputationEventAction
): boolean {
  const validActions = CATEGORY_ACTIONS[category];
  return validActions ? validActions.includes(action) : false;
}

export function isValidCategory(category: string): category is ReputationEventCategory {
  return category in CATEGORY_ACTIONS;
}

export function isValidAction(action: string): action is ReputationEventAction {
  return action in ACTION_DELTAS;
}

// ============ UTILITY ============

async function updateEventIndex(
  sessions: KVNamespace,
  agentId: string,
  eventId: string
): Promise<void> {
  try {
    const key = `reputation_events:${agentId}`;
    const data = await sessions.get(key, 'text');
    let ids: string[] = data ? JSON.parse(data) : [];

    ids.push(eventId);

    // Trim to max size (keep most recent)
    if (ids.length > MAX_EVENT_INDEX) {
      ids = ids.slice(-MAX_EVENT_INDEX);
    }

    await sessions.put(key, JSON.stringify(ids));
  } catch (error) {
    console.error('Failed to update reputation event index:', error);
  }
}

// ============ EXPORTS ============

export default {
  getReputationScore,
  recordReputationEvent,
  listReputationEvents,
  resetReputation,
  getTier,
  applyDecay,
  isValidCategoryAction,
  isValidCategory,
  isValidAction,
  ACTION_DELTAS,
  BASE_SCORE,
  MIN_SCORE,
  MAX_SCORE,
};
