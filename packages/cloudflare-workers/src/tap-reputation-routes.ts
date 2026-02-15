/**
 * TAP Agent Reputation Scoring API Routes
 * 
 * Endpoints for querying agent reputation scores, recording events,
 * listing event history, and resetting scores.
 * 
 * Routes:
 *   GET    /v1/reputation/:agent_id          — Get agent reputation score
 *   POST   /v1/reputation/events             — Record a reputation event
 *   GET    /v1/reputation/:agent_id/events   — List reputation events
 *   POST   /v1/reputation/:agent_id/reset    — Reset agent reputation (admin)
 */

import type { Context } from 'hono';
import { extractBearerToken, verifyToken } from './auth.js';
import {
  getReputationScore,
  recordReputationEvent,
  listReputationEvents,
  resetReputation,
  isValidCategory,
  isValidAction,
  isValidCategoryAction,
  type RecordEventOptions,
  type ReputationEventCategory,
  type ReputationEventAction,
} from './tap-reputation.js';

// ============ VALIDATION HELPERS ============

async function validateAppAccess(c: Context, requireAuth: boolean = true): Promise<{
  valid: boolean;
  appId?: string;
  error?: string;
  status?: number;
}> {
  const queryAppId = c.req.query('app_id');

  let jwtAppId: string | undefined;
  const authHeader = c.req.header('authorization');
  const token = extractBearerToken(authHeader);

  if (token) {
    const result = await verifyToken(token, c.env.JWT_SECRET, c.env);
    if (result.valid && result.payload) {
      jwtAppId = (result.payload as any).app_id;
    }
  }

  const appId = queryAppId || jwtAppId;

  if (requireAuth && !appId) {
    return { valid: false, error: 'MISSING_APP_ID', status: 401 };
  }

  return { valid: true, appId };
}

// ============ ROUTE HANDLERS ============

/**
 * GET /v1/reputation/:agent_id
 * Get agent reputation score
 */
export async function getReputationRoute(c: Context) {
  try {
    const agentId = c.req.param('agent_id');
    if (!agentId) {
      return c.json({
        success: false,
        error: 'MISSING_AGENT_ID',
        message: 'Agent ID is required'
      }, 400);
    }

    const appAccess = await validateAppAccess(c, true);
    if (!appAccess.valid) {
      return c.json({
        success: false,
        error: appAccess.error,
        message: 'Authentication required'
      }, (appAccess.status || 401) as 401);
    }

    const result = await getReputationScore(
      c.env.SESSIONS,
      c.env.AGENTS,
      agentId,
      appAccess.appId!
    );

    if (!result.success || !result.score) {
      const status = result.error?.includes('not found') ? 404 : 500;
      return c.json({
        success: false,
        error: 'REPUTATION_LOOKUP_FAILED',
        message: result.error
      }, status as any);
    }

    const s = result.score;

    return c.json({
      success: true,
      agent_id: s.agent_id,
      app_id: s.app_id,
      score: s.score,
      tier: s.tier,
      event_count: s.event_count,
      positive_events: s.positive_events,
      negative_events: s.negative_events,
      last_event_at: s.last_event_at ? new Date(s.last_event_at).toISOString() : null,
      created_at: new Date(s.created_at).toISOString(),
      updated_at: new Date(s.updated_at).toISOString(),
      category_scores: s.category_scores,
    });

  } catch (error) {
    console.error('Reputation lookup error:', error);
    return c.json({
      success: false,
      error: 'INTERNAL_ERROR',
      message: 'Internal server error'
    }, 500);
  }
}

/**
 * POST /v1/reputation/events
 * Record a reputation event for an agent
 * 
 * Body:
 *   agent_id  — required
 *   category  — required (verification, attestation, delegation, session, violation, endorsement)
 *   action    — required (e.g. "challenge_solved", "attestation_issued")
 *   source_agent_id — optional (for endorsements)
 *   metadata  — optional key/value pairs
 */
export async function recordReputationEventRoute(c: Context) {
  try {
    const appAccess = await validateAppAccess(c, true);
    if (!appAccess.valid) {
      return c.json({
        success: false,
        error: appAccess.error,
        message: 'Authentication required'
      }, (appAccess.status || 401) as 401);
    }

    const body = await c.req.json().catch(() => ({}));

    // Validate required fields
    if (!body.agent_id) {
      return c.json({
        success: false,
        error: 'MISSING_AGENT_ID',
        message: 'agent_id is required'
      }, 400);
    }

    if (!body.category) {
      return c.json({
        success: false,
        error: 'MISSING_CATEGORY',
        message: 'category is required (verification, attestation, delegation, session, violation, endorsement)'
      }, 400);
    }

    if (!isValidCategory(body.category)) {
      return c.json({
        success: false,
        error: 'INVALID_CATEGORY',
        message: `Invalid category: "${body.category}". Must be one of: verification, attestation, delegation, session, violation, endorsement`
      }, 400);
    }

    if (!body.action) {
      return c.json({
        success: false,
        error: 'MISSING_ACTION',
        message: 'action is required (e.g. "challenge_solved", "attestation_issued")'
      }, 400);
    }

    if (!isValidAction(body.action)) {
      return c.json({
        success: false,
        error: 'INVALID_ACTION',
        message: `Invalid action: "${body.action}"`
      }, 400);
    }

    if (!isValidCategoryAction(body.category, body.action)) {
      return c.json({
        success: false,
        error: 'ACTION_CATEGORY_MISMATCH',
        message: `Action "${body.action}" does not belong to category "${body.category}"`
      }, 400);
    }

    const options: RecordEventOptions = {
      agent_id: body.agent_id,
      category: body.category as ReputationEventCategory,
      action: body.action as ReputationEventAction,
      source_agent_id: body.source_agent_id,
      metadata: body.metadata,
    };

    const result = await recordReputationEvent(
      c.env.SESSIONS,
      c.env.AGENTS,
      appAccess.appId!,
      options
    );

    if (!result.success) {
      const status = result.error?.includes('not found') ? 404
        : result.error?.includes('does not belong') ? 403
        : result.error?.includes('cannot endorse itself') ? 400
        : result.error?.includes('does not belong to category') ? 400
        : 400;

      return c.json({
        success: false,
        error: 'EVENT_RECORDING_FAILED',
        message: result.error
      }, status as any);
    }

    const event = result.event!;
    const score = result.score!;

    return c.json({
      success: true,
      event: {
        event_id: event.event_id,
        agent_id: event.agent_id,
        category: event.category,
        action: event.action,
        delta: event.delta,
        score_before: event.score_before,
        score_after: event.score_after,
        source_agent_id: event.source_agent_id || null,
        metadata: event.metadata || null,
        created_at: new Date(event.created_at).toISOString(),
      },
      score: {
        score: score.score,
        tier: score.tier,
        event_count: score.event_count,
      },
    }, 201);

  } catch (error) {
    console.error('Reputation event recording error:', error);
    return c.json({
      success: false,
      error: 'INTERNAL_ERROR',
      message: 'Internal server error'
    }, 500);
  }
}

/**
 * GET /v1/reputation/:agent_id/events
 * List reputation events for an agent
 * 
 * Query params:
 *   category — optional, filter by category
 *   limit    — optional, max events to return (default 50, max 100)
 */
export async function listReputationEventsRoute(c: Context) {
  try {
    const agentId = c.req.param('agent_id');
    if (!agentId) {
      return c.json({
        success: false,
        error: 'MISSING_AGENT_ID',
        message: 'Agent ID is required'
      }, 400);
    }

    const appAccess = await validateAppAccess(c, true);
    if (!appAccess.valid) {
      return c.json({
        success: false,
        error: appAccess.error,
        message: 'Authentication required'
      }, (appAccess.status || 401) as 401);
    }

    const categoryParam = c.req.query('category');
    const limitParam = c.req.query('limit');
    const limit = limitParam ? Math.min(parseInt(limitParam, 10) || 50, 100) : 50;

    let category: ReputationEventCategory | undefined;
    if (categoryParam) {
      if (!isValidCategory(categoryParam)) {
        return c.json({
          success: false,
          error: 'INVALID_CATEGORY',
          message: `Invalid category filter: "${categoryParam}"`
        }, 400);
      }
      category = categoryParam as ReputationEventCategory;
    }

    const result = await listReputationEvents(c.env.SESSIONS, agentId, { category, limit });

    if (!result.success) {
      return c.json({
        success: false,
        error: 'EVENT_LISTING_FAILED',
        message: result.error
      }, 500);
    }

    const events = (result.events || [])
      .filter(e => e.app_id === appAccess.appId)
      .map(e => ({
        event_id: e.event_id,
        agent_id: e.agent_id,
        category: e.category,
        action: e.action,
        delta: e.delta,
        score_before: e.score_before,
        score_after: e.score_after,
        source_agent_id: e.source_agent_id || null,
        metadata: e.metadata || null,
        created_at: new Date(e.created_at).toISOString(),
      }));

    return c.json({
      success: true,
      events,
      count: events.length,
      agent_id: agentId,
    });

  } catch (error) {
    console.error('Reputation event listing error:', error);
    return c.json({
      success: false,
      error: 'INTERNAL_ERROR',
      message: 'Internal server error'
    }, 500);
  }
}

/**
 * POST /v1/reputation/:agent_id/reset
 * Reset agent reputation to default (admin action)
 */
export async function resetReputationRoute(c: Context) {
  try {
    const agentId = c.req.param('agent_id');
    if (!agentId) {
      return c.json({
        success: false,
        error: 'MISSING_AGENT_ID',
        message: 'Agent ID is required'
      }, 400);
    }

    const appAccess = await validateAppAccess(c, true);
    if (!appAccess.valid) {
      return c.json({
        success: false,
        error: appAccess.error,
        message: 'Authentication required'
      }, (appAccess.status || 401) as 401);
    }

    const result = await resetReputation(
      c.env.SESSIONS,
      c.env.AGENTS,
      agentId,
      appAccess.appId!
    );

    if (!result.success) {
      const status = result.error?.includes('not found') ? 404
        : result.error?.includes('does not belong') ? 403
        : 500;

      return c.json({
        success: false,
        error: 'REPUTATION_RESET_FAILED',
        message: result.error
      }, status as any);
    }

    const s = result.score!;

    return c.json({
      success: true,
      agent_id: s.agent_id,
      score: s.score,
      tier: s.tier,
      message: 'Reputation reset to default. All event history cleared.',
    });

  } catch (error) {
    console.error('Reputation reset error:', error);
    return c.json({
      success: false,
      error: 'INTERNAL_ERROR',
      message: 'Internal server error'
    }, 500);
  }
}

export default {
  getReputationRoute,
  recordReputationEventRoute,
  listReputationEventsRoute,
  resetReputationRoute,
};
