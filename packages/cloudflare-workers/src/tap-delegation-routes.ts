/**
 * TAP Delegation Chain API Routes
 * 
 * Endpoints for creating, querying, revoking, and verifying
 * delegation chains between TAP agents.
 * 
 * Routes:
 *   POST   /v1/delegations              — Create delegation
 *   GET    /v1/delegations/:id          — Get delegation details
 *   GET    /v1/delegations              — List delegations (by agent)
 *   POST   /v1/delegations/:id/revoke   — Revoke delegation (cascades)
 *   POST   /v1/verify/delegation        — Verify delegation chain
 */

import type { Context } from 'hono';
import { extractBearerToken, verifyToken } from './auth.js';
import { TAP_VALID_ACTIONS } from './tap-agents.js';
import {
  createDelegation,
  getDelegation,
  listDelegations,
  revokeDelegation,
  verifyDelegationChain,
  type CreateDelegationOptions,
} from './tap-delegation.js';

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
 * POST /v1/delegations
 * Create a delegation from one agent to another
 */
export async function createDelegationRoute(c: Context) {
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
    if (!body.grantor_id || !body.grantee_id) {
      return c.json({
        success: false,
        error: 'MISSING_REQUIRED_FIELDS',
        message: 'grantor_id and grantee_id are required'
      }, 400);
    }

    if (!body.capabilities || !Array.isArray(body.capabilities) || body.capabilities.length === 0) {
      return c.json({
        success: false,
        error: 'MISSING_CAPABILITIES',
        message: 'At least one capability is required'
      }, 400);
    }

    // Validate capability actions
    for (const cap of body.capabilities) {
      if (!cap.action || !(TAP_VALID_ACTIONS as readonly string[]).includes(cap.action)) {
        return c.json({
          success: false,
          error: 'INVALID_CAPABILITY',
          message: `Invalid capability action. Valid: ${TAP_VALID_ACTIONS.join(', ')}`
        }, 400);
      }
    }

    const options: CreateDelegationOptions = {
      grantor_id: body.grantor_id,
      grantee_id: body.grantee_id,
      capabilities: body.capabilities,
      duration_seconds: body.duration_seconds,
      max_depth: body.max_depth,
      parent_delegation_id: body.parent_delegation_id,
      metadata: body.metadata,
    };

    const result = await createDelegation(
      c.env.AGENTS,
      c.env.SESSIONS,
      appAccess.appId!,
      options
    );

    if (!result.success) {
      // Determine appropriate status code
      const status = result.error?.includes('not found') ? 404
        : result.error?.includes('does not belong') ? 403
        : result.error?.includes('Cannot delegate') ? 403
        : result.error?.includes('depth limit') ? 403
        : result.error?.includes('cycle') ? 409
        : result.error?.includes('revoked') ? 410
        : result.error?.includes('expired') ? 410
        : 400;

      return c.json({
        success: false,
        error: 'DELEGATION_CREATION_FAILED',
        message: result.error
      }, status as any);
    }

    const del = result.delegation!;

    return c.json({
      success: true,
      delegation_id: del.delegation_id,
      grantor_id: del.grantor_id,
      grantee_id: del.grantee_id,
      app_id: del.app_id,
      capabilities: del.capabilities,
      chain: del.chain,
      depth: del.depth,
      max_depth: del.max_depth,
      parent_delegation_id: del.parent_delegation_id || null,
      created_at: new Date(del.created_at).toISOString(),
      expires_at: new Date(del.expires_at).toISOString(),
      metadata: del.metadata || null,
    }, 201);

  } catch (error) {
    console.error('Delegation creation error:', error);
    return c.json({
      success: false,
      error: 'INTERNAL_ERROR',
      message: 'Internal server error'
    }, 500);
  }
}

/**
 * GET /v1/delegations/:id
 * Get delegation details
 */
export async function getDelegationRoute(c: Context) {
  try {
    const delegationId = c.req.param('id');
    if (!delegationId) {
      return c.json({
        success: false,
        error: 'MISSING_DELEGATION_ID',
        message: 'Delegation ID is required'
      }, 400);
    }

    const result = await getDelegation(c.env.SESSIONS, delegationId);

    if (!result.success || !result.delegation) {
      return c.json({
        success: false,
        error: 'DELEGATION_NOT_FOUND',
        message: result.error || 'Delegation not found or expired'
      }, 404);
    }

    const del = result.delegation;

    return c.json({
      success: true,
      delegation_id: del.delegation_id,
      grantor_id: del.grantor_id,
      grantee_id: del.grantee_id,
      app_id: del.app_id,
      capabilities: del.capabilities,
      chain: del.chain,
      depth: del.depth,
      max_depth: del.max_depth,
      parent_delegation_id: del.parent_delegation_id || null,
      created_at: new Date(del.created_at).toISOString(),
      expires_at: new Date(del.expires_at).toISOString(),
      revoked: del.revoked,
      revoked_at: del.revoked_at ? new Date(del.revoked_at).toISOString() : null,
      revocation_reason: del.revocation_reason || null,
      metadata: del.metadata || null,
      time_remaining: Math.max(0, del.expires_at - Date.now()),
    });

  } catch (error) {
    console.error('Delegation retrieval error:', error);
    return c.json({
      success: false,
      error: 'INTERNAL_ERROR',
      message: 'Internal server error'
    }, 500);
  }
}

/**
 * GET /v1/delegations
 * List delegations for an agent
 * 
 * Query params:
 *   agent_id    — required, the agent to list delegations for
 *   direction   — 'in', 'out', or 'both' (default: 'both')
 *   include_revoked — 'true' to include revoked delegations
 *   include_expired — 'true' to include expired delegations
 */
export async function listDelegationsRoute(c: Context) {
  try {
    const appAccess = await validateAppAccess(c, true);
    if (!appAccess.valid) {
      return c.json({
        success: false,
        error: appAccess.error,
        message: 'Authentication required'
      }, (appAccess.status || 401) as 401);
    }

    const agentId = c.req.query('agent_id');
    if (!agentId) {
      return c.json({
        success: false,
        error: 'MISSING_AGENT_ID',
        message: 'agent_id query parameter is required'
      }, 400);
    }

    const direction = (c.req.query('direction') || 'both') as 'in' | 'out' | 'both';
    const includeRevoked = c.req.query('include_revoked') === 'true';
    const includeExpired = c.req.query('include_expired') === 'true';

    const result = await listDelegations(c.env.SESSIONS, {
      agent_id: agentId,
      app_id: appAccess.appId,
      direction,
      include_revoked: includeRevoked,
      include_expired: includeExpired,
    });

    if (!result.success) {
      return c.json({
        success: false,
        error: 'LIST_FAILED',
        message: result.error || 'Failed to list delegations'
      }, 500);
    }

    const delegations = result.delegations!.map(del => ({
      delegation_id: del.delegation_id,
      grantor_id: del.grantor_id,
      grantee_id: del.grantee_id,
      capabilities: del.capabilities,
      chain: del.chain,
      depth: del.depth,
      created_at: new Date(del.created_at).toISOString(),
      expires_at: new Date(del.expires_at).toISOString(),
      revoked: del.revoked,
      parent_delegation_id: del.parent_delegation_id || null,
    }));

    return c.json({
      success: true,
      delegations,
      count: delegations.length,
      agent_id: agentId,
      direction,
    });

  } catch (error) {
    console.error('Delegation listing error:', error);
    return c.json({
      success: false,
      error: 'INTERNAL_ERROR',
      message: 'Internal server error'
    }, 500);
  }
}

/**
 * POST /v1/delegations/:id/revoke
 * Revoke a delegation (cascades to sub-delegations)
 */
export async function revokeDelegationRoute(c: Context) {
  try {
    const delegationId = c.req.param('id');
    if (!delegationId) {
      return c.json({
        success: false,
        error: 'MISSING_DELEGATION_ID',
        message: 'Delegation ID is required'
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

    // Verify delegation exists and belongs to this app
    const existing = await getDelegation(c.env.SESSIONS, delegationId);
    if (!existing.success || !existing.delegation) {
      return c.json({
        success: false,
        error: 'DELEGATION_NOT_FOUND',
        message: 'Delegation not found or expired'
      }, 404);
    }

    if (existing.delegation.app_id !== appAccess.appId) {
      return c.json({
        success: false,
        error: 'UNAUTHORIZED',
        message: 'Delegation does not belong to this app'
      }, 403);
    }

    const body = await c.req.json().catch(() => ({}));
    const reason = body.reason || undefined;

    const result = await revokeDelegation(c.env.SESSIONS, delegationId, reason);

    if (!result.success) {
      return c.json({
        success: false,
        error: 'REVOCATION_FAILED',
        message: result.error
      }, 500);
    }

    const del = result.delegation!;

    return c.json({
      success: true,
      delegation_id: del.delegation_id,
      revoked: true,
      revoked_at: del.revoked_at ? new Date(del.revoked_at).toISOString() : null,
      revocation_reason: del.revocation_reason || null,
      message: 'Delegation revoked. Sub-delegations have been cascaded.',
    });

  } catch (error) {
    console.error('Delegation revocation error:', error);
    return c.json({
      success: false,
      error: 'INTERNAL_ERROR',
      message: 'Internal server error'
    }, 500);
  }
}

/**
 * POST /v1/verify/delegation
 * Verify an entire delegation chain is valid
 * 
 * Body: { delegation_id: string }
 * 
 * Returns the full chain and effective capabilities if valid.
 */
export async function verifyDelegationRoute(c: Context) {
  try {
    const body = await c.req.json().catch(() => ({}));

    if (!body.delegation_id) {
      return c.json({
        success: false,
        error: 'MISSING_DELEGATION_ID',
        message: 'delegation_id is required'
      }, 400);
    }

    const result = await verifyDelegationChain(
      c.env.AGENTS,
      c.env.SESSIONS,
      body.delegation_id
    );

    if (!result.valid) {
      return c.json({
        success: false,
        valid: false,
        error: result.error,
      }, 400);
    }

    return c.json({
      success: true,
      valid: true,
      chain_length: result.chain!.length,
      chain: result.chain!.map(del => ({
        delegation_id: del.delegation_id,
        grantor_id: del.grantor_id,
        grantee_id: del.grantee_id,
        capabilities: del.capabilities,
        depth: del.depth,
        created_at: new Date(del.created_at).toISOString(),
        expires_at: new Date(del.expires_at).toISOString(),
      })),
      effective_capabilities: result.effective_capabilities,
    });

  } catch (error) {
    console.error('Delegation verification error:', error);
    return c.json({
      success: false,
      error: 'INTERNAL_ERROR',
      message: 'Internal server error'
    }, 500);
  }
}

export default {
  createDelegationRoute,
  getDelegationRoute,
  listDelegationsRoute,
  revokeDelegationRoute,
  verifyDelegationRoute,
};
