/**
 * TAP Capability Attestation API Routes
 * 
 * Endpoints for issuing, retrieving, revoking, and verifying
 * capability attestation tokens for TAP agents.
 * 
 * Routes:
 *   POST   /v1/attestations              — Issue attestation token
 *   GET    /v1/attestations/:id          — Get attestation details
 *   GET    /v1/attestations              — List attestations for agent
 *   POST   /v1/attestations/:id/revoke   — Revoke attestation
 *   POST   /v1/verify/attestation        — Verify attestation + check capability
 */

import type { Context } from 'hono';
import { extractBearerToken, verifyToken } from './auth.js';
import {
  issueAttestation,
  getAttestation,
  revokeAttestation,
  verifyAttestationToken,
  verifyAndCheckCapability,
  isValidCapabilityPattern,
  type IssueAttestationOptions,
} from './tap-attestation.js';

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
 * POST /v1/attestations
 * Issue a capability attestation token for an agent
 */
export async function issueAttestationRoute(c: Context) {
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

    if (!body.can || !Array.isArray(body.can) || body.can.length === 0) {
      return c.json({
        success: false,
        error: 'MISSING_CAPABILITIES',
        message: 'At least one "can" rule is required (e.g. ["read:invoices", "browse:*"])'
      }, 400);
    }

    // Validate capability patterns
    for (const rule of body.can) {
      if (!isValidCapabilityPattern(rule)) {
        return c.json({
          success: false,
          error: 'INVALID_CAPABILITY_PATTERN',
          message: `Invalid capability pattern in "can": ${rule}. Use "action:resource" format.`
        }, 400);
      }
    }
    if (body.cannot && Array.isArray(body.cannot)) {
      for (const rule of body.cannot) {
        if (!isValidCapabilityPattern(rule)) {
          return c.json({
            success: false,
            error: 'INVALID_CAPABILITY_PATTERN',
            message: `Invalid capability pattern in "cannot": ${rule}. Use "action:resource" format.`
          }, 400);
        }
      }
    }

    const options: IssueAttestationOptions = {
      agent_id: body.agent_id,
      can: body.can,
      cannot: body.cannot,
      restrictions: body.restrictions,
      duration_seconds: body.duration_seconds,
      delegation_id: body.delegation_id,
      metadata: body.metadata,
    };

    const result = await issueAttestation(
      c.env.AGENTS,
      c.env.SESSIONS,
      appAccess.appId!,
      c.env.JWT_SECRET,
      options
    );

    if (!result.success) {
      const status = result.error?.includes('not found') ? 404
        : result.error?.includes('does not belong') ? 403
        : result.error?.includes('Too many rules') ? 400
        : 400;

      return c.json({
        success: false,
        error: 'ATTESTATION_ISSUANCE_FAILED',
        message: result.error
      }, status as any);
    }

    const att = result.attestation!;

    return c.json({
      success: true,
      attestation_id: att.attestation_id,
      agent_id: att.agent_id,
      app_id: att.app_id,
      token: att.token,
      can: att.can,
      cannot: att.cannot,
      restrictions: att.restrictions || null,
      delegation_id: att.delegation_id || null,
      metadata: att.metadata || null,
      created_at: new Date(att.created_at).toISOString(),
      expires_at: new Date(att.expires_at).toISOString(),
    }, 201);

  } catch (error) {
    console.error('Attestation issuance error:', error);
    return c.json({
      success: false,
      error: 'INTERNAL_ERROR',
      message: 'Internal server error'
    }, 500);
  }
}

/**
 * GET /v1/attestations/:id
 * Get attestation details
 */
export async function getAttestationRoute(c: Context) {
  try {
    const attestationId = c.req.param('id');
    if (!attestationId) {
      return c.json({
        success: false,
        error: 'MISSING_ATTESTATION_ID',
        message: 'Attestation ID is required'
      }, 400);
    }

    const result = await getAttestation(c.env.SESSIONS, attestationId);

    if (!result.success || !result.attestation) {
      return c.json({
        success: false,
        error: 'ATTESTATION_NOT_FOUND',
        message: result.error || 'Attestation not found or expired'
      }, 404);
    }

    const att = result.attestation;

    return c.json({
      success: true,
      attestation_id: att.attestation_id,
      agent_id: att.agent_id,
      app_id: att.app_id,
      can: att.can,
      cannot: att.cannot,
      restrictions: att.restrictions || null,
      delegation_id: att.delegation_id || null,
      metadata: att.metadata || null,
      created_at: new Date(att.created_at).toISOString(),
      expires_at: new Date(att.expires_at).toISOString(),
      revoked: att.revoked,
      revoked_at: att.revoked_at ? new Date(att.revoked_at).toISOString() : null,
      revocation_reason: att.revocation_reason || null,
      time_remaining: Math.max(0, att.expires_at - Date.now()),
    });

  } catch (error) {
    console.error('Attestation retrieval error:', error);
    return c.json({
      success: false,
      error: 'INTERNAL_ERROR',
      message: 'Internal server error'
    }, 500);
  }
}

/**
 * GET /v1/attestations
 * List attestations for an agent
 * 
 * Query params:
 *   agent_id — required, the agent to list attestations for
 */
export async function listAttestationsRoute(c: Context) {
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

    // Get the attestation index for this agent
    const indexKey = `agent_attestations:${agentId}`;
    const indexData = await c.env.SESSIONS.get(indexKey, 'text');
    const attestationIds: string[] = indexData ? JSON.parse(indexData) : [];

    // Fetch each attestation (filter out expired/missing)
    const attestations: any[] = [];
    for (const id of attestationIds) {
      const result = await getAttestation(c.env.SESSIONS, id);
      if (result.success && result.attestation) {
        const att = result.attestation;
        // Only include attestations for this app
        if (att.app_id === appAccess.appId) {
          attestations.push({
            attestation_id: att.attestation_id,
            agent_id: att.agent_id,
            can: att.can,
            cannot: att.cannot,
            created_at: new Date(att.created_at).toISOString(),
            expires_at: new Date(att.expires_at).toISOString(),
            revoked: att.revoked,
            delegation_id: att.delegation_id || null,
          });
        }
      }
    }

    return c.json({
      success: true,
      attestations,
      count: attestations.length,
      agent_id: agentId,
    });

  } catch (error) {
    console.error('Attestation listing error:', error);
    return c.json({
      success: false,
      error: 'INTERNAL_ERROR',
      message: 'Internal server error'
    }, 500);
  }
}

/**
 * POST /v1/attestations/:id/revoke
 * Revoke an attestation
 */
export async function revokeAttestationRoute(c: Context) {
  try {
    const attestationId = c.req.param('id');
    if (!attestationId) {
      return c.json({
        success: false,
        error: 'MISSING_ATTESTATION_ID',
        message: 'Attestation ID is required'
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

    // Verify attestation exists and belongs to this app
    const existing = await getAttestation(c.env.SESSIONS, attestationId);
    if (!existing.success || !existing.attestation) {
      return c.json({
        success: false,
        error: 'ATTESTATION_NOT_FOUND',
        message: 'Attestation not found or expired'
      }, 404);
    }

    if (existing.attestation.app_id !== appAccess.appId) {
      return c.json({
        success: false,
        error: 'UNAUTHORIZED',
        message: 'Attestation does not belong to this app'
      }, 403);
    }

    const body = await c.req.json().catch(() => ({}));
    const reason = body.reason || undefined;

    const result = await revokeAttestation(c.env.SESSIONS, attestationId, reason);

    if (!result.success) {
      return c.json({
        success: false,
        error: 'REVOCATION_FAILED',
        message: result.error
      }, 500);
    }

    const att = result.attestation!;

    return c.json({
      success: true,
      attestation_id: att.attestation_id,
      revoked: true,
      revoked_at: att.revoked_at ? new Date(att.revoked_at).toISOString() : null,
      revocation_reason: att.revocation_reason || null,
      message: 'Attestation revoked. Token will be rejected on verification.',
    });

  } catch (error) {
    console.error('Attestation revocation error:', error);
    return c.json({
      success: false,
      error: 'INTERNAL_ERROR',
      message: 'Internal server error'
    }, 500);
  }
}

/**
 * POST /v1/verify/attestation
 * Verify an attestation token and optionally check a specific capability
 * 
 * Body:
 *   token     — required, the attestation JWT token
 *   action    — optional, capability action to check (e.g. "read")
 *   resource  — optional, capability resource to check (e.g. "invoices")
 */
export async function verifyAttestationRoute(c: Context) {
  try {
    const body = await c.req.json().catch(() => ({}));

    if (!body.token) {
      return c.json({
        success: false,
        error: 'MISSING_TOKEN',
        message: 'Attestation token is required'
      }, 400);
    }

    // If action specified, do full verify+check
    if (body.action) {
      const result = await verifyAndCheckCapability(
        c.env.SESSIONS,
        body.token,
        c.env.JWT_SECRET,
        body.action,
        body.resource
      );

      if (!result.allowed) {
        return c.json({
          success: false,
          valid: false,
          allowed: false,
          agent_id: result.agent_id || null,
          error: result.error || result.reason,
          matched_rule: result.matched_rule || null,
          checked_capability: body.resource ? `${body.action}:${body.resource}` : body.action,
        }, result.error ? 401 : 403);
      }

      return c.json({
        success: true,
        valid: true,
        allowed: true,
        agent_id: result.agent_id,
        reason: result.reason,
        matched_rule: result.matched_rule,
        checked_capability: body.resource ? `${body.action}:${body.resource}` : body.action,
      });
    }

    // Otherwise just verify the token
    const verification = await verifyAttestationToken(
      c.env.SESSIONS,
      body.token,
      c.env.JWT_SECRET
    );

    if (!verification.valid || !verification.payload) {
      return c.json({
        success: false,
        valid: false,
        error: verification.error,
      }, 401);
    }

    const payload = verification.payload;

    return c.json({
      success: true,
      valid: true,
      agent_id: payload.sub,
      issuer: payload.iss,
      can: payload.can,
      cannot: payload.cannot,
      restrictions: payload.restrictions || null,
      delegation_id: payload.delegation_id || null,
      issued_at: new Date(payload.iat * 1000).toISOString(),
      expires_at: new Date(payload.exp * 1000).toISOString(),
    });

  } catch (error) {
    console.error('Attestation verification error:', error);
    return c.json({
      success: false,
      error: 'INTERNAL_ERROR',
      message: 'Internal server error'
    }, 500);
  }
}

export default {
  issueAttestationRoute,
  getAttestationRoute,
  listAttestationsRoute,
  revokeAttestationRoute,
  verifyAttestationRoute,
};
