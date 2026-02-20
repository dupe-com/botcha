/**
 * A2A Agent Card Attestation — Route Handlers
 *
 * Routes:
 *   GET  /.well-known/agent.json   — BOTCHA's own A2A Agent Card
 *   POST /v1/a2a/attest            — Attest an A2A Agent Card
 *   POST /v1/a2a/verify-card       — Verify an attested A2A Agent Card
 *   GET  /v1/a2a/cards             — List BOTCHA-verified Agent Cards
 *   GET  /v1/a2a/cards/:id         — Get a specific A2A attestation record
 */

import type { Context } from 'hono';
import { extractBearerToken, verifyToken, getSigningPublicKeyJWK, type ES256SigningKeyJWK } from './auth.js';
import type { KVNamespace as SessionsKV } from './agents.js';
import {
  getBotchaAgentCard,
  attestCard,
  verifyCard,
  getCardAttestation,
  listVerifiedCards,
  type A2AAgentCard,
} from './tap-a2a.js';

// ============ HELPERS ============

function getVerificationPublicKey(env: any) {
  const rawSigningKey = env?.JWT_SIGNING_KEY;
  if (!rawSigningKey) return undefined;
  try {
    const signingKey = JSON.parse(rawSigningKey) as ES256SigningKeyJWK;
    return getSigningPublicKeyJWK(signingKey);
  } catch {
    console.error('Failed to parse JWT_SIGNING_KEY for A2A route verification');
    return undefined;
  }
}

async function validateAppAccess(c: Context, requireAuth: boolean = true): Promise<{
  valid: boolean;
  appId?: string;
  error?: string;
  status?: number;
}> {
  const queryAppId = c.req.query('app_id');
  const authHeader = c.req.header('authorization');
  const token = extractBearerToken(authHeader);

  if (!token) {
    if (!requireAuth) return { valid: true, appId: queryAppId };
    return { valid: false, error: 'UNAUTHORIZED', status: 401 };
  }

  const publicKey = getVerificationPublicKey(c.env);
  const result = await verifyToken(token, c.env.JWT_SECRET, c.env, undefined, publicKey);
  if (!result.valid || !result.payload) {
    return { valid: false, error: 'INVALID_TOKEN', status: 401 };
  }

  const jwtAppId = (result.payload as any).app_id as string | undefined;
  if (!jwtAppId) {
    return { valid: false, error: 'MISSING_APP_ID', status: 403 };
  }

  if (queryAppId && queryAppId !== jwtAppId) {
    return { valid: false, error: 'APP_ID_MISMATCH', status: 403 };
  }

  return { valid: true, appId: jwtAppId };
}

// ============ ROUTE HANDLERS ============

/**
 * GET /.well-known/agent.json
 *
 * BOTCHA's own A2A Agent Card. Serves the standard A2A discovery document
 * so any A2A-compatible agent can discover BOTCHA's skills and auth requirements.
 *
 * No auth required — this is a public discovery endpoint.
 */
export async function agentCardRoute(c: Context) {
  const version = c.env?.BOTCHA_VERSION;
  const card = getBotchaAgentCard(version);

  return c.json(card, 200, {
    'Cache-Control': 'public, max-age=3600',
    'Content-Type': 'application/json',
    'X-A2A-Version': '0.2.2',
  });
}

/**
 * POST /v1/a2a/attest
 *
 * Attest an A2A Agent Card. BOTCHA verifies the card structure, hashes its
 * content, signs a JWT attestation, and embeds it in extensions.botcha_attestation.
 *
 * Request body:
 *   card             — A2A Agent Card JSON (required)
 *   duration_seconds — TTL for attestation (default 86400, max 2592000)
 *   trust_level      — 'basic' | 'verified' | 'enterprise' (default 'verified')
 *
 * Auth: BOTCHA Bearer token (app_id required)
 */
export async function attestCardRoute(c: Context) {
  try {
    const appAccess = await validateAppAccess(c, true);
    if (!appAccess.valid) {
      return c.json({
        success: false,
        error: appAccess.error,
        message: 'Authentication required. Solve a BOTCHA challenge to get a Bearer token.',
        hint: 'GET /v1/token?app_id=<your_app_id> → solve SHA256 → POST /v1/token/verify',
      }, (appAccess.status || 401) as 401 | 403);
    }

    const body = await c.req.json().catch(() => ({}));

    if (!body.card || typeof body.card !== 'object') {
      return c.json({
        success: false,
        error: 'MISSING_CARD',
        message: 'Request body must include a "card" field containing an A2A Agent Card JSON object.',
        example: {
          card: {
            name: 'My Commerce Agent',
            description: 'An A2A-compatible commerce agent',
            url: 'https://myagent.example.com',
            version: '1.0.0',
            capabilities: { streaming: false },
            skills: [{ id: 'browse', name: 'Browse', description: 'Browse products' }],
          },
          duration_seconds: 86400,
        },
      }, 400);
    }

    const card = body.card as A2AAgentCard;

    const result = await attestCard(c.env.SESSIONS, c.env.JWT_SECRET, {
      card,
      app_id: appAccess.appId!,
      duration_seconds: typeof body.duration_seconds === 'number' ? body.duration_seconds : undefined,
      trust_level: typeof body.trust_level === 'string' ? body.trust_level : undefined,
    });

    if (!result.success) {
      const status = result.error?.includes('must have') ? 400
        : result.error?.includes('Invalid') ? 400
        : 500;

      return c.json({
        success: false,
        error: 'ATTESTATION_FAILED',
        message: result.error,
      }, status as 400 | 500);
    }

    const att = result.attestation!;

    return c.json({
      success: true,
      message: 'Agent Card attested successfully. BOTCHA is now the trust oracle for this card.',
      attestation: {
        attestation_id: att.attestation_id,
        agent_url: att.agent_url,
        agent_name: att.agent_name,
        app_id: att.app_id,
        card_hash: att.card_hash,
        trust_level: att.trust_level,
        token: att.token,
        created_at: new Date(att.created_at).toISOString(),
        expires_at: new Date(att.expires_at).toISOString(),
      },
      attested_card: result.attested_card,
      usage: {
        note: 'Embed the attested_card in your A2A discovery endpoint (/.well-known/agent.json)',
        verify: 'Other agents can verify this card via POST /v1/a2a/verify-card',
        registry: 'This card is now listed in GET /v1/a2a/cards?verified=true',
      },
    }, 201);

  } catch (error) {
    console.error('A2A attest route error:', error);
    return c.json({
      success: false,
      error: 'INTERNAL_ERROR',
      message: 'Internal server error',
    }, 500);
  }
}

/**
 * POST /v1/a2a/verify-card
 *
 * Verify a BOTCHA-attested A2A Agent Card. Any agent can call this endpoint
 * to check whether a card's attestation is valid. No auth required.
 *
 * Request body:
 *   card  — A2A Agent Card JSON including extensions.botcha_attestation (required)
 *
 * Returns:
 *   valid: true  → card is verified, claims decoded
 *   valid: false → reason for failure (expired, tampered, revoked, missing)
 */
export async function verifyCardRoute(c: Context) {
  try {
    const body = await c.req.json().catch(() => ({}));

    if (!body.card || typeof body.card !== 'object') {
      return c.json({
        success: false,
        error: 'MISSING_CARD',
        message: 'Request body must include a "card" field containing an A2A Agent Card JSON with extensions.botcha_attestation.',
      }, 400);
    }

    const card = body.card as A2AAgentCard;

    const result = await verifyCard(c.env.SESSIONS, c.env.JWT_SECRET, card);

    if (!result.success) {
      return c.json({
        success: false,
        error: 'VERIFICATION_ERROR',
        message: result.error,
      }, 500);
    }

    if (!result.valid) {
      return c.json({
        success: true,
        valid: false,
        verified: false,
        error: result.error,
        reason: result.reason,
        attestation_id: result.attestation_id || null,
        card_hash: result.card_hash || null,
      }, 200);
    }

    return c.json({
      success: true,
      valid: true,
      verified: true,
      attestation_id: result.attestation_id,
      agent_url: result.agent_url,
      agent_name: result.agent_name,
      card_hash: result.card_hash,
      trust_level: result.trust_level,
      app_id: result.app_id,
      issued_at: result.issued_at,
      expires_at: result.expires_at,
      issuer: 'https://botcha.ai',
      message: '✅ Agent Card verified. BOTCHA attests this agent is who it claims to be.',
    }, 200);

  } catch (error) {
    console.error('A2A verify-card route error:', error);
    return c.json({
      success: false,
      error: 'INTERNAL_ERROR',
      message: 'Internal server error',
    }, 500);
  }
}

/**
 * GET /v1/a2a/cards
 *
 * List BOTCHA-verified A2A Agent Cards from the public registry.
 *
 * Query params:
 *   verified=true   — only non-revoked (default true)
 *   agent_url=      — filter by agent URL
 *   limit=          — max results (default 50, max 200)
 *
 * No auth required — this is a public discovery endpoint.
 */
export async function listCardsRoute(c: Context) {
  try {
    const verifiedParam = c.req.query('verified');
    const agentUrl = c.req.query('agent_url');
    const limitParam = c.req.query('limit');

    const verifiedOnly = verifiedParam !== 'false';
    const limit = limitParam ? Math.min(parseInt(limitParam, 10) || 50, 200) : 50;

    const result = await listVerifiedCards(c.env.SESSIONS, {
      verified_only: verifiedOnly,
      agent_url: agentUrl || undefined,
      limit,
    });

    if (!result.success) {
      return c.json({
        success: false,
        error: 'REGISTRY_ERROR',
        message: result.error,
      }, 500);
    }

    const attestations = result.attestations!;

    return c.json({
      success: true,
      count: attestations.length,
      verified_only: verifiedOnly,
      agent_url_filter: agentUrl || null,
      cards: attestations.map(att => ({
        attestation_id: att.attestation_id,
        agent_url: att.agent_url,
        agent_name: att.agent_name,
        app_id: att.app_id,
        card_hash: att.card_hash,
        trust_level: att.trust_level,
        created_at: new Date(att.created_at).toISOString(),
        expires_at: new Date(att.expires_at).toISOString(),
        revoked: att.revoked,
      })),
      meta: {
        note: 'BOTCHA-verified A2A Agent Card registry. Each entry is a cryptographically attested agent.',
        verify: 'Verify any listed card: POST /v1/a2a/verify-card with the card JSON',
        attest: 'Add your agent: POST /v1/a2a/attest (requires BOTCHA Bearer token)',
      },
    }, 200, {
      'Cache-Control': 'public, max-age=60',
    });

  } catch (error) {
    console.error('A2A list cards route error:', error);
    return c.json({
      success: false,
      error: 'INTERNAL_ERROR',
      message: 'Internal server error',
    }, 500);
  }
}

/**
 * GET /v1/a2a/cards/:id
 *
 * Get a specific A2A attestation record by attestation ID.
 * No auth required — public registry lookup.
 */
export async function getCardAttestationRoute(c: Context) {
  try {
    const attestationId = c.req.param('id');
    if (!attestationId) {
      return c.json({
        success: false,
        error: 'MISSING_ID',
        message: 'Attestation ID is required',
      }, 400);
    }

    const result = await getCardAttestation(c.env.SESSIONS, attestationId);

    if (!result.success || !result.attestation) {
      return c.json({
        success: false,
        error: 'NOT_FOUND',
        message: result.error || 'Attestation not found or expired',
      }, 404);
    }

    const att = result.attestation;

    return c.json({
      success: true,
      attestation_id: att.attestation_id,
      agent_url: att.agent_url,
      agent_name: att.agent_name,
      app_id: att.app_id,
      card_hash: att.card_hash,
      trust_level: att.trust_level,
      created_at: new Date(att.created_at).toISOString(),
      expires_at: new Date(att.expires_at).toISOString(),
      revoked: att.revoked,
      revoked_at: att.revoked_at ? new Date(att.revoked_at).toISOString() : null,
    }, 200);

  } catch (error) {
    console.error('A2A get card attestation route error:', error);
    return c.json({
      success: false,
      error: 'INTERNAL_ERROR',
      message: 'Internal server error',
    }, 500);
  }
}

/**
 * POST /v1/a2a/verify-agent
 *
 * Verify an agent by agent_card (with embedded attestation) or by agent_url.
 * Convenience wrapper: accepts the same payload as /v1/a2a/verify-card
 * plus an `agent_url` shorthand to look up the latest active attestation.
 */
export async function verifyAgentRoute(c: Context) {
  try {
    const body = await c.req
      .json<{ agent_card?: A2AAgentCard; agent_url?: string }>()
      .catch(() => ({} as { agent_card?: A2AAgentCard; agent_url?: string }));

    const sessions = c.env.SESSIONS as unknown as SessionsKV;

    // Shorthand: agent_url lookup
    if (body.agent_url && !body.agent_card) {
      const cards = await listVerifiedCards(sessions, {
        agent_url: body.agent_url,
        verified_only: true,
        limit: 1,
      });

      if (!cards.success || !cards.attestations?.length) {
        return c.json({
          success: false,
          verified: false,
          error: 'NOT_FOUND',
          message: `No active attestation found for agent_url: ${body.agent_url}`,
        }, 404);
      }

      const att = cards.attestations[0];
      return c.json({
        success: true,
        verified: true,
        agent_url: att.agent_url,
        agent_name: att.agent_name,
        attestation_id: att.attestation_id,
        trust_level: att.trust_level,
        issued_at: new Date(att.created_at).toISOString(),
        expires_at: new Date(att.expires_at).toISOString(),
        issuer: 'https://botcha.ai',
      });
    }

    // Full card verification path (same as verify-card)
    if (!body.agent_card) {
      return c.json({
        success: false,
        verified: false,
        error: 'MISSING_CARD',
        message: 'Provide { agent_card: {...} } (Agent Card with embedded attestation) or { agent_url: "..." }',
        example: { agent_card: { name: 'My Agent', url: 'https://example.com', extensions: { botcha_attestation: '...' } } },
      }, 400);
    }

    const result = await verifyCard(sessions, c.env.JWT_SECRET, body.agent_card);

    if (!result.success) {
      return c.json({
        success: false,
        verified: false,
        error: result.error || 'VERIFICATION_FAILED',
        valid: false,
      }, result.error === 'MISSING_CARD' ? 400 : 200);
    }

    return c.json({
      success: true,
      verified: result.valid,
      valid: result.valid,
      attestation_id: result.attestation_id,
      trust_level: result.trust_level,
      card_hash: result.card_hash,
      issued_at: result.issued_at,
      expires_at: result.expires_at,
      issuer: 'https://botcha.ai',
    });
  } catch (error) {
    console.error('A2A verify-agent route error:', error);
    return c.json({ success: false, error: 'INTERNAL_ERROR', message: 'Internal server error' }, 500);
  }
}

/**
 * GET /v1/a2a/trust-level/:agent_url
 *
 * Returns the current trust level for an agent identified by URL.
 * The :agent_url path param should be URL-encoded.
 */
export async function agentTrustLevelRoute(c: Context) {
  try {
    const agentUrl = decodeURIComponent(c.req.param('agent_url') || '');
    const sessions = c.env.SESSIONS as unknown as SessionsKV;

    if (!agentUrl) {
      return c.json({
        success: false,
        error: 'MISSING_AGENT_URL',
        message: 'Provide the agent URL as a URL-encoded path parameter: /v1/a2a/trust-level/:agent_url',
      }, 400);
    }

    const cards = await listVerifiedCards(sessions, {
      agent_url: agentUrl,
      verified_only: true,
      limit: 1,
    });

    if (!cards.success || !cards.attestations?.length) {
      return c.json({
        success: true,
        agent_url: agentUrl,
        trust_level: 'unverified',
        attestation_count: 0,
        message: 'No active BOTCHA attestation found for this agent.',
      });
    }

    const att = cards.attestations[0];
    return c.json({
      success: true,
      agent_url: att.agent_url,
      agent_name: att.agent_name,
      trust_level: att.trust_level,
      attestation_id: att.attestation_id,
      issued_at: new Date(att.created_at).toISOString(),
      expires_at: new Date(att.expires_at).toISOString(),
      verified: !att.revoked,
    });
  } catch (error) {
    console.error('A2A trust-level route error:', error);
    return c.json({ success: false, error: 'INTERNAL_ERROR', message: 'Internal server error' }, 500);
  }
}

export default {
  agentCardRoute,
  attestCardRoute,
  verifyCardRoute,
  listCardsRoute,
  getCardAttestationRoute,
  verifyAgentRoute,
  agentTrustLevelRoute,
};
