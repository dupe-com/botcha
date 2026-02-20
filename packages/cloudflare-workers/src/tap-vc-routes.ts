/**
 * DID/VC API Routes
 *
 * Endpoints:
 *   GET  /.well-known/did.json        — BOTCHA DID Document (did:web:botcha.ai)
 *   POST /v1/credentials/issue        — Issue VC from a valid BOTCHA access_token
 *   POST /v1/credentials/verify       — Verify a VC JWT
 *   GET  /v1/dids/:did/resolve        — Resolve a did:web DID Document
 *
 * All credential issuance requires a valid BOTCHA access_token in the
 * Authorization header (Bearer <token>). The token is the result of a
 * successful BOTCHA challenge solve (/v1/token/verify).
 */

import type { Context } from 'hono';
import {
  extractBearerToken,
  verifyToken,
  getSigningPublicKeyJWK,
  type ES256SigningKeyJWK,
} from './auth.js';
import {
  generateBotchaDIDDocument,
  resolveDIDWeb,
  isValidDIDWeb,
  buildAgentDID,
  parseDID,
} from './tap-did.js';
import { issueVC, verifyVC } from './tap-vc.js';
import { getTAPAgent } from './tap-agents.js';

// ============ HELPERS ============

function getSigningKey(env: any): ES256SigningKeyJWK | undefined {
  const raw = env?.JWT_SIGNING_KEY;
  if (!raw) return undefined;
  try {
    return JSON.parse(raw) as ES256SigningKeyJWK;
  } catch {
    return undefined;
  }
}

function getPublicKeyJwk(env: any) {
  const sk = getSigningKey(env);
  return sk ? getSigningPublicKeyJWK(sk) : undefined;
}

// ============ ROUTES ============

/**
 * GET /.well-known/did.json
 *
 * Returns the BOTCHA DID Document for did:web:botcha.ai.
 * This is a public endpoint — no auth required.
 * Resolvers use this to discover BOTCHA's public keys for VC verification.
 */
export async function didDocumentRoute(c: Context) {
  try {
    const baseUrl = new URL(c.req.url).origin;
    const publicKey = getPublicKeyJwk(c.env);
    const doc = generateBotchaDIDDocument(baseUrl, publicKey);

    return new Response(JSON.stringify(doc, null, 2), {
      status: 200,
      headers: {
        'Content-Type': 'application/did+ld+json',
        'Cache-Control': 'public, max-age=3600',
        'Access-Control-Allow-Origin': '*',
      },
    });
  } catch (error) {
    console.error('DID document error:', error);
    return c.json({ error: 'INTERNAL_ERROR', message: 'Failed to generate DID document' }, 500);
  }
}

/**
 * POST /v1/credentials/issue
 *
 * Exchange a valid BOTCHA access_token for a W3C Verifiable Credential.
 *
 * Request (body, all optional):
 *   {
 *     "agent_id": "agent_xxx",          // Override agent identity in VC
 *     "duration_seconds": 86400,        // VC validity period (default: 24h, max: 30d)
 *   }
 *
 * Headers:
 *   Authorization: Bearer <access_token>   (required — from /v1/token/verify)
 *
 * Response:
 *   {
 *     "success": true,
 *     "credential_id": "urn:botcha:vc:...",
 *     "vc": { ...W3C JSON-LD credential... },
 *     "vc_jwt": "eyJ...",
 *     "issued_at": "2026-...",
 *     "expires_at": "2026-...",
 *   }
 */
export async function issueVCRoute(c: Context) {
  try {
    // 1. Authenticate — require a valid BOTCHA access_token
    const authHeader = c.req.header('authorization');
    const token = extractBearerToken(authHeader);

    if (!token) {
      return c.json({
        success: false,
        error: 'UNAUTHORIZED',
        message: 'Missing Bearer token. Solve a BOTCHA challenge first: POST /v1/token/verify',
      }, 401);
    }

    const publicKey = getPublicKeyJwk(c.env);
    const tokenResult = await verifyToken(token, c.env.JWT_SECRET, c.env, undefined, publicKey);

    if (!tokenResult.valid || !tokenResult.payload) {
      return c.json({
        success: false,
        error: 'INVALID_TOKEN',
        message: tokenResult.error || 'Token is invalid or expired',
      }, 401);
    }

    const tokenPayload = tokenResult.payload;

    // 2. Parse optional request body
    let body: {
      agent_id?: string;
      duration_seconds?: number;
    } = {};

    try {
      body = await c.req.json();
    } catch {
      // No body or non-JSON — that's fine, all fields are optional
    }

    const appId = tokenPayload.app_id;
    if (!appId) {
      return c.json({
        success: false,
        error: 'MISSING_APP_ID',
        message: 'Token is missing app_id claim. Request a token scoped to your app.',
      }, 403);
    }

    // 3. Look up agent DID if agent_id is provided (or from token)
    const resolvedAgentId = body.agent_id || undefined;
    let agentDid: string | undefined;
    let capabilities: string[] | undefined;
    let trustLevel: 'basic' | 'verified' | 'enterprise' = 'basic';

    if (resolvedAgentId) {
      try {
        const agentResult = await getTAPAgent(c.env.AGENTS, resolvedAgentId);
        if (agentResult.success && agentResult.agent) {
          const agent = agentResult.agent;

          // Only include agent DID if it has a registered `did` field (custom) or
          // derive it from their agent_id in BOTCHA's namespace
          if ((agent as any).did) {
            agentDid = (agent as any).did;
          } else if (agent.tap_enabled) {
            // TAP-registered agents get a BOTCHA-namespace DID
            agentDid = buildAgentDID(agent.agent_id);
          }

          // Collect capability strings
          if (agent.capabilities && agent.capabilities.length > 0) {
            capabilities = agent.capabilities.map((cap) =>
              cap.scope && cap.scope.length > 0
                ? `${cap.action}:${cap.scope.join(',')}`
                : cap.action
            );
          }

          trustLevel = agent.trust_level || 'basic';
        }
      } catch {
        // Agent lookup failure is non-fatal — VC will still be issued without agent details
      }
    }

    // 4. Issue the VC
    const signingKey = getSigningKey(c.env);
    const vcResult = await issueVC(
      {
        agent_id: resolvedAgentId,
        app_id: appId,
        solve_time_ms: tokenPayload.solveTime || 0,
        challenge_type: 'speed', // access_tokens are always from speed challenges
        trust_level: trustLevel,
        capabilities,
        agent_did: agentDid,
        duration_seconds: body.duration_seconds,
      },
      signingKey,
      c.env.JWT_SECRET
    );

    if (!vcResult.success) {
      return c.json({
        success: false,
        error: 'VC_ISSUANCE_FAILED',
        message: vcResult.error || 'Failed to issue credential',
      }, 500);
    }

    return c.json({
      success: true,
      credential_id: vcResult.credential_id,
      vc: vcResult.vc,
      vc_jwt: vcResult.vc_jwt,
      issued_at: vcResult.issued_at,
      expires_at: vcResult.expires_at,
      issuer: 'did:web:botcha.ai',
      usage: {
        note: 'Present vc_jwt to any service that accepts BOTCHA Verifiable Credentials.',
        verify_endpoint: `${new URL(c.req.url).origin}/v1/credentials/verify`,
        offline_verify: 'Fetch /.well-known/jwks and verify the JWT signature yourself.',
        did_document: `${new URL(c.req.url).origin}/.well-known/did.json`,
      },
    }, 201);
  } catch (error) {
    console.error('VC issuance route error:', error);
    return c.json({
      success: false,
      error: 'INTERNAL_ERROR',
      message: 'Internal server error',
    }, 500);
  }
}

/**
 * POST /v1/credentials/verify
 *
 * Verify a BOTCHA VC JWT. No auth required — the VC is the credential.
 *
 * Request body:
 *   { "vc_jwt": "eyJ..." }
 *
 * Response (valid):
 *   {
 *     "valid": true,
 *     "issuer": "did:web:botcha.ai",
 *     "credential_id": "urn:botcha:vc:...",
 *     "credential_subject": { ... },
 *     "issued_at": "...",
 *     "expires_at": "...",
 *   }
 *
 * Response (invalid):
 *   { "valid": false, "error": "..." }
 */
export async function verifyVCRoute(c: Context) {
  try {
    let body: { vc_jwt?: string } = {};
    try {
      body = await c.req.json();
    } catch {
      return c.json({
        valid: false,
        error: 'INVALID_REQUEST',
        message: 'Request body must be JSON with a "vc_jwt" field',
      }, 400);
    }

    if (!body.vc_jwt || typeof body.vc_jwt !== 'string') {
      return c.json({
        valid: false,
        error: 'MISSING_VC_JWT',
        message: 'Provide { "vc_jwt": "<JWT string>" } in the request body',
      }, 400);
    }

    const signingKey = getSigningKey(c.env);
    if (!signingKey && !c.env.JWT_SECRET) {
      return c.json({
        valid: false,
        error: 'SERVICE_UNAVAILABLE',
        message: 'VC verification is not configured on this server. Contact support.',
      }, 503);
    }

    const result = await verifyVC(body.vc_jwt, signingKey, c.env.JWT_SECRET);

    if (!result.valid) {
      return c.json({
        valid: false,
        error: result.error || 'Verification failed',
      }, 200); // 200 with valid:false — the request itself succeeded
    }

    return c.json({
      valid: true,
      issuer: result.issuer,
      credential_id: result.credential_id,
      credential_subject: result.credential_subject,
      vc: result.vc,
      issued_at: result.issued_at,
      expires_at: result.expires_at,
    });
  } catch (error) {
    console.error('VC verification route error:', error);
    return c.json({
      valid: false,
      error: 'INTERNAL_ERROR',
      message: 'Internal server error',
    }, 500);
  }
}

/**
 * GET /v1/dids/:did/resolve
 *
 * Resolve a did:web DID Document.
 * This is a public endpoint — no auth required.
 *
 * Supports: did:web:* only (other methods return methodNotSupported)
 *
 * Special case: did:web:botcha.ai is resolved locally (no outbound fetch).
 *
 * Query params:
 *   (none currently)
 *
 * Response:
 *   W3C DID Resolution Result object
 */
export async function resolveDIDRoute(c: Context) {
  try {
    // The DID is URL-encoded in the path param — decode it
    const rawParam = c.req.param('did');
    if (!rawParam) {
      return c.json({
        '@context': 'https://w3id.org/did-resolution/v1',
        didDocument: null,
        didResolutionMetadata: { error: 'invalidDid: DID parameter is missing' },
        didDocumentMetadata: {},
      }, 400);
    }

    // Path parameters may be URL-encoded (e.g. "did%3Aweb%3Aexample.com")
    const did = decodeURIComponent(rawParam);

    // Validate DID format before attempting resolution
    const parsed = parseDID(did);
    if (!parsed.valid) {
      return c.json({
        '@context': 'https://w3id.org/did-resolution/v1',
        didDocument: null,
        didResolutionMetadata: { error: `invalidDid: ${parsed.error}` },
        didDocumentMetadata: {},
      }, 400);
    }

    if (parsed.method !== 'web') {
      return c.json({
        '@context': 'https://w3id.org/did-resolution/v1',
        didDocument: null,
        didResolutionMetadata: {
          error: `methodNotSupported: Method "${parsed.method}" is not supported. Only did:web is implemented.`,
        },
        didDocumentMetadata: {},
      }, 400);
    }

    // Special case: resolve botcha.ai locally
    if (did === 'did:web:botcha.ai') {
      const baseUrl = new URL(c.req.url).origin;
      const publicKey = getPublicKeyJwk(c.env);
      const doc = generateBotchaDIDDocument(baseUrl, publicKey);

      return c.json({
        '@context': 'https://w3id.org/did-resolution/v1',
        didDocument: doc,
        didResolutionMetadata: {
          contentType: 'application/did+ld+json',
          retrieved: new Date().toISOString(),
          duration: 0,
        },
        didDocumentMetadata: {},
      });
    }

    // Resolve external did:web
    const result = await resolveDIDWeb(did);

    const statusCode = result.didDocument ? 200 : 404;
    return c.json(result, statusCode);
  } catch (error) {
    console.error('DID resolution route error:', error);
    return c.json({
      '@context': 'https://w3id.org/did-resolution/v1',
      didDocument: null,
      didResolutionMetadata: { error: 'internalError: Internal server error' },
      didDocumentMetadata: {},
    }, 500);
  }
}

export default {
  didDocumentRoute,
  issueVCRoute,
  verifyVCRoute,
  resolveDIDRoute,
};
