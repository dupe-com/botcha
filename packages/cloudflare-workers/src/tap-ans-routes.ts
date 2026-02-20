/**
 * BOTCHA ANS API Routes — tap-ans-routes.ts
 *
 * HTTP route handlers for ANS (Agent Name Service) integration.
 *
 * Routes:
 *   GET  /v1/ans/resolve/:name    — Resolve ANS name to agent metadata
 *   POST /v1/ans/verify           — Issue BOTCHA verification badge for ANS name
 *   GET  /v1/ans/discover         — List BOTCHA-verified ANS agents
 *   GET  /v1/ans/nonce/:name      — Get a nonce for ANS ownership proof
 *   GET  /v1/ans/botcha           — BOTCHA's own ANS record / identity
 *
 * Trust levels issued:
 *   domain-validated   — ANS TXT record exists and resolves correctly
 *   key-validated      — Caller proved control of the ANS keypair
 *   behavior-validated — Caller also passed a BOTCHA speed/reasoning challenge
 */

import type { Context } from 'hono';
import { extractBearerToken, verifyToken, getSigningPublicKeyJWK, type ES256SigningKeyJWK } from './auth.js';
import {
  parseANSName,
  resolveANSName,
  verifyANSOwnership,
  issueANSBadge,
  saveANSRegistryEntry,
  listANSRegistry,
  generateANSNonce,
  consumeANSNonce,
  getBotchaANSRecord,
  type ANSRegistryEntry,
} from './tap-ans.js';
import { getTAPAgent } from './tap-agents.js';

// ============ HELPERS ============

function getVerificationPublicKey(env: any) {
  const rawSigningKey = env?.JWT_SIGNING_KEY;
  if (!rawSigningKey) return undefined;
  try {
    const signingKey = JSON.parse(rawSigningKey) as ES256SigningKeyJWK;
    return getSigningPublicKeyJWK(signingKey);
  } catch {
    return undefined;
  }
}

async function getOptionalAppId(c: Context): Promise<string | undefined> {
  const queryAppId = c.req.query('app_id');
  if (queryAppId) return queryAppId;

  const authHeader = c.req.header('authorization');
  const token = extractBearerToken(authHeader);
  if (!token) return undefined;

  const publicKey = getVerificationPublicKey(c.env);
  const result = await verifyToken(token, c.env.JWT_SECRET, c.env, undefined, publicKey);
  if (result.valid && result.payload?.app_id) {
    return result.payload.app_id;
  }
  return undefined;
}

/**
 * Sanitize an ANS name parameter from the URL.
 * Handles both path params and query strings.
 */
function sanitizeANSName(input: string): string {
  // Decode URI component (handles %3A for colons, etc.)
  try {
    return decodeURIComponent(input).trim();
  } catch {
    return input.trim();
  }
}

// ============ ROUTE HANDLERS ============

/**
 * GET /v1/ans/resolve/:name
 *
 * Resolve an ANS name to agent metadata via DNS TXT lookup.
 *
 * Accepts:
 *   - Path param:  /v1/ans/resolve/ans%3A%2F%2Fv1.0.myagent.example.com
 *   - Path param:  /v1/ans/resolve/myagent.example.com
 *   - Query param: /v1/ans/resolve/lookup?name=ans://v1.0.myagent.example.com
 *
 * Returns:
 *   - Parsed ANS name components
 *   - DNS TXT record fields (name, pub, cap, url, did)
 *   - Optional Agent Card (if record.url is set)
 *   - BOTCHA verification status (if already in registry)
 */
export async function resolveANSNameRoute(c: Context) {
  try {
    // Support both path param and query param
    const pathParam = c.req.param('name');
    const queryParam = c.req.query('name');
    const rawName = sanitizeANSName(pathParam || queryParam || '');

    if (!rawName) {
      return c.json({
        success: false,
        error: 'MISSING_NAME',
        message: 'ANS name is required. Provide as path param or ?name= query.',
        examples: [
          '/v1/ans/resolve/myagent.example.com',
          '/v1/ans/resolve/v1.0.myagent.example.com',
          '/v1/ans/resolve/lookup?name=ans://v1.0.myagent.example.com',
        ],
      }, 400);
    }

    const result = await resolveANSName(rawName);

    if (!result.success) {
      return c.json({
        success: false,
        error: 'RESOLUTION_FAILED',
        message: result.error,
        name: result.name ? {
          raw: result.name.raw,
          domain: result.name.domain,
          label: result.name.label,
          dns_lookup: result.name.dnsLookupName,
        } : undefined,
        hints: [
          `Add a DNS TXT record at ${result.name?.dnsLookupName ?? '_ans.<domain>'}`,
          'Format: v=ANS1 name=<label> pub=<base64-pubkey> cap=browse,search url=https://...',
          'Reference: https://agentnameregistry.org',
        ],
      }, 404);
    }

    // Check if this ANS name is already BOTCHA-verified
    const registryEntry = await (async () => {
      try {
        const key = `ans_registry:${result.name!.domain}:${result.name!.label}`;
        const raw = await c.env.AGENTS.get(key);
        return raw ? JSON.parse(raw) as ANSRegistryEntry : null;
      } catch {
        return null;
      }
    })();

    return c.json({
      success: true,
      ans_name: {
        raw: result.name!.raw,
        canonical: `ans://${result.name!.version}.${result.name!.fqdn}`,
        version: result.name!.version,
        label: result.name!.label,
        domain: result.name!.domain,
        fqdn: result.name!.fqdn,
        dns_lookup_name: result.name!.dnsLookupName,
      },
      record: result.record ? {
        version: result.record.version,
        name: result.record.name,
        capabilities: result.record.cap || [],
        agent_card_url: result.record.url,
        did: result.record.did,
        has_public_key: Boolean(result.record.pub),
      } : null,
      agent_card: result.agentCard || null,
      botcha_verified: Boolean(registryEntry),
      botcha_badge: registryEntry ? {
        badge_id: registryEntry.badge_id,
        trust_level: registryEntry.trust_level,
        verified_at: new Date(registryEntry.verified_at).toISOString(),
        expires_at: new Date(registryEntry.expires_at).toISOString(),
      } : null,
      resolved_at: result.resolvedAt ? new Date(result.resolvedAt).toISOString() : null,
      get_verified: {
        note: 'Get a BOTCHA verification badge for this ANS name',
        endpoint: 'POST /v1/ans/verify',
        body: {
          ans_name: rawName,
          nonce: '<from GET /v1/ans/nonce/:name>',
          signature: '<sign nonce with your ANS private key>',
        },
      },
    });
  } catch (error) {
    console.error('ANS resolve error:', error);
    return c.json({
      success: false,
      error: 'INTERNAL_ERROR',
      message: 'Internal server error during ANS resolution',
    }, 500);
  }
}

/**
 * GET /v1/ans/nonce/:name
 *
 * Get a fresh nonce for ANS ownership verification.
 * The caller must sign this nonce with their ANS private key,
 * then submit it to POST /v1/ans/verify.
 *
 * Nonces expire in 10 minutes (single use).
 */
export async function getANSNonceRoute(c: Context) {
  try {
    const pathParam = c.req.param('name');
    const queryParam = c.req.query('name');
    const rawName = sanitizeANSName(pathParam || queryParam || '');

    if (!rawName) {
      return c.json({
        success: false,
        error: 'MISSING_NAME',
        message: 'ANS name is required',
      }, 400);
    }

    const parsed = parseANSName(rawName);
    if (!parsed.success || !parsed.components) {
      return c.json({
        success: false,
        error: 'INVALID_ANS_NAME',
        message: parsed.error,
      }, 400);
    }

    const nonce = await generateANSNonce(c.env.AGENTS, rawName);

    return c.json({
      success: true,
      nonce,
      ans_name: rawName,
      expires_in_seconds: 600,
      instructions: {
        step1: 'Sign this nonce with the private key corresponding to the pub= key in your _ans TXT record',
        step2: 'Submit to POST /v1/ans/verify with {ans_name, nonce, signature}',
        algorithm: 'ECDSA-P256 (sign nonce bytes, return base64url signature)',
        note: 'Nonce is single-use and expires in 10 minutes',
      },
    });
  } catch (error) {
    console.error('ANS nonce error:', error);
    return c.json({
      success: false,
      error: 'INTERNAL_ERROR',
      message: 'Internal server error',
    }, 500);
  }
}

/**
 * POST /v1/ans/verify
 *
 * Issue a BOTCHA verification badge for an ANS name.
 *
 * Input (JSON body):
 *   ans_name  string  — ANS name to verify (e.g. "ans://v1.0.myagent.example.com")
 *   nonce     string  — From GET /v1/ans/nonce/:name (required for key-validated+)
 *   signature string  — base64url signature of nonce (required for key-validated+)
 *   algorithm string  — "ECDSA-P256" (default) | "Ed25519"
 *   agent_id  string  — optional BOTCHA agent ID to link to this ANS name
 *
 * Trust levels:
 *   - domain-validated: ANS TXT record exists (no nonce/signature required)
 *   - key-validated:    Caller signs nonce with ANS key (nonce + signature required)
 *   - behavior-validated: (future) key-validated + BOTCHA challenge passed
 *
 * Returns:
 *   BOTCHA-ANS verification badge (JWT credential)
 */
export async function verifyANSNameRoute(c: Context) {
  try {
    // Auth check FIRST — before any DNS work or body parsing
    const authHeader = c.req.header('authorization');
    const token = extractBearerToken(authHeader);
    if (!token) {
      return c.json({
        success: false,
        error: 'UNAUTHORIZED',
        message: 'Bearer token required. Get a token via POST /v1/challenges/{id}/verify',
      }, 401);
    }

    const publicKey = getVerificationPublicKey(c.env);
    const tokenResult = await verifyToken(token, c.env.JWT_SECRET, c.env, undefined, publicKey);
    if (!tokenResult.valid) {
      return c.json({
        success: false,
        error: 'INVALID_TOKEN',
        message: 'Token is invalid or expired',
      }, 401);
    }

    const body = await c.req.json().catch(() => ({}));

    const { ans_name, nonce, signature, algorithm, agent_id } = body as {
      ans_name?: string;
      nonce?: string;
      signature?: string;
      algorithm?: string;
      agent_id?: string;
    };

    if (!ans_name) {
      return c.json({
        success: false,
        error: 'MISSING_ANS_NAME',
        message: 'ans_name is required',
      }, 400);
    }

    // Step 1: Resolve the ANS name
    const resolution = await resolveANSName(ans_name);
    if (!resolution.success || !resolution.name || !resolution.record) {
      return c.json({
        success: false,
        error: 'ANS_RESOLUTION_FAILED',
        message: resolution.error || 'Could not resolve ANS name',
        hint: 'Ensure a valid ANS TXT record exists at the domain',
      }, 422);
    }

    const { name: components, record } = resolution;

    // Step 2: Determine trust level based on what caller provides
    let trustLevel: 'domain-validated' | 'key-validated' | 'behavior-validated' = 'domain-validated';

    if (nonce && signature) {
      // Verify nonce was issued by BOTCHA
      const nonceValid = await consumeANSNonce(c.env.AGENTS, ans_name, nonce);
      if (!nonceValid) {
        return c.json({
          success: false,
          error: 'INVALID_NONCE',
          message: 'Nonce is invalid, expired, or already used. Get a fresh nonce from GET /v1/ans/nonce/:name',
        }, 400);
      }

      // Verify ownership
      const ownershipResult = await verifyANSOwnership(
        { ans_name, nonce, signature, algorithm },
        record,
      );

      if (!ownershipResult.verified) {
        return c.json({
          success: false,
          error: 'OWNERSHIP_VERIFICATION_FAILED',
          message: ownershipResult.error,
          hint: 'Sign the exact nonce bytes with the private key corresponding to the pub= key in your _ans TXT record',
        }, 403);
      }

      trustLevel = 'key-validated';
    }

    // Step 3: Validate linked agent_id if provided
    let resolvedAgentId: string | undefined = agent_id;
    if (agent_id) {
      const agentResult = await getTAPAgent(c.env.AGENTS, agent_id);
      if (!agentResult.success) {
        return c.json({
          success: false,
          error: 'AGENT_NOT_FOUND',
          message: `Agent ${agent_id} not found in BOTCHA registry`,
        }, 404);
      }
    }

    // Step 4: Issue the badge
    const badge = await issueANSBadge(
      components,
      trustLevel,
      c.env.JWT_SECRET,
      {
        agentId: resolvedAgentId,
        capabilities: record.cap,
        agentCardUrl: record.url,
      },
    );

    // Step 5: Save to discovery registry
    const registryEntry: ANSRegistryEntry = {
      ans_name: components.raw,
      domain: components.domain,
      label: components.label,
      agent_id: resolvedAgentId,
      badge_id: badge.badge_id,
      trust_level: trustLevel,
      capabilities: record.cap,
      agent_card_url: record.url,
      verified_at: badge.issued_at,
      expires_at: badge.expires_at,
    };
    await saveANSRegistryEntry(c.env.AGENTS, registryEntry);

    // Step 6: Update agent record with ans_name if agent_id provided
    if (resolvedAgentId) {
      try {
        const agentRaw = await c.env.AGENTS.get(`agent:${resolvedAgentId}`);
        if (agentRaw) {
          const agent = JSON.parse(agentRaw);
          agent.ans_name = components.raw;
          agent.ans_badge_id = badge.badge_id;
          agent.ans_trust_level = trustLevel;
          agent.ans_verified_at = badge.issued_at;
          await c.env.AGENTS.put(`agent:${resolvedAgentId}`, JSON.stringify(agent));
        }
      } catch (err) {
        // Non-fatal: continue if agent update fails
        console.error('Failed to update agent with ANS info:', err);
      }
    }

    return c.json({
      success: true,
      badge: {
        badge_id: badge.badge_id,
        ans_name: badge.ans_name,
        domain: badge.domain,
        agent_id: badge.agent_id,
        verified: badge.verified,
        trust_level: badge.trust_level,
        verification_type: badge.verification_type,
        credential_token: badge.credential_token,
        issued_at: new Date(badge.issued_at).toISOString(),
        expires_at: new Date(badge.expires_at).toISOString(),
        issuer: badge.issuer,
      },
      record: {
        capabilities: record.cap || [],
        agent_card_url: record.url,
        did: record.did,
        has_public_key: Boolean(record.pub),
      },
      trust_levels: {
        current: trustLevel,
        description: trustLevel === 'domain-validated'
          ? 'ANS TXT record exists and resolves. Domain ownership not cryptographically proven.'
          : trustLevel === 'key-validated'
          ? 'Caller proved control of the ANS keypair. Strong ownership proof.'
          : 'Full behavior verification: keypair + BOTCHA challenge passed.',
        upgrade: trustLevel === 'domain-validated' ? {
          to: 'key-validated',
          how: 'Get a nonce from GET /v1/ans/nonce/:name and sign it with your ANS private key',
        } : null,
      },
      discovery: {
        note: 'This agent is now listed in the BOTCHA ANS discovery registry',
        endpoint: 'GET /v1/ans/discover',
      },
    }, 201);
  } catch (error) {
    console.error('ANS verify error:', error);
    return c.json({
      success: false,
      error: 'INTERNAL_ERROR',
      message: 'Internal server error during ANS verification',
    }, 500);
  }
}

/**
 * GET /v1/ans/discover
 *
 * List BOTCHA-verified ANS agents in the public discovery registry.
 * These agents have passed BOTCHA verification and are safe to interact with.
 *
 * Query params:
 *   domain  string  — filter by domain (e.g. ?domain=example.com)
 *   limit   number  — max results (default: 50, max: 100)
 */
export async function discoverANSAgentsRoute(c: Context) {
  try {
    const domain = c.req.query('domain');
    const limitParam = parseInt(c.req.query('limit') || '50', 10);
    const limit = Math.min(Math.max(1, isNaN(limitParam) ? 50 : limitParam), 100);

    const entries = await listANSRegistry(c.env.AGENTS, { domain, limit });

    const agents = entries.map(e => ({
      ans_name: e.ans_name,
      domain: e.domain,
      label: e.label,
      agent_id: e.agent_id,
      trust_level: e.trust_level,
      capabilities: e.capabilities || [],
      agent_card_url: e.agent_card_url,
      verified_at: new Date(e.verified_at).toISOString(),
      expires_at: new Date(e.expires_at).toISOString(),
      badge_id: e.badge_id,
    }));

    return c.json({
      success: true,
      count: agents.length,
      agents,
      registry: {
        description: 'BOTCHA-verified ANS agents. These agents have proven domain ownership and passed BOTCHA verification.',
        trust_levels: {
          'domain-validated': 'ANS TXT record exists',
          'key-validated': 'Proven control of ANS keypair',
          'behavior-validated': 'Keypair + BOTCHA challenge verified',
        },
        get_verified: 'POST /v1/ans/verify',
        resolve_name: 'GET /v1/ans/resolve/:name',
      },
      filter: domain ? { domain } : null,
    });
  } catch (error) {
    console.error('ANS discover error:', error);
    return c.json({
      success: false,
      error: 'INTERNAL_ERROR',
      message: 'Internal server error during ANS discovery',
    }, 500);
  }
}

/**
 * GET /v1/ans/botcha
 *
 * BOTCHA's own ANS record and identity.
 * ans://v1.0.botcha.ai
 *
 * This endpoint serves as BOTCHA's Agent Card for ANS-aware clients.
 * Also returns the DNS TXT record that should be published at _ans.botcha.ai.
 */
export async function getBotchaANSRoute(c: Context) {
  try {
    const botchaRecord = getBotchaANSRecord();

    return c.json({
      success: true,
      identity: {
        ans_name: botchaRecord.ans_name,
        canonical: 'ans://v1.0.botcha.ai',
        dns_record: {
          name: botchaRecord.dns_name,
          type: 'TXT',
          value: botchaRecord.txt_record,
        },
      },
      agent_card: botchaRecord.agent_card,
      endpoints: {
        resolve: 'GET /v1/ans/resolve/:name',
        verify: 'POST /v1/ans/verify',
        discover: 'GET /v1/ans/discover',
        nonce: 'GET /v1/ans/nonce/:name',
      },
      integration: {
        note: 'BOTCHA is the verification layer for ANS. ANS names the agent, BOTCHA verifies it.',
        ans_spec: 'https://agentnameregistry.org',
        botcha_docs: 'https://botcha.ai/ai.txt',
        trust_model: {
          'ANS alone': 'DV-level trust — domain exists',
          'ANS + BOTCHA': 'Full stack — domain exists AND agent behaves like an AI',
        },
      },
    });
  } catch (error) {
    console.error('ANS botcha identity error:', error);
    return c.json({
      success: false,
      error: 'INTERNAL_ERROR',
      message: 'Internal server error',
    }, 500);
  }
}

export default {
  resolveANSNameRoute,
  getANSNonceRoute,
  verifyANSNameRoute,
  discoverANSAgentsRoute,
  getBotchaANSRoute,
};
