/**
 * TAP JWKS — JWK Set Endpoint + Key Format Conversion
 * Implements .well-known/jwks for TAP agent public key discovery
 * Per Visa TAP spec: https://developer.visa.com/capabilities/trusted-agent-protocol
 */

import type { Context } from 'hono';
import type { TAPAgent } from './tap-agents.js';
import type { KVNamespace } from './agents.js';
import { getSigningPublicKeyJWK, type ES256SigningKeyJWK } from './auth.js';

// ============ JWK TYPES ============

export interface JWK {
  kty: string;      // Key type: 'RSA', 'EC', 'OKP'
  kid: string;      // Key ID
  use: string;      // 'sig' for signature
  alg: string;      // Algorithm: 'PS256', 'ES256', 'EdDSA'
  // RSA fields
  n?: string;       // Modulus (base64url)
  e?: string;       // Exponent (base64url)
  // EC fields  
  crv?: string;     // Curve: 'P-256', 'Ed25519'
  x?: string;       // X coordinate (base64url)
  y?: string;       // Y coordinate (base64url, not for Ed25519)
  // Metadata (BOTCHA extension)
  agent_id?: string;
  agent_name?: string;
  expires_at?: string;
}

export interface JWKSet {
  keys: JWK[];
}

// ============ PEM <-> JWK CONVERSION ============

/**
 * Convert PEM public key to JWK format
 */
export async function pemToJwk(
  pem: string,
  algorithm: string,
  kid: string,
  metadata?: {
    agent_id?: string;
    agent_name?: string;
    expires_at?: string;
  }
): Promise<JWK> {
  const keyData = pemToArrayBuffer(pem);
  const importParams = getImportParamsForAlg(algorithm);
  const cryptoKey = await crypto.subtle.importKey('spki', keyData, importParams, true, ['verify']);
  const jwk = (await crypto.subtle.exportKey('jwk', cryptoKey)) as any;

  return {
    ...jwk,
    kid,
    use: 'sig',
    alg: algToJWKAlg(algorithm),
    ...(metadata?.agent_id && { agent_id: metadata.agent_id }),
    ...(metadata?.agent_name && { agent_name: metadata.agent_name }),
    ...(metadata?.expires_at && { expires_at: metadata.expires_at }),
  };
}

/**
 * Convert JWK back to PEM format (for verification)
 */
export async function jwkToPem(jwk: JWK): Promise<string> {
  const importParams = jwkAlgToImportParams(jwk.alg);
  const cryptoKey = await crypto.subtle.importKey('jwk', jwk, importParams, true, ['verify']);
  const spkiBuffer = await crypto.subtle.exportKey('spki', cryptoKey) as ArrayBuffer;
  return arrayBufferToPem(spkiBuffer);
}

// ============ ALGORITHM MAPPING ============

/**
 * Map BOTCHA algorithm names to JWK algorithm identifiers
 */
export function algToJWKAlg(algorithm: string): string {
  switch (algorithm) {
    case 'ecdsa-p256-sha256':
      return 'ES256';
    case 'rsa-pss-sha256':
      return 'PS256';
    case 'ed25519':
      return 'EdDSA';
    default:
      throw new Error(`Unsupported algorithm: ${algorithm}`);
  }
}

/**
 * Get Web Crypto import parameters for BOTCHA algorithm
 */
function getImportParamsForAlg(algorithm: string): any {
  switch (algorithm) {
    case 'ecdsa-p256-sha256':
      return {
        name: 'ECDSA',
        namedCurve: 'P-256',
      };
    case 'rsa-pss-sha256':
      return {
        name: 'RSA-PSS',
        hash: 'SHA-256',
      };
    case 'ed25519':
      // Note: Ed25519 support varies by runtime
      // Cloudflare Workers supports it via Web Crypto
      return {
        name: 'Ed25519',
      };
    default:
      throw new Error(`Unsupported algorithm: ${algorithm}`);
  }
}

/**
 * Get Web Crypto import parameters for JWK algorithm
 */
function jwkAlgToImportParams(alg: string): any {
  switch (alg) {
    case 'ES256':
      return {
        name: 'ECDSA',
        namedCurve: 'P-256',
      };
    case 'PS256':
      return {
        name: 'RSA-PSS',
        hash: 'SHA-256',
      };
    case 'EdDSA':
      return {
        name: 'Ed25519',
      };
    default:
      throw new Error(`Unsupported JWK algorithm: ${alg}`);
  }
}

// ============ PEM UTILITIES ============

/**
 * Convert PEM string to ArrayBuffer
 */
function pemToArrayBuffer(pem: string): ArrayBuffer {
  const base64 = pem
    .replace(/-----BEGIN PUBLIC KEY-----/, '')
    .replace(/-----END PUBLIC KEY-----/, '')
    .replace(/\s/g, '');
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

/**
 * Convert ArrayBuffer to PEM string
 */
function arrayBufferToPem(buffer: ArrayBuffer): string {
  const base64 = btoa(String.fromCharCode(...new Uint8Array(buffer)));
  const lines = base64.match(/.{1,64}/g) || [base64];
  return `-----BEGIN PUBLIC KEY-----\n${lines.join('\n')}\n-----END PUBLIC KEY-----`;
}

// ============ JWKS ENDPOINT HANDLERS ============

/**
 * GET /.well-known/jwks
 * Returns JWK Set for app's TAP-enabled agents.
 * Also includes BOTCHA's own signing public key when JWT_SIGNING_KEY is configured.
 */
export async function jwksRoute(c: Context): Promise<Response> {
  try {
    const allKeys: JWK[] = [];

    // Always include BOTCHA's own signing public key if configured
    const jwtSigningKeyEnv = (c.env as any).JWT_SIGNING_KEY as string | undefined;
    if (jwtSigningKeyEnv) {
      try {
        const privateKeyJwk = JSON.parse(jwtSigningKeyEnv) as ES256SigningKeyJWK;
        const publicKeyJwk = getSigningPublicKeyJWK(privateKeyJwk);
        allKeys.push({
          kty: publicKeyJwk.kty,
          crv: publicKeyJwk.crv,
          x: publicKeyJwk.x,
          y: publicKeyJwk.y,
          kid: 'botcha-signing-1',
          use: 'sig',
          alg: 'ES256',
        });
      } catch (error) {
        console.error('Failed to derive BOTCHA signing public key for JWKS:', error);
      }
    }

    const appId = c.req.query('app_id');

    // If no app_id, return just the BOTCHA signing key (if any)
    if (!appId) {
      return c.json({ keys: allKeys }, 200, {
        'Cache-Control': 'public, max-age=3600',
      });
    }

    const agents = c.env.AGENTS as KVNamespace;
    if (!agents) {
      console.error('AGENTS KV namespace not available');
      return c.json({ keys: allKeys }, 200);
    }

    // Get agent list for this app
    const agentIndexKey = `app_agents:${appId}`;
    const agentIdsData = await agents.get(agentIndexKey, 'text');

    if (!agentIdsData) {
      return c.json({ keys: allKeys }, 200, {
        'Cache-Control': 'public, max-age=3600',
      });
    }

    const agentIds = JSON.parse(agentIdsData) as string[];

    // Fetch all agents in parallel
    const agentPromises = agentIds.map(async (agentId) => {
      const agentData = await agents.get(`agent:${agentId}`, 'text');
      return agentData ? (JSON.parse(agentData) as TAPAgent) : null;
    });

    const agentResults = await Promise.all(agentPromises);

    // Filter to TAP-enabled agents with public keys
    const tapAgents = agentResults.filter(
      (agent): agent is TAPAgent =>
        agent !== null &&
        agent.tap_enabled === true &&
        Boolean(agent.public_key) &&
        Boolean(agent.signature_algorithm)
    );

    // Convert PEM keys to JWK format
    const jwkPromises = tapAgents.map(async (agent) => {
      try {
        return await pemToJwk(
          agent.public_key!,
          agent.signature_algorithm!,
          agent.agent_id,
          {
            agent_id: agent.agent_id,
            agent_name: agent.name,
            expires_at: agent.key_created_at
              ? new Date(agent.key_created_at + 31536000000).toISOString() // +1 year
              : undefined,
          }
        );
      } catch (error) {
        console.error(`Failed to convert key for agent ${agent.agent_id}:`, error);
        return null;
      }
    });

    const agentJwks = (await Promise.all(jwkPromises)).filter((jwk): jwk is JWK => jwk !== null);
    allKeys.push(...agentJwks);

    return c.json({ keys: allKeys }, 200, {
      'Cache-Control': 'public, max-age=3600',
    });
  } catch (error) {
    console.error('JWKS endpoint error:', error);
    // Fail-open: Return empty key set
    return c.json({ keys: [] }, 200);
  }
}

/**
 * GET /v1/keys/:keyId
 * Get a specific key by ID (agent_id)
 */
export async function getKeyRoute(c: Context): Promise<Response> {
  try {
    const keyId = c.req.param('keyId') || c.req.query('keyID');

    if (!keyId) {
      return c.json({ error: 'keyId or keyID parameter required' }, 400);
    }

    const agents = c.env.AGENTS as KVNamespace;
    if (!agents) {
      console.error('AGENTS KV namespace not available');
      return c.json({ error: 'Service unavailable' }, 503);
    }

    // Get agent by ID
    const agentData = await agents.get(`agent:${keyId}`, 'text');

    if (!agentData) {
      return c.json({ error: 'Key not found' }, 404);
    }

    const agent = JSON.parse(agentData) as TAPAgent;

    // Verify agent has TAP enabled and public key
    if (!agent.tap_enabled || !agent.public_key || !agent.signature_algorithm) {
      return c.json({ error: 'Key not found' }, 404);
    }

    // Convert to JWK — if the stored PEM is invalid, return a raw key stub
    let jwk: JWK;
    try {
      jwk = await pemToJwk(agent.public_key, agent.signature_algorithm, agent.agent_id, {
        agent_id: agent.agent_id,
        agent_name: agent.name,
        expires_at: agent.key_created_at
          ? new Date(agent.key_created_at + 31536000000).toISOString()
          : undefined,
      });
    } catch (conversionError) {
      // PEM is stored but can't be converted to JWK (e.g., invalid key material)
      // Return a raw stub so the endpoint doesn't 500
      console.warn('Failed to convert agent key to JWK:', conversionError);
      jwk = {
        kty: agent.signature_algorithm === 'ed25519' ? 'OKP' : 'EC',
        kid: agent.agent_id,
        alg: algToJWKAlg(agent.signature_algorithm),
        use: 'sig',
        raw_pem: agent.public_key,
        error: 'Key material could not be converted to JWK format',
      } as any;
    }

    return c.json(jwk, 200, {
      'Cache-Control': 'public, max-age=3600',
    });
  } catch (error) {
    console.error('Get key error:', error);
    return c.json({ error: 'Internal server error' }, 500);
  }
}

/**
 * GET /v1/keys
 * List keys with optional filters (Visa TAP compatible)
 */
export async function listKeysRoute(c: Context): Promise<Response> {
  try {
    const keyID = c.req.query('keyID');
    const appId = c.req.query('app_id');

    // If keyID provided, return single key (Visa TAP compat)
    if (keyID) {
      return getKeyRoute(c);
    }

    // If app_id provided, return all keys for app (same as jwksRoute)
    if (appId) {
      return jwksRoute(c);
    }

    // No filters: return empty set (don't expose all keys)
    return c.json({ keys: [] }, 200, {
      'Cache-Control': 'public, max-age=3600',
    });
  } catch (error) {
    console.error('List keys error:', error);
    return c.json({ keys: [] }, 200);
  }
}

export default {
  pemToJwk,
  jwkToPem,
  algToJWKAlg,
  jwksRoute,
  getKeyRoute,
  listKeysRoute,
};
