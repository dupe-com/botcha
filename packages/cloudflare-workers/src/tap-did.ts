/**
 * BOTCHA DID — W3C DID Core 1.0 + did:web Method
 *
 * Implements:
 *   - BOTCHA DID Document generation (did:web:botcha.ai)
 *   - Basic did:web resolver (fetch DID Documents from remote hosts)
 *   - DID parsing and validation utilities
 *   - Agent DID helpers (did:web:botcha.ai:agents:<agent_id>)
 *
 * Standards:
 *   - W3C DID Core 1.0: https://www.w3.org/TR/did-core/
 *   - did:web method: https://w3c-ccg.github.io/did-web/
 */

// ============ TYPES ============

export interface VerificationMethod {
  id: string;
  type: string;
  controller: string;
  publicKeyJwk?: Record<string, string | undefined>;
  publicKeyMultibase?: string;
}

export interface ServiceEndpoint {
  id: string;
  type: string;
  serviceEndpoint: string | string[] | Record<string, string>;
  description?: string;
}

export interface DIDDocument {
  '@context': string | string[];
  id: string;
  controller?: string | string[];
  verificationMethod?: VerificationMethod[];
  authentication?: (string | VerificationMethod)[];
  assertionMethod?: (string | VerificationMethod)[];
  keyAgreement?: (string | VerificationMethod)[];
  capabilityInvocation?: (string | VerificationMethod)[];
  capabilityDelegation?: (string | VerificationMethod)[];
  service?: ServiceEndpoint[];
  // Allow additional properties
  [key: string]: unknown;
}

export interface DIDResolutionResult {
  '@context': string;
  didDocument: DIDDocument | null;
  didResolutionMetadata: {
    contentType?: string;
    error?: string;
    retrieved?: string;
    duration?: number;
  };
  didDocumentMetadata: {
    created?: string;
    updated?: string;
    deactivated?: boolean;
  };
}

export interface DIDParseResult {
  valid: boolean;
  method?: string;
  methodSpecificId?: string;
  error?: string;
}

// ============ CONSTANTS ============

const BOTCHA_DID = 'did:web:botcha.ai';

const DID_CORE_CONTEXT = 'https://www.w3.org/ns/did/v1';
const JWS_2020_CONTEXT = 'https://w3id.org/security/suites/jws-2020/v1';
const DID_RESOLUTION_CONTEXT = 'https://w3id.org/did-resolution/v1';

// ============ DID DOCUMENT GENERATION ============

/**
 * Generate the canonical BOTCHA DID Document for did:web:botcha.ai.
 *
 * The ES256 signing key from BOTCHA's JWKS is registered as the
 * assertionMethod — meaning VCs signed by this key are cryptographically
 * tied to the botcha.ai DID Document.
 *
 * If no signing key is available (e.g. HS256-only deployment), the
 * verificationMethod array is empty and VCs cannot be verified offline.
 */
export function generateBotchaDIDDocument(
  baseUrl: string,
  signingPublicKeyJwk?: {
    kty: string;
    crv?: string;
    x?: string;
    y?: string;
    kid?: string;
    use?: string;
    alg?: string;
  }
): DIDDocument {
  const keyId = `${BOTCHA_DID}#key-1`;

  const verificationMethods: VerificationMethod[] = [];

  if (signingPublicKeyJwk) {
    verificationMethods.push({
      id: keyId,
      type: 'JsonWebKey2020',
      controller: BOTCHA_DID,
      publicKeyJwk: {
        kty: signingPublicKeyJwk.kty || 'EC',
        crv: signingPublicKeyJwk.crv || 'P-256',
        x: signingPublicKeyJwk.x || '',
        y: signingPublicKeyJwk.y || '',
        kid: signingPublicKeyJwk.kid || 'botcha-signing-1',
        use: 'sig',
        alg: 'ES256',
      },
    });
  }

  const authAndAssert: (string | VerificationMethod)[] =
    verificationMethods.length > 0 ? [keyId] : [];

  return {
    '@context': [DID_CORE_CONTEXT, JWS_2020_CONTEXT],
    id: BOTCHA_DID,
    controller: BOTCHA_DID,
    verificationMethod: verificationMethods,
    authentication: authAndAssert,
    assertionMethod: authAndAssert,
    service: [
      {
        id: `${BOTCHA_DID}#botcha-api`,
        type: 'LinkedDomains',
        serviceEndpoint: baseUrl,
        description: 'BOTCHA Verification API',
      },
      {
        id: `${BOTCHA_DID}#jwks`,
        type: 'JwkSet',
        serviceEndpoint: `${baseUrl}/.well-known/jwks`,
        description: 'BOTCHA JSON Web Key Set',
      },
      {
        id: `${BOTCHA_DID}#vc-issuer`,
        type: 'CredentialIssuanceService',
        serviceEndpoint: `${baseUrl}/v1/credentials/issue`,
        description: 'BOTCHA Verifiable Credential Issuance',
      },
    ],
  };
}

// ============ DID PARSING ============

/**
 * Parse and validate a DID string.
 *
 * Valid DID format: did:method:method-specific-id
 *   - must start with "did:"
 *   - method: lowercase alphanumeric
 *   - method-specific-id: non-empty
 */
export function parseDID(did: string): DIDParseResult {
  if (!did || typeof did !== 'string') {
    return { valid: false, error: 'DID must be a non-empty string' };
  }

  if (!did.startsWith('did:')) {
    return { valid: false, error: 'DID must start with "did:"' };
  }

  // Split into parts: ["did", "method", "method-specific-id", ...]
  const parts = did.split(':');
  if (parts.length < 3) {
    return {
      valid: false,
      error: 'DID must have at least 3 colon-separated parts: did:method:id',
    };
  }

  const method = parts[1];
  const methodSpecificId = parts.slice(2).join(':');

  if (!method || !/^[a-z0-9]+$/.test(method)) {
    return { valid: false, error: 'DID method must be lowercase alphanumeric' };
  }

  if (!methodSpecificId) {
    return { valid: false, error: 'DID method-specific ID is empty' };
  }

  return { valid: true, method, methodSpecificId };
}

// ============ DID:WEB URL RESOLUTION ============

/**
 * Convert a did:web DID to an HTTPS URL for DID Document fetching.
 *
 * Spec rules (https://w3c-ccg.github.io/did-web/):
 *   did:web:example.com             → https://example.com/.well-known/did.json
 *   did:web:example.com:user:alice  → https://example.com/user/alice/did.json
 *   did:web:example.com%3A8080      → https://example.com:8080/.well-known/did.json
 *
 * Algorithm:
 *   1. Split the method-specific-id on unencoded ':' characters.
 *   2. The first segment is the host — percent-decode it (e.g. %3A → ':' for port).
 *   3. Remaining segments are path components — join with '/'.
 *
 * Returns null if the DID cannot be converted to a valid URL.
 */
export function didWebToUrl(did: string): string | null {
  if (!did.startsWith('did:web:')) return null;

  const suffix = did.slice('did:web:'.length);
  if (!suffix) return null;

  // Split on literal ':' FIRST (before any percent-decoding)
  // This correctly separates path components from the host.
  const parts = suffix.split(':');

  // Decode only the first segment (the host/domain — may have %3A for port)
  const host = decodeURIComponent(parts[0]);
  if (!host) return null;

  if (parts.length === 1) {
    // Simple domain (possibly with decoded port): did:web:example.com or did:web:example.com%3A8080
    return `https://${host}/.well-known/did.json`;
  } else {
    // Path-based: did:web:example.com:path:to:resource
    // → https://example.com/path/to/resource/did.json
    const pathSegments = parts.slice(1).map(decodeURIComponent);
    const path = pathSegments.join('/');
    return `https://${host}/${path}/did.json`;
  }
}

// ============ DID:WEB RESOLUTION ============

/**
 * Resolve a did:web DID by fetching its DID Document from the network.
 *
 * Supports:
 *   - did:web:example.com (fetches /.well-known/did.json)
 *   - did:web:example.com:path:resource (fetches /path/resource/did.json)
 *
 * Note: Only did:web is supported. Other methods return methodNotSupported.
 * Cloudflare Workers support outbound fetch, so this works in production.
 */
export async function resolveDIDWeb(did: string): Promise<DIDResolutionResult> {
  const startTime = Date.now();

  // Parse and validate
  const parsed = parseDID(did);
  if (!parsed.valid) {
    return buildError('invalidDid', parsed.error || 'Invalid DID', startTime);
  }

  if (parsed.method !== 'web') {
    return buildError('methodNotSupported', `Method "${parsed.method}" is not supported. Only did:web is implemented.`, startTime);
  }

  const url = didWebToUrl(did);
  if (!url) {
    return buildError('invalidDid', 'Cannot construct resolution URL from DID', startTime);
  }

  // Special case: self-resolution for did:web:botcha.ai
  // The caller should handle this by providing the local DID document instead.
  // We still attempt the fetch to allow staging/dev environments to work.

  try {
    const response = await fetch(url, {
      headers: {
        Accept: 'application/did+ld+json, application/json',
        'User-Agent': 'BOTCHA-DID-Resolver/1.0 (+https://botcha.ai)',
      },
    });

    if (!response.ok) {
      return buildError(
        'notFound',
        `HTTP ${response.status} fetching ${url}`,
        startTime
      );
    }

    const contentType = response.headers.get('content-type') || 'application/json';
    const doc = (await response.json()) as DIDDocument;

    // Validate that the resolved document's `id` matches the requested DID
    if (doc.id && doc.id !== did) {
      return buildError(
        'invalidDid',
        `DID Document id mismatch: expected "${did}", got "${doc.id}"`,
        startTime
      );
    }

    return {
      '@context': DID_RESOLUTION_CONTEXT,
      didDocument: doc,
      didResolutionMetadata: {
        contentType: 'application/did+ld+json',
        retrieved: new Date().toISOString(),
        duration: Date.now() - startTime,
      },
      didDocumentMetadata: {},
    };
  } catch (error) {
    return buildError(
      'internalError',
      error instanceof Error ? error.message : 'Fetch failed',
      startTime
    );
  }
}

// ============ AGENT DID HELPERS ============

/**
 * Build a did:web DID for a BOTCHA-registered agent.
 *   agent_abc123 → did:web:botcha.ai:agents:agent_abc123
 */
export function buildAgentDID(agentId: string): string {
  return `did:web:botcha.ai:agents:${agentId}`;
}

/**
 * Extract agent_id from a BOTCHA agent DID, if applicable.
 * Returns null if the DID is not a BOTCHA agent DID.
 */
export function parseAgentDID(did: string): string | null {
  const prefix = 'did:web:botcha.ai:agents:';
  if (!did.startsWith(prefix)) return null;
  const agentId = did.slice(prefix.length);
  return agentId || null;
}

/**
 * Check if a DID is a valid did:web DID (basic format validation).
 */
export function isValidDIDWeb(did: string): boolean {
  const parsed = parseDID(did);
  if (!parsed.valid || parsed.method !== 'web') return false;
  const url = didWebToUrl(did);
  return url !== null;
}

// ============ UTILITIES ============

function buildError(
  errorCode: string,
  message: string,
  startTime: number
): DIDResolutionResult {
  return {
    '@context': DID_RESOLUTION_CONTEXT,
    didDocument: null,
    didResolutionMetadata: {
      error: `${errorCode}: ${message}`,
      duration: Date.now() - startTime,
    },
    didDocumentMetadata: {},
  };
}

export default {
  generateBotchaDIDDocument,
  parseDID,
  didWebToUrl,
  resolveDIDWeb,
  buildAgentDID,
  parseAgentDID,
  isValidDIDWeb,
};
