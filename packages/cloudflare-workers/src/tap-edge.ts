/**
 * TAP Edge Verification — CDN-layer TAP signature verification
 * 
 * Drop-in Hono middleware for Cloudflare Workers that:
 * 1. Intercepts requests with TAP signature headers
 * 2. Fetches agent public keys from BOTCHA or Visa JWKS
 * 3. Verifies RFC 9421 signatures
 * 4. Adds verification result headers to the proxied request
 * 5. Passes through non-TAP requests unmodified
 * 
 * Usage:
 * ```typescript
 * import { createTAPEdgeMiddleware } from '@dupecom/botcha/edge';
 * 
 * app.use('*', createTAPEdgeMiddleware({
 *   jwksUrls: ['https://botcha.ai/.well-known/jwks?app_id=YOUR_APP'],
 *   allowUnverified: false,  // Block unsigned requests
 *   requireTag: true,        // Require agent-browser-auth or agent-payer-auth tag
 * }));
 * ```
 */

import type { Context, MiddlewareHandler } from 'hono';

// ============ TYPES ============

export interface TAPEdgeOptions {
  // Key sources (checked in order)
  jwksUrls?: string[];           // JWKS endpoints to fetch keys from
  staticKeys?: Map<string, string>; // kid → PEM key (for testing/local)
  
  // Behavior
  allowUnverified?: boolean;     // Allow requests without TAP headers (default: true)
  requireTag?: boolean;          // Require agent-browser-auth or agent-payer-auth (default: false)
  blockOnFailure?: boolean;      // Return 403 on verification failure (default: true)
  
  // Caching
  keyCacheTtl?: number;          // Key cache TTL in seconds (default: 3600)
  
  // Callbacks
  onVerified?: (result: EdgeVerificationResult) => void;
  onFailed?: (result: EdgeVerificationResult) => void;
}

export interface EdgeVerificationResult {
  verified: boolean;
  tag?: string;                  // agent-browser-auth | agent-payer-auth
  agentKeyId?: string;
  algorithm?: string;
  nonce?: string;
  timestamp?: number;
  error?: string;
  source?: 'botcha' | 'visa' | 'static' | 'unknown';
}

export interface ParsedEdgeSignatureInput {
  label: string;          // 'sig1' or 'sig2'
  components: string[];   // ['@authority', '@path']
  created: number;
  expires?: number;
  keyId: string;
  algorithm: string;
  nonce?: string;
  tag?: string;           // 'agent-browser-auth' | 'agent-payer-auth'
}

interface KeyCacheEntry {
  key: string;
  fetchedAt: number;
  source: string;
}

interface KeyResolutionResult {
  key: string;
  source: string;
}

// Headers added to proxied request after verification
export const TAP_EDGE_HEADERS = {
  VERIFIED: 'X-TAP-Verified',           // 'true' or 'false'
  TAG: 'X-TAP-Tag',                     // 'agent-browser-auth' or 'agent-payer-auth'
  KEY_ID: 'X-TAP-Key-ID',              // Which key was used
  AGENT_SOURCE: 'X-TAP-Agent-Source',   // 'botcha' | 'visa' | 'static'
  NONCE: 'X-TAP-Nonce',                // For body object linking downstream
  TIMESTAMP: 'X-TAP-Timestamp',        // Signature creation time
} as const;

// ============ MAIN MIDDLEWARE ============

export function createTAPEdgeMiddleware(options: TAPEdgeOptions = {}): MiddlewareHandler {
  const {
    jwksUrls = [],
    staticKeys = new Map(),
    allowUnverified = true,
    requireTag = false,
    blockOnFailure = true,
    keyCacheTtl = 3600,
    onVerified,
    onFailed,
  } = options;
  
  // In-memory key cache (per-isolate in CF Workers)
  const keyCache = new Map<string, KeyCacheEntry>();
  
  return async (c: Context, next: () => Promise<void>) => {
    // 1. Check for TAP signature headers
    const signatureInput = c.req.header('signature-input');
    const signature = c.req.header('signature');
    
    if (!signatureInput || !signature) {
      if (!allowUnverified) {
        return c.json({ error: 'TAP_REQUIRED', message: 'TAP signature headers required' }, 403);
      }
      c.header(TAP_EDGE_HEADERS.VERIFIED, 'false');
      await next();
      return;
    }
    
    // 2. Parse signature input
    const parsed = parseEdgeSignatureInput(signatureInput);
    if (!parsed) {
      const result: EdgeVerificationResult = { verified: false, error: 'Invalid signature-input format' };
      onFailed?.(result);
      if (blockOnFailure) {
        return c.json({ error: 'TAP_INVALID', message: 'Invalid TAP signature format' }, 403);
      }
      c.header(TAP_EDGE_HEADERS.VERIFIED, 'false');
      await next();
      return;
    }
    
    // 3. Check tag requirement
    if (requireTag && !parsed.tag) {
      return c.json({ error: 'TAP_TAG_REQUIRED', message: 'TAP tag required (agent-browser-auth or agent-payer-auth)' }, 403);
    }
    
    // 4. Resolve public key
    const keyResult = await resolveKey(parsed.keyId, jwksUrls, staticKeys, keyCache, keyCacheTtl);
    if (!keyResult) {
      const result: EdgeVerificationResult = { verified: false, error: 'Public key not found', agentKeyId: parsed.keyId };
      onFailed?.(result);
      if (blockOnFailure) {
        return c.json({ error: 'TAP_KEY_NOT_FOUND', message: `Public key not found for keyId: ${parsed.keyId}` }, 403);
      }
      c.header(TAP_EDGE_HEADERS.VERIFIED, 'false');
      await next();
      return;
    }
    
    // 5. Verify signature
    const verificationResult = await verifyEdgeSignature(c.req, parsed, signature, keyResult.key, parsed.algorithm);
    
    if (verificationResult.verified) {
      verificationResult.source = keyResult.source as any;
      onVerified?.(verificationResult);
      
      // Add verification headers
      c.header(TAP_EDGE_HEADERS.VERIFIED, 'true');
      if (parsed.tag) c.header(TAP_EDGE_HEADERS.TAG, parsed.tag);
      c.header(TAP_EDGE_HEADERS.KEY_ID, parsed.keyId);
      c.header(TAP_EDGE_HEADERS.AGENT_SOURCE, keyResult.source);
      if (parsed.nonce) c.header(TAP_EDGE_HEADERS.NONCE, parsed.nonce);
      if (parsed.created) c.header(TAP_EDGE_HEADERS.TIMESTAMP, String(parsed.created));
    } else {
      onFailed?.(verificationResult);
      if (blockOnFailure) {
        return c.json({ error: 'TAP_VERIFICATION_FAILED', message: verificationResult.error }, 403);
      }
      c.header(TAP_EDGE_HEADERS.VERIFIED, 'false');
    }
    
    await next();
  };
}

// ============ HELPER FUNCTIONS ============

/**
 * Parse signature-input header according to RFC 9421
 * Supports BOTH sig1 (BOTCHA) and sig2 (Visa TAP) labels
 */
export function parseEdgeSignatureInput(input: string): ParsedEdgeSignatureInput | null {
  try {
    // Match sig1 OR sig2
    const sigMatch = input.match(/(sig[12])=\(([^)]+)\)/);
    if (!sigMatch) return null;
    
    const label = sigMatch[1];
    const components = sigMatch[2]
      .split(' ')
      .map(h => h.replace(/"/g, ''));
    
    // Extract all params (keyid/keyId, alg, created, expires, nonce, tag)
    const keyIdMatch = input.match(/keyid="([^"]+)"/i);
    const algMatch = input.match(/alg="([^"]+)"/);
    const createdMatch = input.match(/created=(\d+)/);
    const expiresMatch = input.match(/expires=(\d+)/);
    const nonceMatch = input.match(/nonce="([^"]+)"/);
    const tagMatch = input.match(/tag="([^"]+)"/);
    
    if (!keyIdMatch || !algMatch || !createdMatch) return null;
    
    return {
      label,
      keyId: keyIdMatch[1],
      algorithm: algMatch[1],
      created: parseInt(createdMatch[1]),
      expires: expiresMatch ? parseInt(expiresMatch[1]) : undefined,
      nonce: nonceMatch ? nonceMatch[1] : undefined,
      tag: tagMatch ? tagMatch[1] : undefined,
      components
    };
  } catch {
    return null;
  }
}

/**
 * Resolve public key from static keys, cache, or JWKS endpoints
 */
async function resolveKey(
  keyId: string,
  jwksUrls: string[],
  staticKeys: Map<string, string>,
  cache: Map<string, KeyCacheEntry>,
  cacheTtl: number
): Promise<KeyResolutionResult | null> {
  // 1. Check static keys
  if (staticKeys.has(keyId)) {
    return { key: staticKeys.get(keyId)!, source: 'static' };
  }
  
  // 2. Check cache
  const cached = cache.get(keyId);
  if (cached && (Date.now() - cached.fetchedAt) / 1000 < cacheTtl) {
    return { key: cached.key, source: cached.source };
  }
  
  // 3. Fetch from JWKS endpoints
  for (const url of jwksUrls) {
    try {
      const resp = await fetch(url);
      if (!resp.ok) continue;
      const jwks = await resp.json() as { keys: any[] };
      const matchingKey = jwks.keys?.find((k: any) => k.kid === keyId);
      if (matchingKey) {
        const pem = await jwkToPublicKeyPem(matchingKey);
        const source = url.includes('visa.com') ? 'visa' : 
                       url.includes('botcha') ? 'botcha' : 'unknown';
        cache.set(keyId, { key: pem, fetchedAt: Date.now(), source });
        return { key: pem, source };
      }
    } catch (e) {
      console.error(`Failed to fetch JWKS from ${url}:`, e);
    }
  }
  
  return null;
}

/**
 * Convert JWK to PEM format using Web Crypto
 */
export async function jwkToPublicKeyPem(jwk: any): Promise<string> {
  const algorithm = jwkAlgToImportParams(jwk.alg || jwk.kty);
  const key = await crypto.subtle.importKey('jwk', jwk, algorithm, true, ['verify']);
  const spki = await crypto.subtle.exportKey('spki', key);
  const base64 = btoa(String.fromCharCode(...new Uint8Array(spki as ArrayBuffer)));
  const lines = base64.match(/.{1,64}/g) || [base64];
  return `-----BEGIN PUBLIC KEY-----\n${lines.join('\n')}\n-----END PUBLIC KEY-----`;
}

/**
 * Get Web Crypto import parameters for JWK algorithm
 */
function jwkAlgToImportParams(alg: string): any {
  switch (alg) {
    case 'ES256':
      return { name: 'ECDSA', namedCurve: 'P-256' };
    case 'PS256':
      return { name: 'RSA-PSS', hash: 'SHA-256' };
    case 'EdDSA':
      return { name: 'Ed25519' };
    case 'EC':
      // Default EC to P-256
      return { name: 'ECDSA', namedCurve: 'P-256' };
    case 'RSA':
      return { name: 'RSA-PSS', hash: 'SHA-256' };
    case 'OKP':
      // Octet Key Pair - Ed25519
      return { name: 'Ed25519' };
    default:
      throw new Error(`Unsupported JWK algorithm: ${alg}`);
  }
}

/**
 * Verify edge signature against signature base
 */
export async function verifyEdgeSignature(
  req: any,
  parsed: ParsedEdgeSignatureInput,
  signature: string,
  publicKey: string,
  algorithm: string
): Promise<EdgeVerificationResult> {
  try {
    // 1. Validate timestamps
    const timestampValidation = validateEdgeTimestamps(parsed.created, parsed.expires);
    if (!timestampValidation.valid) {
      return { verified: false, error: timestampValidation.error };
    }
    
    // 2. Get authority from host header
    // Try multiple ways to get the host
    let authority = req.header('host') || req.header(':authority') || '';
    
    // Fallback: try to extract from URL if available
    if (!authority && 'url' in req && typeof req.url === 'string') {
      try {
        authority = new URL(req.url).hostname;
      } catch {
        // ignore URL parse errors
      }
    }
    
    // Get path from req - Hono Request has .path property
    let path: string;
    if ('path' in req && typeof req.path === 'string') {
      path = req.path;
    } else if ('url' in req) {
      path = new URL(req.url as string).pathname;
    } else {
      path = '/';
    }
    
    // 3. Build signature base
    const signatureBase = buildEdgeSignatureBase(authority, path, parsed);
    
    // 4. Verify cryptographic signature
    const isValid = await verifyCryptoSignature(
      signatureBase,
      signature,
      publicKey,
      algorithm,
      parsed.label
    );
    
    if (!isValid) {
      return { verified: false, error: 'Signature verification failed' };
    }
    
    return {
      verified: true,
      tag: parsed.tag,
      agentKeyId: parsed.keyId,
      algorithm: parsed.algorithm,
      nonce: parsed.nonce,
      timestamp: parsed.created,
    };
    
  } catch (error) {
    return {
      verified: false,
      error: `Verification error: ${error instanceof Error ? error.message : 'Unknown error'}`
    };
  }
}

/**
 * Build signature base string according to RFC 9421 TAP format
 */
export function buildEdgeSignatureBase(
  authority: string,
  path: string,
  parsed: ParsedEdgeSignatureInput
): string {
  const lines: string[] = [];
  
  // Add component lines (values are bare, no quotes)
  for (const component of parsed.components) {
    if (component === '@authority') {
      lines.push(`"@authority": ${authority}`);
    } else if (component === '@path') {
      lines.push(`"@path": ${path}`);
    } else if (component === '@method') {
      lines.push(`"@method": GET`); // Edge typically handles GET requests
    }
    // Note: Other headers would need to be passed in if components include them
  }
  
  // Build @signature-params line with ALL fields
  const componentsList = parsed.components.map(c => `"${c}"`).join(' ');
  let paramsLine = `"@signature-params": ${parsed.label}=(${componentsList});created=${parsed.created};keyid="${parsed.keyId}";alg="${parsed.algorithm}"`;
  
  if (parsed.expires !== undefined) {
    paramsLine += `;expires=${parsed.expires}`;
  }
  if (parsed.nonce) {
    paramsLine += `;nonce="${parsed.nonce}"`;
  }
  if (parsed.tag) {
    paramsLine += `;tag="${parsed.tag}"`;
  }
  
  lines.push(paramsLine);
  
  return lines.join('\n');
}

/**
 * Validate created/expires timestamps according to TAP spec
 */
function validateEdgeTimestamps(created: number, expires?: number): { valid: boolean; error?: string } {
  const now = Math.floor(Date.now() / 1000);
  const clockSkew = 30; // 30 seconds tolerance for clock drift
  
  // created must be in the past (with clock skew)
  if (created > now + clockSkew) {
    return { valid: false, error: 'Signature timestamp is in the future' };
  }
  
  // If expires is present, validate it
  if (expires !== undefined) {
    // expires must be in the future
    if (expires < now) {
      return { valid: false, error: 'Signature has expired' };
    }
    
    // expires - created must be <= 480 seconds (8 minutes per TAP spec)
    const window = expires - created;
    if (window > 480) {
      return { valid: false, error: 'Signature validity window exceeds 8 minutes' };
    }
  } else {
    // No expires - fall back to 5-minute tolerance on created (backward compat)
    const age = now - created;
    if (age > 300) {
      return { valid: false, error: 'Signature timestamp too old' };
    }
    if (age < -clockSkew) {
      return { valid: false, error: 'Signature timestamp too new' };
    }
  }
  
  return { valid: true };
}

/**
 * Verify cryptographic signature using Web Crypto API
 */
async function verifyCryptoSignature(
  signatureBase: string,
  signature: string,
  publicKeyPem: string,
  algorithm: string,
  label: string
): Promise<boolean> {
  try {
    // Extract signature bytes using the correct label
    const sigPattern = new RegExp(`${label}=:([^:]+):`);
    const sigMatch = signature.match(sigPattern);
    if (!sigMatch) return false;
    
    const signatureBytes = Uint8Array.from(atob(sigMatch[1]), c => c.charCodeAt(0));
    
    // Import public key
    const keyData = importPublicKey(publicKeyPem, algorithm);
    const cryptoKey = await crypto.subtle.importKey(
      'spki',
      keyData,
      getImportParams(algorithm),
      false,
      ['verify']
    );
    
    // Verify signature
    const encoder = new TextEncoder();
    const data = encoder.encode(signatureBase);
    
    return await crypto.subtle.verify(
      getVerifyParams(algorithm),
      cryptoKey,
      signatureBytes,
      data
    );
    
  } catch (error) {
    console.error('Crypto signature verification error:', error);
    return false;
  }
}

/**
 * Import public key - handles PEM SPKI and raw Ed25519 formats
 */
function importPublicKey(key: string, algorithm: string): ArrayBuffer {
  // Check if it's a raw Ed25519 key (32 bytes base64)
  if (algorithm.toLowerCase().includes('ed25519') || algorithm === 'Ed25519') {
    if (isRawEd25519Key(key)) {
      return rawEd25519ToSPKI(key);
    }
  }
  
  // Otherwise parse as PEM
  return pemToArrayBuffer(key);
}

/**
 * Detect raw Ed25519 public key (32 bytes = 43-44 base64 chars)
 */
function isRawEd25519Key(key: string): boolean {
  const stripped = key.replace(/[\s\n\r-]/g, '').replace(/BEGIN.*?END[^-]*-*/g, '');
  try {
    const decoded = atob(stripped.replace(/-/g, '+').replace(/_/g, '/'));
    return decoded.length === 32;
  } catch {
    return false;
  }
}

/**
 * Convert raw 32-byte Ed25519 key to SPKI format
 */
function rawEd25519ToSPKI(rawKey: string): ArrayBuffer {
  const rawBytes = Uint8Array.from(atob(rawKey), c => c.charCodeAt(0));
  
  if (rawBytes.length !== 32) {
    throw new Error('Invalid Ed25519 key length');
  }
  
  // SPKI header for Ed25519 (12 bytes)
  const spkiHeader = new Uint8Array([
    0x30, 0x2a,             // SEQUENCE (42 bytes)
    0x30, 0x05,             // SEQUENCE (5 bytes) - algorithm
    0x06, 0x03, 0x2b, 0x65, 0x70,  // OID 1.3.101.112 (Ed25519)
    0x03, 0x21, 0x00        // BIT STRING (33 bytes, 0 unused bits)
  ]);
  
  const spki = new Uint8Array(spkiHeader.length + rawBytes.length);
  spki.set(spkiHeader, 0);
  spki.set(rawBytes, spkiHeader.length);
  
  return spki.buffer;
}

/**
 * Convert PEM public key to ArrayBuffer
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
 * Get Web Crypto API algorithm parameters for key import
 */
function getImportParams(algorithm: string): any {
  const alg = algorithm.toLowerCase();
  
  if (alg.includes('ed25519')) {
    return { name: 'Ed25519' };
  }
  
  switch (algorithm) {
    case 'ecdsa-p256-sha256':
      return { name: 'ECDSA', namedCurve: 'P-256' };
    case 'rsa-pss-sha256':
      return { name: 'RSA-PSS', hash: 'SHA-256' };
    default:
      throw new Error(`Unsupported algorithm: ${algorithm}`);
  }
}

/**
 * Get Web Crypto API algorithm parameters for signature verification
 */
function getVerifyParams(algorithm: string): any {
  const alg = algorithm.toLowerCase();
  
  if (alg.includes('ed25519')) {
    return { name: 'Ed25519' };
  }
  
  switch (algorithm) {
    case 'ecdsa-p256-sha256':
      return { name: 'ECDSA', hash: 'SHA-256' };
    case 'rsa-pss-sha256':
      return { name: 'RSA-PSS', saltLength: 32 };
    default:
      throw new Error(`Unsupported algorithm: ${algorithm}`);
  }
}

// ============ CONVENIENCE PRESETS ============

/**
 * Strict mode: require TAP on all requests, block failures
 */
export const tapEdgeStrict = (jwksUrls: string[]) => createTAPEdgeMiddleware({
  jwksUrls,
  allowUnverified: false,
  requireTag: true,
  blockOnFailure: true
});

/**
 * Flexible mode: verify if present, pass through if not
 */
export const tapEdgeFlexible = (jwksUrls: string[]) => createTAPEdgeMiddleware({
  jwksUrls,
  allowUnverified: true,
  requireTag: false,
  blockOnFailure: false
});

/**
 * Development mode: log only, never block
 */
export const tapEdgeDev = () => createTAPEdgeMiddleware({
  allowUnverified: true,
  blockOnFailure: false,
  onVerified: (r) => console.log('[TAP] Verified:', r),
  onFailed: (r) => console.log('[TAP] Failed:', r),
});

// ============ EXPORTS ============

export default {
  createTAPEdgeMiddleware,
  tapEdgeStrict,
  tapEdgeFlexible,
  tapEdgeDev,
  TAP_EDGE_HEADERS,
};
