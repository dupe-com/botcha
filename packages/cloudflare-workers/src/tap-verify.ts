/**
 * TAP Cryptographic Verification
 * HTTP Message Signatures (RFC 9421) implementation for Trusted Agent Protocol
 * 
 * Integrates with existing BOTCHA verification middleware to provide
 * enterprise-grade cryptographic agent authentication
 * 
 * FEATURES:
 * - Ed25519, ECDSA P-256, RSA-PSS signature verification
 * - Full RFC 9421 compliance (sig1/sig2 labels, expires, nonce, tag)
 * - Nonce replay protection via KV
 * - TAP timestamp validation (created, expires, 8-minute max window)
 * - Backward compatible with existing BOTCHA agents
 */

import { TAP_VALID_ACTIONS } from './tap-agents.js';
import type { KVNamespace } from './agents.js';

// ============ TYPES ============

export interface TAPVerificationRequest {
  method: string;
  path: string;
  headers: Record<string, string>;
  body?: string;
}

export interface TAPVerificationResult {
  verified: boolean;
  agent_id?: string;
  verification_method: 'tap' | 'challenge' | 'signature-only';
  challenges_passed: {
    computational: boolean;
    cryptographic: boolean;
  };
  session_id?: string;
  error?: string;
  metadata?: {
    solve_time_ms?: number;
    signature_valid?: boolean;
    intent_valid?: boolean;
    capabilities?: string[];
    tag?: string;              // agent-browser-auth | agent-payer-auth
    nonce?: string;            // for linking to body objects
    key_id?: string;           // which key was used
    algorithm?: string;        // which algorithm was used
  };
}

export interface TAPHeaders {
  'x-tap-agent-id'?: string;
  'x-tap-user-context'?: string;
  'x-tap-intent'?: string;
  'x-tap-timestamp'?: string;
  'signature'?: string;
  'signature-input'?: string;
}

export interface ParsedSignatureInput {
  label: string;          // 'sig1' or 'sig2'
  components: string[];   // ['@authority', '@path']
  created: number;
  expires?: number;
  keyId: string;
  algorithm: string;
  nonce?: string;
  tag?: string;           // 'agent-browser-auth' | 'agent-payer-auth'
}

// ============ HTTP MESSAGE SIGNATURES (RFC 9421) ============

/**
 * Verify HTTP Message Signature according to RFC 9421
 */
export async function verifyHTTPMessageSignature(
  request: TAPVerificationRequest,
  publicKey: string,
  algorithm: string,
  nonces?: KVNamespace | null
): Promise<{ valid: boolean; error?: string; metadata?: { nonce?: string; tag?: string; key_id?: string } }> {
  try {
    const { headers } = request;
    const signature = headers['signature'];
    const signatureInput = headers['signature-input'];
    
    if (!signature || !signatureInput) {
      return { valid: false, error: 'Missing signature headers' };
    }
    
    // Parse signature input
    const parsed = parseSignatureInput(signatureInput);
    if (!parsed) {
      return { valid: false, error: 'Invalid signature-input format' };
    }
    
    // Validate timestamps
    const timestampValidation = validateTimestamps(parsed.created, parsed.expires);
    if (!timestampValidation.valid) {
      return { valid: false, error: timestampValidation.error };
    }
    
    // Check nonce replay (if nonce provided and KV available)
    if (parsed.nonce && nonces) {
      const nonceCheck = await checkAndStoreNonce(nonces, parsed.nonce);
      if (nonceCheck.replay) {
        return { valid: false, error: 'Nonce replay detected' };
      }
    }
    
    // Build signature base
    const signatureBase = buildSignatureBase(
      request.method,
      request.path,
      headers,
      parsed
    );
    
    // Verify signature
    const isValid = await verifyCryptoSignature(
      signatureBase,
      signature,
      publicKey,
      algorithm,
      parsed.label
    );
    
    return {
      valid: isValid,
      error: isValid ? undefined : 'Signature verification failed',
      metadata: {
        nonce: parsed.nonce,
        tag: parsed.tag,
        key_id: parsed.keyId
      }
    };
    
  } catch (error) {
    return { valid: false, error: `Verification error: ${error instanceof Error ? error.message : 'Unknown error'}` };
  }
}

/**
 * Parse signature-input header according to RFC 9421
 * Supports BOTH sig1 (BOTCHA) and sig2 (Visa TAP) labels
 */
function parseSignatureInput(input: string): ParsedSignatureInput | null {
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
 * Validate created/expires timestamps according to TAP spec
 */
function validateTimestamps(created: number, expires?: number): { valid: boolean; error?: string } {
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
      return { valid: false, error: 'Signature timestamp too old or too new' };
    }
    if (age < -clockSkew) {
      return { valid: false, error: 'Signature timestamp too old or too new' };
    }
  }
  
  return { valid: true };
}

/**
 * Build signature base string according to RFC 9421 TAP format
 * 
 * Format:
 * "@authority": example.com
 * "@path": /example-product
 * "@signature-params": sig2=("@authority" "@path");created=1735689600;keyid="poqk...";alg="Ed25519";expires=1735693200;nonce="e8N7...";tag="agent-browser-auth"
 */
function buildSignatureBase(
  method: string,
  path: string,
  headers: Record<string, string>,
  parsed: ParsedSignatureInput
): string {
  const lines: string[] = [];
  
  // Add component lines (values are bare, no quotes)
  for (const component of parsed.components) {
    if (component === '@method') {
      lines.push(`"@method": ${method.toUpperCase()}`);
    } else if (component === '@path') {
      lines.push(`"@path": ${path}`);
    } else if (component === '@authority') {
      const authority = headers['host'] || headers[':authority'] || '';
      lines.push(`"@authority": ${authority}`);
    } else {
      const value = headers[component];
      if (value !== undefined) {
        lines.push(`"${component}": ${value}`);
      }
    }
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
    
    // Import public key (handles both PEM and raw Ed25519)
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
 * SPKI format: ASN.1 header + 32-byte public key
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

/** Algorithm params for key import (compatible with Web Crypto & CF Workers) */
interface CryptoImportParams {
  name: string;
  hash?: string;
  namedCurve?: string;
}

/** Algorithm params for signature verify (compatible with Web Crypto & CF Workers) */
interface CryptoVerifyParams {
  name: string;
  hash?: string;
  saltLength?: number;
}

/**
 * Get Web Crypto API algorithm parameters for key import
 */
function getImportParams(algorithm: string): CryptoImportParams {
  const alg = algorithm.toLowerCase();
  
  if (alg.includes('ed25519')) {
    return { name: 'Ed25519' };  // No hash or curve needed
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
function getVerifyParams(algorithm: string): CryptoVerifyParams {
  const alg = algorithm.toLowerCase();
  
  if (alg.includes('ed25519')) {
    return { name: 'Ed25519' };  // No hash needed
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

// ============ NONCE REPLAY PROTECTION ============

/**
 * Check if nonce was already used and store it if new
 * Returns { replay: true } if nonce was seen before
 */
export async function checkAndStoreNonce(
  nonces: KVNamespace | null,
  nonce: string
): Promise<{ replay: boolean }> {
  if (!nonces || !nonce) return { replay: false };
  
  try {
    // Hash nonce for fixed-length KV key
    const encoder = new TextEncoder();
    const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(nonce));
    const hashHex = Array.from(new Uint8Array(hashBuffer))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
    const key = `nonce:${hashHex}`;
    
    // Check if already seen
    const existing = await nonces.get(key);
    if (existing) return { replay: true };
    
    // Store with 8-minute TTL (480 seconds per TAP spec)
    await nonces.put(key, '1', { expirationTtl: 480 });
    return { replay: false };
  } catch (error) {
    console.error('Nonce check error:', error);
    // Fail-open on KV errors (don't block legitimate requests)
    return { replay: false };
  }
}

// ============ TAP INTENT VALIDATION ============

/**
 * Parse and validate TAP intent from headers
 */
export function parseTAPIntent(intentString: string): {
  valid: boolean;
  intent?: {
    action: string;
    resource?: string;
    scope?: string[];
    duration?: number;
  };
  error?: string;
} {
  try {
    const intent = JSON.parse(intentString);
    
    if (!intent.action || typeof intent.action !== 'string') {
      return { valid: false, error: 'Intent must specify action' };
    }
    
    if (!(TAP_VALID_ACTIONS as readonly string[]).includes(intent.action)) {
      return { valid: false, error: `Invalid action: ${intent.action}` };
    }
    
    return {
      valid: true,
      intent: {
        action: intent.action,
        resource: intent.resource,
        scope: Array.isArray(intent.scope) ? intent.scope : undefined,
        duration: typeof intent.duration === 'number' ? intent.duration : undefined
      }
    };
    
  } catch {
    return { valid: false, error: 'Invalid JSON in intent' };
  }
}

// ============ TAP HEADER EXTRACTION ============

/**
 * Extract TAP-specific headers from request
 * Supports BOTH standard TAP (sig2 + tag) and BOTCHA extended (x-tap-* headers)
 */
export function extractTAPHeaders(headers: Record<string, string>): {
  hasTAPHeaders: boolean;
  tapHeaders: TAPHeaders;
  isTAPStandard?: boolean;  // true if using sig2 + tag pattern
} {
  const tapHeaders: TAPHeaders = {
    'x-tap-agent-id': headers['x-tap-agent-id'],
    'x-tap-user-context': headers['x-tap-user-context'],
    'x-tap-intent': headers['x-tap-intent'],
    'x-tap-timestamp': headers['x-tap-timestamp'],
    'signature': headers['signature'],
    'signature-input': headers['signature-input']
  };
  
  // Check for standard TAP (sig2 + agent tag)
  const signatureInput = headers['signature-input'] || '';
  const hasAgentTag = /tag="agent-(browser|payer)-auth"/.test(signatureInput);
  const hasSig2 = /sig2=\(/.test(signatureInput);
  const isTAPStandard = hasAgentTag && hasSig2;
  
  // BOTCHA extended: requires x-tap-agent-id + x-tap-intent + signature
  const hasBOTCHAExtended = Boolean(
    tapHeaders['x-tap-agent-id'] &&
    tapHeaders['x-tap-intent'] &&
    tapHeaders['signature'] &&
    tapHeaders['signature-input']
  );
  
  const hasTAPHeaders = isTAPStandard || hasBOTCHAExtended;
  
  return { hasTAPHeaders, tapHeaders, isTAPStandard };
}

// ============ VERIFICATION MODES ============

/**
 * Determine appropriate verification mode based on headers
 */
export function getVerificationMode(headers: Record<string, string>): {
  mode: 'tap' | 'signature-only' | 'challenge-only';
  hasTAPHeaders: boolean;
  hasChallenge: boolean;
} {
  const { hasTAPHeaders } = extractTAPHeaders(headers);
  const hasChallenge = Boolean(
    headers['x-botcha-challenge-id'] && 
    (headers['x-botcha-answers'] || headers['x-botcha-solution'])
  );
  
  let mode: 'tap' | 'signature-only' | 'challenge-only';
  
  if (hasTAPHeaders && hasChallenge) {
    mode = 'tap'; // Full dual authentication
  } else if (hasTAPHeaders) {
    mode = 'signature-only'; // Crypto only
  } else {
    mode = 'challenge-only'; // Computational only
  }
  
  return { mode, hasTAPHeaders, hasChallenge };
}

// ============ TAG MAPPING ============

/**
 * Map TAP action to appropriate tag
 */
export function actionToTag(action: string): 'agent-browser-auth' | 'agent-payer-auth' {
  const payerActions = ['purchase'];
  return payerActions.includes(action) ? 'agent-payer-auth' : 'agent-browser-auth';
}

// ============ CHALLENGE RESPONSE BUILDERS ============

/**
 * Build appropriate challenge response for TAP verification failure
 */
export function buildTAPChallengeResponse(
  verificationResult: TAPVerificationResult,
  challengeData?: any
) {
  const response: any = {
    success: false,
    error: 'TAP_VERIFICATION_FAILED',
    code: 'TAP_CHALLENGE',
    message: '🔐 Enterprise agent authentication required',
    verification_method: verificationResult.verification_method,
    challenges_passed: verificationResult.challenges_passed,
    details: verificationResult.error
  };
  
  // Add computational challenge if needed
  if (!verificationResult.challenges_passed.computational && challengeData) {
    response.challenge = {
      id: challengeData.id,
      type: challengeData.type || 'speed',
      problems: challengeData.problems || challengeData.challenges,
      timeLimit: `${challengeData.timeLimit}ms`,
      instructions: challengeData.instructions || 'Solve computational challenge'
    };
  }
  
  // Add TAP requirements
  response.tap_requirements = {
    cryptographic_signature: !verificationResult.challenges_passed.cryptographic,
    computational_challenge: !verificationResult.challenges_passed.computational,
    required_headers: [
      'x-tap-agent-id',
      'x-tap-user-context',
      'x-tap-intent', 
      'x-tap-timestamp',
      'signature',
      'signature-input'
    ],
    supported_algorithms: ['ed25519', 'Ed25519', 'ecdsa-p256-sha256', 'rsa-pss-sha256'],
    jwks_url: 'https://botcha.ai/.well-known/jwks'
  };
  
  return response;
}

export default {
  verifyHTTPMessageSignature,
  parseTAPIntent,
  extractTAPHeaders,
  getVerificationMode,
  buildTAPChallengeResponse,
  checkAndStoreNonce,
  actionToTag
};
