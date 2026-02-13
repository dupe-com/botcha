/**
 * TAP Cryptographic Verification
 * HTTP Message Signatures (RFC 9421) implementation for Trusted Agent Protocol
 * 
 * Integrates with existing BOTCHA verification middleware to provide
 * enterprise-grade cryptographic agent authentication
 */

import { TAP_VALID_ACTIONS } from './tap-agents.js';

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

// ============ HTTP MESSAGE SIGNATURES (RFC 9421) ============

/**
 * Verify HTTP Message Signature according to RFC 9421
 */
export async function verifyHTTPMessageSignature(
  request: TAPVerificationRequest,
  publicKey: string,
  algorithm: string
): Promise<{ valid: boolean; error?: string }> {
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
    
    // Check timestamp (prevent replay attacks)
    if (parsed.created) {
      const now = Math.floor(Date.now() / 1000);
      const maxAge = 300; // 5 minutes
      if (Math.abs(now - parsed.created) > maxAge) {
        return { valid: false, error: 'Signature timestamp too old or too new' };
      }
    }
    
    // Build signature base
    const signatureBase = buildSignatureBase(
      request.method,
      request.path,
      headers,
      parsed.components,
      parsed.created,
      parsed.keyId,
      parsed.algorithm
    );
    
    // Verify signature
    const isValid = await verifyCryptoSignature(
      signatureBase,
      signature,
      publicKey,
      algorithm
    );
    
    return { valid: isValid, error: isValid ? undefined : 'Signature verification failed' };
    
  } catch (error) {
    return { valid: false, error: `Verification error: ${error instanceof Error ? error.message : 'Unknown error'}` };
  }
}

/**
 * Parse signature-input header according to RFC 9421
 */
function parseSignatureInput(input: string): {
  keyId: string;
  algorithm: string;
  created: number;
  components: string[];
} | null {
  try {
    // Parse: sig1=("@method" "@path" "x-tap-agent-id");keyid="agent-123";alg="ecdsa-p256-sha256";created=1234567890
    const sigMatch = input.match(/sig1=\(([^)]+)\)/);
    if (!sigMatch) return null;
    
    const components = sigMatch[1]
      .split(' ')
      .map(h => h.replace(/"/g, ''));
    
    const keyIdMatch = input.match(/keyid="([^"]+)"/);
    const algMatch = input.match(/alg="([^"]+)"/);
    const createdMatch = input.match(/created=(\d+)/);
    
    if (!keyIdMatch || !algMatch || !createdMatch) return null;
    
    return {
      keyId: keyIdMatch[1],
      algorithm: algMatch[1],
      created: parseInt(createdMatch[1]),
      components
    };
  } catch {
    return null;
  }
}

/**
 * Build signature base string according to RFC 9421
 */
function buildSignatureBase(
  method: string,
  path: string,
  headers: Record<string, string>,
  components: string[],
  created: number,
  keyId: string,
  algorithm: string
): string {
  const lines: string[] = [];
  
  for (const component of components) {
    if (component === '@method') {
      lines.push(`"@method": ${method.toUpperCase()}`);
    } else if (component === '@path') {
      lines.push(`"@path": ${path}`);
    } else if (component === '@authority') {
      lines.push(`"@authority": ${headers['host'] || ''}`);
    } else {
      const value = headers[component];
      if (value !== undefined) {
        lines.push(`"${component}": ${value}`);
      }
    }
  }
  
  // Add signature parameters
  const componentsList = components.map(c => `"${c}"`).join(' ');
  lines.push(`"@signature-params": (${componentsList});keyid="${keyId}";alg="${algorithm}";created=${created}`);
  
  return lines.join('\n');
}

/**
 * Verify cryptographic signature using Web Crypto API
 */
async function verifyCryptoSignature(
  signatureBase: string,
  signature: string,
  publicKeyPem: string,
  algorithm: string
): Promise<boolean> {
  try {
    // Extract signature bytes
    const sigMatch = signature.match(/sig1=:([^:]+):/);
    if (!sigMatch) return false;
    
    const signatureBytes = Uint8Array.from(atob(sigMatch[1]), c => c.charCodeAt(0));
    
    // Import public key
    const keyData = pemToArrayBuffer(publicKeyPem);
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
  switch (algorithm) {
    case 'ecdsa-p256-sha256':
      return { name: 'ECDSA', hash: 'SHA-256' };
    case 'rsa-pss-sha256':
      return { name: 'RSA-PSS', saltLength: 32 };
    default:
      throw new Error(`Unsupported algorithm: ${algorithm}`);
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
 */
export function extractTAPHeaders(headers: Record<string, string>): {
  hasTAPHeaders: boolean;
  tapHeaders: TAPHeaders;
} {
  const tapHeaders: TAPHeaders = {
    'x-tap-agent-id': headers['x-tap-agent-id'],
    'x-tap-user-context': headers['x-tap-user-context'],
    'x-tap-intent': headers['x-tap-intent'],
    'x-tap-timestamp': headers['x-tap-timestamp'],
    'signature': headers['signature'],
    'signature-input': headers['signature-input']
  };
  
  const hasTAPHeaders = Boolean(
    tapHeaders['x-tap-agent-id'] &&
    tapHeaders['x-tap-intent'] &&
    tapHeaders['signature'] &&
    tapHeaders['signature-input']
  );
  
  return { hasTAPHeaders, tapHeaders };
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
    supported_algorithms: ['ecdsa-p256-sha256', 'rsa-pss-sha256']
  };
  
  return response;
}

export default {
  verifyHTTPMessageSignature,
  parseTAPIntent,
  extractTAPHeaders,
  getVerificationMode,
  buildTAPChallengeResponse
};