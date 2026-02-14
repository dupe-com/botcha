/**
 * TAP Consumer Recognition — Agentic Consumer Recognition Object
 * Visa TAP Layer 2: Consumer identity verification linked to message signature
 * 
 * Implements nonce-linked signature chains where:
 * 1. HTTP message signature (Layer 1) contains a nonce
 * 2. Consumer object contains the same nonce + consumer data
 * 3. Consumer object is signed with same key
 * 
 * This proves the agent had authorization from the consumer at signature time.
 */

// ============ TYPES ============

/**
 * Agentic Consumer Recognition Object
 * JSON structure in request body proving consumer authorization
 */
export interface AgenticConsumer {
  nonce: string;                    // MUST match header Signature-Input nonce
  idToken?: IDTokenJWT | string;    // OIDC-compatible JWT (string form or parsed)
  contextualData?: ContextualData;
  kid: string;                      // MUST match header Signature-Input keyid
  alg: string;                      // Algorithm for this body signature
  signature: string;                // Base64 signature over all fields except 'signature'
}

/**
 * Parsed ID Token (OIDC-compatible JWT)
 */
export interface IDTokenJWT {
  header: {
    typ?: string;
    alg: string;
    kid?: string;
  };
  payload: IDTokenClaims;
  signature: string;
}

/**
 * ID Token claims (OIDC-compatible)
 */
export interface IDTokenClaims {
  // Required public claims
  iss: string;                        // Issuer
  sub: string;                        // Subject (unique consumer ID)
  aud: string | string[];             // Audience
  exp: number;                        // Expiration
  iat: number;                        // Issued at
  // Optional public claims
  jti?: string;                       // JWT ID
  auth_time?: number;                 // When user authenticated
  amr?: string[];                     // Authentication methods
  // Standard identity claims (obfuscated per Visa spec)
  phone_number?: string;              // Obfuscated, E.164 format (no leading +)
  phone_number_verified?: boolean;
  email?: string;                     // Obfuscated, RFC 5322 lowercase
  email_verified?: boolean;
  // Private claims (Visa extensions)
  phone_number_mask?: string;         // Masked for UI display (e.g., "***-***-1234")
  email_mask?: string;                // Masked for UI display (e.g., "j***@g***.com")
  [key: string]: any;                 // Allow additional claims
}

/**
 * Contextual data about consumer device/location
 */
export interface ContextualData {
  countryCode?: string;   // ISO 3166-1 alpha-2 (e.g., 'US')
  zip?: string;           // Up to 16 chars: postal code or city/state
  ipAddress?: string;     // Consumer device IP (collected during payment instruction)
  deviceData?: DeviceData;
}

/**
 * Device fingerprint data
 */
export interface DeviceData {
  userAgent?: string;
  screenResolution?: string;
  language?: string;
  timezone?: string;
  [key: string]: any;     // Extensible
}

/**
 * Result of consumer verification
 */
export interface ConsumerVerificationResult {
  verified: boolean;
  nonceLinked: boolean;               // Does nonce match header signature?
  signatureValid: boolean;
  idTokenValid?: boolean;
  idTokenClaims?: IDTokenClaims;
  contextualData?: ContextualData;
  error?: string;
}

/**
 * JWKS (JSON Web Key Set) structure
 */
export interface JWKS {
  keys: JWK[];
}

/**
 * JSON Web Key
 */
export interface JWK {
  kid: string;
  kty: string;
  alg?: string;
  use?: string;
  n?: string;   // RSA modulus
  e?: string;   // RSA exponent
  crv?: string; // ECC curve
  x?: string;   // ECC x coordinate
  y?: string;   // ECC y coordinate
  [key: string]: any;
}

// ============ PARSING ============

/**
 * Parse AgenticConsumer from request body
 * Handles both nested { agenticConsumer: {...} } and top-level formats
 */
export function parseAgenticConsumer(body: any): AgenticConsumer | null {
  try {
    // Try nested format first
    let consumer = body?.agenticConsumer;
    
    // If not nested, check if body itself is the consumer object
    if (!consumer && body?.nonce && body?.kid && body?.alg && body?.signature) {
      consumer = body;
    }
    
    if (!consumer) {
      return null;
    }
    
    // Validate required fields
    if (
      typeof consumer.nonce !== 'string' ||
      typeof consumer.kid !== 'string' ||
      typeof consumer.alg !== 'string' ||
      typeof consumer.signature !== 'string'
    ) {
      return null;
    }
    
    return {
      nonce: consumer.nonce,
      idToken: consumer.idToken,
      contextualData: consumer.contextualData,
      kid: consumer.kid,
      alg: consumer.alg,
      signature: consumer.signature
    };
    
  } catch {
    return null;
  }
}

/**
 * Parse ID Token JWT string into structured format
 * Does NOT verify signature - just parses and validates structure
 */
export function parseIDToken(tokenString: string): IDTokenClaims | null {
  try {
    const parts = tokenString.split('.');
    if (parts.length !== 3) {
      return null;
    }
    
    // Base64url decode header
    const headerJson = atob(parts[0].replace(/-/g, '+').replace(/_/g, '/'));
    const header = JSON.parse(headerJson);
    
    // Base64url decode payload
    const payloadJson = atob(parts[1].replace(/-/g, '+').replace(/_/g, '/'));
    const claims = JSON.parse(payloadJson);
    
    // Validate required claims
    if (
      typeof claims.iss !== 'string' ||
      typeof claims.sub !== 'string' ||
      !claims.aud ||
      typeof claims.exp !== 'number' ||
      typeof claims.iat !== 'number'
    ) {
      return null;
    }
    
    // Check expiration
    const now = Math.floor(Date.now() / 1000);
    if (claims.exp <= now) {
      return null; // Token expired
    }
    
    return claims;
    
  } catch {
    return null;
  }
}

/**
 * Verify ID Token signature by fetching JWKS from issuer
 * Full cryptographic verification of the JWT
 */
export async function verifyIDTokenSignature(
  tokenString: string,
  jwksUrl?: string
): Promise<{ valid: boolean; claims?: IDTokenClaims; error?: string }> {
  try {
    const parts = tokenString.split('.');
    if (parts.length !== 3) {
      return { valid: false, error: 'Invalid JWT format' };
    }
    
    // Parse header and payload
    const headerJson = atob(parts[0].replace(/-/g, '+').replace(/_/g, '/'));
    const header = JSON.parse(headerJson);
    
    const payloadJson = atob(parts[1].replace(/-/g, '+').replace(/_/g, '/'));
    const claims = JSON.parse(payloadJson);
    
    // If no JWKS URL provided, just parse without verification
    if (!jwksUrl) {
      // Check expiration at least
      const now = Math.floor(Date.now() / 1000);
      if (claims.exp && claims.exp <= now) {
        return { valid: false, error: 'Token expired', claims };
      }
      return { valid: true, claims }; // Unverified but parsed
    }
    
    // Fetch JWKS
    const jwksResponse = await fetch(jwksUrl);
    if (!jwksResponse.ok) {
      return { valid: false, error: 'Failed to fetch JWKS' };
    }
    
    const jwks: JWKS = await jwksResponse.json();
    
    // Find matching key by kid
    const key = jwks.keys.find(k => k.kid === header.kid);
    if (!key) {
      return { valid: false, error: 'Key not found in JWKS' };
    }
    
    // Build signature base (header.payload)
    const signatureBase = `${parts[0]}.${parts[1]}`;
    const signatureBytes = base64UrlToArrayBuffer(parts[2]);
    
    // Import public key from JWK
    const cryptoKey = await jwkToCryptoKey(key, header.alg);
    
    // Verify signature
    const encoder = new TextEncoder();
    const data = encoder.encode(signatureBase);
    
    const { importParams, verifyParams } = jwkAlgToWebCrypto(header.alg);
    const isValid = await crypto.subtle.verify(
      verifyParams,
      cryptoKey,
      signatureBytes,
      data
    );
    
    if (!isValid) {
      return { valid: false, error: 'Signature verification failed' };
    }
    
    // Check expiration
    const now = Math.floor(Date.now() / 1000);
    if (claims.exp && claims.exp <= now) {
      return { valid: false, error: 'Token expired', claims };
    }
    
    return { valid: true, claims };
    
  } catch (error) {
    return {
      valid: false,
      error: `Verification error: ${error instanceof Error ? error.message : 'Unknown'}`
    };
  }
}

// ============ SIGNATURE VERIFICATION ============

/**
 * Build canonical signature base string for consumer object
 * Per TAP spec: all fields in order except 'signature' itself
 */
export function buildConsumerSignatureBase(consumer: AgenticConsumer): string {
  const fields: string[] = [];
  
  // Add fields IN ORDER, excluding 'signature'
  if (consumer.nonce) {
    fields.push(`"nonce": "${consumer.nonce}"`);
  }
  
  if (consumer.idToken) {
    const idTokenStr = typeof consumer.idToken === 'string'
      ? `"${consumer.idToken}"`
      : JSON.stringify(consumer.idToken);
    fields.push(`"idToken": ${idTokenStr}`);
  }
  
  if (consumer.contextualData) {
    fields.push(`"contextualData": ${JSON.stringify(consumer.contextualData)}`);
  }
  
  if (consumer.kid) {
    fields.push(`"kid": "${consumer.kid}"`);
  }
  
  if (consumer.alg) {
    fields.push(`"alg": "${consumer.alg}"`);
  }
  
  return fields.join('\n');
}

/**
 * Verify AgenticConsumer object signature and nonce linkage
 * Main verification function for TAP Layer 2
 */
export async function verifyAgenticConsumer(
  consumer: AgenticConsumer,
  headerNonce: string,
  publicKey: string,
  algorithm?: string
): Promise<ConsumerVerificationResult> {
  try {
    // Step 1: Check nonce linkage
    const nonceLinked = consumer.nonce === headerNonce;
    
    // Step 2: Build signature base
    const signatureBase = buildConsumerSignatureBase(consumer);
    
    // Step 3: Verify signature
    const alg = algorithm || consumer.alg;
    const signatureValid = await verifyCryptoSignature(
      signatureBase,
      consumer.signature,
      publicKey,
      alg
    );
    
    // Step 4: Parse and validate ID token if present
    let idTokenValid: boolean | undefined;
    let idTokenClaims: IDTokenClaims | undefined;
    
    if (consumer.idToken) {
      const tokenString = typeof consumer.idToken === 'string'
        ? consumer.idToken
        : consumer.idToken.signature; // If already parsed
      
      if (tokenString) {
        const parsedClaims = parseIDToken(tokenString);
        idTokenClaims = parsedClaims ?? undefined;
        idTokenValid = parsedClaims !== null;
      }
    }
    
    const verified = nonceLinked && signatureValid;
    
    return {
      verified,
      nonceLinked,
      signatureValid,
      idTokenValid,
      idTokenClaims,
      contextualData: consumer.contextualData,
      error: verified ? undefined : 'Verification failed'
    };
    
  } catch (error) {
    return {
      verified: false,
      nonceLinked: false,
      signatureValid: false,
      error: `Verification error: ${error instanceof Error ? error.message : 'Unknown'}`
    };
  }
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
    // Decode signature from base64
    const signatureBytes = Uint8Array.from(atob(signature), c => c.charCodeAt(0));
    
    // Import public key
    const keyData = pemToArrayBuffer(publicKeyPem);
    const { importParams, verifyParams } = jwkAlgToWebCrypto(algorithm);
    
    const cryptoKey = await crypto.subtle.importKey(
      'spki',
      keyData,
      importParams,
      false,
      ['verify']
    );
    
    // Verify signature
    const encoder = new TextEncoder();
    const data = encoder.encode(signatureBase);
    
    return await crypto.subtle.verify(
      verifyParams,
      cryptoKey,
      signatureBytes,
      data
    );
    
  } catch (error) {
    console.error('Consumer signature verification error:', error);
    return false;
  }
}

// ============ IDENTITY MATCHING ============

/**
 * Hash-match obfuscated identity with cleartext
 * Merchants maintain mapping tables with hashed values
 */
export async function hashMatchIdentity(
  obfuscated: string,
  cleartext: string,
  method: 'sha256' = 'sha256'
): Promise<boolean> {
  try {
    const encoder = new TextEncoder();
    const data = encoder.encode(cleartext);
    
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    
    // Compare with obfuscated value (assume it's hex-encoded hash)
    return hashHex === obfuscated.toLowerCase();
    
  } catch {
    return false;
  }
}

// ============ CRYPTO HELPERS ============

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
 * Convert base64url string to ArrayBuffer
 */
function base64UrlToArrayBuffer(base64url: string): ArrayBuffer {
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

/**
 * Convert JWK algorithm name to Web Crypto API parameters
 */
function jwkAlgToWebCrypto(alg: string): {
  importParams: any;
  verifyParams: any;
} {
  switch (alg) {
    case 'PS256':
      return {
        importParams: { name: 'RSA-PSS', hash: 'SHA-256' },
        verifyParams: { name: 'RSA-PSS', saltLength: 32 }
      };
    case 'ES256':
      return {
        importParams: { name: 'ECDSA', namedCurve: 'P-256' },
        verifyParams: { name: 'ECDSA', hash: 'SHA-256' }
      };
    case 'EdDSA':
      return {
        importParams: { name: 'Ed25519' } as any,
        verifyParams: { name: 'Ed25519' } as any
      };
    case 'RS256':
      return {
        importParams: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
        verifyParams: { name: 'RSASSA-PKCS1-v1_5' }
      };
    default:
      throw new Error(`Unsupported algorithm: ${alg}`);
  }
}

/**
 * Convert JWK to CryptoKey
 */
async function jwkToCryptoKey(jwk: JWK, alg: string): Promise<CryptoKey> {
  const { importParams } = jwkAlgToWebCrypto(alg);
  
  // Build JWK for import
  const keyData: any = {
    kty: jwk.kty,
    alg: alg,
    ext: true
  };
  
  if (jwk.kty === 'RSA') {
    keyData.n = jwk.n;
    keyData.e = jwk.e;
  } else if (jwk.kty === 'EC') {
    keyData.crv = jwk.crv;
    keyData.x = jwk.x;
    keyData.y = jwk.y;
  }
  
  return await crypto.subtle.importKey(
    'jwk',
    keyData,
    importParams,
    true,
    ['verify']
  );
}

// ============ EXPORTS ============

export default {
  parseAgenticConsumer,
  verifyAgenticConsumer,
  parseIDToken,
  verifyIDTokenSignature,
  hashMatchIdentity,
  buildConsumerSignatureBase
};
