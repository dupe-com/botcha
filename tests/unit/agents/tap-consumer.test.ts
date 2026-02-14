/**
 * Tests for TAP Consumer Recognition (Layer 2)
 * Validates nonce-linked signature chains and consumer identity verification
 */

import { describe, it, expect, beforeAll } from 'vitest';
import {
  parseAgenticConsumer,
  verifyAgenticConsumer,
  parseIDToken,
  verifyIDTokenSignature,
  hashMatchIdentity,
  buildConsumerSignatureBase,
  type AgenticConsumer,
  type IDTokenClaims
} from '../../../packages/cloudflare-workers/src/tap-consumer.js';

// ============ TEST HELPERS ============

/**
 * Create a test JWT with specified claims (unsigned)
 */
function createTestJWT(claims: Record<string, any>, header?: Record<string, any>): string {
  const h = {
    alg: 'none',
    typ: 'JWT',
    ...header
  };
  
  // Base64url encode (proper implementation)
  const base64UrlEncode = (obj: any): string => {
    const json = JSON.stringify(obj);
    const base64 = btoa(json);
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  };
  
  const headerB64 = base64UrlEncode(h);
  const payloadB64 = base64UrlEncode(claims);
  
  return `${headerB64}.${payloadB64}.test-signature`;
}

/**
 * Generate ECDSA P-256 key pair for testing
 */
async function generateECDSAKeyPair() {
  return await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  );
}

/**
 * Sign data with private key
 */
async function signData(data: string, privateKey: CryptoKey): Promise<string> {
  const encoder = new TextEncoder();
  const dataBytes = encoder.encode(data);
  
  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    privateKey,
    dataBytes
  );
  
  // Convert to base64
  const signatureArray = Array.from(new Uint8Array(signature));
  return btoa(String.fromCharCode(...signatureArray));
}

/**
 * Export public key to PEM format
 */
async function exportPublicKeyToPEM(publicKey: CryptoKey): Promise<string> {
  const exported = await crypto.subtle.exportKey('spki', publicKey);
  const exportedArray = Array.from(new Uint8Array(exported));
  const base64 = btoa(String.fromCharCode(...exportedArray));
  
  // Format as PEM
  const lines = base64.match(/.{1,64}/g) || [];
  return `-----BEGIN PUBLIC KEY-----\n${lines.join('\n')}\n-----END PUBLIC KEY-----`;
}

// ============ TEST DATA ============

const validConsumerData = {
  nonce: 'e8N7S2MFd/qrd6T2R3tdfAuuANngKI7LFtKYI/vowzk4lAZyadIX6wW25MwG7DCT9RUKAJ0qVkU0mEeLElW1qg==',
  kid: 'poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U',
  alg: 'ES256',
  contextualData: {
    countryCode: 'US',
    zip: '94102',
    ipAddress: '192.168.1.1',
    deviceData: {
      userAgent: 'Mozilla/5.0',
      language: 'en-US',
      timezone: 'America/Los_Angeles'
    }
  }
};

const validIDTokenClaims: IDTokenClaims = {
  iss: 'https://auth.example.com',
  sub: 'user-12345',
  aud: 'merchant-app',
  exp: Math.floor(Date.now() / 1000) + 3600, // Valid for 1 hour
  iat: Math.floor(Date.now() / 1000),
  jti: 'jwt-id-12345',
  email: '5f3c4a2e1b8d7a6c9e0f1a2b3c4d5e6f',
  email_verified: true,
  email_mask: 'j***@g***.com',
  phone_number: '15551234567',
  phone_number_verified: true,
  phone_number_mask: '***-***-4567'
};

// ============ TESTS ============

describe('TAP Consumer Recognition - Parsing', () => {
  it('should parse consumer object from nested format', () => {
    const body = {
      agenticConsumer: {
        ...validConsumerData,
        signature: 'test-signature'
      }
    };
    
    const result = parseAgenticConsumer(body);
    
    expect(result).not.toBeNull();
    expect(result?.nonce).toBe(validConsumerData.nonce);
    expect(result?.kid).toBe(validConsumerData.kid);
    expect(result?.alg).toBe(validConsumerData.alg);
    expect(result?.signature).toBe('test-signature');
  });
  
  it('should parse consumer object from top-level format', () => {
    const body = {
      ...validConsumerData,
      signature: 'test-signature'
    };
    
    const result = parseAgenticConsumer(body);
    
    expect(result).not.toBeNull();
    expect(result?.nonce).toBe(validConsumerData.nonce);
    expect(result?.kid).toBe(validConsumerData.kid);
  });
  
  it('should return null for missing required fields', () => {
    const missingNonce = {
      agenticConsumer: {
        kid: 'test-kid',
        alg: 'ES256',
        signature: 'test-sig'
        // nonce is missing
      }
    };
    
    expect(parseAgenticConsumer(missingNonce)).toBeNull();
    
    const missingKid = {
      agenticConsumer: {
        nonce: 'test-nonce',
        alg: 'ES256',
        signature: 'test-sig'
        // kid is missing
      }
    };
    
    expect(parseAgenticConsumer(missingKid)).toBeNull();
  });
  
  it('should return null for invalid body structure', () => {
    expect(parseAgenticConsumer(null)).toBeNull();
    expect(parseAgenticConsumer(undefined)).toBeNull();
    expect(parseAgenticConsumer({})).toBeNull();
    expect(parseAgenticConsumer({ unrelated: 'data' })).toBeNull();
  });
  
  it('should preserve contextualData and idToken', () => {
    const idToken = createTestJWT(validIDTokenClaims);
    
    const body = {
      agenticConsumer: {
        ...validConsumerData,
        idToken,
        signature: 'test-signature'
      }
    };
    
    const result = parseAgenticConsumer(body);
    
    expect(result).not.toBeNull();
    expect(result?.idToken).toBe(idToken);
    expect(result?.contextualData).toEqual(validConsumerData.contextualData);
  });
});

describe('TAP Consumer Recognition - Signature Base', () => {
  it('should build correct canonical signature base', () => {
    const consumer: AgenticConsumer = {
      nonce: 'test-nonce',
      kid: 'test-kid',
      alg: 'ES256',
      signature: 'should-be-excluded',
      contextualData: {
        countryCode: 'US',
        zip: '94102'
      }
    };
    
    const base = buildConsumerSignatureBase(consumer);
    
    // Verify format
    const lines = base.split('\n');
    expect(lines.length).toBe(4); // nonce, contextualData, kid, alg (signature excluded)
    
    expect(lines[0]).toContain('"nonce": "test-nonce"');
    expect(lines[1]).toContain('"contextualData":');
    expect(lines[2]).toContain('"kid": "test-kid"');
    expect(lines[3]).toContain('"alg": "ES256"');
    
    // Signature should NOT be in base
    expect(base).not.toContain('should-be-excluded');
  });
  
  it('should handle consumer with idToken string', () => {
    const idToken = createTestJWT(validIDTokenClaims);
    
    const consumer: AgenticConsumer = {
      nonce: 'test-nonce',
      idToken,
      kid: 'test-kid',
      alg: 'ES256',
      signature: 'test-sig'
    };
    
    const base = buildConsumerSignatureBase(consumer);
    
    expect(base).toContain('"idToken":');
    expect(base).toContain(idToken);
  });
  
  it('should handle optional fields gracefully', () => {
    const minimalConsumer: AgenticConsumer = {
      nonce: 'test-nonce',
      kid: 'test-kid',
      alg: 'ES256',
      signature: 'test-sig'
    };
    
    const base = buildConsumerSignatureBase(minimalConsumer);
    
    const lines = base.split('\n');
    expect(lines.length).toBe(3); // Only nonce, kid, alg
    expect(base).not.toContain('idToken');
    expect(base).not.toContain('contextualData');
  });
});

describe('TAP Consumer Recognition - Nonce Linkage', () => {
  let keyPair: CryptoKeyPair;
  let publicKeyPEM: string;
  
  beforeAll(async () => {
    keyPair = await generateECDSAKeyPair();
    publicKeyPEM = await exportPublicKeyToPEM(keyPair.publicKey);
  });
  
  it('should verify nonce linkage when nonces match', async () => {
    const headerNonce = 'matching-nonce-12345';
    
    const consumer: AgenticConsumer = {
      nonce: headerNonce,
      kid: 'test-kid',
      alg: 'ES256',
      signature: 'test-sig'
    };
    
    // Sign the consumer data
    const signatureBase = buildConsumerSignatureBase(consumer);
    const signature = await signData(signatureBase, keyPair.privateKey);
    consumer.signature = signature;
    
    const result = await verifyAgenticConsumer(
      consumer,
      headerNonce,
      publicKeyPEM,
      'ES256'
    );
    
    expect(result.nonceLinked).toBe(true);
  });
  
  it('should fail nonce linkage when nonces do not match', async () => {
    const headerNonce = 'header-nonce-12345';
    const bodyNonce = 'different-nonce-67890';
    
    const consumer: AgenticConsumer = {
      nonce: bodyNonce,
      kid: 'test-kid',
      alg: 'ES256',
      signature: 'test-sig'
    };
    
    const signatureBase = buildConsumerSignatureBase(consumer);
    const signature = await signData(signatureBase, keyPair.privateKey);
    consumer.signature = signature;
    
    const result = await verifyAgenticConsumer(
      consumer,
      headerNonce,
      publicKeyPEM,
      'ES256'
    );
    
    expect(result.nonceLinked).toBe(false);
    expect(result.verified).toBe(false);
  });
});

describe('TAP Consumer Recognition - Signature Verification', () => {
  let keyPair: CryptoKeyPair;
  let publicKeyPEM: string;
  
  beforeAll(async () => {
    keyPair = await generateECDSAKeyPair();
    publicKeyPEM = await exportPublicKeyToPEM(keyPair.publicKey);
  });
  
  it('should verify valid ECDSA P-256 signature', async () => {
    const consumer: AgenticConsumer = {
      nonce: 'test-nonce',
      kid: 'test-kid',
      alg: 'ES256',
      signature: 'placeholder',
      contextualData: {
        countryCode: 'US',
        zip: '94102'
      }
    };
    
    // Sign the data
    const signatureBase = buildConsumerSignatureBase(consumer);
    const signature = await signData(signatureBase, keyPair.privateKey);
    consumer.signature = signature;
    
    const result = await verifyAgenticConsumer(
      consumer,
      'test-nonce',
      publicKeyPEM,
      'ES256'
    );
    
    expect(result.signatureValid).toBe(true);
    expect(result.nonceLinked).toBe(true);
    expect(result.verified).toBe(true);
    expect(result.contextualData).toEqual(consumer.contextualData);
  });
  
  it('should reject tampered data', async () => {
    const consumer: AgenticConsumer = {
      nonce: 'test-nonce',
      kid: 'test-kid',
      alg: 'ES256',
      signature: 'placeholder',
      contextualData: {
        countryCode: 'US'
      }
    };
    
    // Sign original data
    const signatureBase = buildConsumerSignatureBase(consumer);
    const signature = await signData(signatureBase, keyPair.privateKey);
    consumer.signature = signature;
    
    // Tamper with data AFTER signing
    consumer.contextualData = {
      countryCode: 'CA' // Changed!
    };
    
    const result = await verifyAgenticConsumer(
      consumer,
      'test-nonce',
      publicKeyPEM,
      'ES256'
    );
    
    expect(result.signatureValid).toBe(false);
    expect(result.verified).toBe(false);
  });
  
  it('should reject signature with wrong public key', async () => {
    const consumer: AgenticConsumer = {
      nonce: 'test-nonce',
      kid: 'test-kid',
      alg: 'ES256',
      signature: 'placeholder'
    };
    
    // Sign with one key
    const signatureBase = buildConsumerSignatureBase(consumer);
    const signature = await signData(signatureBase, keyPair.privateKey);
    consumer.signature = signature;
    
    // Verify with different key
    const otherKeyPair = await generateECDSAKeyPair();
    const otherPublicKeyPEM = await exportPublicKeyToPEM(otherKeyPair.publicKey);
    
    const result = await verifyAgenticConsumer(
      consumer,
      'test-nonce',
      otherPublicKeyPEM,
      'ES256'
    );
    
    expect(result.signatureValid).toBe(false);
    expect(result.verified).toBe(false);
  });
});

describe('TAP Consumer Recognition - ID Token Parsing', () => {
  it('should parse valid ID token', () => {
    const jwt = createTestJWT(validIDTokenClaims);
    
    const claims = parseIDToken(jwt);
    
    expect(claims).not.toBeNull();
    expect(claims?.iss).toBe(validIDTokenClaims.iss);
    expect(claims?.sub).toBe(validIDTokenClaims.sub);
    expect(claims?.aud).toBe(validIDTokenClaims.aud);
    expect(claims?.email).toBe(validIDTokenClaims.email);
    expect(claims?.email_mask).toBe(validIDTokenClaims.email_mask);
    expect(claims?.phone_number).toBe(validIDTokenClaims.phone_number);
    expect(claims?.phone_number_mask).toBe(validIDTokenClaims.phone_number_mask);
  });
  
  it('should reject expired token', () => {
    const expiredClaims = {
      ...validIDTokenClaims,
      exp: Math.floor(Date.now() / 1000) - 3600 // Expired 1 hour ago
    };
    
    const jwt = createTestJWT(expiredClaims);
    
    const claims = parseIDToken(jwt);
    
    expect(claims).toBeNull();
  });
  
  it('should reject token with missing required claims', () => {
    // Missing 'sub'
    const missingSubClaims = {
      iss: 'https://auth.example.com',
      aud: 'merchant-app',
      exp: Math.floor(Date.now() / 1000) + 3600,
      iat: Math.floor(Date.now() / 1000)
      // sub is missing
    };
    
    const jwt = createTestJWT(missingSubClaims);
    
    expect(parseIDToken(jwt)).toBeNull();
  });
  
  it('should handle all standard and private claims', () => {
    const fullClaims = {
      ...validIDTokenClaims,
      auth_time: Math.floor(Date.now() / 1000) - 300,
      amr: ['pwd', 'mfa']
    };
    
    const jwt = createTestJWT(fullClaims);
    
    const claims = parseIDToken(jwt);
    
    expect(claims).not.toBeNull();
    expect(claims?.auth_time).toBe(fullClaims.auth_time);
    expect(claims?.amr).toEqual(fullClaims.amr);
  });
  
  it('should reject malformed JWT', () => {
    expect(parseIDToken('not.a.jwt')).toBeNull();
    expect(parseIDToken('only-one-part')).toBeNull();
    expect(parseIDToken('two.parts')).toBeNull();
    expect(parseIDToken('')).toBeNull();
  });
});

describe('TAP Consumer Recognition - ID Token Verification', () => {
  it('should parse token without JWKS URL (unverified mode)', async () => {
    const jwt = createTestJWT(validIDTokenClaims, { kid: 'test-kid-123' });
    
    const result = await verifyIDTokenSignature(jwt);
    
    expect(result.valid).toBe(true);
    expect(result.claims).toBeDefined();
    expect(result.claims?.iss).toBe(validIDTokenClaims.iss);
  });
  
  it('should reject expired token even without JWKS', async () => {
    const expiredClaims = {
      ...validIDTokenClaims,
      exp: Math.floor(Date.now() / 1000) - 3600
    };
    
    const jwt = createTestJWT(expiredClaims);
    
    const result = await verifyIDTokenSignature(jwt);
    
    expect(result.valid).toBe(false);
    expect(result.error).toContain('expired');
  });
  
  it('should reject malformed JWT', async () => {
    const result = await verifyIDTokenSignature('invalid-jwt');
    
    expect(result.valid).toBe(false);
    expect(result.error).toContain('Invalid JWT format');
  });
});

describe('TAP Consumer Recognition - Identity Matching', () => {
  it('should match SHA-256 hashed email', async () => {
    const cleartext = 'user@example.com';
    
    // Compute expected hash
    const encoder = new TextEncoder();
    const data = encoder.encode(cleartext);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const obfuscated = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    
    const result = await hashMatchIdentity(obfuscated, cleartext, 'sha256');
    
    expect(result).toBe(true);
  });
  
  it('should reject non-matching hash', async () => {
    const cleartext = 'user@example.com';
    const wrongHash = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
    
    const result = await hashMatchIdentity(wrongHash, cleartext, 'sha256');
    
    expect(result).toBe(false);
  });
  
  it('should be case-insensitive for hash comparison', async () => {
    const cleartext = 'user@example.com';
    
    // Compute hash
    const encoder = new TextEncoder();
    const data = encoder.encode(cleartext);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashLower = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    const hashUpper = hashLower.toUpperCase();
    
    // Both should match
    expect(await hashMatchIdentity(hashLower, cleartext)).toBe(true);
    expect(await hashMatchIdentity(hashUpper, cleartext)).toBe(true);
  });
});

describe('TAP Consumer Recognition - End-to-End', () => {
  let keyPair: CryptoKeyPair;
  let publicKeyPEM: string;
  
  beforeAll(async () => {
    keyPair = await generateECDSAKeyPair();
    publicKeyPEM = await exportPublicKeyToPEM(keyPair.publicKey);
  });
  
  it('should verify complete consumer object with ID token', async () => {
    const idToken = createTestJWT(validIDTokenClaims, { kid: 'id-token-key' });
    const headerNonce = 'e2e-test-nonce-12345';
    
    const consumer: AgenticConsumer = {
      nonce: headerNonce,
      idToken,
      contextualData: {
        countryCode: 'US',
        zip: '94102',
        ipAddress: '192.168.1.100'
      },
      kid: 'consumer-key-123',
      alg: 'ES256',
      signature: 'placeholder'
    };
    
    // Sign consumer data
    const signatureBase = buildConsumerSignatureBase(consumer);
    const signature = await signData(signatureBase, keyPair.privateKey);
    consumer.signature = signature;
    
    const result = await verifyAgenticConsumer(
      consumer,
      headerNonce,
      publicKeyPEM,
      'ES256'
    );
    
    expect(result.verified).toBe(true);
    expect(result.nonceLinked).toBe(true);
    expect(result.signatureValid).toBe(true);
    expect(result.idTokenValid).toBe(true);
    expect(result.idTokenClaims).toBeDefined();
    expect(result.idTokenClaims?.email).toBe(validIDTokenClaims.email);
    expect(result.contextualData).toEqual(consumer.contextualData);
  });
  
  it('should handle consumer without ID token', async () => {
    const headerNonce = 'no-id-token-nonce';
    
    const consumer: AgenticConsumer = {
      nonce: headerNonce,
      contextualData: {
        countryCode: 'CA',
        ipAddress: '10.0.0.1'
      },
      kid: 'test-kid',
      alg: 'ES256',
      signature: 'placeholder'
    };
    
    const signatureBase = buildConsumerSignatureBase(consumer);
    const signature = await signData(signatureBase, keyPair.privateKey);
    consumer.signature = signature;
    
    const result = await verifyAgenticConsumer(
      consumer,
      headerNonce,
      publicKeyPEM,
      'ES256'
    );
    
    expect(result.verified).toBe(true);
    expect(result.nonceLinked).toBe(true);
    expect(result.signatureValid).toBe(true);
    expect(result.idTokenValid).toBeUndefined();
    expect(result.idTokenClaims).toBeUndefined();
  });
  
  it('should fail when both nonce and signature are invalid', async () => {
    const consumer: AgenticConsumer = {
      nonce: 'wrong-nonce',
      kid: 'test-kid',
      alg: 'ES256',
      signature: 'invalid-signature-data'
    };
    
    const result = await verifyAgenticConsumer(
      consumer,
      'correct-nonce',
      publicKeyPEM,
      'ES256'
    );
    
    expect(result.verified).toBe(false);
    expect(result.nonceLinked).toBe(false);
    expect(result.signatureValid).toBe(false);
  });
});
