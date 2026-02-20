/**
 * BOTCHA Verifiable Credentials — W3C VC Data Model 2.0
 *
 * Implements:
 *   - VC issuance: sign a BotchaVerification credential as a JWT
 *   - VC verification: validate signature, expiry, and issuer
 *   - Credential schema aligned with the VC Data Model 2.0 spec
 *
 * Encoding:
 *   VCs are encoded as JWT-VCs per the VC Data Model 2.0 spec.
 *   The JWT payload contains a "vc" claim with the JSON-LD credential,
 *   plus standard JWT claims (iss, sub, jti, iat, nbf, exp).
 *
 * Signing:
 *   - Preferred: ES256 with the BOTCHA JWT_SIGNING_KEY (verifiable offline)
 *   - Fallback:  HS256 with JWT_SECRET (verifiable only by botcha.ai)
 *
 * Standards:
 *   - W3C VC Data Model 2.0: https://www.w3.org/TR/vc-data-model-2.0/
 *   - VC-JWT: https://www.w3.org/TR/vc-data-model-2.0/#json-web-token
 *   - DID Core 1.0: https://www.w3.org/TR/did-core/
 */

import { SignJWT, jwtVerify, importJWK, decodeProtectedHeader } from 'jose';
import type { ES256SigningKeyJWK } from './auth.js';
import { getSigningPublicKeyJWK } from './auth.js';

// ============ TYPES ============

export interface BotchaCredentialSubject {
  id?: string;               // Agent DID (optional; set when agent has a registered DID)
  agent_id: string;          // BOTCHA agent_id (or "anonymous")
  app_id: string;            // App that ran the challenge
  challenge_type: string;    // e.g. "speed", "hybrid", "reasoning"
  solve_time_ms: number;     // How fast the challenge was solved (ms)
  trust_level: 'basic' | 'verified' | 'enterprise';
  capabilities?: string[];   // Agent capabilities (from TAP registration)
}

export interface VerifiableCredential {
  '@context': string[];
  type: string[];
  id: string;                 // urn:botcha:vc:<uuid>
  issuer: string;             // did:web:botcha.ai
  credentialSubject: BotchaCredentialSubject;
  validFrom: string;          // ISO 8601
  validUntil: string;         // ISO 8601
}

export interface IssueVCOptions {
  /** BOTCHA agent_id — from agent registration (optional; anonymous if not registered) */
  agent_id?: string;
  /** App that created the challenge */
  app_id: string;
  /** Challenge solve time in milliseconds */
  solve_time_ms: number;
  /** Challenge type (speed, hybrid, reasoning) */
  challenge_type?: string;
  /** Agent trust level */
  trust_level?: 'basic' | 'verified' | 'enterprise';
  /** Agent capabilities (strings like "browse:products") */
  capabilities?: string[];
  /** Agent DID — embedded as credentialSubject.id when present */
  agent_did?: string;
  /** Validity period in seconds (default: 86400 = 24 h; max: 2592000 = 30 days) */
  duration_seconds?: number;
}

export interface VCIssuanceResult {
  success: boolean;
  /** The W3C VC JSON-LD object */
  vc?: VerifiableCredential;
  /** The signed JWT-VC (what you send to relying parties) */
  vc_jwt?: string;
  credential_id?: string;
  issued_at?: string;
  expires_at?: string;
  error?: string;
}

export interface VCVerificationResult {
  valid: boolean;
  vc?: VerifiableCredential;
  credential_subject?: BotchaCredentialSubject;
  issuer?: string;
  credential_id?: string;
  issued_at?: string;
  expires_at?: string;
  error?: string;
}

// ============ CONSTANTS ============

const VC_ISSUER_DID = 'did:web:botcha.ai';
const VC_CONTEXT_V2 = 'https://www.w3.org/ns/credentials/v2';
const DEFAULT_VC_DURATION = 86_400;          // 24 hours (seconds)
const MAX_VC_DURATION     = 86_400 * 30;     // 30 days (seconds)

// ============ ISSUANCE ============

/**
 * Issue a W3C Verifiable Credential for a successful BOTCHA verification.
 *
 * The VC is encoded as a JWT-VC signed with BOTCHA's ES256 key.
 * If no ES256 key is available, falls back to HS256.
 *
 * The JWT payload includes:
 *   iss = did:web:botcha.ai
 *   sub = agent DID or agent_id
 *   jti = credential ID (urn:botcha:vc:<uuid>)
 *   vc  = the full JSON-LD credential object
 *   type = "botcha-vc" (BOTCHA-specific claim for quick type-checking)
 */
export async function issueVC(
  options: IssueVCOptions,
  signingKey?: ES256SigningKeyJWK,
  secret?: string
): Promise<VCIssuanceResult> {
  try {
    if (!signingKey && !secret) {
      return { success: false, error: 'No signing key or secret provided' };
    }

    const durationSeconds = Math.min(
      options.duration_seconds ?? DEFAULT_VC_DURATION,
      MAX_VC_DURATION
    );

    const now = new Date();
    const expiresAt = new Date(now.getTime() + durationSeconds * 1_000);
    const credentialId = `urn:botcha:vc:${crypto.randomUUID()}`;

    // Build credentialSubject
    const credentialSubject: BotchaCredentialSubject = {
      agent_id: options.agent_id || 'anonymous',
      app_id: options.app_id,
      challenge_type: options.challenge_type || 'speed',
      solve_time_ms: options.solve_time_ms,
      trust_level: options.trust_level || 'basic',
    };

    if (options.capabilities && options.capabilities.length > 0) {
      credentialSubject.capabilities = options.capabilities;
    }

    // Set subject DID if agent has one
    if (options.agent_did) {
      credentialSubject.id = options.agent_did;
    }

    // Build the JSON-LD VC object
    const vc: VerifiableCredential = {
      '@context': [VC_CONTEXT_V2],
      type: ['VerifiableCredential', 'BotchaVerification'],
      id: credentialId,
      issuer: VC_ISSUER_DID,
      validFrom: now.toISOString(),
      validUntil: expiresAt.toISOString(),
      credentialSubject,
    };

    // Determine signing key + algorithm
    let signKey: CryptoKey | Uint8Array;
    let protectedHeader: { alg: string; kid?: string; typ: string };

    if (signingKey) {
      signKey = (await importJWK(signingKey, 'ES256')) as CryptoKey;
      protectedHeader = {
        alg: 'ES256',
        kid: signingKey.kid || 'botcha-signing-1',
        typ: 'JWT',
      };
    } else {
      // HS256 fallback — valid JWT but not verifiable offline
      signKey = new TextEncoder().encode(secret!);
      protectedHeader = { alg: 'HS256', typ: 'JWT' };
    }

    // JWT-VC claim mapping (VC Data Model 2.0 §6.3.1):
    //   iss  → issuer
    //   sub  → credentialSubject.id (or agent_id)
    //   jti  → id (credential identifier)
    //   nbf  → validFrom
    //   exp  → validUntil
    //   vc   → the JSON-LD credential object
    const jwtPayload: Record<string, unknown> = {
      vc,
      type: 'botcha-vc', // BOTCHA-specific type claim for fast filtering
    };

    const subjectId = credentialSubject.id || options.agent_id || 'anonymous';

    const vcJwt = await new SignJWT(jwtPayload)
      .setProtectedHeader(protectedHeader)
      .setIssuer(VC_ISSUER_DID)
      .setSubject(subjectId)
      .setJti(credentialId)
      .setIssuedAt()
      .setNotBefore(Math.floor(now.getTime() / 1_000))
      .setExpirationTime(Math.floor(expiresAt.getTime() / 1_000))
      .sign(signKey);

    return {
      success: true,
      vc,
      vc_jwt: vcJwt,
      credential_id: credentialId,
      issued_at: now.toISOString(),
      expires_at: expiresAt.toISOString(),
    };
  } catch (error) {
    console.error('VC issuance failed:', error);
    return {
      success: false,
      error: error instanceof Error ? error.message : 'VC issuance failed',
    };
  }
}

// ============ VERIFICATION ============

/**
 * Verify a BOTCHA VC JWT.
 *
 * Checks (in order):
 *   1. JWT signature (ES256 or HS256)
 *   2. JWT expiration (exp claim)
 *   3. Token type claim = "botcha-vc"
 *   4. Issuer claim = "did:web:botcha.ai"
 *   5. Presence of `vc` claim with credentialSubject
 *
 * Returns the decoded VC and credential subject if valid.
 */
export async function verifyVC(
  vcJwt: string,
  signingKey?: ES256SigningKeyJWK,
  secret?: string
): Promise<VCVerificationResult> {
  try {
    if (!signingKey && !secret) {
      return { valid: false, error: 'No verification key or secret provided' };
    }

    // Detect algorithm from token header
    const header = decodeProtectedHeader(vcJwt);

    let verifyKey: CryptoKey | Uint8Array;
    let algorithms: string[];

    if (header.alg === 'ES256' && signingKey) {
      const publicKeyJwk = getSigningPublicKeyJWK(signingKey);
      verifyKey = (await importJWK(publicKeyJwk, 'ES256')) as CryptoKey;
      algorithms = ['ES256'];
    } else if (secret) {
      verifyKey = new TextEncoder().encode(secret);
      algorithms = ['HS256'];
    } else {
      return {
        valid: false,
        error: `Token signed with ${header.alg} but no compatible key provided`,
      };
    }

    const { payload } = await jwtVerify(vcJwt, verifyKey, { algorithms });

    // Check BOTCHA-specific type claim
    if (payload.type !== 'botcha-vc') {
      return {
        valid: false,
        error: `Invalid token type "${payload.type}". Expected "botcha-vc".`,
      };
    }

    // Check issuer
    if (payload.iss !== VC_ISSUER_DID) {
      return {
        valid: false,
        error: `Invalid issuer "${payload.iss}". Expected "${VC_ISSUER_DID}".`,
      };
    }

    // Extract VC object
    const vc = payload.vc as VerifiableCredential | undefined;
    if (!vc || !vc.credentialSubject) {
      return {
        valid: false,
        error: 'VC payload is missing or malformed (no credentialSubject)',
      };
    }

    return {
      valid: true,
      vc,
      credential_subject: vc.credentialSubject,
      issuer: payload.iss as string,
      credential_id: payload.jti as string | undefined,
      issued_at: payload.iat
        ? new Date((payload.iat as number) * 1_000).toISOString()
        : undefined,
      expires_at: payload.exp
        ? new Date((payload.exp as number) * 1_000).toISOString()
        : undefined,
    };
  } catch (error) {
    return {
      valid: false,
      error: error instanceof Error ? error.message : 'VC verification failed',
    };
  }
}

// ============ UTILITIES ============

/**
 * Extract the BOTCHA access_token payload from the Authorization header.
 * Returns null if the token is missing or cannot be decoded (does NOT verify).
 */
export function extractVCPayloadClaims(vcJwt: string): {
  agent_id?: string;
  app_id?: string;
  solve_time_ms?: number;
  challenge_type?: string;
  trust_level?: string;
} | null {
  try {
    const parts = vcJwt.split('.');
    if (parts.length !== 3) return null;
    const padded = parts[1] + '='.repeat((4 - (parts[1].length % 4)) % 4);
    const decoded = JSON.parse(atob(padded.replace(/-/g, '+').replace(/_/g, '/')));
    const vc = decoded?.vc as VerifiableCredential | undefined;
    if (!vc?.credentialSubject) return null;
    const cs = vc.credentialSubject;
    return {
      agent_id: cs.agent_id,
      app_id: cs.app_id,
      solve_time_ms: cs.solve_time_ms,
      challenge_type: cs.challenge_type,
      trust_level: cs.trust_level,
    };
  } catch {
    return null;
  }
}

export default {
  issueVC,
  verifyVC,
  extractVCPayloadClaims,
};
