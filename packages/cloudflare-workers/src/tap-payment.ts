/**
 * TAP Payment — Agentic Payment Container + 402 Browsing IOU
 * Visa TAP Layer 3: Payment verification linked to message signature
 * 
 * FEATURES:
 * - Agentic Payment Container parsing and verification
 * - Signature verification linked to header nonce (prevents replay)
 * - Multiple payment types: cardMetadata, credentialHash, payload, browsingIOU
 * - 402 Payment Required flow with invoice management
 * - Browsing IOU verification and fulfillment
 */

import type { KVNamespace } from './agents.js';

// ============ TYPES ============

export interface AgenticPaymentContainer {
  nonce: string;              // MUST match header Signature-Input nonce
  kid: string;                // MUST match header Signature-Input keyid
  alg: string;                // Algorithm for body signature
  signature: string;          // Base64 signature
  // One or more of the following payment types:
  cardMetadata?: CardMetadata;
  credentialHash?: CredentialHash;
  payload?: string;           // Encrypted payment payload (encrypted with merchant public key)
  browsingIOU?: BrowsingIOU;
}

export interface CardMetadata {
  lastFour: string;                   // Last 4 digits of physical card
  paymentAccountReference: string;    // PAR — links tokens/virtual cards to funding account
  shortDescription?: string;
  cardData?: CardDataItem[];
}

export interface CardDataItem {
  contentType: string;
  content: {
    mimeType: string;
    width: number;
    height: number;
  };
}

export interface CredentialHash {
  hash: string;         // SHA-256(PAN + expMonth + expYear + CVV)
  algorithm: string;    // 'sha256'
}

export interface BrowsingIOU {
  invoiceId: string;        // From merchant's 402 response
  amount: string;           // From merchant's 402 response
  cardAcceptorId: string;   // CAID from 402
  acquirerId: string;       // Acquirer ID
  uri: string;              // URI of gated resource
  sequenceCounter: string;  // Agent tracking number
  paymentService: string;   // Agent's payment service provider
  kid: string;
  alg: string;
  signature: string;        // Separate signature for IOU
}

// Invoice types for 402 flow
export interface Invoice {
  invoice_id: string;
  app_id: string;
  resource_uri: string;
  amount: string;
  currency: string;
  card_acceptor_id: string;
  description?: string;
  created_at: number;
  expires_at: number;
  status: 'pending' | 'fulfilled' | 'expired';
}

export interface PaymentVerificationResult {
  verified: boolean;
  nonceLinked: boolean;
  signatureValid: boolean;
  paymentType: 'cardMetadata' | 'credentialHash' | 'payload' | 'browsingIOU' | 'unknown';
  cardMetadata?: CardMetadata;
  credentialHashValid?: boolean;
  iouValid?: boolean;
  error?: string;
}

// ============ PAYMENT CONTAINER PARSING ============

/**
 * Parse agenticPaymentContainer from request body
 * Returns null if required fields are missing
 */
export function parsePaymentContainer(body: any): AgenticPaymentContainer | null {
  if (!body || typeof body !== 'object') {
    return null;
  }

  const container = body.agenticPaymentContainer;
  if (!container || typeof container !== 'object') {
    return null;
  }

  // Required fields
  if (!container.nonce || typeof container.nonce !== 'string') return null;
  if (!container.kid || typeof container.kid !== 'string') return null;
  if (!container.alg || typeof container.alg !== 'string') return null;
  if (!container.signature || typeof container.signature !== 'string') return null;

  return {
    nonce: container.nonce,
    kid: container.kid,
    alg: container.alg,
    signature: container.signature,
    cardMetadata: container.cardMetadata,
    credentialHash: container.credentialHash,
    payload: container.payload,
    browsingIOU: container.browsingIOU,
  };
}

// ============ PAYMENT TYPE DETECTION ============

/**
 * Detect which payment type is present in the container
 */
export function detectPaymentType(container: AgenticPaymentContainer): string {
  if (container.browsingIOU) return 'browsingIOU';
  if (container.credentialHash) return 'credentialHash';
  if (container.payload) return 'payload';
  if (container.cardMetadata) return 'cardMetadata';
  return 'unknown';
}

// ============ SIGNATURE VERIFICATION ============

/**
 * Build signature base for payment container
 * Per spec: canonical representation of all fields except `signature`, in order received
 */
export function buildPaymentSignatureBase(container: AgenticPaymentContainer): string {
  const fields: string[] = [];
  
  // Add fields in canonical order (order matters for verification)
  if (container.nonce) fields.push(`"nonce": "${container.nonce}"`);
  if (container.cardMetadata) fields.push(`"cardMetadata": ${JSON.stringify(container.cardMetadata)}`);
  if (container.credentialHash) fields.push(`"credentialHash": ${JSON.stringify(container.credentialHash)}`);
  if (container.payload) fields.push(`"payload": "${container.payload}"`);
  if (container.browsingIOU) fields.push(`"browsingIOU": ${JSON.stringify(container.browsingIOU)}`);
  if (container.kid) fields.push(`"kid": "${container.kid}"`);
  if (container.alg) fields.push(`"alg": "${container.alg}"`);
  
  return fields.join('\n');
}

/**
 * Verify payment container signature
 * 
 * Steps:
 * 1. Check nonce linkage (container.nonce === headerNonce)
 * 2. Build signature base (all fields except signature)
 * 3. Verify signature using Web Crypto
 * 4. Determine payment type
 */
export async function verifyPaymentContainer(
  container: AgenticPaymentContainer,
  headerNonce: string,
  publicKey: string,
  algorithm: string
): Promise<PaymentVerificationResult> {
  try {
    // Step 1: Check nonce linkage
    const nonceLinked = container.nonce === headerNonce;
    if (!nonceLinked) {
      return {
        verified: false,
        nonceLinked: false,
        signatureValid: false,
        paymentType: detectPaymentType(container) as any,
        error: 'Nonce mismatch: payment container nonce does not match header nonce',
      };
    }

    // Step 2: Build signature base
    const signatureBase = buildPaymentSignatureBase(container);

    // Step 3: Verify signature
    const signatureValid = await verifyCryptoSignature(
      signatureBase,
      container.signature,
      publicKey,
      algorithm
    );

    if (!signatureValid) {
      return {
        verified: false,
        nonceLinked: true,
        signatureValid: false,
        paymentType: detectPaymentType(container) as any,
        error: 'Signature verification failed',
      };
    }

    // Step 4: Determine payment type
    const paymentType = detectPaymentType(container);

    return {
      verified: true,
      nonceLinked: true,
      signatureValid: true,
      paymentType: paymentType as any,
      cardMetadata: container.cardMetadata,
    };

  } catch (error) {
    return {
      verified: false,
      nonceLinked: false,
      signatureValid: false,
      paymentType: 'unknown',
      error: `Verification error: ${error instanceof Error ? error.message : 'Unknown error'}`,
    };
  }
}

/**
 * Verify cryptographic signature using Web Crypto API
 */
async function verifyCryptoSignature(
  signatureBase: string,
  signatureB64: string,
  publicKeyPem: string,
  algorithm: string
): Promise<boolean> {
  try {
    // Decode signature from base64
    const signatureBytes = Uint8Array.from(atob(signatureB64), c => c.charCodeAt(0));

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
    console.error('Crypto signature verification error:', error);
    return false;
  }
}

// ============ CREDENTIAL HASH VERIFICATION ============

/**
 * Verify credential hash against card data
 * Per Visa spec: SHA-256(PAN + expMonth + expYear + CVV)
 */
export async function verifyCredentialHash(
  providedHash: string,
  pan: string,
  expMonth: string,
  expYear: string,
  cvv: string
): Promise<boolean> {
  try {
    const input = `${pan}${expMonth}${expYear}${cvv}`;
    const encoder = new TextEncoder();
    const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(input));
    const computedHash = btoa(String.fromCharCode(...new Uint8Array(hashBuffer)));
    return computedHash === providedHash;
  } catch (error) {
    console.error('Credential hash verification error:', error);
    return false;
  }
}

// ============ 402 INVOICE MANAGEMENT ============

/**
 * Create an invoice for gated content
 */
export async function createInvoice(
  invoices: KVNamespace,
  appId: string,
  options: {
    resource_uri: string;
    amount: string;
    currency: string;
    card_acceptor_id: string;
    description?: string;
    ttl_seconds?: number;
  }
): Promise<{ success: boolean; invoice?: Invoice; error?: string }> {
  try {
    // Generate unique invoice ID
    const invoiceId = await generateInvoiceId();
    
    const now = Math.floor(Date.now() / 1000);
    const ttl = options.ttl_seconds || 3600; // Default 1 hour
    
    const invoice: Invoice = {
      invoice_id: invoiceId,
      app_id: appId,
      resource_uri: options.resource_uri,
      amount: options.amount,
      currency: options.currency,
      card_acceptor_id: options.card_acceptor_id,
      description: options.description,
      created_at: now,
      expires_at: now + ttl,
      status: 'pending',
    };

    // Store in KV with TTL
    await invoices.put(
      `invoice:${invoiceId}`,
      JSON.stringify(invoice),
      { expirationTtl: ttl }
    );

    return { success: true, invoice };

  } catch (error) {
    return {
      success: false,
      error: `Failed to create invoice: ${error instanceof Error ? error.message : 'Unknown error'}`,
    };
  }
}

/**
 * Get invoice by ID
 */
export async function getInvoice(
  invoices: KVNamespace,
  invoiceId: string
): Promise<{ success: boolean; invoice?: Invoice; error?: string }> {
  try {
    const data = await invoices.get(`invoice:${invoiceId}`, 'text');
    
    if (!data) {
      return { success: false, error: 'Invoice not found or expired' };
    }

    const invoice = JSON.parse(data) as Invoice;
    
    // Check if expired
    const now = Math.floor(Date.now() / 1000);
    if (invoice.expires_at < now) {
      return { success: false, error: 'Invoice expired' };
    }

    return { success: true, invoice };

  } catch (error) {
    return {
      success: false,
      error: `Failed to get invoice: ${error instanceof Error ? error.message : 'Unknown error'}`,
    };
  }
}

/**
 * Build a TAP-compliant 402 response body
 */
export function build402Response(invoice: Invoice): {
  status: 402;
  body: {
    error: 'PAYMENT_REQUIRED';
    invoice_id: string;
    amount: string;
    currency: string;
    card_acceptor_id: string;
    resource_uri: string;
    description?: string;
    expires_at: string;
    accept_payment: string[];
  };
} {
  return {
    status: 402,
    body: {
      error: 'PAYMENT_REQUIRED',
      invoice_id: invoice.invoice_id,
      amount: invoice.amount,
      currency: invoice.currency,
      card_acceptor_id: invoice.card_acceptor_id,
      resource_uri: invoice.resource_uri,
      description: invoice.description,
      expires_at: new Date(invoice.expires_at * 1000).toISOString(),
      accept_payment: ['browsingIOU', 'credentialHash', 'payload'],
    },
  };
}

// ============ BROWSING IOU VERIFICATION ============

/**
 * Build signature base for Browsing IOU
 * All fields except signature, kid, alg
 */
function buildIOUSignatureBase(iou: BrowsingIOU): string {
  const fields: string[] = [];
  
  if (iou.invoiceId) fields.push(`"invoiceId": "${iou.invoiceId}"`);
  if (iou.amount) fields.push(`"amount": "${iou.amount}"`);
  if (iou.cardAcceptorId) fields.push(`"cardAcceptorId": "${iou.cardAcceptorId}"`);
  if (iou.acquirerId) fields.push(`"acquirerId": "${iou.acquirerId}"`);
  if (iou.uri) fields.push(`"uri": "${iou.uri}"`);
  if (iou.sequenceCounter) fields.push(`"sequenceCounter": "${iou.sequenceCounter}"`);
  if (iou.paymentService) fields.push(`"paymentService": "${iou.paymentService}"`);
  
  return fields.join('\n');
}

/**
 * Verify Browsing IOU against invoice
 */
export async function verifyBrowsingIOU(
  iou: BrowsingIOU,
  invoice: Invoice,
  publicKey: string,
  algorithm: string
): Promise<{ valid: boolean; error?: string }> {
  try {
    // Step 1: Check IOU fields match invoice
    if (iou.invoiceId !== invoice.invoice_id) {
      return { valid: false, error: 'Invoice ID mismatch' };
    }
    
    if (iou.amount !== invoice.amount) {
      return { valid: false, error: 'Amount mismatch' };
    }
    
    if (iou.cardAcceptorId !== invoice.card_acceptor_id) {
      return { valid: false, error: 'Card Acceptor ID mismatch' };
    }
    
    if (iou.uri !== invoice.resource_uri) {
      return { valid: false, error: 'Resource URI mismatch' };
    }

    // Step 2: Build IOU signature base
    const signatureBase = buildIOUSignatureBase(iou);

    // Step 3: Verify IOU signature
    const signatureValid = await verifyCryptoSignature(
      signatureBase,
      iou.signature,
      publicKey,
      algorithm
    );

    if (!signatureValid) {
      return { valid: false, error: 'IOU signature verification failed' };
    }

    return { valid: true };

  } catch (error) {
    return {
      valid: false,
      error: `IOU verification error: ${error instanceof Error ? error.message : 'Unknown error'}`,
    };
  }
}

/**
 * Fulfill invoice and generate access token
 */
export async function fulfillInvoice(
  invoices: KVNamespace,
  invoiceId: string,
  iou: BrowsingIOU
): Promise<{ success: boolean; access_token?: string; error?: string }> {
  try {
    // Get invoice
    const result = await getInvoice(invoices, invoiceId);
    if (!result.success || !result.invoice) {
      return { success: false, error: result.error };
    }

    const invoice = result.invoice;

    // Check if already fulfilled
    if (invoice.status === 'fulfilled') {
      return { success: false, error: 'Invoice already fulfilled' };
    }

    // Mark as fulfilled
    invoice.status = 'fulfilled';
    const ttl = invoice.expires_at - Math.floor(Date.now() / 1000);
    
    if (ttl <= 0) {
      return { success: false, error: 'Invoice expired' };
    }

    await invoices.put(
      `invoice:${invoiceId}`,
      JSON.stringify(invoice),
      { expirationTtl: ttl }
    );

    // Generate access token
    const accessToken = await generateAccessToken();
    
    // Store access token with 5-minute TTL
    await invoices.put(
      `access:${accessToken}`,
      JSON.stringify({
        invoice_id: invoiceId,
        resource_uri: invoice.resource_uri,
        created_at: Math.floor(Date.now() / 1000),
      }),
      { expirationTtl: 300 } // 5 minutes
    );

    return { success: true, access_token: accessToken };

  } catch (error) {
    return {
      success: false,
      error: `Failed to fulfill invoice: ${error instanceof Error ? error.message : 'Unknown error'}`,
    };
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
 * Map JWK algorithm to Web Crypto API parameters
 */
function jwkAlgToWebCrypto(alg: string): {
  importParams: any;
  verifyParams: any;
} {
  switch (alg) {
    case 'PS256':
    case 'RSA-PSS-SHA256':
    case 'rsa-pss-sha256':
      return {
        importParams: { name: 'RSA-PSS', hash: 'SHA-256' },
        verifyParams: { name: 'RSA-PSS', saltLength: 32 },
      };
    case 'ES256':
    case 'ECDSA-P256-SHA256':
    case 'ecdsa-p256-sha256':
      return {
        importParams: { name: 'ECDSA', namedCurve: 'P-256' },
        verifyParams: { name: 'ECDSA', hash: 'SHA-256' },
      };
    case 'EdDSA':
    case 'Ed25519':
    case 'ed25519':
      return {
        importParams: { name: 'Ed25519' },
        verifyParams: { name: 'Ed25519' },
      };
    default:
      throw new Error(`Unsupported algorithm: ${alg}`);
  }
}

/**
 * Generate unique invoice ID (random hex)
 */
async function generateInvoiceId(): Promise<string> {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Generate access token (random hex)
 */
async function generateAccessToken(): Promise<string> {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

// ============ EXPORTS ============

export default {
  parsePaymentContainer,
  verifyPaymentContainer,
  verifyCredentialHash,
  createInvoice,
  getInvoice,
  build402Response,
  verifyBrowsingIOU,
  fulfillInvoice,
  detectPaymentType,
  buildPaymentSignatureBase,
};
