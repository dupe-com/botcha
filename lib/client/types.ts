/**
 * BOTCHA Client SDK Type Definitions
 * 
 * Types for the BotchaClient SDK including challenges, tokens, and configuration.
 */

export type SpeedProblem = number | { num: number; operation?: string };

export interface BotchaClientOptions {
  /** Base URL of BOTCHA service (default: https://botcha.ai) */
  baseUrl?: string;
  /** Custom identity header value */
  agentIdentity?: string;
  /** Max retries for challenge solving */
  maxRetries?: number;
  /** Enable automatic token acquisition and management (default: true) */
  autoToken?: boolean;
  /** Audience claim for token (optional) */
  audience?: string;
  /** Multi-tenant application ID (optional) */
  appId?: string;
}

export interface ChallengeResponse {
  success: boolean;
  challenge?: {
    id: string;
    problems: SpeedProblem[];
    timeLimit: number;
    instructions: string;
  };
}

export interface StandardChallengeResponse {
  success: boolean;
  challenge?: {
    id: string;
    puzzle: string;
    timeLimit: number;
    hint?: string;
  };
}

export interface VerifyResponse {
  success: boolean;
  message: string;
  solveTimeMs?: number;
  verdict?: string;
}

export interface TokenResponse {
  success: boolean;
  token: string | null;
  access_token?: string;
  refresh_token?: string;
  expires_in?: number;
  refresh_expires_in?: number;
  expiresIn?: string;
  challenge?: {
    id: string;
    problems: SpeedProblem[];
    timeLimit: number;
    instructions: string;
  };
  nextStep?: string;
  verified?: boolean;
  solveTimeMs?: number;
}

/**
 * Stream-related types for BotchaStreamClient
 */

export interface StreamSession {
  session: string;
  url: string;
}

export interface StreamEvent {
  event: 'ready' | 'instruction' | 'challenge' | 'result' | 'error';
  data: any;
}

export interface Problem {
  num: number;
  operation?: string;
}

export interface VerifyResult {
  success: boolean;
  token?: string;
  message?: string;
  solveTimeMs?: number;
}

export interface StreamChallengeOptions {
  /** Callback for instruction messages */
  onInstruction?: (message: string) => void;
  /** Callback to solve challenges - return answers array */
  onChallenge?: (problems: Problem[]) => Promise<string[]> | string[];
  /** Callback for final verification result */
  onResult?: (result: VerifyResult) => void;
  /** Timeout for the full verification flow in milliseconds (default: 30000) */
  timeout?: number;
}

// ============ App Management Types ============

export interface CreateAppResponse {
  success: boolean;
  app_id: string;
  app_secret: string;
  email: string;
  email_verified: boolean;
  verification_required: boolean;
  warning: string;
  credential_advice: string;
  created_at: string;
  rate_limit: number;
  next_step: string;
}

export interface VerifyEmailResponse {
  success: boolean;
  email_verified?: boolean;
  error?: string;
  message?: string;
}

export interface ResendVerificationResponse {
  success: boolean;
  message?: string;
  error?: string;
}

export interface RecoverAccountResponse {
  success: boolean;
  message: string;
}

export interface RotateSecretResponse {
  success: boolean;
  app_id?: string;
  app_secret?: string;
  warning?: string;
  rotated_at?: string;
  error?: string;
  message?: string;
}

// ============ TAP (Trusted Agent Protocol) Types ============

export type TAPAction = 'browse' | 'compare' | 'purchase' | 'audit' | 'search';
export type TAPTrustLevel = 'basic' | 'verified' | 'enterprise';
export type TAPSignatureAlgorithm = 'ecdsa-p256-sha256' | 'rsa-pss-sha256' | 'ed25519';
export type TAPTag = 'agent-browser-auth' | 'agent-payer-auth';

export interface TAPCapability {
  action: TAPAction;
  scope?: string[];
  restrictions?: {
    max_amount?: number;
    rate_limit?: number;
    [key: string]: any;
  };
}

export interface TAPIntent {
  action: TAPAction;
  resource?: string;
  scope?: string[];
  duration?: number;
}

export interface RegisterTAPAgentOptions {
  name: string;
  operator?: string;
  version?: string;
  public_key?: string;
  signature_algorithm?: TAPSignatureAlgorithm;
  capabilities?: TAPCapability[];
  trust_level?: TAPTrustLevel;
  issuer?: string;
  key_expires_at?: string;  // ISO 8601 expiration date
}

export interface TAPAgentResponse {
  success: boolean;
  agent_id: string;
  app_id: string;
  name: string;
  operator?: string;
  version?: string;
  created_at: string;
  tap_enabled: boolean;
  trust_level?: TAPTrustLevel;
  capabilities?: TAPCapability[];
  signature_algorithm?: TAPSignatureAlgorithm;
  issuer?: string;
  has_public_key: boolean;
  key_fingerprint?: string;
  last_verified_at?: string | null;
  key_expires_at?: string | null;
  public_key?: string;
}

export interface TAPAgentListResponse {
  success: boolean;
  agents: TAPAgentResponse[];
  count: number;
  tap_enabled_count: number;
}

export interface CreateTAPSessionOptions {
  agent_id: string;
  user_context: string;
  intent: TAPIntent;
}

export interface TAPSessionResponse {
  success: boolean;
  session_id: string;
  agent_id: string;
  app_id?: string;
  capabilities?: TAPCapability[];
  intent: TAPIntent;
  created_at?: string;
  expires_at: string;
  time_remaining?: number;
}

// ============ JWK / JWKS Types ============

export interface JWK {
  kty: string;
  kid: string;
  use: string;
  alg: string;
  n?: string;
  e?: string;
  crv?: string;
  x?: string;
  y?: string;
  agent_id?: string;
  agent_name?: string;
  expires_at?: string;
}

export interface JWKSet {
  keys: JWK[];
}

// ============ Agentic Consumer Recognition Types ============

export interface ContextualData {
  countryCode?: string;
  zip?: string;
  ipAddress?: string;
  deviceData?: Record<string, any>;
}

export interface IDTokenClaims {
  iss: string;
  sub: string;
  aud: string | string[];
  exp: number;
  iat: number;
  jti?: string;
  auth_time?: number;
  amr?: string[];
  phone_number?: string;
  phone_number_verified?: boolean;
  phone_number_mask?: string;
  email?: string;
  email_verified?: boolean;
  email_mask?: string;
}

export interface AgenticConsumerResult {
  verified: boolean;
  nonceLinked: boolean;
  signatureValid: boolean;
  idTokenValid?: boolean;
  idTokenClaims?: IDTokenClaims;
  contextualData?: ContextualData;
  error?: string;
}

// ============ Agentic Payment Types ============

export interface CardMetadata {
  lastFour: string;
  paymentAccountReference: string;
  shortDescription?: string;
  cardData?: Array<{
    contentType: string;
    content: { mimeType: string; width: number; height: number };
  }>;
}

export interface CredentialHash {
  hash: string;
  algorithm: string;
}

export interface BrowsingIOU {
  invoiceId: string;
  amount: string;
  cardAcceptorId: string;
  acquirerId: string;
  uri: string;
  sequenceCounter: string;
  paymentService: string;
  kid: string;
  alg: string;
  signature: string;
}

// ============ Invoice Types (402 Flow) ============

export interface CreateInvoiceOptions {
  resource_uri: string;
  amount: string;
  currency: string;
  card_acceptor_id: string;
  description?: string;
  ttl_seconds?: number;
}

export interface InvoiceResponse {
  success: boolean;
  invoice_id: string;
  app_id: string;
  resource_uri: string;
  amount: string;
  currency: string;
  card_acceptor_id: string;
  description?: string;
  created_at: string;
  expires_at: string;
  status: 'pending' | 'fulfilled' | 'expired';
}

export interface VerifyIOUResponse {
  success: boolean;
  verified: boolean;
  access_token?: string;
  expires_at?: string;
  error?: string;
}
