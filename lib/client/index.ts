import crypto from 'crypto';

// SDK version - hardcoded since npm_package_version is unreliable when used as a library
const SDK_VERSION = '0.19.0';

// Export types
export type {
  SpeedProblem,
  BotchaClientOptions,
  ChallengeResponse,
  StandardChallengeResponse,
  VerifyResponse,
  TokenResponse,
  StreamSession,
  StreamEvent,
  Problem,
  VerifyResult,
  StreamChallengeOptions,
  CreateAppResponse,
  VerifyEmailResponse,
  ResendVerificationResponse,
  RecoverAccountResponse,
  RotateSecretResponse,
  TAPAction,
  TAPTrustLevel,
  TAPSignatureAlgorithm,
  TAPCapability,
  TAPIntent,
  RegisterTAPAgentOptions,
  TAPAgentResponse,
  TAPAgentListResponse,
  CreateTAPSessionOptions,
  TAPSessionResponse,
  JWK,
  JWKSet,
  CreateInvoiceOptions,
  InvoiceResponse,
  BrowsingIOU,
  VerifyIOUResponse,
  CreateDelegationOptions,
  DelegationResponse,
  DelegationListResponse,
  RevokeDelegationResponse,
  DelegationVerifyResponse,
  IssueAttestationOptions,
  AttestationResponse,
  AttestationListResponse,
  RevokeAttestationResponse,
  AttestationVerifyResponse,
  ReputationTier,
  ReputationEventCategory,
  ReputationEventAction,
  ReputationScoreResponse,
  RecordReputationEventOptions,
  ReputationEventResponse,
  ReputationEventListResponse,
  ReputationResetResponse,
} from './types.js';

import type {
  SpeedProblem,
  BotchaClientOptions,
  ChallengeResponse,
  StandardChallengeResponse,
  VerifyResponse,
  TokenResponse,
  CreateAppResponse,
  VerifyEmailResponse,
  ResendVerificationResponse,
  RecoverAccountResponse,
  RotateSecretResponse,
  RegisterTAPAgentOptions,
  TAPAgentResponse,
  TAPAgentListResponse,
  CreateTAPSessionOptions,
  TAPSessionResponse,
  TAPSignatureAlgorithm,
  JWK,
  JWKSet,
  CreateInvoiceOptions,
  InvoiceResponse,
  BrowsingIOU,
  VerifyIOUResponse,
  CreateDelegationOptions,
  DelegationResponse,
  DelegationListResponse,
  RevokeDelegationResponse,
  DelegationVerifyResponse,
  IssueAttestationOptions,
  AttestationResponse,
  AttestationListResponse,
  RevokeAttestationResponse,
  AttestationVerifyResponse,
  RecordReputationEventOptions,
  ReputationScoreResponse,
  ReputationEventResponse,
  ReputationEventListResponse,
  ReputationResetResponse,
} from './types.js';

// Export stream client
export { BotchaStreamClient } from './stream.js';

/**
 * BOTCHA Client SDK for AI Agents
 * 
 * Automatically handles BOTCHA challenges when accessing protected endpoints.
 * 
 * @example
 * ```typescript
 * import { BotchaClient } from '@dupecom/botcha/client';
 * 
 * const client = new BotchaClient();
 * 
 * // Automatically solves challenges and retries
 * const response = await client.fetch('https://api.example.com/agent-only');
 * ```
 */
export class BotchaClient {
  private baseUrl: string;
  private agentIdentity: string;
  private maxRetries: number;
  private autoToken: boolean;
  private appId?: string;
  private opts: BotchaClientOptions;
  private cachedToken: string | null = null;
  private _refreshToken: string | null = null;
  private tokenExpiresAt: number | null = null;

  constructor(options: BotchaClientOptions = {}) {
    this.opts = options;
    this.baseUrl = options.baseUrl || 'https://botcha.ai';
    this.agentIdentity = options.agentIdentity || `BotchaClient/${SDK_VERSION}`;
    this.maxRetries = options.maxRetries || 3;
    this.autoToken = options.autoToken !== undefined ? options.autoToken : true;
    this.appId = options.appId;
  }

  /**
   * Solve a BOTCHA speed challenge
   * 
   * @param problems - Array of numbers to hash
   * @returns Array of SHA256 first 8 hex chars for each number
   */
  solve(problems: number[]): string[] {
    return problems.map(num =>
      crypto.createHash('sha256').update(num.toString()).digest('hex').substring(0, 8)
    );
  }

  /**
   * Get a JWT token from the BOTCHA service using the token flow.
   * Automatically solves the challenge and verifies to obtain a token.
   * Token is cached until near expiry (refreshed at 4 minutes).
   * 
   * @returns JWT token string
   * @throws Error if token acquisition fails
   */
  async getToken(): Promise<string> {
    // Check if we have a valid cached token (refresh at 1 minute before expiry)
    if (this.cachedToken && this.tokenExpiresAt) {
      const now = Date.now();
      const timeUntilExpiry = this.tokenExpiresAt - now;
      const refreshThreshold = 1 * 60 * 1000; // 1 minute before expiry
      
      if (timeUntilExpiry > refreshThreshold) {
        return this.cachedToken;
      }
    }

    // Step 1: Get challenge from GET /v1/token
    const tokenUrl = this.appId 
      ? `${this.baseUrl}/v1/token?app_id=${encodeURIComponent(this.appId)}`
      : `${this.baseUrl}/v1/token`;
    const challengeRes = await fetch(tokenUrl, {
      headers: { 'User-Agent': this.agentIdentity },
    });

    if (!challengeRes.ok) {
      throw new Error(`Token request failed with status ${challengeRes.status} ${challengeRes.statusText}`);
    }

    const challengeData = await challengeRes.json() as TokenResponse;
    
    if (!challengeData.challenge) {
      throw new Error('No challenge provided in token response');
    }

    // Step 2: Solve the challenge
    const problems = normalizeProblems(challengeData.challenge.problems);
    if (!problems) {
      throw new Error('Invalid challenge problems format');
    }
    const answers = this.solve(problems);

    // Step 3: Submit solution to POST /v1/token/verify
    const verifyBody: any = {
      id: challengeData.challenge.id,
      answers,
    };
    
    // Include audience if specified
    if (this.opts.audience) {
      verifyBody.audience = this.opts.audience;
    }
    
    // Include app_id if specified
    if (this.appId) {
      verifyBody.app_id = this.appId;
    }

    const verifyRes = await fetch(`${this.baseUrl}/v1/token/verify`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': this.agentIdentity,
      },
      body: JSON.stringify(verifyBody),
    });

    if (!verifyRes.ok) {
      throw new Error(`Token verification failed with status ${verifyRes.status} ${verifyRes.statusText}`);
    }

    const verifyData = await verifyRes.json() as TokenResponse;

    if (!verifyData.success && !verifyData.verified) {
      throw new Error('Failed to obtain token from verification');
    }

    // Extract access token (prefer access_token field, fall back to token for backward compat)
    const accessToken = verifyData.access_token || verifyData.token;
    if (!accessToken) {
      throw new Error('Failed to obtain token from verification');
    }

    // Store refresh token if provided
    if (verifyData.refresh_token) {
      this._refreshToken = verifyData.refresh_token;
    }

    // Cache the token - use expires_in from response (in seconds), default to 5 minutes
    const expiresInSeconds = verifyData.expires_in || 300; // Default to 5 minutes
    this.cachedToken = accessToken;
    this.tokenExpiresAt = Date.now() + expiresInSeconds * 1000;

    return this.cachedToken;
  }

  /**
   * Refresh the access token using the refresh token.
   * Only works if a refresh token was obtained from a previous getToken() call.
   * 
   * @returns New JWT access token string
   * @throws Error if refresh fails or no refresh token available
   */
  async refreshToken(): Promise<string> {
    if (!this._refreshToken) {
      throw new Error('No refresh token available. Call getToken() first.');
    }

    const refreshRes = await fetch(`${this.baseUrl}/v1/token/refresh`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': this.agentIdentity,
      },
      body: JSON.stringify({
        refresh_token: this._refreshToken,
      }),
    });

    if (!refreshRes.ok) {
      throw new Error(`Token refresh failed with status ${refreshRes.status} ${refreshRes.statusText}`);
    }

    const refreshData = await refreshRes.json() as TokenResponse;

    if (!refreshData.access_token) {
      throw new Error('Failed to obtain access token from refresh');
    }

    // Update cached token with new access token
    this.cachedToken = refreshData.access_token;
    const expiresInSeconds = refreshData.expires_in || 300; // Default to 5 minutes
    this.tokenExpiresAt = Date.now() + expiresInSeconds * 1000;

    return this.cachedToken;
  }

  /**
   * Clear the cached token, forcing a refresh on the next request
   */
  clearToken(): void {
    this.cachedToken = null;
    this._refreshToken = null;
    this.tokenExpiresAt = null;
  }

  /**
   * Get and solve a challenge from BOTCHA service
   */
  async solveChallenge(): Promise<{ id: string; answers: string[] }> {
    const challengeUrl = this.appId
      ? `${this.baseUrl}/api/speed-challenge?app_id=${encodeURIComponent(this.appId)}`
      : `${this.baseUrl}/api/speed-challenge`;
    const res = await fetch(challengeUrl, {
      headers: { 'User-Agent': this.agentIdentity },
    });

    if (!res.ok) {
      throw new Error(`Challenge request failed with status ${res.status} ${res.statusText}`);
    }

    const contentType = res.headers.get('content-type') || '';
    if (!contentType.toLowerCase().includes('application/json')) {
      throw new Error('Expected JSON response for challenge request');
    }
    
    const data = await res.json() as ChallengeResponse;
    
    if (!data.success || !data.challenge) {
      throw new Error('Failed to get challenge');
    }

    const problems = normalizeProblems(data.challenge.problems);
    if (!problems) {
      throw new Error('Invalid challenge problems format');
    }
    const answers = this.solve(problems);
    return { id: data.challenge.id, answers };
  }

  /**
   * Verify a solved challenge
   */
  async verify(id: string, answers: string[]): Promise<VerifyResponse> {
    const res = await fetch(`${this.baseUrl}/api/speed-challenge`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': this.agentIdentity,
      },
      body: JSON.stringify({ id, answers }),
    });

    if (!res.ok) {
      throw new Error(`Verification request failed with status ${res.status} ${res.statusText}`);
    }

    const contentType = res.headers.get('content-type') || '';
    if (!contentType.toLowerCase().includes('application/json')) {
      throw new Error('Expected JSON response for verification request');
    }

    return await res.json() as VerifyResponse;
  }

  /**
   * Fetch a URL, automatically solving BOTCHA challenges if encountered.
   * If autoToken is enabled (default), automatically acquires and uses JWT tokens.
   * 
   * @example
   * ```typescript
   * const response = await client.fetch('https://api.example.com/agent-only');
   * const data = await response.json();
   * ```
   */
  async fetch(url: string, init?: RequestInit): Promise<Response> {
    const headers = new Headers(init?.headers);
    headers.set('User-Agent', this.agentIdentity);

    // If autoToken is enabled, try to use token-based auth
    if (this.autoToken) {
      try {
        const token = await this.getToken();
        headers.set('Authorization', `Bearer ${token}`);
      } catch (error) {
        // If token acquisition fails, fall back to challenge header method
        console.warn('Failed to acquire token, falling back to challenge headers:', error);
      }
    }

    let response = await fetch(url, {
      ...init,
      headers,
    });
    
    // Handle 401 by trying refresh first, then full re-verify if refresh fails
    if (response.status === 401 && this.autoToken) {
      try {
        // Try refresh token first if available
        let token: string;
        if (this._refreshToken) {
          try {
            token = await this.refreshToken();
          } catch (refreshError) {
            // Refresh failed, clear tokens and do full re-verify
            this.clearToken();
            token = await this.getToken();
          }
        } else {
          // No refresh token, clear and do full re-verify
          this.clearToken();
          token = await this.getToken();
        }
        headers.set('Authorization', `Bearer ${token}`);
        response = await fetch(url, { ...init, headers });
      } catch (error) {
        // Token refresh/acquisition failed, return the 401 response
      }
    }

    let retries = 0;

    // Fall back to challenge header method for 403 responses
    while (response.status === 403 && retries < this.maxRetries) {
      // Clone response before reading body to preserve it for the caller
      const clonedResponse = response.clone();
      const body = await clonedResponse.json().catch(() => null);
      
      // Check if this is a BOTCHA challenge
      const challenge = body?.challenge;
      if (!challenge) {
        break;
      }

      if (!canRetryBody(init?.body)) {
        break;
      }

      const retryHeaders = new Headers(init?.headers);
      retryHeaders.set('User-Agent', this.agentIdentity);

      if (challenge?.problems && Array.isArray(challenge.problems)) {
        const problems = normalizeProblems(challenge.problems);
        if (!problems) {
          break;
        }
        const answers = this.solve(problems);
        retryHeaders.set('X-Botcha-Id', challenge.id);
        retryHeaders.set('X-Botcha-Challenge-Id', challenge.id);
        retryHeaders.set('X-Botcha-Answers', JSON.stringify(answers));
        retryHeaders.set('X-Botcha-Solution', JSON.stringify(answers));
      } else if (challenge?.puzzle && typeof challenge.puzzle === 'string') {
        const solution = solveStandardPuzzle(challenge.puzzle);
        retryHeaders.set('X-Botcha-Challenge-Id', challenge.id);
        retryHeaders.set('X-Botcha-Solution', solution);
      } else {
        break;
      }

      response = await fetch(url, { ...init, headers: retryHeaders });
      retries++;
    }

    return response;
  }

  /**
   * Create headers with pre-solved challenge for manual use
   * 
   * @example
   * ```typescript
   * const headers = await client.createHeaders();
   * const response = await fetch('https://api.example.com/agent-only', { headers });
   * ```
   */
  async createHeaders(): Promise<Record<string, string>> {
    const { id, answers } = await this.solveChallenge();
    
    const headers: Record<string, string> = {
      'X-Botcha-Id': id,
      'X-Botcha-Challenge-Id': id,
      'X-Botcha-Answers': JSON.stringify(answers),
      'User-Agent': this.agentIdentity,
    };
    
    // Include X-Botcha-App-Id header if appId is set
    if (this.appId) {
      headers['X-Botcha-App-Id'] = this.appId;
    }
    
    return headers;
  }

  // ============ APP MANAGEMENT ============

  /**
   * Create a new BOTCHA app. Email is required.
   * 
   * The returned `app_secret` is only shown once — save it securely.
   * A 6-digit verification code will be sent to the provided email.
   * 
   * @param email - Email address for the app owner
   * @returns App creation response including app_id and app_secret
   * @throws Error if app creation fails
   * 
   * @example
   * ```typescript
   * const app = await client.createApp('agent@example.com');
   * console.log(app.app_id);     // 'app_abc123'
   * console.log(app.app_secret); // 'sk_...' (save this!)
   * ```
   */
  async createApp(email: string): Promise<CreateAppResponse> {
    const res = await fetch(`${this.baseUrl}/v1/apps`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': this.agentIdentity,
      },
      body: JSON.stringify({ email }),
    });

    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as Record<string, unknown>;
      throw new Error(
        (body.message as string) || `App creation failed with status ${res.status}`
      );
    }

    const data = await res.json() as CreateAppResponse;

    // Auto-set appId for subsequent requests
    if (data.app_id) {
      this.appId = data.app_id;
    }

    return data;
  }

  /**
   * Verify the email address for an app using the 6-digit code sent via email.
   * 
   * @param appId - The app ID (defaults to the client's appId)
   * @param code - The 6-digit verification code from the email
   * @returns Verification response
   * @throws Error if verification fails
   * 
   * @example
   * ```typescript
   * const result = await client.verifyEmail('123456');
   * console.log(result.email_verified); // true
   * ```
   */
  async verifyEmail(code: string, appId?: string): Promise<VerifyEmailResponse> {
    const id = appId || this.appId;
    if (!id) {
      throw new Error('No app ID. Call createApp() first or pass appId.');
    }

    const res = await fetch(`${this.baseUrl}/v1/apps/${encodeURIComponent(id)}/verify-email`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': this.agentIdentity,
      },
      body: JSON.stringify({ code }),
    });

    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as Record<string, unknown>;
      throw new Error(
        (body.message as string) || `Email verification failed with status ${res.status}`
      );
    }

    return await res.json() as VerifyEmailResponse;
  }

  /**
   * Resend the email verification code.
   * 
   * @param appId - The app ID (defaults to the client's appId)
   * @returns Response with success status
   * @throws Error if resend fails
   */
  async resendVerification(appId?: string): Promise<ResendVerificationResponse> {
    const id = appId || this.appId;
    if (!id) {
      throw new Error('No app ID. Call createApp() first or pass appId.');
    }

    const res = await fetch(`${this.baseUrl}/v1/apps/${encodeURIComponent(id)}/resend-verification`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': this.agentIdentity,
      },
    });

    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as Record<string, unknown>;
      throw new Error(
        (body.message as string) || `Resend verification failed with status ${res.status}`
      );
    }

    return await res.json() as ResendVerificationResponse;
  }

  /**
   * Request account recovery via verified email.
   * Sends a device code to the registered email address.
   * 
   * Anti-enumeration: always returns the same response shape
   * whether or not the email exists.
   * 
   * @param email - The email address associated with the app
   * @returns Recovery response (always success for anti-enumeration)
   */
  async recoverAccount(email: string): Promise<RecoverAccountResponse> {
    const res = await fetch(`${this.baseUrl}/v1/auth/recover`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': this.agentIdentity,
      },
      body: JSON.stringify({ email }),
    });

    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as Record<string, unknown>;
      throw new Error(
        (body.message as string) || `Account recovery failed with status ${res.status}`
      );
    }

    return await res.json() as RecoverAccountResponse;
  }

  /**
   * Rotate the app secret. Requires an active dashboard session (Bearer token).
   * The old secret is immediately invalidated.
   * 
   * @param appId - The app ID (defaults to the client's appId)
   * @returns New app_secret (save it — only shown once)
   * @throws Error if rotation fails or auth is missing
   * 
   * @example
   * ```typescript
   * const result = await client.rotateSecret();
   * console.log(result.app_secret); // 'sk_new_...' (save this!)
   * ```
   */
  async rotateSecret(appId?: string): Promise<RotateSecretResponse> {
    const id = appId || this.appId;
    if (!id) {
      throw new Error('No app ID. Call createApp() first or pass appId.');
    }

    // Rotate secret requires a dashboard session token
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'User-Agent': this.agentIdentity,
    };

    // Use cached token if available (from dashboard auth)
    if (this.cachedToken) {
      headers['Authorization'] = `Bearer ${this.cachedToken}`;
    }

    const res = await fetch(`${this.baseUrl}/v1/apps/${encodeURIComponent(id)}/rotate-secret`, {
      method: 'POST',
      headers,
    });

    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as Record<string, unknown>;
      throw new Error(
        (body.message as string) || `Secret rotation failed with status ${res.status}`
      );
    }

    return await res.json() as RotateSecretResponse;
  }

  // ============ TAP (TRUSTED AGENT PROTOCOL) ============

  /**
   * Register an agent with TAP (Trusted Agent Protocol) capabilities.
   * Enables cryptographic agent authentication with optional public key signing.
   *
   * @param options - Registration options including name, public key, capabilities
   * @returns TAP agent details including agent_id
   * @throws Error if registration fails
   *
   * @example
   * ```typescript
   * const agent = await client.registerTAPAgent({
   *   name: 'my-shopping-agent',
   *   operator: 'acme-corp',
   *   capabilities: [{ action: 'browse', scope: ['products'] }],
   *   trust_level: 'verified',
   * });
   * console.log(agent.agent_id);
   * ```
   */
  async registerTAPAgent(options: RegisterTAPAgentOptions): Promise<TAPAgentResponse> {
    const url = this.appId
      ? `${this.baseUrl}/v1/agents/register/tap?app_id=${encodeURIComponent(this.appId)}`
      : `${this.baseUrl}/v1/agents/register/tap`;

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'User-Agent': this.agentIdentity,
    };

    if (this.cachedToken) {
      headers['Authorization'] = `Bearer ${this.cachedToken}`;
    }

    const res = await fetch(url, {
      method: 'POST',
      headers,
      body: JSON.stringify(options),
    });

    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as Record<string, unknown>;
      throw new Error(
        (body.message as string) || `TAP agent registration failed with status ${res.status}`
      );
    }

    return await res.json() as TAPAgentResponse;
  }

  /**
   * Get a TAP agent by ID.
   *
   * @param agentId - The agent ID to retrieve
   * @returns TAP agent details
   * @throws Error if agent not found
   */
  async getTAPAgent(agentId: string): Promise<TAPAgentResponse> {
    const res = await fetch(`${this.baseUrl}/v1/agents/${encodeURIComponent(agentId)}/tap`, {
      headers: { 'User-Agent': this.agentIdentity },
    });

    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as Record<string, unknown>;
      throw new Error(
        (body.message as string) || `TAP agent retrieval failed with status ${res.status}`
      );
    }

    return await res.json() as TAPAgentResponse;
  }

  /**
   * List TAP agents for the current app.
   *
   * @param tapOnly - If true, only return TAP-enabled agents (default: false)
   * @returns List of TAP agents with counts
   * @throws Error if listing fails
   */
  async listTAPAgents(tapOnly: boolean = false): Promise<TAPAgentListResponse> {
    let url = this.appId
      ? `${this.baseUrl}/v1/agents/tap?app_id=${encodeURIComponent(this.appId)}`
      : `${this.baseUrl}/v1/agents/tap`;

    if (tapOnly) {
      url += url.includes('?') ? '&tap_only=true' : '?tap_only=true';
    }

    const headers: Record<string, string> = {
      'User-Agent': this.agentIdentity,
    };

    if (this.cachedToken) {
      headers['Authorization'] = `Bearer ${this.cachedToken}`;
    }

    const res = await fetch(url, { headers });

    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as Record<string, unknown>;
      throw new Error(
        (body.message as string) || `TAP agent listing failed with status ${res.status}`
      );
    }

    return await res.json() as TAPAgentListResponse;
  }

  /**
   * Create a TAP session after agent verification.
   *
   * @param options - Session options including agent_id, user_context, and intent
   * @returns TAP session details including session_id and expiry
   * @throws Error if session creation fails
   *
   * @example
   * ```typescript
   * const session = await client.createTAPSession({
   *   agent_id: 'agent_abc123',
   *   user_context: 'user-hash',
   *   intent: { action: 'browse', resource: 'products', duration: 3600 },
   * });
   * console.log(session.session_id, session.expires_at);
   * ```
   */
  async createTAPSession(options: CreateTAPSessionOptions): Promise<TAPSessionResponse> {
    const res = await fetch(`${this.baseUrl}/v1/sessions/tap`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': this.agentIdentity,
      },
      body: JSON.stringify(options),
    });

    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as Record<string, unknown>;
      throw new Error(
        (body.message as string) || `TAP session creation failed with status ${res.status}`
      );
    }

    return await res.json() as TAPSessionResponse;
  }

  /**
   * Get a TAP session by ID.
   *
   * @param sessionId - The session ID to retrieve
   * @returns TAP session details including time_remaining
   * @throws Error if session not found or expired
   */
  async getTAPSession(sessionId: string): Promise<TAPSessionResponse> {
    const res = await fetch(`${this.baseUrl}/v1/sessions/${encodeURIComponent(sessionId)}/tap`, {
      headers: { 'User-Agent': this.agentIdentity },
    });

    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as Record<string, unknown>;
      throw new Error(
        (body.message as string) || `TAP session retrieval failed with status ${res.status}`
      );
    }

    return await res.json() as TAPSessionResponse;
  }

  /**
   * Helper method for making authenticated requests to the BOTCHA API
   */
  private async request(method: string, path: string, body?: any): Promise<any> {
    const headers: Record<string, string> = {
      'User-Agent': this.agentIdentity,
    };

    if (body !== undefined) {
      headers['Content-Type'] = 'application/json';
    }

    if (this.cachedToken) {
      headers['Authorization'] = `Bearer ${this.cachedToken}`;
    }

    const res = await fetch(`${this.baseUrl}${path}`, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });

    if (!res.ok) {
      const errorBody = await res.json().catch(() => ({})) as Record<string, unknown>;
      throw new Error(
        (errorBody.message as string) || `Request failed with status ${res.status}`
      );
    }

    return await res.json();
  }

  // ============ JWKS & KEY MANAGEMENT ============

  /**
   * Get the JWK Set for an app's TAP agents.
   * Fetches from /.well-known/jwks endpoint.
   *
   * @param appId - Optional app ID (uses client's appId if not specified)
   * @returns JWK Set with keys array
   * @throws Error if request fails
   *
   * @example
   * ```typescript
   * const jwks = await client.getJWKS();
   * console.log(jwks.keys); // Array of JWK objects
   * ```
   */
  async getJWKS(appId?: string): Promise<JWKSet> {
    const params = appId ? `?app_id=${encodeURIComponent(appId)}` : this.appId ? `?app_id=${encodeURIComponent(this.appId)}` : '';
    return await this.request('GET', `/.well-known/jwks${params}`) as JWKSet;
  }

  /**
   * Get a specific public key by key ID.
   *
   * @param keyId - The key identifier (agent_id)
   * @returns JWK object with key data
   * @throws Error if key not found
   *
   * @example
   * ```typescript
   * const key = await client.getKeyById('agent_abc123');
   * console.log(key.kid, key.alg);
   * ```
   */
  async getKeyById(keyId: string): Promise<JWK> {
    return await this.request('GET', `/v1/keys/${encodeURIComponent(keyId)}`) as JWK;
  }

  /**
   * Rotate an agent's key pair.
   *
   * @param agentId - The agent ID
   * @param options - Key rotation options including public_key and signature_algorithm
   * @returns Updated agent response
   * @throws Error if rotation fails
   *
   * @example
   * ```typescript
   * const agent = await client.rotateAgentKey('agent_abc123', {
   *   public_key: '-----BEGIN PUBLIC KEY-----...',
   *   signature_algorithm: 'ecdsa-p256-sha256',
   *   key_expires_at: '2027-01-01T00:00:00Z',
   * });
   * ```
   */
  async rotateAgentKey(agentId: string, options: {
    public_key: string;
    signature_algorithm: TAPSignatureAlgorithm;
    key_expires_at?: string;
  }): Promise<TAPAgentResponse> {
    return await this.request('POST', `/v1/agents/${encodeURIComponent(agentId)}/tap/rotate-key`, options) as TAPAgentResponse;
  }

  // ============ INVOICE & PAYMENT (402 Flow) ============

  /**
   * Create an invoice for gated content (402 micropayment flow).
   *
   * @param options - Invoice options including resource_uri, amount, currency, card_acceptor_id
   * @returns Invoice details with invoice_id
   * @throws Error if creation fails
   *
   * @example
   * ```typescript
   * const invoice = await client.createInvoice({
   *   resource_uri: 'https://example.com/premium-content',
   *   amount: '500',
   *   currency: 'USD',
   *   card_acceptor_id: 'CAID_ABC123',
   *   description: 'Premium article access',
   *   ttl_seconds: 3600,
   * });
   * console.log(invoice.invoice_id);
   * ```
   */
  async createInvoice(options: CreateInvoiceOptions): Promise<InvoiceResponse> {
    return await this.request('POST', '/v1/invoices', options) as InvoiceResponse;
  }

  /**
   * Get an invoice by ID.
   *
   * @param invoiceId - The invoice ID
   * @returns Invoice details including status and expiry
   * @throws Error if invoice not found
   *
   * @example
   * ```typescript
   * const invoice = await client.getInvoice('inv_abc123');
   * console.log(invoice.status, invoice.amount);
   * ```
   */
  async getInvoice(invoiceId: string): Promise<InvoiceResponse> {
    return await this.request('GET', `/v1/invoices/${encodeURIComponent(invoiceId)}`) as InvoiceResponse;
  }

  /**
   * Verify a Browsing IOU against an invoice.
   *
   * @param invoiceId - The invoice ID to verify against
   * @param iou - The Browsing IOU object with signature
   * @returns Verification result with access_token if successful
   * @throws Error if verification fails
   *
   * @example
   * ```typescript
   * const result = await client.verifyBrowsingIOU('inv_abc123', {
   *   invoiceId: 'inv_abc123',
   *   amount: '500',
   *   cardAcceptorId: 'CAID_ABC123',
   *   acquirerId: 'ACQ_XYZ',
   *   uri: 'https://example.com/premium-content',
   *   sequenceCounter: '1',
   *   paymentService: 'agent-pay',
   *   kid: 'agent_def456',
   *   alg: 'ES256',
   *   signature: 'base64-signature...',
   * });
   * console.log(result.verified, result.access_token);
   * ```
   */
  async verifyBrowsingIOU(invoiceId: string, iou: BrowsingIOU): Promise<VerifyIOUResponse> {
    return await this.request('POST', `/v1/invoices/${encodeURIComponent(invoiceId)}/verify-iou`, iou) as VerifyIOUResponse;
  }

  // ============ Delegation Chain Methods ============

  /**
   * Create a delegation from one agent to another.
   * Grants a subset of the grantor's capabilities to the grantee.
   * 
   * @example
   * ```typescript
   * const delegation = await client.createDelegation({
   *   grantor_id: 'agent_abc123',
   *   grantee_id: 'agent_def456',
   *   capabilities: [{ action: 'browse', scope: ['products'] }],
   *   duration_seconds: 3600,
   * });
   * ```
   */
  async createDelegation(options: CreateDelegationOptions): Promise<DelegationResponse> {
    return await this.request('POST', '/v1/delegations', options) as DelegationResponse;
  }

  /**
   * Get delegation details by ID.
   */
  async getDelegation(delegationId: string): Promise<DelegationResponse> {
    return await this.request('GET', `/v1/delegations/${encodeURIComponent(delegationId)}`) as DelegationResponse;
  }

  /**
   * List delegations for an agent.
   * 
   * @param agentId - The agent to list delegations for
   * @param options - Optional filters
   */
  async listDelegations(agentId: string, options?: {
    direction?: 'in' | 'out' | 'both';
    include_revoked?: boolean;
    include_expired?: boolean;
  }): Promise<DelegationListResponse> {
    const params = new URLSearchParams({ agent_id: agentId });
    if (options?.direction) params.set('direction', options.direction);
    if (options?.include_revoked) params.set('include_revoked', 'true');
    if (options?.include_expired) params.set('include_expired', 'true');
    return await this.request('GET', `/v1/delegations?${params.toString()}`) as DelegationListResponse;
  }

  /**
   * Revoke a delegation. Cascades to all sub-delegations.
   * 
   * @param delegationId - The delegation to revoke
   * @param reason - Optional reason for revocation
   */
  async revokeDelegation(delegationId: string, reason?: string): Promise<RevokeDelegationResponse> {
    return await this.request('POST', `/v1/delegations/${encodeURIComponent(delegationId)}/revoke`, 
      reason ? { reason } : {}
    ) as RevokeDelegationResponse;
  }

  /**
   * Verify a delegation chain is valid.
   * Returns the full chain and effective capabilities if valid.
   * 
   * @param delegationId - The leaf delegation to verify (walks up the chain)
   */
  async verifyDelegationChain(delegationId: string): Promise<DelegationVerifyResponse> {
    return await this.request('POST', '/v1/verify/delegation', { delegation_id: delegationId }) as DelegationVerifyResponse;
  }

  // ============ Capability Attestation Methods ============

  /**
   * Issue a capability attestation token for an agent.
   * Grants fine-grained "action:resource" permissions with explicit deny.
   * 
   * @example
   * ```typescript
   * const att = await client.issueAttestation({
   *   agent_id: 'agent_abc123',
   *   can: ['read:invoices', 'browse:*'],
   *   cannot: ['write:transfers'],
   *   duration_seconds: 3600,
   * });
   * // Use att.token in X-Botcha-Attestation header
   * ```
   */
  async issueAttestation(options: IssueAttestationOptions): Promise<AttestationResponse> {
    return await this.request('POST', '/v1/attestations', options) as AttestationResponse;
  }

  /**
   * Get attestation details by ID.
   */
  async getAttestation(attestationId: string): Promise<AttestationResponse> {
    return await this.request('GET', `/v1/attestations/${encodeURIComponent(attestationId)}`) as AttestationResponse;
  }

  /**
   * List attestations for an agent.
   * 
   * @param agentId - The agent to list attestations for
   */
  async listAttestations(agentId: string): Promise<AttestationListResponse> {
    const params = new URLSearchParams({ agent_id: agentId });
    return await this.request('GET', `/v1/attestations?${params.toString()}`) as AttestationListResponse;
  }

  /**
   * Revoke an attestation. Token will be rejected on future verification.
   * 
   * @param attestationId - The attestation to revoke
   * @param reason - Optional reason for revocation
   */
  async revokeAttestation(attestationId: string, reason?: string): Promise<RevokeAttestationResponse> {
    return await this.request('POST', `/v1/attestations/${encodeURIComponent(attestationId)}/revoke`,
      reason ? { reason } : {}
    ) as RevokeAttestationResponse;
  }

  /**
   * Verify an attestation token and optionally check a specific capability.
   * 
   * @param token - The attestation JWT token
   * @param action - Optional action to check (e.g. "read")
   * @param resource - Optional resource to check (e.g. "invoices")
   */
  async verifyAttestation(token: string, action?: string, resource?: string): Promise<AttestationVerifyResponse> {
    const body: Record<string, string> = { token };
    if (action) body.action = action;
    if (resource) body.resource = resource;
    return await this.request('POST', '/v1/verify/attestation', body) as AttestationVerifyResponse;
  }

  // ============ Agent Reputation Scoring Methods ============

  /**
   * Get the reputation score for an agent.
   * Returns the current score, tier, event counts, and category breakdown.
   * 
   * @example
   * ```typescript
   * const rep = await client.getReputation('agent_abc123');
   * console.log(`Score: ${rep.score}, Tier: ${rep.tier}`);
   * // Score: 750, Tier: good
   * ```
   */
  async getReputation(agentId: string): Promise<ReputationScoreResponse> {
    return await this.request('GET', `/v1/reputation/${encodeURIComponent(agentId)}`) as ReputationScoreResponse;
  }

  /**
   * Record a reputation event for an agent.
   * Adjusts the agent's score based on the event type.
   * 
   * @example
   * ```typescript
   * const result = await client.recordReputationEvent({
   *   agent_id: 'agent_abc123',
   *   category: 'verification',
   *   action: 'challenge_solved',
   * });
   * console.log(`New score: ${result.score.score}`);
   * ```
   */
  async recordReputationEvent(options: RecordReputationEventOptions): Promise<ReputationEventResponse> {
    return await this.request('POST', '/v1/reputation/events', options) as ReputationEventResponse;
  }

  /**
   * List reputation events for an agent.
   * 
   * @param agentId - The agent to list events for
   * @param options - Optional filters (category, limit)
   */
  async listReputationEvents(agentId: string, options?: {
    category?: string;
    limit?: number;
  }): Promise<ReputationEventListResponse> {
    const params = new URLSearchParams();
    if (options?.category) params.set('category', options.category);
    if (options?.limit) params.set('limit', options.limit.toString());
    const query = params.toString();
    const path = `/v1/reputation/${encodeURIComponent(agentId)}/events${query ? `?${query}` : ''}`;
    return await this.request('GET', path) as ReputationEventListResponse;
  }

  /**
   * Reset an agent's reputation to default (admin action).
   * Clears all event history and resets score to 500 (neutral).
   * 
   * @param agentId - The agent to reset
   */
  async resetReputation(agentId: string): Promise<ReputationResetResponse> {
    return await this.request('POST', `/v1/reputation/${encodeURIComponent(agentId)}/reset`) as ReputationResetResponse;
  }
}

/**
 * Convenience function for one-off solves
 * 
 * @example
 * ```typescript
 * const answers = solveBotcha([123456, 789012]);
 * // Returns: ['a1b2c3d4', 'e5f6g7h8']
 * ```
 */
export function solveBotcha(problems: number[]): string[] {
  return problems.map(num =>
    crypto.createHash('sha256').update(num.toString()).digest('hex').substring(0, 8)
  );
}

export default BotchaClient;

function normalizeProblems(problems: SpeedProblem[]): number[] | null {
  if (!Array.isArray(problems)) return null;
  const numbers: number[] = [];
  for (const problem of problems) {
    if (typeof problem === 'number') {
      numbers.push(problem);
      continue;
    }
    if (typeof problem === 'object' && problem !== null && typeof problem.num === 'number') {
      numbers.push(problem.num);
      continue;
    }
    return null;
  }
  return numbers;
}

function solveStandardPuzzle(puzzle: string): string {
  const primeMatch = puzzle.match(/first\s+(\d+)\s+prime/i);
  if (!primeMatch) {
    throw new Error('Unsupported standard challenge puzzle format');
  }
  const primeCount = Number.parseInt(primeMatch[1], 10);
  if (!Number.isFinite(primeCount) || primeCount <= 0) {
    throw new Error('Invalid prime count in puzzle');
  }
  const primes = generatePrimes(primeCount);
  const concatenated = primes.join('');
  const hash = crypto.createHash('sha256').update(concatenated).digest('hex');
  return hash.substring(0, 16);
}

function generatePrimes(count: number): number[] {
  const primes: number[] = [];
  let num = 2;

  while (primes.length < count) {
    if (isPrime(num)) {
      primes.push(num);
    }
    num++;
  }

  return primes;
}

function isPrime(n: number): boolean {
  if (n < 2) return false;
  if (n === 2) return true;
  if (n % 2 === 0) return false;

  for (let i = 3; i <= Math.sqrt(n); i += 2) {
    if (n % i === 0) return false;
  }

  return true;
}

function canRetryBody(body: RequestInit['body']): boolean {
  if (body == null) return true;
  if (typeof body === 'string') return true;
  if (body instanceof URLSearchParams) return true;
  if (body instanceof ArrayBuffer) return true;
  if (ArrayBuffer.isView(body)) return true;
  if (typeof Blob !== 'undefined' && body instanceof Blob) return true;
  if (typeof FormData !== 'undefined' && body instanceof FormData) return true;
  return false;
}
