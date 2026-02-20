/**
 * TAP-Enhanced Agent Registry
 * Extends the basic BOTCHA agent registry with Trusted Agent Protocol features
 * 
 * Provides enterprise-grade cryptographic agent authentication with:
 * - HTTP Message Signatures (RFC 9421)
 * - Capability-based access control
 * - Intent declaration and validation
 * - Session management with expiration
 */

import { Agent, KVNamespace, generateAgentId } from './agents.js';

// ============ TAP TYPES ============

/**
 * TAP-enhanced agent record (backward compatible with Agent)
 */
export interface TAPAgent extends Agent {
  // Cryptographic identity (optional for backward compatibility)
  public_key?: string;           // PEM-encoded public key
  signature_algorithm?: 'ecdsa-p256-sha256' | 'rsa-pss-sha256' | 'ed25519';
  key_created_at?: number;       // When the key was generated
  key_expires_at?: number;       // When the key expires (epoch ms)
  
  // Capabilities and permissions
  capabilities?: TAPCapability[];
  trust_level?: 'basic' | 'verified' | 'enterprise';
  
  // TAP metadata
  issuer?: string;              // Who issued/verified this agent
  tap_enabled?: boolean;        // Whether agent supports TAP
  last_verified_at?: number;    // Last successful TAP verification

  // ANS (Agent Name Service) integration
  ans_name?: string;            // ANS name e.g. "ans://v1.0.myagent.example.com"
  ans_badge_id?: string;        // BOTCHA-issued ANS verification badge ID
  ans_trust_level?: 'domain-validated' | 'key-validated' | 'behavior-validated';
  ans_verified_at?: number;     // When ANS verification was last performed
  // W3C DID — optional self-sovereign identity for the agent
  // When set, this DID is embedded as credentialSubject.id in issued VCs.
  // Accepts any valid DID (e.g. did:web:example.com:agents:my-agent, did:key:z6Mk...).
  did?: string;}

/** Valid TAP capability actions — single source of truth */
export const TAP_VALID_ACTIONS = ['browse', 'compare', 'purchase', 'audit', 'search'] as const;
export type TAPAction = typeof TAP_VALID_ACTIONS[number];

export interface TAPCapability {
  action: TAPAction;
  scope?: string[];             // Resource patterns ['products', 'orders', '*']
  restrictions?: {
    max_amount?: number;        // For purchase actions
    rate_limit?: number;        // Requests per hour
    [key: string]: any;
  };
}

export interface TAPSession {
  session_id: string;
  agent_id: string;
  app_id: string;
  user_context: string;         // Anonymous hash of user ID
  capabilities: TAPCapability[];
  intent: TAPIntent;
  created_at: number;
  expires_at: number;
}

export interface TAPIntent {
  action: string;
  resource?: string;
  scope?: string[];
  duration?: number;            // Session duration in seconds
}

// ============ TAP AGENT MANAGEMENT ============

/**
 * Register an agent with TAP capabilities
 */
export async function registerTAPAgent(
  agents: KVNamespace,
  appId: string,
  registration: {
    name: string;
    operator?: string;
    version?: string;
    public_key?: string;
    signature_algorithm?: 'ecdsa-p256-sha256' | 'rsa-pss-sha256' | 'ed25519';
    capabilities?: TAPCapability[];
    trust_level?: 'basic' | 'verified' | 'enterprise';
    issuer?: string;
    ans_name?: string;   // optional ANS identity link
    /** Optional W3C DID for this agent — embedded as credentialSubject.id in issued VCs */
    did?: string;  }
): Promise<{ success: boolean; agent?: TAPAgent; error?: string }> {
  try {
    const agentId = generateAgentId();
    const now = Date.now();
    
    const agent: TAPAgent = {
      agent_id: agentId,
      app_id: appId,
      name: registration.name,
      operator: registration.operator,
      version: registration.version,
      created_at: now,
      
      // TAP fields
      public_key: registration.public_key,
      signature_algorithm: registration.signature_algorithm,
      key_created_at: registration.public_key ? now : undefined,
      capabilities: registration.capabilities || [],
      trust_level: registration.trust_level || 'basic',
      issuer: registration.issuer,
      tap_enabled: Boolean(registration.public_key),
      last_verified_at: undefined,

      // ANS fields
      ans_name: registration.ans_name,
      // W3C DID (optional)
      did: registration.did,    };

    // Validate TAP configuration
    if (agent.public_key) {
      if (!agent.signature_algorithm) {
        return { success: false, error: 'signature_algorithm required when public_key provided' };
      }
      
      // Validate public key format
      if (!isValidPublicKey(agent.public_key, agent.signature_algorithm)) {
        return { success: false, error: 'Invalid public key format' };
      }
    }

    // Store agent
    await agents.put(`agent:${agentId}`, JSON.stringify(agent));
    
    // Update app's agent index
    await updateAppAgentIndex(agents, appId, agentId, 'add');
    
    return { success: true, agent };
    
  } catch (error) {
    console.error('Failed to register TAP agent:', error);
    return { success: false, error: 'Internal server error' };
  }
}

/**
 * Get agent with TAP capabilities
 */
export async function getTAPAgent(
  agents: KVNamespace,
  agentId: string
): Promise<{ success: boolean; agent?: TAPAgent; error?: string }> {
  try {
    const agentData = await agents.get(`agent:${agentId}`, 'text');
    if (!agentData) {
      return { success: false, error: 'Agent not found' };
    }
    
    const agent = JSON.parse(agentData) as TAPAgent;
    return { success: true, agent };
    
  } catch (error) {
    console.error('Failed to get TAP agent:', error);
    return { success: false, error: 'Internal server error' };
  }
}

/**
 * Update agent's last verification timestamp
 */
export async function updateAgentVerification(
  agents: KVNamespace,
  agentId: string,
  verificationSuccess: boolean
): Promise<void> {
  try {
    const result = await getTAPAgent(agents, agentId);
    if (result.success && result.agent) {
      result.agent.last_verified_at = verificationSuccess ? Date.now() : result.agent.last_verified_at;
      await agents.put(`agent:${agentId}`, JSON.stringify(result.agent));
    }
  } catch (error) {
    console.error('Failed to update agent verification:', error);
    // Fail silently - verification updates are not critical
  }
}

/**
 * List TAP-enabled agents for an app
 */
export async function listTAPAgents(
  agents: KVNamespace,
  appId: string,
  tapOnly: boolean = false
): Promise<{ success: boolean; agents?: TAPAgent[]; error?: string }> {
  try {
    const indexData = await agents.get(`app_agents:${appId}`, 'text');
    if (!indexData) {
      return { success: true, agents: [] };
    }
    
    const agentIds = JSON.parse(indexData) as string[];
    const agentPromises = agentIds.map(id => getTAPAgent(agents, id));
    const results = await Promise.all(agentPromises);
    
    const tapAgents = results
      .filter(r => r.success && r.agent)
      .map(r => r.agent!)
      .filter(agent => !tapOnly || agent.tap_enabled);
    
    return { success: true, agents: tapAgents };
    
  } catch (error) {
    console.error('Failed to list TAP agents:', error);
    return { success: false, error: 'Internal server error' };
  }
}

// ============ TAP SESSION MANAGEMENT ============

/**
 * Create a TAP session after successful verification
 */
export async function createTAPSession(
  sessions: KVNamespace,
  agentId: string,
  appId: string,
  userContext: string,
  capabilities: TAPCapability[],
  intent: TAPIntent
): Promise<{ success: boolean; session?: TAPSession; error?: string }> {
  try {
    const sessionId = generateSessionId();
    const now = Date.now();
    const MAX_SESSION_DURATION = 86400; // 24 hours max
    const duration = Math.min(intent.duration || 3600, MAX_SESSION_DURATION);
    const expiresAt = now + duration * 1000;
    
    const session: TAPSession = {
      session_id: sessionId,
      agent_id: agentId,
      app_id: appId,
      user_context: userContext,
      capabilities,
      intent,
      created_at: now,
      expires_at: expiresAt
    };
    
    // Store session with TTL
    const ttlSeconds = Math.floor((expiresAt - now) / 1000);
    await sessions.put(`session:${sessionId}`, JSON.stringify(session), {
      expirationTtl: ttlSeconds
    });
    
    return { success: true, session };
    
  } catch (error) {
    console.error('Failed to create TAP session:', error);
    return { success: false, error: 'Internal server error' };
  }
}

/**
 * Get and validate TAP session
 */
export async function getTAPSession(
  sessions: KVNamespace,
  sessionId: string
): Promise<{ success: boolean; session?: TAPSession; error?: string }> {
  try {
    const sessionData = await sessions.get(`session:${sessionId}`, 'text');
    if (!sessionData) {
      return { success: false, error: 'Session not found or expired' };
    }
    
    const session = JSON.parse(sessionData) as TAPSession;
    
    // Double-check expiration
    if (Date.now() > session.expires_at) {
      return { success: false, error: 'Session expired' };
    }
    
    return { success: true, session };
    
  } catch (error) {
    console.error('Failed to get TAP session:', error);
    return { success: false, error: 'Internal server error' };
  }
}

// ============ UTILITY FUNCTIONS ============

function generateSessionId(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Returns true if the string is a valid JWK JSON (EC, RSA, or OKP public key).
 * Accepts a raw JWK JSON string.
 */
export function isValidJWK(key: string): boolean {
  try {
    const jwk = JSON.parse(key);
    if (!jwk || typeof jwk !== 'object') return false;
    if (!jwk.kty) return false;
    if (jwk.kty === 'EC') return Boolean(jwk.crv && jwk.x && jwk.y);
    if (jwk.kty === 'RSA') return Boolean(jwk.n && jwk.e);
    if (jwk.kty === 'OKP') return Boolean(jwk.crv && jwk.x);
    return false;
  } catch {
    return false;
  }
}

function isValidPublicKey(key: string, algorithm?: string): boolean {
  // PEM format
  if (key.includes('BEGIN PUBLIC KEY') && key.includes('END PUBLIC KEY') && key.length > 100) {
    return true;
  }
  // JWK JSON string (EC P-256, RSA, or OKP/Ed25519)
  if (isValidJWK(key)) return true;
  // Raw Ed25519 key (32 bytes = ~44 base64 chars)
  if (algorithm === 'ed25519') {
    const stripped = key.replace(/[\s]/g, '');
    try {
      const decoded = atob(stripped.replace(/-/g, '+').replace(/_/g, '/'));
      return decoded.length === 32;
    } catch { return false; }
  }
  return false;
}

async function updateAppAgentIndex(
  agents: KVNamespace,
  appId: string,
  agentId: string,
  operation: 'add' | 'remove'
): Promise<void> {
  try {
    const indexData = await agents.get(`app_agents:${appId}`, 'text');
    let agentIds: string[] = indexData ? JSON.parse(indexData) : [];
    
    if (operation === 'add' && !agentIds.includes(agentId)) {
      agentIds.push(agentId);
    } else if (operation === 'remove') {
      agentIds = agentIds.filter(id => id !== agentId);
    }
    
    await agents.put(`app_agents:${appId}`, JSON.stringify(agentIds));
  } catch (error) {
    console.error('Failed to update agent index:', error);
    // Fail silently - index updates are not critical
  }
}

// ============ CAPABILITY VALIDATION ============

export function validateCapability(
  agentCapabilities: TAPCapability[],
  requiredAction: string,
  requiredScope?: string
): { valid: boolean; error?: string } {
  const matchingCaps = agentCapabilities.filter(cap => cap.action === requiredAction);
  
  if (matchingCaps.length === 0) {
    return { valid: false, error: `Agent lacks capability: ${requiredAction}` };
  }
  
  if (!requiredScope) {
    return { valid: true };
  }
  
  const hasScope = matchingCaps.some(cap => 
    !cap.scope || 
    cap.scope.includes('*') || 
    cap.scope.includes(requiredScope)
  );
  
  if (!hasScope) {
    return { valid: false, error: `Agent lacks scope '${requiredScope}' for action '${requiredAction}'` };
  }
  
  return { valid: true };
}

export default {
  registerTAPAgent,
  getTAPAgent,
  listTAPAgents,
  updateAgentVerification,
  createTAPSession,
  getTAPSession,
  validateCapability
};