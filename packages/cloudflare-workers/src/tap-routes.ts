/**
 * TAP-Enhanced Agent API Routes
 * Extends existing BOTCHA agent API with Trusted Agent Protocol features
 * 
 * Provides backward-compatible endpoints with optional TAP functionality
 */

import type { Context } from 'hono';
import { extractBearerToken, verifyToken } from './auth';
import { 
  registerTAPAgent, 
  getTAPAgent, 
  listTAPAgents, 
  updateAgentVerification,
  createTAPSession,
  getTAPSession,
  validateCapability,
  TAPAgent,
  TAPCapability
} from './tap-agents';
import { 
  verifyHTTPMessageSignature,
  parseTAPIntent,
  extractTAPHeaders,
  TAPVerificationResult
} from './tap-verify';

// ============ VALIDATION HELPERS ============

async function validateAppAccess(c: Context, requireAuth: boolean = true): Promise<{
  valid: boolean;
  appId?: string;
  error?: string;
  status?: number;
}> {
  // Extract app_id from query param or JWT
  const queryAppId = c.req.query('app_id');
  
  // Try to get from JWT Bearer token
  let jwtAppId: string | undefined;
  const authHeader = c.req.header('authorization');
  const token = extractBearerToken(authHeader);
  
  if (token) {
    const result = await verifyToken(token, c.env.JWT_SECRET, c.env);
    if (result.valid && result.payload) {
      jwtAppId = (result.payload as any).app_id;
    }
  }
  
  const appId = queryAppId || jwtAppId;
  
  if (requireAuth && !appId) {
    return {
      valid: false,
      error: 'MISSING_APP_ID',
      status: 401
    };
  }
  
  // TODO: Validate app exists (integrate with existing app validation)
  
  return { valid: true, appId };
}

function validateTAPRegistration(body: any): {
  valid: boolean;
  data?: {
    name: string;
    operator?: string;
    version?: string;
    public_key?: string;
    signature_algorithm?: 'ecdsa-p256-sha256' | 'rsa-pss-sha256';
    capabilities?: TAPCapability[];
    trust_level?: 'basic' | 'verified' | 'enterprise';
    issuer?: string;
  };
  error?: string;
} {
  if (!body.name || typeof body.name !== 'string') {
    return { valid: false, error: 'Agent name is required' };
  }
  
  // Validate public key if provided
  if (body.public_key) {
    if (!body.signature_algorithm) {
      return { valid: false, error: 'signature_algorithm required when public_key provided' };
    }
    
    const validAlgorithms = ['ecdsa-p256-sha256', 'rsa-pss-sha256'];
    if (!validAlgorithms.includes(body.signature_algorithm)) {
      return { valid: false, error: `Unsupported algorithm. Supported: ${validAlgorithms.join(', ')}` };
    }
    
    if (!body.public_key.includes('BEGIN PUBLIC KEY')) {
      return { valid: false, error: 'Invalid PEM public key format' };
    }
  }
  
  // Validate capabilities if provided
  if (body.capabilities) {
    if (!Array.isArray(body.capabilities)) {
      return { valid: false, error: 'Capabilities must be an array' };
    }
    
    const validActions = ['browse', 'compare', 'purchase', 'audit', 'search'];
    for (const cap of body.capabilities) {
      if (!cap.action || !validActions.includes(cap.action)) {
        return { valid: false, error: `Invalid capability action. Valid: ${validActions.join(', ')}` };
      }
    }
  }
  
  return {
    valid: true,
    data: {
      name: body.name,
      operator: body.operator,
      version: body.version,
      public_key: body.public_key,
      signature_algorithm: body.signature_algorithm,
      capabilities: body.capabilities,
      trust_level: body.trust_level || 'basic',
      issuer: body.issuer
    }
  };
}

// ============ TAP AGENT ROUTES ============

/**
 * POST /v1/agents/register/tap
 * Enhanced agent registration with TAP capabilities
 */
export async function registerTAPAgentRoute(c: Context) {
  try {
    // Validate app access
    const appAccess = await validateAppAccess(c, true);
    if (!appAccess.valid) {
      return c.json({
        success: false,
        error: appAccess.error,
        message: 'Authentication required'
      }, appAccess.status);
    }
    
    // Parse and validate request body
    const body = await c.req.json().catch(() => ({}));
    const validation = validateTAPRegistration(body);
    
    if (!validation.valid) {
      return c.json({
        success: false,
        error: 'INVALID_REQUEST',
        message: validation.error
      }, 400);
    }
    
    // Register TAP-enhanced agent
    const result = await registerTAPAgent(
      c.env.AGENTS,
      appAccess.appId!,
      validation.data!
    );
    
    if (!result.success) {
      return c.json({
        success: false,
        error: 'AGENT_CREATION_FAILED',
        message: result.error || 'Failed to create agent'
      }, 500);
    }
    
    const agent = result.agent!;
    
    // Return enhanced agent info
    return c.json({
      success: true,
      agent_id: agent.agent_id,
      app_id: agent.app_id,
      name: agent.name,
      operator: agent.operator,
      version: agent.version,
      created_at: new Date(agent.created_at).toISOString(),
      
      // TAP-specific fields
      tap_enabled: agent.tap_enabled,
      trust_level: agent.trust_level,
      capabilities: agent.capabilities,
      signature_algorithm: agent.signature_algorithm,
      issuer: agent.issuer,
      
      // Security info (don't expose full public key)
      has_public_key: Boolean(agent.public_key),
      key_fingerprint: agent.public_key ? 
        generateKeyFingerprint(agent.public_key) : undefined
    }, 201);
    
  } catch (error) {
    console.error('TAP agent registration error:', error);
    return c.json({
      success: false,
      error: 'INTERNAL_ERROR',
      message: 'Internal server error'
    }, 500);
  }
}

/**
 * GET /v1/agents/:id/tap
 * Get agent with TAP capabilities
 */
export async function getTAPAgentRoute(c: Context) {
  try {
    const agentId = c.req.param('id');
    if (!agentId) {
      return c.json({
        success: false,
        error: 'MISSING_AGENT_ID',
        message: 'Agent ID is required'
      }, 400);
    }
    
    const result = await getTAPAgent(c.env.AGENTS, agentId);
    
    if (!result.success) {
      return c.json({
        success: false,
        error: 'AGENT_NOT_FOUND',
        message: result.error || 'Agent not found'
      }, 404);
    }
    
    const agent = result.agent!;
    
    return c.json({
      success: true,
      agent_id: agent.agent_id,
      app_id: agent.app_id,
      name: agent.name,
      operator: agent.operator,
      version: agent.version,
      created_at: new Date(agent.created_at).toISOString(),
      
      // TAP info
      tap_enabled: agent.tap_enabled,
      trust_level: agent.trust_level,
      capabilities: agent.capabilities,
      signature_algorithm: agent.signature_algorithm,
      issuer: agent.issuer,
      last_verified_at: agent.last_verified_at ? 
        new Date(agent.last_verified_at).toISOString() : null,
      
      // Public key info (secure)
      has_public_key: Boolean(agent.public_key),
      key_fingerprint: agent.public_key ? 
        generateKeyFingerprint(agent.public_key) : undefined,
      public_key: agent.public_key // Include for verification
    });
    
  } catch (error) {
    console.error('TAP agent retrieval error:', error);
    return c.json({
      success: false,
      error: 'INTERNAL_ERROR',
      message: 'Internal server error'
    }, 500);
  }
}

/**
 * GET /v1/agents/tap
 * List TAP-enabled agents for an app
 */
export async function listTAPAgentsRoute(c: Context) {
  try {
    const appAccess = await validateAppAccess(c, true);
    if (!appAccess.valid) {
      return c.json({
        success: false,
        error: appAccess.error,
        message: 'Authentication required'
      }, appAccess.status);
    }
    
    const tapOnly = c.req.query('tap_only') === 'true';
    
    const result = await listTAPAgents(c.env.AGENTS, appAccess.appId!, tapOnly);
    
    if (!result.success) {
      return c.json({
        success: false,
        error: 'LIST_FAILED',
        message: result.error || 'Failed to list agents'
      }, 500);
    }
    
    const agents = result.agents!.map(agent => ({
      agent_id: agent.agent_id,
      name: agent.name,
      operator: agent.operator,
      version: agent.version,
      created_at: new Date(agent.created_at).toISOString(),
      tap_enabled: agent.tap_enabled,
      trust_level: agent.trust_level,
      capabilities: agent.capabilities,
      last_verified_at: agent.last_verified_at ? 
        new Date(agent.last_verified_at).toISOString() : null
    }));
    
    return c.json({
      success: true,
      agents,
      count: agents.length,
      tap_enabled_count: agents.filter(a => a.tap_enabled).length
    });
    
  } catch (error) {
    console.error('TAP agent listing error:', error);
    return c.json({
      success: false,
      error: 'INTERNAL_ERROR',
      message: 'Internal server error'
    }, 500);
  }
}

// ============ TAP SESSION ROUTES ============

/**
 * POST /v1/sessions/tap
 * Create TAP session after verification
 */
export async function createTAPSessionRoute(c: Context) {
  try {
    const body = await c.req.json().catch(() => ({}));
    
    if (!body.agent_id || !body.user_context || !body.intent) {
      return c.json({
        success: false,
        error: 'MISSING_REQUIRED_FIELDS',
        message: 'agent_id, user_context, and intent are required'
      }, 400);
    }
    
    // Get agent
    const agentResult = await getTAPAgent(c.env.AGENTS, body.agent_id);
    if (!agentResult.success) {
      return c.json({
        success: false,
        error: 'AGENT_NOT_FOUND',
        message: 'Agent not found'
      }, 404);
    }
    
    const agent = agentResult.agent!;
    
    // Parse intent
    const intentResult = parseTAPIntent(JSON.stringify(body.intent));
    if (!intentResult.valid) {
      return c.json({
        success: false,
        error: 'INVALID_INTENT',
        message: intentResult.error
      }, 400);
    }
    
    // Validate capability
    const capabilityCheck = validateCapability(
      agent.capabilities || [],
      intentResult.intent!.action,
      intentResult.intent!.resource
    );
    
    if (!capabilityCheck.valid) {
      return c.json({
        success: false,
        error: 'INSUFFICIENT_CAPABILITY',
        message: capabilityCheck.error
      }, 403);
    }
    
    // Create session
    const sessionResult = await createTAPSession(
      c.env.SESSIONS,
      agent.agent_id,
      agent.app_id,
      body.user_context,
      agent.capabilities || [],
      intentResult.intent!
    );
    
    if (!sessionResult.success) {
      return c.json({
        success: false,
        error: 'SESSION_CREATION_FAILED',
        message: sessionResult.error
      }, 500);
    }
    
    const session = sessionResult.session!;
    
    return c.json({
      success: true,
      session_id: session.session_id,
      agent_id: session.agent_id,
      capabilities: session.capabilities,
      intent: session.intent,
      expires_at: new Date(session.expires_at).toISOString()
    }, 201);
    
  } catch (error) {
    console.error('TAP session creation error:', error);
    return c.json({
      success: false,
      error: 'INTERNAL_ERROR',
      message: 'Internal server error'
    }, 500);
  }
}

/**
 * GET /v1/sessions/:id/tap
 * Get TAP session info
 */
export async function getTAPSessionRoute(c: Context) {
  try {
    const sessionId = c.req.param('id');
    if (!sessionId) {
      return c.json({
        success: false,
        error: 'MISSING_SESSION_ID',
        message: 'Session ID is required'
      }, 400);
    }
    
    const result = await getTAPSession(c.env.SESSIONS, sessionId);
    
    if (!result.success) {
      return c.json({
        success: false,
        error: 'SESSION_NOT_FOUND',
        message: result.error || 'Session not found or expired'
      }, 404);
    }
    
    const session = result.session!;
    
    return c.json({
      success: true,
      session_id: session.session_id,
      agent_id: session.agent_id,
      app_id: session.app_id,
      capabilities: session.capabilities,
      intent: session.intent,
      created_at: new Date(session.created_at).toISOString(),
      expires_at: new Date(session.expires_at).toISOString(),
      time_remaining: Math.max(0, session.expires_at - Date.now())
    });
    
  } catch (error) {
    console.error('TAP session retrieval error:', error);
    return c.json({
      success: false,
      error: 'INTERNAL_ERROR', 
      message: 'Internal server error'
    }, 500);
  }
}

// ============ UTILITY FUNCTIONS ============

function generateKeyFingerprint(publicKey: string): string {
  // Simple fingerprint generation - in production use proper crypto hash
  const normalized = publicKey.replace(/\s/g, '').replace(/-----[^-]+-----/g, '');
  let hash = 0;
  for (let i = 0; i < normalized.length; i++) {
    const char = normalized.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash; // Convert to 32-bit integer
  }
  return Math.abs(hash).toString(16).padStart(8, '0');
}

export default {
  registerTAPAgentRoute,
  getTAPAgentRoute,
  listTAPAgentsRoute,
  createTAPSessionRoute,
  getTAPSessionRoute
};