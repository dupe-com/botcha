/**
 * BOTCHA Agent Registry
 * 
 * Agent registration and management:
 * - Crypto-random agent IDs
 * - KV storage for agent metadata
 * - App-scoped agent lists
 * - Fail-open design for resilience
 */

// KV binding type (matches Cloudflare Workers KV API)
export type KVNamespace = {
  get: (key: string, type?: 'text' | 'json' | 'arrayBuffer' | 'stream') => Promise<any>;
  put: (key: string, value: string, options?: { expirationTtl?: number }) => Promise<void>;
  delete: (key: string) => Promise<void>;
};

// ============ TYPES ============

/**
 * Agent record stored in KV
 */
export interface Agent {
  agent_id: string;       // Unique ID like "agent_" + 16 hex chars
  app_id: string;         // Parent app that owns this agent
  name: string;           // Human-readable agent name
  operator?: string;      // Optional operator/company name  
  version?: string;       // Optional agent version
  created_at: number;     // Unix timestamp ms
}

// ============ CRYPTO UTILITIES ============

/**
 * Generate a crypto-random agent ID
 * Format: 'agent_' + 16 hex chars
 * 
 * Example: agent_a1b2c3d4e5f6a7b8
 */
export function generateAgentId(): string {
  const bytes = new Uint8Array(8); // 8 bytes = 16 hex chars
  crypto.getRandomValues(bytes);
  const hexString = Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
  return `agent_${hexString}`;
}

// ============ AGENT MANAGEMENT ============

/**
 * Create a new agent and add it to the app's agent list
 * 
 * Stores in KV at:
 * - `agent:{agent_id}` — Agent record
 * - `agents:{app_id}` — Array of agent_ids for this app
 * 
 * @param kv - KV namespace for storage
 * @param app_id - Parent app that owns this agent
 * @param data - Agent metadata (name, operator, version)
 * @returns Agent record with generated agent_id
 */
export async function createAgent(
  kv: KVNamespace,
  app_id: string,
  data: { name: string; operator?: string; version?: string }
): Promise<Agent | null> {
  try {
    const agent_id = generateAgentId();

    const agent: Agent = {
      agent_id,
      app_id,
      name: data.name,
      operator: data.operator,
      version: data.version,
      created_at: Date.now(),
    };

    // Get existing agent list for this app (if any)
    let agentIds: string[] = [];
    try {
      const existingList = await kv.get(`agents:${app_id}`, 'text');
      if (existingList) {
        agentIds = JSON.parse(existingList);
      }
    } catch (error) {
      console.warn(`Failed to fetch existing agent list for app ${app_id}, starting fresh:`, error);
      // Fail-open: Continue with empty list
    }

    // Add new agent_id to the list
    agentIds.push(agent_id);

    // Read tap-agents index too, keep both in sync
    let tapAgentIds: string[] = [];
    try {
      const tapList = await kv.get(`app_agents:${app_id}`, 'text');
      if (tapList) tapAgentIds = JSON.parse(tapList);
    } catch {}
    if (!tapAgentIds.includes(agent_id)) tapAgentIds.push(agent_id);

    // Store agent record and update both index keys
    await Promise.all([
      kv.put(`agent:${agent_id}`, JSON.stringify(agent)),
      kv.put(`agents:${app_id}`, JSON.stringify(agentIds)),
      kv.put(`app_agents:${app_id}`, JSON.stringify(tapAgentIds)),
    ]);

    return agent;
  } catch (error) {
    console.error(`Failed to create agent for app ${app_id}:`, error);
    // Fail-open: Return null instead of throwing
    return null;
  }
}

/**
 * Get agent by agent_id
 * 
 * @param kv - KV namespace
 * @param agent_id - The agent ID to retrieve
 * @returns Agent record or null if not found
 */
export async function getAgent(
  kv: KVNamespace,
  agent_id: string
): Promise<Agent | null> {
  try {
    const data = await kv.get(`agent:${agent_id}`, 'text');
    
    if (!data) {
      return null;
    }

    return JSON.parse(data) as Agent;
  } catch (error) {
    console.error(`Failed to get agent ${agent_id}:`, error);
    // Fail-open: Return null instead of throwing
    return null;
  }
}

/**
 * Delete an agent and remove it from the app's agent index.
 * Also removes from the tap-agents app_agents:{appId} index if present.
 *
 * @returns true if deleted, false if not found, null on error
 */
export async function deleteAgent(
  kv: KVNamespace,
  agent_id: string,
  app_id: string
): Promise<{ success: boolean; error?: string }> {
  try {
    // Verify agent exists and belongs to the app
    const existing = await kv.get(`agent:${agent_id}`, 'text');
    if (!existing) {
      return { success: false, error: 'Agent not found' };
    }
    const agent = JSON.parse(existing) as Agent;
    if (agent.app_id !== app_id) {
      return { success: false, error: 'Agent does not belong to this app' };
    }

    // Remove agent record and update both index keys in parallel
    const [agentsRaw, appAgentsRaw] = await Promise.all([
      kv.get(`agents:${app_id}`, 'text'),
      kv.get(`app_agents:${app_id}`, 'text'),
    ]);

    const ops: Promise<void>[] = [kv.delete(`agent:${agent_id}`)];

    if (agentsRaw) {
      const ids: string[] = JSON.parse(agentsRaw).filter((id: string) => id !== agent_id);
      ops.push(kv.put(`agents:${app_id}`, JSON.stringify(ids)));
    }
    if (appAgentsRaw) {
      const ids: string[] = JSON.parse(appAgentsRaw).filter((id: string) => id !== agent_id);
      ops.push(kv.put(`app_agents:${app_id}`, JSON.stringify(ids)));
    }

    await Promise.all(ops);
    return { success: true };
  } catch (error) {
    console.error(`Failed to delete agent ${agent_id}:`, error);
    return { success: false, error: 'Internal server error' };
  }
}

/**
 * List all agents for an app
 * 
 * @param kv - KV namespace
 * @param app_id - The app ID to list agents for
 * @returns Array of agent records (empty array if none found)
 */
export async function listAgents(
  kv: KVNamespace,
  app_id: string
): Promise<Agent[]> {
  try {
    // Get the list of agent IDs for this app
    const agentIdsData = await kv.get(`agents:${app_id}`, 'text');
    
    if (!agentIdsData) {
      return [];
    }

    const agentIds: string[] = JSON.parse(agentIdsData);

    // Fetch all agent records in parallel
    const agentPromises = agentIds.map(agent_id => getAgent(kv, agent_id));
    const agents = await Promise.all(agentPromises);

    // Filter out any null results (failed fetches) and return
    return agents.filter((agent): agent is Agent => agent !== null);
  } catch (error) {
    console.error(`Failed to list agents for app ${app_id}:`, error);
    // Fail-open: Return empty array instead of throwing
    return [];
  }
}
