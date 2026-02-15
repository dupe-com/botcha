/**
 * TAP Delegation Chains
 * 
 * "User X authorized Agent Y to do Z until time T."
 * 
 * Signed, auditable chains of trust between TAP agents. A delegation grants
 * a subset of one agent's capabilities to another agent, with time bounds
 * and depth limits. Delegations can be chained (A→B→C) with each link
 * only narrowing capabilities, never expanding them.
 * 
 * Key invariants:
 * - Capabilities can only be narrowed (subset enforcement)
 * - Chain depth is capped (default max: 3)
 * - Revoking a delegation cascades to all sub-delegations
 * - Expired delegations are automatically invalid
 * - Both grantor and grantee must belong to the same app
 */

import type { KVNamespace } from './agents.js';
import { TAPCapability, TAPAction, TAP_VALID_ACTIONS, getTAPAgent, type TAPAgent } from './tap-agents.js';

// ============ TYPES ============

export interface Delegation {
  delegation_id: string;
  grantor_id: string;           // Agent granting capabilities
  grantee_id: string;           // Agent receiving capabilities
  app_id: string;               // Owning application
  capabilities: TAPCapability[];// Delegated capabilities (subset of grantor's)
  parent_delegation_id?: string;// If sub-delegation, points to parent
  chain: string[];              // Full chain: [root_agent, ..., grantee]
  depth: number;                // 0 = direct from root, 1+ = sub-delegation
  max_depth: number;            // How deep sub-delegation can go
  created_at: number;           // epoch ms
  expires_at: number;           // epoch ms
  revoked: boolean;
  revoked_at?: number;
  revocation_reason?: string;
  metadata?: Record<string, string>; // Optional context (e.g., purpose, requester)
}

export interface CreateDelegationOptions {
  grantor_id: string;
  grantee_id: string;
  capabilities: TAPCapability[];
  duration_seconds?: number;    // Default: 3600 (1 hour)
  max_depth?: number;           // Default: 3
  parent_delegation_id?: string;
  metadata?: Record<string, string>;
}

export interface DelegationResult {
  success: boolean;
  delegation?: Delegation;
  error?: string;
}

export interface DelegationListResult {
  success: boolean;
  delegations?: Delegation[];
  error?: string;
}

export interface DelegationVerifyResult {
  valid: boolean;
  chain?: Delegation[];
  effective_capabilities?: TAPCapability[];
  error?: string;
}

// ============ CONSTANTS ============

const MAX_DELEGATION_DEPTH = 10;     // Absolute max depth
const DEFAULT_MAX_DEPTH = 3;         // Default max depth
const DEFAULT_DURATION = 3600;       // 1 hour in seconds
const MAX_DURATION = 86400 * 30;     // 30 days max
const DELEGATION_PREFIX = 'del_';

// ============ CORE FUNCTIONS ============

/**
 * Generate a unique delegation ID
 */
function generateDelegationId(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return DELEGATION_PREFIX + Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Check if capabilitiesB is a subset of capabilitiesA.
 * 
 * A capability in B is valid if there exists a capability in A with the same
 * action, and B's scope is a subset of A's scope (or A has wildcard scope).
 * B's restrictions must be equal or stricter.
 */
export function isCapabilitySubset(
  parent: TAPCapability[],
  child: TAPCapability[]
): { valid: boolean; error?: string } {
  for (const childCap of child) {
    // Find matching parent capability by action
    const parentCap = parent.find(p => p.action === childCap.action);
    if (!parentCap) {
      return { 
        valid: false, 
        error: `Cannot delegate capability '${childCap.action}': grantor does not have it` 
      };
    }

    // Check scope subset
    if (childCap.scope && childCap.scope.length > 0) {
      // If parent has no scope or wildcard, child's scope is valid
      if (parentCap.scope && !parentCap.scope.includes('*')) {
        for (const s of childCap.scope) {
          if (s !== '*' && !parentCap.scope.includes(s)) {
            return { 
              valid: false, 
              error: `Cannot delegate scope '${s}' for '${childCap.action}': grantor lacks it` 
            };
          }
          // Child requesting wildcard but parent doesn't have it
          if (s === '*') {
            return { 
              valid: false, 
              error: `Cannot delegate wildcard scope for '${childCap.action}': grantor has restricted scope` 
            };
          }
        }
      }
    }

    // Check restrictions — child must be equal or stricter
    if (parentCap.restrictions) {
      if (!childCap.restrictions) {
        // Parent has restrictions but child doesn't — child is less restrictive
        // This is NOT allowed: delegated capabilities must be at least as restrictive
        return { 
          valid: false, 
          error: `Cannot delegate '${childCap.action}' without restrictions: grantor has restrictions` 
        };
      }
      
      // max_amount: child's must be <= parent's
      if (parentCap.restrictions.max_amount !== undefined) {
        if (childCap.restrictions.max_amount === undefined || 
            childCap.restrictions.max_amount > parentCap.restrictions.max_amount) {
          return { 
            valid: false, 
            error: `Cannot delegate max_amount > ${parentCap.restrictions.max_amount} for '${childCap.action}'` 
          };
        }
      }

      // rate_limit: child's must be <= parent's
      if (parentCap.restrictions.rate_limit !== undefined) {
        if (childCap.restrictions.rate_limit === undefined || 
            childCap.restrictions.rate_limit > parentCap.restrictions.rate_limit) {
          return { 
            valid: false, 
            error: `Cannot delegate rate_limit > ${parentCap.restrictions.rate_limit} for '${childCap.action}'` 
          };
        }
      }
    }
  }
  
  return { valid: true };
}

/**
 * Create a delegation from one agent to another.
 * 
 * Validates:
 * - Both agents exist and belong to the same app
 * - Grantor has the capabilities being delegated
 * - Capabilities are a valid subset (never expanded)
 * - Chain depth is within limits
 * - Parent delegation (if sub-delegation) is valid and not revoked/expired
 */
export async function createDelegation(
  agents: KVNamespace,
  sessions: KVNamespace,
  appId: string,
  options: CreateDelegationOptions
): Promise<DelegationResult> {
  try {
    // Validate basic inputs
    if (!options.grantor_id || !options.grantee_id) {
      return { success: false, error: 'grantor_id and grantee_id are required' };
    }
    if (options.grantor_id === options.grantee_id) {
      return { success: false, error: 'Cannot delegate to self' };
    }
    if (!options.capabilities || options.capabilities.length === 0) {
      return { success: false, error: 'At least one capability is required' };
    }

    // Validate capability actions
    for (const cap of options.capabilities) {
      if (!(TAP_VALID_ACTIONS as readonly string[]).includes(cap.action)) {
        return { success: false, error: `Invalid capability action: ${cap.action}` };
      }
    }

    // Validate max_depth (will be overridden for sub-delegations below)
    let maxDepth = Math.min(
      options.max_depth ?? DEFAULT_MAX_DEPTH,
      MAX_DELEGATION_DEPTH
    );

    // Get grantor agent
    const grantorResult = await getTAPAgent(agents, options.grantor_id);
    if (!grantorResult.success || !grantorResult.agent) {
      return { success: false, error: 'Grantor agent not found' };
    }
    const grantor = grantorResult.agent;

    // Get grantee agent
    const granteeResult = await getTAPAgent(agents, options.grantee_id);
    if (!granteeResult.success || !granteeResult.agent) {
      return { success: false, error: 'Grantee agent not found' };
    }
    const grantee = granteeResult.agent;

    // Verify same app
    if (grantor.app_id !== appId) {
      return { success: false, error: 'Grantor does not belong to this app' };
    }
    if (grantee.app_id !== appId) {
      return { success: false, error: 'Grantee does not belong to this app' };
    }

    // Determine effective capabilities of the grantor
    let grantorCapabilities = grantor.capabilities || [];
    let chain: string[] = [options.grantor_id, options.grantee_id];
    let depth = 0;

    // If this is a sub-delegation, validate the parent delegation
    if (options.parent_delegation_id) {
      const parentDel = await getDelegation(sessions, options.parent_delegation_id);
      if (!parentDel.success || !parentDel.delegation) {
        return { success: false, error: 'Parent delegation not found' };
      }
      
      const parent = parentDel.delegation;

      // Parent must not be revoked
      if (parent.revoked) {
        return { success: false, error: 'Parent delegation has been revoked' };
      }

      // Parent must not be expired
      if (Date.now() > parent.expires_at) {
        return { success: false, error: 'Parent delegation has expired' };
      }

      // Grantor must be the grantee of the parent delegation
      if (parent.grantee_id !== options.grantor_id) {
        return { success: false, error: 'Grantor is not the grantee of the parent delegation' };
      }

      // Must be same app
      if (parent.app_id !== appId) {
        return { success: false, error: 'Parent delegation belongs to a different app' };
      }

      // Check depth limits — inherit max_depth from parent chain
      depth = parent.depth + 1;
      maxDepth = parent.max_depth; // Always inherit from parent
      if (depth >= maxDepth) {
        return { success: false, error: `Delegation depth limit reached (max: ${maxDepth})` };
      }

      // For sub-delegations, the effective capabilities come from the parent
      grantorCapabilities = parent.capabilities;
      chain = [...parent.chain, options.grantee_id];

      // Prevent cycles
      if (parent.chain.includes(options.grantee_id)) {
        return { success: false, error: 'Delegation would create a cycle' };
      }
    }

    // Validate capability subset
    const subsetCheck = isCapabilitySubset(grantorCapabilities, options.capabilities);
    if (!subsetCheck.valid) {
      return { success: false, error: subsetCheck.error };
    }

    // Calculate expiration
    const durationSeconds = Math.min(
      options.duration_seconds ?? DEFAULT_DURATION,
      MAX_DURATION
    );

    // If sub-delegation, cannot outlive parent
    const now = Date.now();
    let expiresAt = now + durationSeconds * 1000;
    if (options.parent_delegation_id) {
      const parentDel = await getDelegation(sessions, options.parent_delegation_id);
      if (parentDel.delegation) {
        expiresAt = Math.min(expiresAt, parentDel.delegation.expires_at);
      }
    }

    // Create the delegation
    const delegationId = generateDelegationId();
    const delegation: Delegation = {
      delegation_id: delegationId,
      grantor_id: options.grantor_id,
      grantee_id: options.grantee_id,
      app_id: appId,
      capabilities: options.capabilities,
      parent_delegation_id: options.parent_delegation_id,
      chain,
      depth,
      max_depth: maxDepth,
      created_at: now,
      expires_at: expiresAt,
      revoked: false,
      metadata: options.metadata,
    };

    // Store delegation with TTL
    const ttlSeconds = Math.max(1, Math.floor((expiresAt - now) / 1000));
    await sessions.put(
      `delegation:${delegationId}`,
      JSON.stringify(delegation),
      { expirationTtl: ttlSeconds }
    );

    // Update grantor's outbound index
    await updateDelegationIndex(
      sessions, `agent_delegations_out:${options.grantor_id}`, delegationId, 'add'
    );

    // Update grantee's inbound index
    await updateDelegationIndex(
      sessions, `agent_delegations_in:${options.grantee_id}`, delegationId, 'add'
    );

    return { success: true, delegation };

  } catch (error) {
    console.error('Failed to create delegation:', error);
    return { success: false, error: 'Internal server error' };
  }
}

/**
 * Get a delegation by ID
 */
export async function getDelegation(
  sessions: KVNamespace,
  delegationId: string
): Promise<DelegationResult> {
  try {
    const data = await sessions.get(`delegation:${delegationId}`, 'text');
    if (!data) {
      return { success: false, error: 'Delegation not found or expired' };
    }

    const delegation = JSON.parse(data) as Delegation;
    return { success: true, delegation };

  } catch (error) {
    console.error('Failed to get delegation:', error);
    return { success: false, error: 'Internal server error' };
  }
}

/**
 * List delegations for an agent (inbound, outbound, or both)
 */
export async function listDelegations(
  sessions: KVNamespace,
  options: {
    agent_id?: string;
    app_id?: string;
    direction?: 'in' | 'out' | 'both';
    include_revoked?: boolean;
    include_expired?: boolean;
  }
): Promise<DelegationListResult> {
  try {
    const delegationIds = new Set<string>();
    const direction = options.direction || 'both';

    if (options.agent_id) {
      // Get delegations by agent
      if (direction === 'out' || direction === 'both') {
        const outData = await sessions.get(`agent_delegations_out:${options.agent_id}`, 'text');
        if (outData) {
          for (const id of JSON.parse(outData) as string[]) {
            delegationIds.add(id);
          }
        }
      }
      if (direction === 'in' || direction === 'both') {
        const inData = await sessions.get(`agent_delegations_in:${options.agent_id}`, 'text');
        if (inData) {
          for (const id of JSON.parse(inData) as string[]) {
            delegationIds.add(id);
          }
        }
      }
    }

    if (delegationIds.size === 0) {
      return { success: true, delegations: [] };
    }

    // Fetch all delegations
    const now = Date.now();
    const delegations: Delegation[] = [];

    for (const id of delegationIds) {
      const result = await getDelegation(sessions, id);
      if (result.success && result.delegation) {
        const d = result.delegation;

        // Filter by app_id if specified
        if (options.app_id && d.app_id !== options.app_id) continue;

        // Filter out revoked unless requested
        if (d.revoked && !options.include_revoked) continue;

        // Filter out expired unless requested
        if (now > d.expires_at && !options.include_expired) continue;

        delegations.push(d);
      }
    }

    // Sort by created_at descending (newest first)
    delegations.sort((a, b) => b.created_at - a.created_at);

    return { success: true, delegations };

  } catch (error) {
    console.error('Failed to list delegations:', error);
    return { success: false, error: 'Internal server error' };
  }
}

/**
 * Revoke a delegation and cascade to all sub-delegations.
 * 
 * When a delegation is revoked, all delegations that have it as a parent
 * (directly or transitively) are also revoked. This is enforced by marking
 * each delegation record as revoked.
 */
export async function revokeDelegation(
  sessions: KVNamespace,
  delegationId: string,
  reason?: string
): Promise<DelegationResult> {
  try {
    const result = await getDelegation(sessions, delegationId);
    if (!result.success || !result.delegation) {
      return { success: false, error: 'Delegation not found' };
    }

    const delegation = result.delegation;

    if (delegation.revoked) {
      return { success: true, delegation }; // Already revoked, idempotent
    }

    // Mark as revoked
    delegation.revoked = true;
    delegation.revoked_at = Date.now();
    delegation.revocation_reason = reason;

    // Re-store with remaining TTL (or short TTL if already expired)
    const remainingTtl = Math.max(60, Math.floor((delegation.expires_at - Date.now()) / 1000));
    await sessions.put(
      `delegation:${delegationId}`,
      JSON.stringify(delegation),
      { expirationTtl: remainingTtl }
    );

    // Cascade: find and revoke sub-delegations
    // We search the grantee's outbound delegations for any that reference this as parent
    await cascadeRevocation(sessions, delegationId, reason);

    return { success: true, delegation };

  } catch (error) {
    console.error('Failed to revoke delegation:', error);
    return { success: false, error: 'Internal server error' };
  }
}

/**
 * Recursively revoke all sub-delegations of a given delegation.
 */
async function cascadeRevocation(
  sessions: KVNamespace,
  parentDelegationId: string,
  reason?: string
): Promise<void> {
  // Get the parent delegation to find the grantee
  const parentResult = await getDelegation(sessions, parentDelegationId);
  if (!parentResult.success || !parentResult.delegation) return;

  const granteeId = parentResult.delegation.grantee_id;

  // Get grantee's outbound delegations
  const outData = await sessions.get(`agent_delegations_out:${granteeId}`, 'text');
  if (!outData) return;

  const outIds = JSON.parse(outData) as string[];

  for (const childId of outIds) {
    const childResult = await getDelegation(sessions, childId);
    if (!childResult.success || !childResult.delegation) continue;
    
    const child = childResult.delegation;
    
    // Only revoke if this child's parent is our delegation
    if (child.parent_delegation_id === parentDelegationId && !child.revoked) {
      // Revoke this child (which will cascade further)
      await revokeDelegation(sessions, childId, reason || `Parent delegation ${parentDelegationId} revoked`);
    }
  }
}

/**
 * Verify an entire delegation chain is valid.
 * 
 * Walks from the leaf delegation up through parent delegations to the root,
 * verifying each link is:
 * - Not revoked
 * - Not expired
 * - Capabilities are valid subsets
 * 
 * Returns the full chain and effective (intersected) capabilities.
 */
export async function verifyDelegationChain(
  agents: KVNamespace,
  sessions: KVNamespace,
  delegationId: string
): Promise<DelegationVerifyResult> {
  try {
    const chain: Delegation[] = [];
    let currentId: string | undefined = delegationId;
    const now = Date.now();

    // Walk up the chain
    while (currentId) {
      const result = await getDelegation(sessions, currentId);
      if (!result.success || !result.delegation) {
        return { valid: false, error: `Delegation ${currentId} not found or expired` };
      }

      const del = result.delegation;

      // Check revocation
      if (del.revoked) {
        return { 
          valid: false, 
          error: `Delegation ${currentId} has been revoked${del.revocation_reason ? ': ' + del.revocation_reason : ''}` 
        };
      }

      // Check expiration
      if (now > del.expires_at) {
        return { valid: false, error: `Delegation ${currentId} has expired` };
      }

      // Verify grantor agent exists
      const grantorResult = await getTAPAgent(agents, del.grantor_id);
      if (!grantorResult.success) {
        return { valid: false, error: `Grantor agent ${del.grantor_id} not found` };
      }

      chain.unshift(del); // Add to front (building root→leaf order)
      currentId = del.parent_delegation_id;
    }

    if (chain.length === 0) {
      return { valid: false, error: 'Empty delegation chain' };
    }

    // Verify capability narrowing at each step
    // The root delegation's capabilities must be a subset of the root grantor's capabilities
    const rootDel = chain[0];
    const rootGrantorResult = await getTAPAgent(agents, rootDel.grantor_id);
    if (!rootGrantorResult.success || !rootGrantorResult.agent) {
      return { valid: false, error: 'Root grantor agent not found' };
    }

    const rootCheck = isCapabilitySubset(
      rootGrantorResult.agent.capabilities || [],
      rootDel.capabilities
    );
    if (!rootCheck.valid) {
      return { valid: false, error: `Root delegation invalid: ${rootCheck.error}` };
    }

    // Verify each subsequent link narrows from its parent
    for (let i = 1; i < chain.length; i++) {
      const parentCaps = chain[i - 1].capabilities;
      const childCaps = chain[i].capabilities;
      
      const check = isCapabilitySubset(parentCaps, childCaps);
      if (!check.valid) {
        return { 
          valid: false, 
          error: `Chain link ${i} invalid: ${check.error}` 
        };
      }
    }

    // Effective capabilities = leaf delegation's capabilities
    // (since each step only narrows, the leaf is the most restricted)
    const effectiveCapabilities = chain[chain.length - 1].capabilities;

    return {
      valid: true,
      chain,
      effective_capabilities: effectiveCapabilities,
    };

  } catch (error) {
    console.error('Failed to verify delegation chain:', error);
    return { valid: false, error: 'Internal server error' };
  }
}

// ============ UTILITY FUNCTIONS ============

/**
 * Update an agent's delegation index (inbound or outbound)
 */
async function updateDelegationIndex(
  sessions: KVNamespace,
  key: string,
  delegationId: string,
  operation: 'add' | 'remove'
): Promise<void> {
  try {
    const data = await sessions.get(key, 'text');
    let ids: string[] = data ? JSON.parse(data) : [];

    if (operation === 'add' && !ids.includes(delegationId)) {
      ids.push(delegationId);
    } else if (operation === 'remove') {
      ids = ids.filter(id => id !== delegationId);
    }

    // No TTL on indexes — they reference delegations which have their own TTL
    await sessions.put(key, JSON.stringify(ids));
  } catch (error) {
    console.error('Failed to update delegation index:', error);
    // Fail silently — index updates are not critical
  }
}

export default {
  createDelegation,
  getDelegation,
  listDelegations,
  revokeDelegation,
  verifyDelegationChain,
  isCapabilitySubset,
};
