/**
 * TAP command - Trusted Agent Protocol commands
 */
import { Output } from '../lib/output.js';

export interface TAPOptions {
  url: string;
  json?: boolean;
  verbose?: boolean;
  quiet?: boolean;
}

export interface RegisterOptions extends TAPOptions {
  name: string;
  operator?: string;
  trustLevel?: string;
}

export interface GetOptions extends TAPOptions {
  agentId: string;
}

export interface ListOptions extends TAPOptions {
  tapOnly?: boolean;
}

export interface SessionOptions extends TAPOptions {
  agentId: string;
  intent: string;
  userContext?: string;
}

/**
 * Register a TAP agent
 * POST /v1/agents/register/tap
 */
export async function registerCommand(options: RegisterOptions): Promise<void> {
  const output = new Output(options);
  const startTime = Date.now();

  try {
    // Validate required fields
    if (!options.url) {
      output.error('--url is required');
      process.exit(1);
    }

    if (!options.name) {
      output.error('--name is required');
      process.exit(1);
    }

    output.debug('Registering TAP agent...');

    const baseUrl = new URL(options.url).origin;
    const endpoint = `${baseUrl}/v1/agents/register/tap`;

    // Build request body
    const body: any = {
      name: options.name,
    };

    if (options.operator) {
      body.operator = options.operator;
    }

    if (options.trustLevel) {
      body.trust_level = options.trustLevel;
    }

    output.debug(`Endpoint: ${endpoint}`);
    output.debug(`Request body: ${JSON.stringify(body, null, 2)}`);

    const response = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(body),
    });

    const data = await response.json();
    const responseTime = Date.now() - startTime;

    if (!response.ok) {
      if (options.json) {
        output.json({
          success: false,
          error: data.error || 'REGISTRATION_FAILED',
          message: data.message || response.statusText,
          status: response.status,
        });
      } else {
        output.error(`Registration failed: ${data.message || response.statusText}`);
        output.section('Status', response.status.toString());
        output.section('Error', data.error || 'UNKNOWN');
      }
      process.exit(1);
    }

    if (options.json) {
      output.json({
        success: true,
        ...data,
        responseTimeMs: responseTime,
      });
    } else {
      output.success(`Agent registered in ${responseTime}ms!`);
      output.section('Agent ID', data.agent_id);
      output.section('Name', data.name);
      output.section('App ID', data.app_id);
      
      if (data.operator) {
        output.section('Operator', data.operator);
      }
      
      if (data.trust_level) {
        output.section('Trust Level', data.trust_level);
      }
      
      if (data.tap_enabled) {
        output.section('TAP Enabled', 'true');
      }
      
      if (options.verbose) {
        console.log('\nFull Response:');
        console.log(JSON.stringify(data, null, 2));
      }
    }

  } catch (error) {
    if (options.json) {
      output.json({
        success: false,
        error: error instanceof Error ? error.message : String(error),
      });
    } else {
      output.error(`Registration failed: ${error instanceof Error ? error.message : String(error)}`);
    }
    process.exit(1);
  }
}

/**
 * Get TAP agent details
 * GET /v1/agents/:id/tap
 */
export async function getCommand(options: GetOptions): Promise<void> {
  const output = new Output(options);
  const startTime = Date.now();

  try {
    if (!options.url) {
      output.error('--url is required');
      process.exit(1);
    }

    if (!options.agentId) {
      output.error('--agent-id is required');
      process.exit(1);
    }

    output.debug(`Getting TAP agent ${options.agentId}...`);

    const baseUrl = new URL(options.url).origin;
    const endpoint = `${baseUrl}/v1/agents/${options.agentId}/tap`;

    output.debug(`Endpoint: ${endpoint}`);

    const response = await fetch(endpoint, {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
      },
    });

    const data = await response.json();
    const responseTime = Date.now() - startTime;

    if (!response.ok) {
      if (options.json) {
        output.json({
          success: false,
          error: data.error || 'GET_FAILED',
          message: data.message || response.statusText,
          status: response.status,
        });
      } else {
        output.error(`Get failed: ${data.message || response.statusText}`);
        output.section('Status', response.status.toString());
        output.section('Error', data.error || 'UNKNOWN');
      }
      process.exit(1);
    }

    if (options.json) {
      output.json({
        success: true,
        ...data,
        responseTimeMs: responseTime,
      });
    } else {
      output.success(`Agent retrieved in ${responseTime}ms!`);
      output.section('Agent ID', data.agent_id);
      output.section('Name', data.name);
      output.section('App ID', data.app_id);
      
      if (data.operator) {
        output.section('Operator', data.operator);
      }
      
      if (data.version) {
        output.section('Version', data.version);
      }
      
      if (data.trust_level) {
        output.section('Trust Level', data.trust_level);
      }
      
      if (data.tap_enabled !== undefined) {
        output.section('TAP Enabled', data.tap_enabled ? 'true' : 'false');
      }
      
      if (data.signature_algorithm) {
        output.section('Signature Algorithm', data.signature_algorithm);
      }
      
      if (data.has_public_key) {
        output.section('Has Public Key', 'true');
        if (data.key_fingerprint) {
          output.section('Key Fingerprint', data.key_fingerprint);
        }
      }
      
      if (data.created_at) {
        output.section('Created At', data.created_at);
      }
      
      if (data.capabilities && Array.isArray(data.capabilities)) {
        output.section('Capabilities', data.capabilities.length.toString());
        if (options.verbose && data.capabilities.length > 0) {
          console.log('\nCapabilities:');
          data.capabilities.forEach((cap: any, idx: number) => {
            console.log(`  ${idx + 1}. ${cap.action}${cap.resource ? ` on ${cap.resource}` : ''}`);
            if (cap.constraints) {
              console.log(`     Constraints: ${JSON.stringify(cap.constraints)}`);
            }
          });
        }
      }
      
      if (options.verbose) {
        console.log('\nFull Response:');
        console.log(JSON.stringify(data, null, 2));
      }
    }

  } catch (error) {
    if (options.json) {
      output.json({
        success: false,
        error: error instanceof Error ? error.message : String(error),
      });
    } else {
      output.error(`Get failed: ${error instanceof Error ? error.message : String(error)}`);
    }
    process.exit(1);
  }
}

/**
 * List TAP agents
 * GET /v1/agents/tap
 */
export async function listCommand(options: ListOptions): Promise<void> {
  const output = new Output(options);
  const startTime = Date.now();

  try {
    if (!options.url) {
      output.error('--url is required');
      process.exit(1);
    }

    output.debug('Listing TAP agents...');

    const baseUrl = new URL(options.url).origin;
    const url = new URL(`${baseUrl}/v1/agents/tap`);
    
    if (options.tapOnly) {
      url.searchParams.set('tap_only', 'true');
    }

    output.debug(`Endpoint: ${url.toString()}`);

    const response = await fetch(url.toString(), {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
      },
    });

    const data = await response.json();
    const responseTime = Date.now() - startTime;

    if (!response.ok) {
      if (options.json) {
        output.json({
          success: false,
          error: data.error || 'LIST_FAILED',
          message: data.message || response.statusText,
          status: response.status,
        });
      } else {
        output.error(`List failed: ${data.message || response.statusText}`);
        output.section('Status', response.status.toString());
        output.section('Error', data.error || 'UNKNOWN');
      }
      process.exit(1);
    }

    if (options.json) {
      output.json({
        success: true,
        ...data,
        responseTimeMs: responseTime,
      });
    } else {
      output.success(`Agents retrieved in ${responseTime}ms!`);
      output.section('Total Count', data.count?.toString() || '0');
      
      if (data.tap_enabled_count !== undefined) {
        output.section('TAP Enabled', data.tap_enabled_count.toString());
      }
      
      if (data.agents && Array.isArray(data.agents) && data.agents.length > 0) {
        console.log('\nAgents:\n');
        
        // Display as table
        const headers = ['Agent ID', 'Name', 'Operator', 'Trust Level', 'TAP'];
        const rows = data.agents.map((agent: any) => [
          agent.agent_id,
          agent.name || '-',
          agent.operator || '-',
          agent.trust_level || '-',
          agent.tap_enabled ? '✓' : '✗',
        ]);
        
        output.table(headers, rows);
        
        if (options.verbose) {
          console.log('\nDetailed Information:');
          data.agents.forEach((agent: any, idx: number) => {
            console.log(`\n${idx + 1}. ${agent.name} (${agent.agent_id})`);
            if (agent.version) {
              console.log(`   Version: ${agent.version}`);
            }
            if (agent.created_at) {
              console.log(`   Created: ${agent.created_at}`);
            }
            if (agent.capabilities && Array.isArray(agent.capabilities)) {
              console.log(`   Capabilities: ${agent.capabilities.length}`);
            }
            if (agent.last_verified_at) {
              console.log(`   Last Verified: ${agent.last_verified_at}`);
            }
          });
        }
      } else {
        console.log('\nNo agents found.');
      }
    }

  } catch (error) {
    if (options.json) {
      output.json({
        success: false,
        error: error instanceof Error ? error.message : String(error),
      });
    } else {
      output.error(`List failed: ${error instanceof Error ? error.message : String(error)}`);
    }
    process.exit(1);
  }
}

/**
 * Create TAP session
 * POST /v1/sessions/tap
 */
export async function sessionCommand(options: SessionOptions): Promise<void> {
  const output = new Output(options);
  const startTime = Date.now();

  try {
    if (!options.url) {
      output.error('--url is required');
      process.exit(1);
    }

    if (!options.agentId) {
      output.error('--agent-id is required');
      process.exit(1);
    }

    if (!options.intent) {
      output.error('--intent is required');
      process.exit(1);
    }

    output.debug('Creating TAP session...');

    const baseUrl = new URL(options.url).origin;
    const endpoint = `${baseUrl}/v1/sessions/tap`;

    // Parse intent JSON
    let intentObj;
    try {
      intentObj = JSON.parse(options.intent);
    } catch {
      output.error('--intent must be valid JSON');
      if (!options.json) {
        console.log('\nExample:');
        console.log('  --intent \'{"action":"read","resource":"documents"}\'');
      }
      process.exit(1);
    }

    // Build request body
    const body: any = {
      agent_id: options.agentId,
      intent: intentObj,
      user_context: options.userContext || crypto.randomUUID(),
    };

    output.debug(`Endpoint: ${endpoint}`);
    output.debug(`Request body: ${JSON.stringify(body, null, 2)}`);

    const response = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(body),
    });

    const data = await response.json();
    const responseTime = Date.now() - startTime;

    if (!response.ok) {
      if (options.json) {
        output.json({
          success: false,
          error: data.error || 'SESSION_FAILED',
          message: data.message || response.statusText,
          status: response.status,
        });
      } else {
        output.error(`Session creation failed: ${data.message || response.statusText}`);
        output.section('Status', response.status.toString());
        output.section('Error', data.error || 'UNKNOWN');
        
        if (data.error === 'INSUFFICIENT_CAPABILITY') {
          console.log('\nThe agent does not have the required capability for this action.');
          console.log('Register the agent with appropriate capabilities first.');
        }
      }
      process.exit(1);
    }

    if (options.json) {
      output.json({
        success: true,
        ...data,
        responseTimeMs: responseTime,
      });
    } else {
      output.success(`Session created in ${responseTime}ms!`);
      output.section('Session ID', data.session_id);
      output.section('Agent ID', data.agent_id);
      
      if (data.expires_at) {
        output.section('Expires At', data.expires_at);
      }
      
      if (data.capabilities && Array.isArray(data.capabilities)) {
        output.section('Capabilities', data.capabilities.length.toString());
      }
      
      if (data.intent) {
        output.section('Intent Action', data.intent.action);
        if (data.intent.resource) {
          output.section('Intent Resource', data.intent.resource);
        }
      }
      
      if (options.verbose) {
        console.log('\nFull Response:');
        console.log(JSON.stringify(data, null, 2));
      }
    }

  } catch (error) {
    if (options.json) {
      output.json({
        success: false,
        error: error instanceof Error ? error.message : String(error),
      });
    } else {
      output.error(`Session creation failed: ${error instanceof Error ? error.message : String(error)}`);
    }
    process.exit(1);
  }
}

export default {
  register: registerCommand,
  get: getCommand,
  list: listCommand,
  session: sessionCommand,
};
