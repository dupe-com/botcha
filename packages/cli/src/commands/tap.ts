/**
 * TAP command - Trusted Agent Protocol commands
 * Config-aware: reads ~/.botcha/config.json for defaults
 */
import { Output } from '../lib/output.js';
import { loadConfig, saveConfig, resolve } from '../lib/config.js';

// ============ OPTION INTERFACES ============

export interface TAPOptions {
  url?: string;
  appId?: string;
  json?: boolean;
  verbose?: boolean;
  quiet?: boolean;
}

export interface RegisterOptions extends TAPOptions {
  name: string;
  operator?: string;
  trustLevel?: string;
  capabilities?: string; // comma-separated: "browse,search,purchase"
}

export interface GetOptions extends TAPOptions {
  agentId?: string; // optional — falls back to config.agent_id
}

export interface ListOptions extends TAPOptions {
  tapOnly?: boolean;
}

export interface SessionOptions extends TAPOptions {
  agentId?: string;
  // Friendly flags (alternative to --intent JSON)
  action?: string;
  resource?: string;
  duration?: string;
  // Raw JSON fallback
  intent?: string;
  userContext?: string;
}

export interface StatusOptions extends TAPOptions {
  sessionId?: string;
}

export interface RotateKeyOptions extends TAPOptions {
  agentId?: string;
  publicKey: string;
  algorithm: string;
  keyExpiresAt?: string;
}

export interface InvoiceCreateOptions extends TAPOptions {
  resource: string;
  amount: string;
  currency: string;
  cardAcceptorId: string;
}

export interface InvoiceGetOptions extends TAPOptions {
  invoiceId: string;
}

export interface InvoiceVerifyOptions extends TAPOptions {
  invoiceId: string;
  iouFile: string;
}

// ============ HELPERS ============

function buildUrl(baseUrl: string, path: string, appId?: string): string {
  const url = new URL(path, baseUrl);
  if (appId) {
    url.searchParams.set('app_id', appId);
  }
  return url.toString();
}

/** Parse --duration "1h" / "30m" / "3600" into seconds */
function parseDuration(input: string): number {
  const match = input.match(/^(\d+)\s*(h|hr|hrs|hours?|m|min|mins|minutes?|s|sec|secs|seconds?)?$/i);
  if (!match) return parseInt(input, 10) || 3600;
  const num = parseInt(match[1], 10);
  const unit = (match[2] || 's').toLowerCase();
  if (unit.startsWith('h')) return num * 3600;
  if (unit.startsWith('m')) return num * 60;
  return num;
}

/** Resolve url/appId/agentId from flags + config, exit if missing */
function resolveConfig(options: TAPOptions, output: Output, need: { url?: boolean; appId?: boolean; agentId?: boolean } = {}) {
  const config = loadConfig();
  const url = resolve(options.url, config.url);
  const appId = resolve(options.appId, config.app_id);
  const agentId = resolve((options as any).agentId, config.agent_id);

  if (need.url && !url) {
    output.error('No URL. Pass --url or run: botcha init --email you@example.com');
    process.exit(1);
  }
  if (need.appId && !appId) {
    output.error('No app_id. Pass --app-id or run: botcha init --email you@example.com');
    process.exit(1);
  }
  if (need.agentId && !agentId) {
    output.error('No agent_id. Pass --agent-id or register one: botcha tap register --name "my-agent"');
    process.exit(1);
  }
  return { url: url!, appId, agentId, config };
}

function handleError(output: Output, options: TAPOptions, label: string, error: unknown): never {
  if (options.json) {
    output.json({ success: false, error: error instanceof Error ? error.message : String(error) });
  } else {
    output.error(`${label}: ${error instanceof Error ? error.message : String(error)}`);
  }
  process.exit(1);
}

// ============ REGISTER ============

export async function registerCommand(options: RegisterOptions): Promise<void> {
  const output = new Output(options);
  const startTime = Date.now();

  try {
    if (!options.name) {
      output.error('--name is required');
      process.exit(1);
    }

    const { url, appId, config } = resolveConfig(options, output, { url: true, appId: true });

    output.debug('Registering TAP agent...');

    const baseUrl = new URL(url).origin;
    const endpoint = buildUrl(baseUrl, '/v1/agents/register/tap', appId);

    // Build request body
    const body: any = { name: options.name };
    if (options.operator) body.operator = options.operator;
    if (options.trustLevel) body.trust_level = options.trustLevel;

    // Parse --capabilities "browse,search,purchase" into proper format
    if (options.capabilities) {
      body.capabilities = options.capabilities.split(',').map((action: string) => ({
        action: action.trim(),
        scope: ['*'],
      }));
    }

    output.debug(`Endpoint: ${endpoint}`);
    output.debug(`Body: ${JSON.stringify(body, null, 2)}`);

    const response = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });

    const data: any = await response.json();
    const responseTime = Date.now() - startTime;

    if (!response.ok) {
      if (options.json) {
        output.json({ success: false, error: data.error, message: data.message, status: response.status });
      } else {
        output.error(`Registration failed: ${data.message || response.statusText}`);
      }
      process.exit(1);
    }

    // Save as default agent
    config.agent_id = data.agent_id;
    saveConfig(config);

    if (options.json) {
      output.json({ success: true, ...data, responseTimeMs: responseTime });
    } else {
      output.success(`Agent registered in ${responseTime}ms!`);
      output.section('Agent ID', data.agent_id);
      output.section('Name', data.name);
      if (data.operator) output.section('Operator', data.operator);
      if (data.trust_level) output.section('Trust Level', data.trust_level);
      if (data.capabilities?.length) {
        output.section('Capabilities', data.capabilities.map((c: any) => c.action).join(', '));
      }
      console.log();
      output.info('Saved as default agent. Next:');
      console.log('  botcha tap session --action browse --resource products');
    }
  } catch (error) {
    handleError(output, options, 'Registration failed', error);
  }
}

// ============ GET ============

export async function getCommand(options: GetOptions): Promise<void> {
  const output = new Output(options);
  const startTime = Date.now();

  try {
    const { url, agentId } = resolveConfig(options, output, { url: true, agentId: true });

    output.debug(`Getting TAP agent ${agentId}...`);

    const baseUrl = new URL(url).origin;
    const endpoint = buildUrl(baseUrl, `/v1/agents/${encodeURIComponent(agentId!)}/tap`);

    const response = await fetch(endpoint, { headers: { 'Accept': 'application/json' } });
    const data: any = await response.json();
    const responseTime = Date.now() - startTime;

    if (!response.ok) {
      if (options.json) {
        output.json({ success: false, error: data.error, message: data.message, status: response.status });
      } else {
        output.error(`Agent not found: ${data.message || response.statusText}`);
      }
      process.exit(1);
    }

    if (options.json) {
      output.json({ success: true, ...data, responseTimeMs: responseTime });
    } else {
      output.success(`Agent retrieved in ${responseTime}ms!`);
      output.section('Agent ID', data.agent_id);
      output.section('Name', data.name);
      output.section('App ID', data.app_id);
      if (data.operator) output.section('Operator', data.operator);
      if (data.version) output.section('Version', data.version);
      if (data.trust_level) output.section('Trust Level', data.trust_level);
      output.section('TAP Enabled', data.tap_enabled ? 'yes' : 'no');
      if (data.created_at) output.section('Created', data.created_at);
      if (data.capabilities?.length) {
        output.section('Capabilities', data.capabilities.map((c: any) => c.action).join(', '));
      }
      if (options.verbose) {
        console.log('\n' + JSON.stringify(data, null, 2));
      }
    }
  } catch (error) {
    handleError(output, options, 'Get failed', error);
  }
}

// ============ LIST ============

export async function listCommand(options: ListOptions): Promise<void> {
  const output = new Output(options);
  const startTime = Date.now();

  try {
    const { url, appId } = resolveConfig(options, output, { url: true, appId: true });

    output.debug('Listing TAP agents...');

    const baseUrl = new URL(url).origin;
    const endpoint = buildUrl(baseUrl, '/v1/agents/tap', appId);
    const fullUrl = new URL(endpoint);
    if (options.tapOnly) fullUrl.searchParams.set('tap_only', 'true');

    const response = await fetch(fullUrl.toString(), { headers: { 'Accept': 'application/json' } });
    const data: any = await response.json();
    const responseTime = Date.now() - startTime;

    if (!response.ok) {
      if (options.json) {
        output.json({ success: false, error: data.error, message: data.message, status: response.status });
      } else {
        output.error(`List failed: ${data.message || response.statusText}`);
      }
      process.exit(1);
    }

    if (options.json) {
      output.json({ success: true, ...data, responseTimeMs: responseTime });
    } else {
      output.success(`${data.count || 0} agent(s) found (${responseTime}ms)`);
      if (data.agents?.length > 0) {
        console.log();
        const headers = ['Agent ID', 'Name', 'Capabilities', 'Trust', 'TAP'];
        const rows = data.agents.map((a: any) => [
          a.agent_id,
          a.name || '-',
          a.capabilities?.map((c: any) => c.action).join(',') || '-',
          a.trust_level || '-',
          a.tap_enabled ? 'yes' : 'no',
        ]);
        output.table(headers, rows);
      } else {
        console.log('\n  No agents yet. Create one:');
        console.log('  botcha tap register --name "my-agent" --capabilities browse,search');
      }
    }
  } catch (error) {
    handleError(output, options, 'List failed', error);
  }
}

// ============ SESSION ============

export async function sessionCommand(options: SessionOptions): Promise<void> {
  const output = new Output(options);
  const startTime = Date.now();

  try {
    const { url, agentId } = resolveConfig(options, output, { url: true, agentId: true });

    // Build intent from friendly flags OR raw JSON
    let intentObj: any;
    if (options.intent) {
      try {
        intentObj = JSON.parse(options.intent);
      } catch {
        output.error('--intent must be valid JSON. Or use: --action browse --resource products --duration 1h');
        process.exit(1);
      }
    } else if (options.action) {
      intentObj = { action: options.action };
      if (options.resource) intentObj.resource = options.resource;
      if (options.duration) intentObj.duration = parseDuration(options.duration);
    } else {
      output.error('Specify intent. Either:\n  --action browse --resource products --duration 1h\n  --intent \'{"action":"browse","resource":"products"}\'');
      process.exit(1);
    }

    output.debug('Creating TAP session...');

    const baseUrl = new URL(url).origin;
    const endpoint = buildUrl(baseUrl, '/v1/sessions/tap');

    const body = {
      agent_id: agentId,
      intent: intentObj,
      user_context: options.userContext || crypto.randomUUID(),
    };

    const response = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });

    const data: any = await response.json();
    const responseTime = Date.now() - startTime;

    if (!response.ok) {
      if (options.json) {
        output.json({ success: false, error: data.error, message: data.message, status: response.status });
      } else {
        output.error(`Session failed: ${data.message || response.statusText}`);
        if (data.error === 'INSUFFICIENT_CAPABILITY') {
          console.log('\n  Agent lacks this capability. Re-register with:');
          console.log(`  botcha tap register --name "my-agent" --capabilities ${intentObj.action || 'browse'}`);
        }
      }
      process.exit(1);
    }

    if (options.json) {
      output.json({ success: true, ...data, responseTimeMs: responseTime });
    } else {
      output.success(`Session created in ${responseTime}ms!`);
      output.section('Session ID', data.session_id);
      output.section('Agent', data.agent_id);
      output.section('Expires', data.expires_at);
      if (data.intent) {
        const parts = [data.intent.action, data.intent.resource].filter(Boolean);
        output.section('Intent', parts.join(' on '));
      }
      if (data.capabilities?.length) {
        output.section('Capabilities', data.capabilities.map((c: any) => c.action).join(', '));
      }
      console.log();
      output.info('Check session:');
      console.log(`  botcha tap status --session-id ${data.session_id}`);
    }
  } catch (error) {
    handleError(output, options, 'Session failed', error);
  }
}

// ============ JWKS ============

export async function jwksCommand(options: TAPOptions): Promise<void> {
  const output = new Output(options);
  const startTime = Date.now();

  try {
    const { url, appId } = resolveConfig(options, output, { url: true });

    output.debug('Fetching JWKS...');

    const baseUrl = new URL(url).origin;
    const endpoint = buildUrl(baseUrl, '/.well-known/jwks', appId);

    const response = await fetch(endpoint, { headers: { 'Accept': 'application/json' } });
    const data: any = await response.json();
    const responseTime = Date.now() - startTime;

    if (!response.ok) {
      if (options.json) {
        output.json({ success: false, error: data.error, message: data.message, status: response.status });
      } else {
        output.error(`JWKS fetch failed: ${data.message || response.statusText}`);
      }
      process.exit(1);
    }

    if (options.json) {
      output.json({ success: true, ...data, responseTimeMs: responseTime });
    } else {
      output.success(`JWKS retrieved in ${responseTime}ms!`);
      console.log('\n' + JSON.stringify(data, null, 2));
    }
  } catch (error) {
    handleError(output, options, 'JWKS fetch failed', error);
  }
}

// ============ ROTATE KEY ============

export async function rotateKeyCommand(options: RotateKeyOptions): Promise<void> {
  const output = new Output(options);
  const startTime = Date.now();

  try {
    if (!options.publicKey) {
      output.error('--public-key is required');
      process.exit(1);
    }
    if (!options.algorithm) {
      output.error('--algorithm is required (ecdsa-p256-sha256, rsa-pss-sha256, ed25519)');
      process.exit(1);
    }

    const { url, agentId } = resolveConfig(options, output, { url: true, agentId: true });

    output.debug(`Rotating key for agent ${agentId}...`);

    // Read public key from file if it looks like a path
    let publicKeyValue = options.publicKey;
    if (publicKeyValue.startsWith('/') || publicKeyValue.startsWith('./') || publicKeyValue.endsWith('.pem')) {
      try {
        const fs = await import('fs/promises');
        publicKeyValue = await fs.readFile(publicKeyValue, 'utf-8');
        output.debug(`Read public key from file: ${options.publicKey}`);
      } catch (err) {
        output.error(`Failed to read public key file: ${err instanceof Error ? err.message : String(err)}`);
        process.exit(1);
      }
    }

    const baseUrl = new URL(url).origin;
    const endpoint = buildUrl(baseUrl, `/v1/agents/${encodeURIComponent(agentId!)}/tap/rotate-key`);

    const body: any = {
      public_key: publicKeyValue,
      algorithm: options.algorithm
    };

    if (options.keyExpiresAt) {
      body.key_expires_at = options.keyExpiresAt;
    }

    const response = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });

    const data: any = await response.json();
    const responseTime = Date.now() - startTime;

    if (!response.ok) {
      if (options.json) {
        output.json({ success: false, error: data.error, message: data.message, status: response.status });
      } else {
        output.error(`Key rotation failed: ${data.message || response.statusText}`);
      }
      process.exit(1);
    }

    if (options.json) {
      output.json({ success: true, ...data, responseTimeMs: responseTime });
    } else {
      output.success(`Key rotated in ${responseTime}ms!`);
      output.section('Agent ID', data.agent_id);
      output.section('Algorithm', data.signature_algorithm);
      if (data.key_expires_at) output.section('Key Expires', data.key_expires_at);
      if (data.key_rotated_at) output.section('Rotated At', data.key_rotated_at);
    }
  } catch (error) {
    handleError(output, options, 'Key rotation failed', error);
  }
}

// ============ INVOICE CREATE ============

export async function invoiceCreateCommand(options: InvoiceCreateOptions): Promise<void> {
  const output = new Output(options);
  const startTime = Date.now();

  try {
    if (!options.resource || !options.amount || !options.currency || !options.cardAcceptorId) {
      output.error('--resource, --amount, --currency, and --card-acceptor-id are required');
      process.exit(1);
    }

    const { url, appId } = resolveConfig(options, output, { url: true, appId: true });

    output.debug('Creating invoice...');

    const baseUrl = new URL(url).origin;
    const endpoint = buildUrl(baseUrl, '/v1/tap/invoices', appId);

    const body = {
      resource: options.resource,
      amount: options.amount,
      currency: options.currency,
      card_acceptor_id: options.cardAcceptorId
    };

    const response = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });

    const data: any = await response.json();
    const responseTime = Date.now() - startTime;

    if (!response.ok) {
      if (options.json) {
        output.json({ success: false, error: data.error, message: data.message, status: response.status });
      } else {
        output.error(`Invoice creation failed: ${data.message || response.statusText}`);
      }
      process.exit(1);
    }

    if (options.json) {
      output.json({ success: true, ...data, responseTimeMs: responseTime });
    } else {
      output.success(`Invoice created in ${responseTime}ms!`);
      output.section('Invoice ID', data.invoice_id);
      output.section('Resource', data.resource);
      output.section('Amount', `${data.amount} ${data.currency}`);
      output.section('Status', data.status);
      if (data.expires_at) output.section('Expires', data.expires_at);
    }
  } catch (error) {
    handleError(output, options, 'Invoice creation failed', error);
  }
}

// ============ INVOICE GET ============

export async function invoiceGetCommand(options: InvoiceGetOptions): Promise<void> {
  const output = new Output(options);
  const startTime = Date.now();

  try {
    if (!options.invoiceId) {
      output.error('--invoice-id is required');
      process.exit(1);
    }

    const { url, appId } = resolveConfig(options, output, { url: true });

    output.debug(`Getting invoice ${options.invoiceId}...`);

    const baseUrl = new URL(url).origin;
    const endpoint = buildUrl(baseUrl, `/v1/tap/invoices/${encodeURIComponent(options.invoiceId)}`, appId);

    const response = await fetch(endpoint, { headers: { 'Accept': 'application/json' } });
    const data: any = await response.json();
    const responseTime = Date.now() - startTime;

    if (!response.ok) {
      if (options.json) {
        output.json({ success: false, error: data.error, message: data.message, status: response.status });
      } else {
        output.error(`Invoice not found: ${data.message || response.statusText}`);
      }
      process.exit(1);
    }

    if (options.json) {
      output.json({ success: true, ...data, responseTimeMs: responseTime });
    } else {
      output.success(`Invoice retrieved in ${responseTime}ms!`);
      output.section('Invoice ID', data.invoice_id);
      output.section('Resource', data.resource);
      output.section('Amount', `${data.amount} ${data.currency}`);
      output.section('Status', data.status);
      if (data.card_acceptor_id) output.section('Card Acceptor', data.card_acceptor_id);
      if (data.created_at) output.section('Created', data.created_at);
      if (data.expires_at) output.section('Expires', data.expires_at);
      if (options.verbose) {
        console.log('\n' + JSON.stringify(data, null, 2));
      }
    }
  } catch (error) {
    handleError(output, options, 'Invoice get failed', error);
  }
}

// ============ INVOICE VERIFY ============

export async function invoiceVerifyCommand(options: InvoiceVerifyOptions): Promise<void> {
  const output = new Output(options);
  const startTime = Date.now();

  try {
    if (!options.invoiceId || !options.iouFile) {
      output.error('--invoice-id and --iou-file are required');
      process.exit(1);
    }

    const { url, appId } = resolveConfig(options, output, { url: true });

    output.debug(`Verifying invoice ${options.invoiceId}...`);

    // Read IOU file
    let iouData: any;
    try {
      const fs = await import('fs/promises');
      const iouContent = await fs.readFile(options.iouFile, 'utf-8');
      iouData = JSON.parse(iouContent);
    } catch (err) {
      output.error(`Failed to read IOU file: ${err instanceof Error ? err.message : String(err)}`);
      process.exit(1);
    }

    const baseUrl = new URL(url).origin;
    const endpoint = buildUrl(baseUrl, `/v1/tap/invoices/${encodeURIComponent(options.invoiceId)}/verify`, appId);

    const response = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ iou: iouData }),
    });

    const data: any = await response.json();
    const responseTime = Date.now() - startTime;

    if (!response.ok) {
      if (options.json) {
        output.json({ success: false, error: data.error, message: data.message, status: response.status });
      } else {
        output.error(`Invoice verification failed: ${data.message || response.statusText}`);
      }
      process.exit(1);
    }

    if (options.json) {
      output.json({ success: true, ...data, responseTimeMs: responseTime });
    } else {
      output.success(`Invoice verified in ${responseTime}ms!`);
      output.section('Valid', data.valid ? 'YES' : 'NO');
      output.section('Invoice ID', data.invoice_id);
      if (data.amount_matched !== undefined) output.section('Amount Match', data.amount_matched ? 'YES' : 'NO');
      if (data.signature_valid !== undefined) output.section('Signature Valid', data.signature_valid ? 'YES' : 'NO');
      if (data.error) output.section('Error', data.error);
      if (options.verbose) {
        console.log('\n' + JSON.stringify(data, null, 2));
      }
    }
  } catch (error) {
    handleError(output, options, 'Invoice verification failed', error);
  }
}

// ============ STATUS ============

export async function statusCommand(options: StatusOptions): Promise<void> {
  const output = new Output(options);
  const startTime = Date.now();

  try {
    const { url, agentId, appId } = resolveConfig(options, output, { url: true });
    const baseUrl = new URL(url).origin;

    // If session ID given, show that session
    if (options.sessionId) {
      const endpoint = buildUrl(baseUrl, `/v1/sessions/${encodeURIComponent(options.sessionId)}/tap`);
      const response = await fetch(endpoint, { headers: { 'Accept': 'application/json' } });
      const data: any = await response.json();
      const responseTime = Date.now() - startTime;

      if (!response.ok) {
        if (options.json) {
          output.json({ success: false, error: data.error, message: data.message });
        } else {
          output.error(`Session not found: ${data.message || response.statusText}`);
        }
        process.exit(1);
      }

      if (options.json) {
        output.json({ success: true, ...data, responseTimeMs: responseTime });
        return;
      }

      output.header('\nSession Status\n');
      output.section('Session ID', data.session_id);
      output.section('Agent', data.agent_id);
      if (data.intent) {
        const parts = [data.intent.action, data.intent.resource].filter(Boolean);
        output.section('Intent', parts.join(' on '));
      }
      output.section('Created', data.created_at);
      output.section('Expires', data.expires_at);
      if (data.time_remaining != null) {
        const mins = Math.floor(data.time_remaining / 60000);
        const secs = Math.floor((data.time_remaining % 60000) / 1000);
        output.section('Time Left', `${mins}m ${secs}s`);
      }
      return;
    }

    // Otherwise, show overview: agent info + agent list
    if (options.json) {
      const result: any = { success: true };
      if (agentId) {
        const agentRes = await fetch(buildUrl(baseUrl, `/v1/agents/${encodeURIComponent(agentId)}/tap`), { headers: { 'Accept': 'application/json' } });
        if (agentRes.ok) result.agent = await agentRes.json();
      }
      if (appId) {
        const listRes = await fetch(buildUrl(baseUrl, '/v1/agents/tap', appId), { headers: { 'Accept': 'application/json' } });
        if (listRes.ok) result.agents = await listRes.json();
      }
      output.json(result);
      return;
    }

    output.header('\nBOTCHA Status\n');
    output.section('URL', url);
    if (appId) output.section('App ID', appId);

    // Show default agent
    if (agentId) {
      output.section('Default Agent', agentId);
      try {
        const agentRes = await fetch(buildUrl(baseUrl, `/v1/agents/${encodeURIComponent(agentId)}/tap`), { headers: { 'Accept': 'application/json' } });
        if (agentRes.ok) {
          const agent: any = await agentRes.json();
          output.section('  Name', agent.name);
          if (agent.capabilities?.length) {
            output.section('  Capabilities', agent.capabilities.map((c: any) => c.action).join(', '));
          }
          output.section('  Trust Level', agent.trust_level || 'basic');
        }
      } catch {
        // Non-fatal
      }
    } else {
      output.warn('No default agent. Register one:');
      console.log('  botcha tap register --name "my-agent" --capabilities browse,search');
    }

    // Show agent count
    if (appId) {
      try {
        const listRes = await fetch(buildUrl(baseUrl, '/v1/agents/tap', appId), { headers: { 'Accept': 'application/json' } });
        if (listRes.ok) {
          const list: any = await listRes.json();
          console.log();
          output.section('Total Agents', (list.count || 0).toString());
          output.section('TAP Enabled', (list.tap_enabled_count || 0).toString());
        }
      } catch {
        // Non-fatal
      }
    }
    console.log();
  } catch (error) {
    handleError(output, options, 'Status failed', error);
  }
}

// ============ EXPORT ============

export default {
  register: registerCommand,
  get: getCommand,
  list: listCommand,
  session: sessionCommand,
  status: statusCommand,
  jwks: jwksCommand,
  rotateKey: rotateKeyCommand,
  invoiceCreate: invoiceCreateCommand,
  invoiceGet: invoiceGetCommand,
  invoiceVerify: invoiceVerifyCommand,
};
