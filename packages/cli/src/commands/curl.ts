/**
 * Curl command — solve a BOTCHA challenge and make an authenticated curl request
 * 
 * Example: botcha curl https://api.example.com/protected -X POST -d '{"query":"test"}'
 * Automatically acquires a BOTCHA token and injects the Authorization header.
 */
import { execSync } from 'node:child_process';
import { BotchaClient } from '@dupecom/botcha/client';
import { Output } from '../lib/output.js';
import { loadConfig, resolve } from '../lib/config.js';

export interface CurlOptions {
  url?: string;
  appId?: string;
  type?: string;
  verbose?: boolean;
  quiet?: boolean;
}

export async function curlCommand(
  targetUrl: string,
  passthroughArgs: string[],
  options: CurlOptions,
): Promise<void> {
  const config = loadConfig();
  const baseUrl = resolve(options.url, config.url) || 'https://botcha.ai';
  const appId = resolve(options.appId, config.app_id);

  const output = new Output(options);

  try {
    // Step 1: Acquire token
    output.debug(`BOTCHA service: ${baseUrl}`);
    output.debug(`App ID: ${appId || '(none)'}`);
    output.debug('Solving challenge...');

    const startTime = Date.now();

    const client = new BotchaClient({
      baseUrl: new URL(baseUrl).origin,
      appId,
    });

    const token = await client.getToken();
    const solveTime = Date.now() - startTime;

    if (options.verbose) {
      output.success(`Token acquired in ${solveTime}ms`);
    }

    // Step 2: Build curl command
    // The Authorization header is injected; user can still add their own headers
    const curlArgs: string[] = [
      '-H', `Authorization: Bearer ${token}`,
      ...passthroughArgs,
      targetUrl,
    ];

    // Build the full command string with proper escaping
    const curlCmd = ['curl', ...curlArgs.map(shellEscape)].join(' ');

    if (options.verbose) {
      output.debug(`Running: ${curlCmd}`);
      console.log(); // blank line before curl output
    }

    // Step 3: Execute curl, inheriting stdio for streaming output
    execSync(curlCmd, { stdio: 'inherit' });

  } catch (error) {
    // execSync throws if curl exits non-zero — that's fine, exit code propagates
    if (error && typeof error === 'object' && 'status' in error) {
      process.exit((error as any).status ?? 1);
    }
    output.error(`Failed: ${error instanceof Error ? error.message : String(error)}`);
    process.exit(1);
  }
}

/** Escape a single argument for shell use */
function shellEscape(arg: string): string {
  // If the arg is safe, return as-is
  if (/^[a-zA-Z0-9_\-=:/.@,+%]+$/.test(arg)) {
    return arg;
  }
  // Otherwise wrap in single quotes, escaping any embedded single quotes
  return `'${arg.replace(/'/g, "'\\''")}'`;
}
