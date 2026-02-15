/**
 * Token command — solve a BOTCHA challenge and output a JWT token
 * 
 * Designed for piping: `botcha token | xargs -I {} curl -H "Authorization: Bearer {}" https://api.example.com`
 * Default output is JUST the raw token string (no decoration).
 */
import { BotchaClient } from '@dupecom/botcha/client';
import { Output } from '../lib/output.js';
import { loadConfig, resolve } from '../lib/config.js';

export interface TokenOptions {
  url?: string;
  appId?: string;
  type?: string;
  json?: boolean;
  verbose?: boolean;
  quiet?: boolean;
}

export async function tokenCommand(options: TokenOptions): Promise<void> {
  const config = loadConfig();
  const baseUrl = resolve(options.url, config.url) || 'https://botcha.ai';
  const appId = resolve(options.appId, config.app_id);
  const challengeType = options.type || 'hybrid';

  // For verbose/json we use Output; for plain mode we write directly to stdout
  const output = new Output(options);

  const startTime = Date.now();

  try {
    output.debug(`Service URL: ${baseUrl}`);
    output.debug(`App ID: ${appId || '(none)'}`);
    output.debug(`Challenge type: ${challengeType}`);

    const client = new BotchaClient({
      baseUrl: new URL(baseUrl).origin,
      appId,
    });

    output.debug('Solving challenge to acquire token...');

    const token = await client.getToken();
    const solveTime = Date.now() - startTime;

    // Decode JWT payload for metadata (expiry, etc.)
    let expiresAt: string | undefined;
    let issuedAt: string | undefined;
    try {
      const payload = JSON.parse(
        Buffer.from(token.split('.')[1], 'base64url').toString('utf-8')
      );
      if (payload.exp) {
        expiresAt = new Date(payload.exp * 1000).toISOString();
      }
      if (payload.iat) {
        issuedAt = new Date(payload.iat * 1000).toISOString();
      }
    } catch {
      // JWT decode is best-effort for metadata
    }

    if (options.json) {
      output.json({
        token,
        type: challengeType,
        expires_at: expiresAt || null,
        issued_at: issuedAt || null,
        solve_time_ms: solveTime,
      });
    } else if (options.verbose) {
      output.success(`Token acquired in ${solveTime}ms`);
      output.section('Type', challengeType);
      if (issuedAt) output.section('Issued', issuedAt);
      if (expiresAt) output.section('Expires', expiresAt);
      output.timing('Solve time', solveTime);
      console.log();
      console.log(token);
      console.log();
      output.info('Usage:');
      console.log(`  curl -H "Authorization: Bearer ${token}" https://example.com`);
    } else {
      // Default: raw token only — pipe-friendly
      process.stdout.write(token);
    }

  } catch (error) {
    if (options.json) {
      output.json({
        token: null,
        type: challengeType,
        error: error instanceof Error ? error.message : String(error),
      });
    } else {
      output.error(`Token acquisition failed: ${error instanceof Error ? error.message : String(error)}`);
    }
    process.exit(1);
  }
}
