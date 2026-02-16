/**
 * Init command — one-shot setup for BOTCHA CLI
 * Creates an app, auto-verifies email, saves config to ~/.botcha/config.json
 *
 * Usage:
 *   botcha init --email you@example.com
 *   botcha init --email you@example.com --name "My Agent"
 *
 * The flow:
 *   1. POST /v1/apps → get app_id, app_secret, verification_code
 *   2. POST /v1/apps/:id/verify-email → auto-verify with the code
 *   3. Save config to ~/.botcha/config.json
 *   4. Done. Ready to use.
 */
import { Output } from '../lib/output.js';
import { loadConfig, saveConfig, configPath } from '../lib/config.js';

export interface InitOptions {
  email: string;
  name?: string;
  url?: string;
  json?: boolean;
  verbose?: boolean;
  quiet?: boolean;
}

export async function initCommand(options: InitOptions): Promise<void> {
  const output = new Output(options);

  if (!options.email) {
    output.error('--email is required');
    process.exit(1);
  }

  const config = loadConfig();
  const url = options.url || config.url;

  output.header('\nBOTCHA Setup\n');

  // Check if already initialized
  if (config.app_id && config.app_secret) {
    output.warn(`Already initialized (app_id: ${config.app_id})`);
    output.info('Creating a new app will overwrite the existing config.');
    output.info('');
  }

  // Step 1: Create app
  const spinner = output.spinner('Creating app...');

  try {
    const createBody: Record<string, string> = { email: options.email };
    if (options.name) createBody.name = options.name;

    const response = await fetch(`${url}/v1/apps`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(createBody),
    });

    const data: any = await response.json();

    if (!response.ok) {
      spinner.stop();
      output.error(`App creation failed: ${data.message || response.statusText}`);
      process.exit(1);
    }

    spinner.stop();
    output.success('App created');
    output.debug(`app_id: ${data.app_id}`);

    // Step 2: Auto-verify email using the verification code from the response
    const verifySpinner = output.spinner('Verifying email...');

    if (data.verification_code && data.app_secret) {
      try {
        const verifyResponse = await fetch(`${url}/v1/apps/${data.app_id}/verify-email`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            code: data.verification_code,
            app_secret: data.app_secret,
          }),
        });

        const verifyData: any = await verifyResponse.json();
        verifySpinner.stop();

        if (verifyResponse.ok && verifyData.email_verified) {
          output.success('Email verified');
        } else {
          output.warn(`Email verification failed: ${verifyData.message || 'unknown error'}`);
          output.info(`Verify manually: POST ${url}/v1/apps/${data.app_id}/verify-email`);
        }
      } catch (verifyError) {
        verifySpinner.stop();
        output.warn('Email verification request failed (app was created successfully)');
        output.info(`Verify manually: POST ${url}/v1/apps/${data.app_id}/verify-email`);
      }
    } else {
      verifySpinner.stop();
      output.warn('No verification code in response — verify your email manually');
    }

    // Step 3: Save config
    config.url = url;
    config.app_id = data.app_id;
    config.app_secret = data.app_secret;
    config.email = options.email;
    saveConfig(config);

    // Step 4: Output
    if (options.json) {
      output.json({
        success: true,
        app_id: data.app_id,
        app_secret: data.app_secret,
        email: options.email,
        email_verified: true,
        config_path: configPath(),
      });
      return;
    }

    console.log();
    output.section('App ID', data.app_id);
    output.section('Email', options.email);
    output.section('Status', 'verified');
    output.section('Config', configPath());
    console.log();
    output.warn('Save your app_secret — it cannot be retrieved again:');
    console.log(`  ${data.app_secret}`);
    console.log();
    output.info('You\'re ready to go! Try:');
    console.log('  botcha token                    # Get a JWT token');
    console.log('  botcha test https://botcha.ai   # Test a BOTCHA-protected endpoint');
    console.log('  botcha tap register --name "my-agent"  # Register a TAP agent');
    console.log();

  } catch (error) {
    output.error(`Setup failed: ${error instanceof Error ? error.message : String(error)}`);
    process.exit(1);
  }
}
