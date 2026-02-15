#!/usr/bin/env node
/**
 * BOTCHA CLI - Test, debug, and interact with BOTCHA from the command line
 */
import { Command } from 'commander';
import { testCommand } from './commands/test.js';
import { solveCommand } from './commands/solve.js';
import { benchmarkCommand } from './commands/benchmark.js';
import { headersCommand } from './commands/headers.js';
import { discoverCommand } from './commands/discover.js';
import { initCommand } from './commands/init.js';
import { tokenCommand } from './commands/token.js';
import { curlCommand } from './commands/curl.js';
import tapCommand from './commands/tap.js';

const program = new Command();

program
  .name('botcha')
  .description('CLI tool for testing and debugging BOTCHA-protected endpoints')
  .version('0.4.0');

// Init command (one-time setup)
program
  .command('init')
  .description('One-time setup: create an app and save config to ~/.botcha')
  .requiredOption('--email <email>', 'Email for your BOTCHA app')
  .option('--url <url>', 'BOTCHA service URL (default: https://botcha.ai)')
  .option('--json', 'Output as JSON')
  .option('-v, --verbose', 'Show detailed output')
  .option('-q, --quiet', 'Minimal output')
  .action(initCommand);

// Test command
program
  .command('test <url>')
  .description('Check if URL is BOTCHA-protected and test verification')
  .option('--json', 'Output as JSON')
  .option('-v, --verbose', 'Show detailed output')
  .option('-q, --quiet', 'Minimal output')
  .action(testCommand);

// Solve command
program
  .command('solve <type>')
  .description('Solve a BOTCHA challenge (types: speed, token)')
  .requiredOption('--url <url>', 'URL to solve challenge from')
  .option('--json', 'Output as JSON')
  .option('-v, --verbose', 'Show detailed output')
  .option('-q, --quiet', 'Minimal output')
  .action(solveCommand);

// Benchmark command
program
  .command('benchmark <url>')
  .description('Test performance and reliability')
  .option('-n, --iterations <number>', 'Number of iterations to run', '10')
  .option('--json', 'Output as JSON')
  .option('-v, --verbose', 'Show detailed output')
  .option('-q, --quiet', 'Minimal output')
  .action((url, options) => {
    benchmarkCommand(url, {
      ...options,
      iterations: parseInt(options.iterations, 10),
    });
  });

// Headers command
program
  .command('headers <url>')
  .description('Show BOTCHA headers from a URL')
  .option('--json', 'Output as JSON')
  .option('-v, --verbose', 'Show all headers')
  .option('-q, --quiet', 'Minimal output')
  .action(headersCommand);

// Discover command
program
  .command('discover <url>')
  .description('Find all BOTCHA discovery endpoints on a domain')
  .option('--json', 'Output as JSON')
  .option('-v, --verbose', 'Show recommendations')
  .option('-q, --quiet', 'Minimal output')
  .action(discoverCommand);

// Token command — get a JWT token for use with curl or other tools
program
  .command('token')
  .description('Get a BOTCHA JWT token (pipe-friendly: prints raw token by default)')
  .option('--url <url>', 'BOTCHA service URL (default: from config or https://botcha.ai)')
  .option('--app-id <id>', 'App ID (default: from config)')
  .option('--type <type>', 'Challenge type (speed, reasoning, hybrid)', 'hybrid')
  .option('--json', 'Output as JSON with metadata')
  .option('-v, --verbose', 'Show challenge details and expiry')
  .option('-q, --quiet', 'Minimal output')
  .action(tokenCommand);

// Curl command — authenticated curl with automatic BOTCHA token
program
  .command('curl <targetUrl>')
  .description('Make an authenticated curl request with automatic BOTCHA token')
  .option('--url <url>', 'BOTCHA service URL (default: from config or https://botcha.ai)')
  .option('--app-id <id>', 'App ID (default: from config)')
  .option('--type <type>', 'Challenge type (speed, reasoning, hybrid)', 'hybrid')
  .option('-v, --verbose', 'Show BOTCHA handshake before curl output')
  .option('-q, --quiet', 'Minimal output')
  .allowUnknownOption(true)
  .action((targetUrl, options, command) => {
    // Collect unknown args (everything Commander didn't parse) as passthrough to curl
    const passthroughArgs = command.args.filter((a: string) => a !== targetUrl);
    curlCommand(targetUrl, passthroughArgs, options);
  });

// ============ TAP COMMANDS ============
// --url and --app-id are optional (reads from ~/.botcha/config.json)

const tap = program
  .command('tap')
  .description('Trusted Agent Protocol (TAP) commands');

tap.command('register')
  .description('Register a TAP agent')
  .requiredOption('--name <name>', 'Agent name')
  .option('--capabilities <list>', 'Comma-separated capabilities (browse,search,purchase)')
  .option('--operator <operator>', 'Agent operator/organization')
  .option('--trust-level <level>', 'Trust level (basic, verified, enterprise)')
  .option('--url <url>', 'BOTCHA service URL')
  .option('--app-id <id>', 'App ID')
  .option('--json', 'Output as JSON')
  .option('-v, --verbose', 'Show detailed output')
  .option('-q, --quiet', 'Minimal output')
  .action(tapCommand.register);

tap.command('get')
  .description('Get TAP agent details')
  .option('--agent-id <id>', 'Agent ID (default: last registered)')
  .option('--url <url>', 'BOTCHA service URL')
  .option('--json', 'Output as JSON')
  .option('-v, --verbose', 'Show detailed output')
  .option('-q, --quiet', 'Minimal output')
  .action(tapCommand.get);

tap.command('list')
  .description('List TAP agents')
  .option('--tap-only', 'Only show TAP-enabled agents')
  .option('--url <url>', 'BOTCHA service URL')
  .option('--app-id <id>', 'App ID')
  .option('--json', 'Output as JSON')
  .option('-v, --verbose', 'Show detailed output')
  .option('-q, --quiet', 'Minimal output')
  .action(tapCommand.list);

tap.command('session')
  .description('Create TAP session')
  .option('--action <action>', 'Intent action (browse, search, purchase, etc.)')
  .option('--resource <resource>', 'Intent resource (products, reviews, etc.)')
  .option('--duration <duration>', 'Session duration (1h, 30m, 3600)')
  .option('--intent <json>', 'Raw intent as JSON (alternative to --action/--resource/--duration)')
  .option('--agent-id <id>', 'Agent ID (default: last registered)')
  .option('--user-context <hash>', 'User context hash')
  .option('--url <url>', 'BOTCHA service URL')
  .option('--json', 'Output as JSON')
  .option('-v, --verbose', 'Show detailed output')
  .option('-q, --quiet', 'Minimal output')
  .action(tapCommand.session);

tap.command('status')
  .description('Show current agent, session, and config')
  .option('--session-id <id>', 'Check a specific session')
  .option('--url <url>', 'BOTCHA service URL')
  .option('--json', 'Output as JSON')
  .option('-v, --verbose', 'Show detailed output')
  .option('-q, --quiet', 'Minimal output')
  .action(tapCommand.status);

// Parse and execute
program.parse();
