#!/usr/bin/env node
/**
 * BOTCHA CLI - Test, debug, and interact with BOTCHA from the command line
 */
import { Command } from 'commander';
import { testCommand } from './commands/test.js';
import { solveCommand } from './commands/solve.js';
import { benchmarkCommand } from './commands/benchmark.js';
import { headersCommand } from './commands/headers.js';

const program = new Command();

program
  .name('botcha')
  .description('CLI tool for testing and debugging BOTCHA-protected endpoints')
  .version('0.1.0');

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

// Parse and execute
program.parse();
