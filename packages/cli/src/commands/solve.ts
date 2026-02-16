/**
 * Solve command - Solve BOTCHA challenges and output tokens
 */
import { BotchaClient } from '@dupecom/botcha/client';
import { Output } from '../lib/output.js';
import { loadConfig } from '../lib/config.js';

export interface SolveOptions {
  url: string;
  json?: boolean;
  verbose?: boolean;
  quiet?: boolean;
}

export async function solveCommand(type: string, options: SolveOptions): Promise<void> {
  const output = new Output(options);
  const config = loadConfig();
  
  if (!options.url) {
    output.error('--url is required');
    process.exit(1);
  }

  const client = new BotchaClient({ baseUrl: new URL(options.url).origin, appId: config.app_id });
  const startTime = Date.now();

  try {
    switch (type.toLowerCase()) {
      case 'speed': {
        output.debug('Solving speed challenge...');
        const { id, answers } = await client.solveChallenge();
        const solveTime = Date.now() - startTime;

        if (options.json) {
          output.json({
            type: 'speed',
            challengeId: id,
            answers,
            solveTimeMs: solveTime,
          });
        } else {
          output.success(`Solved in ${solveTime}ms!`);
          output.section('Challenge ID', id);
          output.section('Answers', answers.length);
          if (options.verbose) {
            console.log('\nAnswers:', answers);
          }
        }
        break;
      }

      case 'token': {
        output.debug('Getting token...');
        const token = await client.getToken();
        const solveTime = Date.now() - startTime;

        if (options.json) {
          output.json({
            type: 'token',
            token,
            solveTimeMs: solveTime,
          });
        } else {
          output.success(`Token acquired in ${solveTime}ms!`);
          console.log('\nToken:');
          console.log(token);
          console.log('\nUse with:');
          console.log(`  Authorization: Bearer ${token}`);
        }
        break;
      }

      default:
        output.error(`Unknown challenge type: ${type}`);
        output.info('Supported types: speed, token');
        process.exit(1);
    }

  } catch (error) {
    if (options.json) {
      output.json({
        type,
        success: false,
        error: error instanceof Error ? error.message : String(error),
      });
    } else {
      output.error(`Solve failed: ${error instanceof Error ? error.message : String(error)}`);
    }
    process.exit(1);
  }
}
