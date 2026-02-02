/**
 * Test command - Check if URL is BOTCHA-protected and test verification
 */
import { BotchaClient } from '@dupecom/botcha/client';
import { Output, formatUrl } from '../lib/output.js';

export interface TestOptions {
  json?: boolean;
  verbose?: boolean;
  quiet?: boolean;
}

export async function testCommand(url: string, options: TestOptions): Promise<void> {
  const output = new Output(options);
  
  output.header(`\n🔍 Testing ${formatUrl(url)}...\n`);

  const client = new BotchaClient({ baseUrl: new URL(url).origin });
  const startTime = Date.now();

  try {
    // First, make a request to see if BOTCHA is required
    output.debug('Making initial request...');
    const response = await client.fetch(url);
    const totalTime = Date.now() - startTime;

    // Check for BOTCHA headers
    const botchaHeaders: Record<string, string> = {};
    response.headers.forEach((value: string, key: string) => {
      if (key.toLowerCase().startsWith('x-botcha-')) {
        botchaHeaders[key] = value;
      }
    });

    const hasBotcha = Object.keys(botchaHeaders).length > 0;

    if (options.json) {
      const result = {
        url,
        protected: hasBotcha,
        statusCode: response.status,
        success: response.ok,
        headers: botchaHeaders,
        totalTimeMs: totalTime,
      };
      output.json(result);
      return;
    }

    if (hasBotcha) {
      output.success('BOTCHA Detected!');
      
      if (botchaHeaders['x-botcha-version']) {
        output.section('Version', botchaHeaders['x-botcha-version']);
      }
      if (botchaHeaders['x-botcha-methods']) {
        output.section('Methods', botchaHeaders['x-botcha-methods']);
      }
    } else {
      output.warn('No BOTCHA protection detected');
    }

    console.log();

    if (response.ok) {
      output.success(`Access Granted! (${response.status})`);
      output.timing('Total Time', totalTime);
      
      // Try to show response body
      const contentType = response.headers.get('content-type') || '';
      if (contentType.includes('application/json')) {
        const data = await response.json();
        console.log('\nResponse:');
        console.log(JSON.stringify(data, null, 2));
      }
    } else {
      output.error(`Access Denied! (${response.status} ${response.statusText})`);
      output.timing('Total Time', totalTime);
      process.exit(1);
    }

  } catch (error) {
    if (options.json) {
      output.json({
        url,
        success: false,
        error: error instanceof Error ? error.message : String(error),
      });
    } else {
      output.error(`Test failed: ${error instanceof Error ? error.message : String(error)}`);
    }
    process.exit(1);
  }
}
