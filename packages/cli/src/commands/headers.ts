/**
 * Headers command - Show BOTCHA headers from a URL
 */
import { Output, formatUrl } from '../lib/output.js';

export interface HeadersOptions {
  json?: boolean;
  verbose?: boolean;
  quiet?: boolean;
}

export async function headersCommand(url: string, options: HeadersOptions): Promise<void> {
  const output = new Output(options);
  
  output.header(`\n🔍 Fetching headers from ${formatUrl(url)}...\n`);

  try {
    const response = await fetch(url, {
      method: 'HEAD',
    });

    const botchaHeaders: Record<string, string> = {};
    const allHeaders: Record<string, string> = {};

    response.headers.forEach((value, key) => {
      allHeaders[key] = value;
      if (key.toLowerCase().startsWith('x-botcha-')) {
        botchaHeaders[key] = value;
      }
    });

    if (options.json) {
      output.json({
        url,
        statusCode: response.status,
        botchaHeaders,
        allHeaders: options.verbose ? allHeaders : undefined,
      });
      return;
    }

    if (Object.keys(botchaHeaders).length === 0) {
      output.warn('No BOTCHA headers found');
      if (options.verbose) {
        console.log('\nAll headers:');
        for (const [key, value] of Object.entries(allHeaders)) {
          console.log(`  ${key}: ${value}`);
        }
      }
    } else {
      output.success('BOTCHA headers found:');
      console.log();
      for (const [key, value] of Object.entries(botchaHeaders)) {
        console.log(`  ${key}: ${value}`);
      }

      if (options.verbose) {
        console.log('\nAll headers:');
        for (const [key, value] of Object.entries(allHeaders)) {
          if (!key.toLowerCase().startsWith('x-botcha-')) {
            console.log(`  ${key}: ${value}`);
          }
        }
      }
    }

  } catch (error) {
    if (options.json) {
      output.json({
        url,
        success: false,
        error: error instanceof Error ? error.message : String(error),
      });
    } else {
      output.error(`Failed to fetch headers: ${error instanceof Error ? error.message : String(error)}`);
    }
    process.exit(1);
  }
}
