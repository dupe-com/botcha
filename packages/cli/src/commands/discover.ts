/**
 * Discover command - Find all BOTCHA discovery endpoints
 */
import { Output, formatUrl } from '../lib/output.js';

export interface DiscoverOptions {
  json?: boolean;
  verbose?: boolean;
  quiet?: boolean;
}

interface DiscoveryResult {
  endpoint: string;
  path: string;
  found: boolean;
  description: string;
  details?: string;
}

const DISCOVERY_ENDPOINTS = [
  {
    path: '/robots.txt',
    description: 'Robots.txt with BOTCHA instructions',
    check: (content: string) => {
      const hasBotcha = content.toLowerCase().includes('botcha') ||
        content.includes('User-agent: AI') ||
        content.includes('User-agent: *') && content.includes('Allow: /agent');
      return {
        found: hasBotcha,
        details: hasBotcha ? 'Contains AI agent instructions' : undefined,
      };
    },
  },
  {
    path: '/ai.txt',
    description: 'AI agent discovery file',
    check: (content: string) => ({
      found: content.length > 0,
      details: content.length > 0 ? 'AI discovery file present' : undefined,
    }),
  },
  {
    path: '/.well-known/ai-plugin.json',
    description: 'AI plugin manifest',
    check: (content: string) => {
      try {
        const manifest = JSON.parse(content);
        const hasBotcha = manifest.auth?.type === 'botcha' ||
          JSON.stringify(manifest).toLowerCase().includes('botcha');
        return {
          found: true,
          details: hasBotcha
            ? `Plugin: ${manifest.name_for_human || manifest.name || 'unknown'} (BOTCHA auth)`
            : `Plugin: ${manifest.name_for_human || manifest.name || 'unknown'}`,
        };
      } catch {
        return { found: false };
      }
    },
  },
  {
    path: '/openapi.json',
    description: 'OpenAPI specification',
    check: (content: string) => {
      try {
        const spec = JSON.parse(content);
        const hasBotcha = JSON.stringify(spec).toLowerCase().includes('botcha');
        return {
          found: true,
          details: hasBotcha
            ? `OpenAPI ${spec.openapi || spec.swagger || '?'} (BOTCHA documented)`
            : `OpenAPI ${spec.openapi || spec.swagger || '?'}`,
        };
      } catch {
        return { found: false };
      }
    },
  },
  {
    path: '/.well-known/botcha.json',
    description: 'BOTCHA configuration',
    check: (content: string) => {
      try {
        const config = JSON.parse(content);
        return {
          found: true,
          details: `Version: ${config.version || '?'}, Methods: ${config.methods?.join(', ') || '?'}`,
        };
      } catch {
        return { found: false };
      }
    },
  },
];

async function checkEndpoint(
  baseUrl: string,
  endpoint: typeof DISCOVERY_ENDPOINTS[0],
  output: Output
): Promise<DiscoveryResult> {
  const url = new URL(endpoint.path, baseUrl).toString();
  
  output.debug(`Checking ${url}...`);
  
  try {
    const response = await fetch(url, {
      headers: {
        'User-Agent': 'BOTCHA-CLI/0.1.0',
        'Accept': 'text/plain, application/json, */*',
      },
    });

    if (!response.ok) {
      return {
        endpoint: url,
        path: endpoint.path,
        found: false,
        description: endpoint.description,
      };
    }

    const content = await response.text();
    const result = endpoint.check(content);

    return {
      endpoint: url,
      path: endpoint.path,
      found: result.found,
      description: endpoint.description,
      details: result.details,
    };
  } catch (error) {
    output.debug(`Error checking ${url}: ${error instanceof Error ? error.message : String(error)}`);
    return {
      endpoint: url,
      path: endpoint.path,
      found: false,
      description: endpoint.description,
    };
  }
}

async function checkEmbeddedChallenge(
  baseUrl: string,
  output: Output
): Promise<DiscoveryResult> {
  output.debug(`Checking ${baseUrl} for embedded challenge...`);
  
  try {
    const response = await fetch(baseUrl, {
      headers: {
        'User-Agent': 'BOTCHA-CLI/0.1.0',
        'Accept': 'text/html, */*',
      },
    });

    const html = await response.text();
    
    // Check for embedded BOTCHA script
    const hasEmbedded = html.includes('application/botcha+json') ||
      html.includes('data-botcha') ||
      html.includes('__BOTCHA__');
    
    // Check for BOTCHA headers
    const hasBotchaHeaders = Array.from(response.headers.keys())
      .some(key => key.toLowerCase().startsWith('x-botcha-'));

    const found = hasEmbedded || hasBotchaHeaders;
    let details: string | undefined;
    
    if (hasEmbedded) {
      details = 'Embedded challenge script detected';
    } else if (hasBotchaHeaders) {
      details = 'BOTCHA headers present';
    }

    return {
      endpoint: baseUrl,
      path: '/',
      found,
      description: 'Embedded challenge in HTML',
      details,
    };
  } catch (error) {
    output.debug(`Error checking embedded: ${error instanceof Error ? error.message : String(error)}`);
    return {
      endpoint: baseUrl,
      path: '/',
      found: false,
      description: 'Embedded challenge in HTML',
    };
  }
}

export async function discoverCommand(url: string, options: DiscoverOptions): Promise<void> {
  const output = new Output(options);
  
  // Ensure URL has a trailing slash for proper path resolution
  const baseUrl = url.endsWith('/') ? url.slice(0, -1) : url;
  
  output.header(`\n🔍 Discovering BOTCHA endpoints at ${formatUrl(baseUrl)}\n`);

  const spinner = output.spinner('Checking discovery endpoints...');

  // Check all endpoints in parallel
  const results = await Promise.all([
    ...DISCOVERY_ENDPOINTS.map(endpoint => checkEndpoint(baseUrl, endpoint, output)),
    checkEmbeddedChallenge(baseUrl, output),
  ]);

  spinner.stop();

  const foundCount = results.filter(r => r.found).length;
  const totalCount = results.length;

  if (options.json) {
    output.json({
      url: baseUrl,
      results,
      score: foundCount,
      maxScore: totalCount,
      hasProtection: foundCount > 0,
    });
    return;
  }

  // Display results
  console.log('Discovery Results:\n');
  
  for (const result of results) {
    const icon = result.found ? '✅' : '❌';
    const status = result.found ? result.path : result.path;
    console.log(`${icon} ${status} - ${result.description}`);
    if (result.found && result.details) {
      console.log(`   ${result.details}`);
    }
  }

  console.log();
  
  // Discovery score
  const stars = foundCount >= 4 ? '⭐⭐⭐' :
    foundCount >= 2 ? '⭐⭐' :
    foundCount >= 1 ? '⭐' : '';
  
  if (foundCount === 0) {
    output.warn(`Discovery Score: ${foundCount}/${totalCount} - No BOTCHA endpoints found`);
  } else if (foundCount < 3) {
    output.info(`Discovery Score: ${foundCount}/${totalCount} ${stars}`);
  } else {
    output.success(`Discovery Score: ${foundCount}/${totalCount} ${stars}`);
  }

  // Recommendations
  if (options.verbose && foundCount < totalCount) {
    console.log('\nRecommendations:');
    
    const missing = results.filter(r => !r.found);
    for (const result of missing.slice(0, 3)) {
      console.log(`  • Add ${result.path} - ${result.description}`);
    }
  }
}
