/**
 * BotchaTool - LangChain Tool for solving BOTCHA challenges
 */

import { StructuredTool } from '@langchain/core/tools';
import { z } from 'zod';
import { BotchaClient } from '@dupecom/botcha/client';
import type { BotchaToolOptions, BotchaToolInput } from './types.js';

/**
 * LangChain Tool that enables AI agents to solve BOTCHA challenges
 * 
 * @example
 * ```typescript
 * import { BotchaTool } from '@dupecom/botcha-langchain';
 * 
 * const tool = new BotchaTool({
 *   baseUrl: 'https://api.botcha.ai'
 * });
 * 
 * // Use in a LangChain agent
 * const agent = createReactAgent({
 *   llm,
 *   tools: [tool],
 *   // ... other config
 * });
 * 
 * // Agent can now call this tool to get tokens
 * ```
 */
export class BotchaTool extends StructuredTool {
  name: string;
  description: string;
  schema = z.object({
    action: z.literal('getToken').describe('Action to perform: getToken to get a JWT token'),
  });

  private client: BotchaClient;

  constructor(options: BotchaToolOptions = {}) {
    super();
    
    this.name = options.name || 'botcha_solver';
    this.description = options.description || 
      'Solves BOTCHA challenges to get authentication tokens for accessing bot-only APIs. ' +
      'Call with action="getToken" to get a JWT token that can be used in Authorization headers.';

    // Create BotchaClient with the provided options
    this.client = new BotchaClient({
      baseUrl: options.baseUrl,
      agentIdentity: options.agentIdentity,
      maxRetries: options.maxRetries,
      autoToken: options.autoToken,
    });
  }

  /**
   * Execute the tool - get a BOTCHA token
   */
  protected async _call(input: BotchaToolInput): Promise<string> {
    try {
      if (input.action === 'getToken') {
        const token = await this.client.getToken();
        return `Successfully obtained BOTCHA token. Use in Authorization: Bearer ${token}`;
      }
      
      return 'Invalid action. Use action="getToken" to get a token.';
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      return `Failed to solve BOTCHA challenge: ${errorMessage}`;
    }
  }

  /**
   * Get the raw token without formatting (useful for programmatic access)
   */
  async getToken(): Promise<string> {
    return await this.client.getToken();
  }

  /**
   * Clear the cached token
   */
  clearToken(): void {
    this.client.clearToken();
  }
}
