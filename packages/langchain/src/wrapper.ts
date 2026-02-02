/**
 * BotchaRequestWrapper - Wraps fetch to automatically handle BOTCHA challenges
 */

import { BotchaClient } from '@dupecom/botcha/client';
import type { BotchaRequestWrapperOptions } from './types.js';

/**
 * Wraps HTTP requests to automatically solve BOTCHA challenges
 * 
 * Use this when you want to make HTTP requests to BOTCHA-protected endpoints
 * without manually managing tokens or challenges.
 * 
 * @example
 * ```typescript
 * import { BotchaRequestWrapper } from '@dupecom/botcha-langchain';
 * 
 * const wrapper = new BotchaRequestWrapper({
 *   baseUrl: 'https://api.botcha.ai'
 * });
 * 
 * // Automatically solves challenges if needed
 * const response = await wrapper.fetch('https://protected-api.com/data');
 * const data = await response.json();
 * ```
 */
export class BotchaRequestWrapper {
  private client: BotchaClient;
  private fetchFn: typeof fetch;

  constructor(options: BotchaRequestWrapperOptions = {}) {
    // Create BotchaClient with the provided options
    this.client = new BotchaClient({
      baseUrl: options.baseUrl,
      agentIdentity: options.agentIdentity,
      maxRetries: options.maxRetries,
      autoToken: options.autoToken,
    });

    // Use custom fetch if provided, otherwise use global fetch
    this.fetchFn = options.fetchFn || fetch;
  }

  /**
   * Fetch a URL, automatically solving BOTCHA challenges if encountered
   * 
   * This method uses the BotchaClient's fetch method, which:
   * - Automatically acquires JWT tokens (if autoToken is enabled)
   * - Retries with challenge solutions if 403 responses are received
   * - Handles both token-based and challenge header authentication
   * 
   * @param url - URL to fetch
   * @param init - Fetch options
   * @returns Response object
   */
  async fetch(url: string, init?: RequestInit): Promise<Response> {
    // Delegate to BotchaClient's fetch method which handles all the BOTCHA logic
    return await this.client.fetch(url, init);
  }

  /**
   * Get a JWT token for manual use
   * 
   * @returns JWT token string
   */
  async getToken(): Promise<string> {
    return await this.client.getToken();
  }

  /**
   * Clear the cached token, forcing a refresh on the next request
   */
  clearToken(): void {
    this.client.clearToken();
  }

  /**
   * Create headers with pre-solved challenge for manual use
   * 
   * @returns Headers object with BOTCHA challenge solution
   */
  async createHeaders(): Promise<Record<string, string>> {
    return await this.client.createHeaders();
  }
}
