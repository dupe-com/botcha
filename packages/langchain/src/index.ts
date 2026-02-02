/**
 * @dupecom/botcha-langchain
 * 
 * LangChain integration for BOTCHA - make AI agents transparently solve BOTCHA challenges
 * 
 * @example
 * ```typescript
 * // Use as a LangChain Tool
 * import { BotchaTool } from '@dupecom/botcha-langchain';
 * 
 * const tool = new BotchaTool({ baseUrl: 'https://api.botcha.ai' });
 * // Add to your agent's tools array
 * 
 * // Use as a fetch wrapper
 * import { BotchaRequestWrapper } from '@dupecom/botcha-langchain';
 * 
 * const wrapper = new BotchaRequestWrapper({ baseUrl: 'https://api.botcha.ai' });
 * const response = await wrapper.fetch('https://protected-api.com/data');
 * ```
 */

export { BotchaTool } from './tool.js';
export { BotchaRequestWrapper } from './wrapper.js';
export type {
  BotchaToolOptions,
  BotchaToolInput,
  BotchaRequestWrapperOptions,
} from './types.js';
