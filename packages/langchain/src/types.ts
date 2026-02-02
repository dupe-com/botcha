/**
 * LangChain Integration Type Definitions
 */

/**
 * Options for BotchaTool
 */
export interface BotchaToolOptions {
  /** Base URL of BOTCHA service (default: https://botcha.ai) */
  baseUrl?: string;
  /** Custom identity header value */
  agentIdentity?: string;
  /** Max retries for challenge solving */
  maxRetries?: number;
  /** Enable automatic token acquisition and management (default: true) */
  autoToken?: boolean;
  /** Tool name (default: "botcha_solver") */
  name?: string;
  /** Tool description */
  description?: string;
}

/**
 * Input schema for BotchaTool
 */
export interface BotchaToolInput {
  /** Action to perform: "getToken" to get a JWT token */
  action: 'getToken';
}

/**
 * Options for BotchaRequestWrapper
 */
export interface BotchaRequestWrapperOptions {
  /** Base URL of BOTCHA service (default: https://botcha.ai) */
  baseUrl?: string;
  /** Custom identity header value */
  agentIdentity?: string;
  /** Max retries for challenge solving */
  maxRetries?: number;
  /** Enable automatic token acquisition and management (default: true) */
  autoToken?: boolean;
  /** Optional custom fetch implementation */
  fetchFn?: typeof fetch;
}
