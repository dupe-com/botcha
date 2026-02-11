/**
 * BOTCHA Client SDK Type Definitions
 * 
 * Types for the BotchaClient SDK including challenges, tokens, and configuration.
 */

export type SpeedProblem = number | { num: number; operation?: string };

export interface BotchaClientOptions {
  /** Base URL of BOTCHA service (default: https://botcha.ai) */
  baseUrl?: string;
  /** Custom identity header value */
  agentIdentity?: string;
  /** Max retries for challenge solving */
  maxRetries?: number;
  /** Enable automatic token acquisition and management (default: true) */
  autoToken?: boolean;
  /** Audience claim for token (optional) */
  audience?: string;
}

export interface ChallengeResponse {
  success: boolean;
  challenge?: {
    id: string;
    problems: SpeedProblem[];
    timeLimit: number;
    instructions: string;
  };
}

export interface StandardChallengeResponse {
  success: boolean;
  challenge?: {
    id: string;
    puzzle: string;
    timeLimit: number;
    hint?: string;
  };
}

export interface VerifyResponse {
  success: boolean;
  message: string;
  solveTimeMs?: number;
  verdict?: string;
}

export interface TokenResponse {
  success: boolean;
  token: string | null;
  access_token?: string;
  refresh_token?: string;
  expires_in?: number;
  refresh_expires_in?: number;
  expiresIn?: string;
  challenge?: {
    id: string;
    problems: SpeedProblem[];
    timeLimit: number;
    instructions: string;
  };
  nextStep?: string;
  verified?: boolean;
  solveTimeMs?: number;
}

/**
 * Stream-related types for BotchaStreamClient
 */

export interface StreamSession {
  session: string;
  url: string;
}

export interface StreamEvent {
  event: 'ready' | 'instruction' | 'challenge' | 'result' | 'error';
  data: any;
}

export interface Problem {
  num: number;
  operation?: string;
}

export interface VerifyResult {
  success: boolean;
  token?: string;
  message?: string;
  solveTimeMs?: number;
}

export interface StreamChallengeOptions {
  /** Callback for instruction messages */
  onInstruction?: (message: string) => void;
  /** Callback to solve challenges - return answers array */
  onChallenge?: (problems: Problem[]) => Promise<string[]> | string[];
  /** Callback for final verification result */
  onResult?: (result: VerifyResult) => void;
  /** Timeout for the full verification flow in milliseconds (default: 30000) */
  timeout?: number;
}
