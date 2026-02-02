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
  expiresIn?: string;
  challenge?: {
    id: string;
    problems: SpeedProblem[];
    timeLimit: number;
    instructions: string;
  };
  nextStep?: string;
}
