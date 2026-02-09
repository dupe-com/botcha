import crypto from 'crypto';
import type {
  StreamSession,
  StreamChallengeOptions,
  Problem,
  VerifyResult,
} from './types.js';

// SDK version
const SDK_VERSION = '0.4.0';

/**
 * BotchaStreamClient - SSE-based streaming challenge client
 * 
 * Handles Server-Sent Events (SSE) streaming for interactive challenge flows.
 * Automatically connects, solves challenges, and returns JWT tokens.
 * 
 * Note: For Node.js usage, ensure you're running Node 18+ with native EventSource support,
 * or install the 'eventsource' polyfill package.
 * 
 * @example
 * ```typescript
 * import { BotchaStreamClient } from '@dupecom/botcha/client';
 * 
 * const client = new BotchaStreamClient();
 * 
 * // Simple usage with built-in SHA256 solver
 * const token = await client.verify();
 * 
 * // Custom callbacks for monitoring
 * const token = await client.verify({
 *   onInstruction: (msg) => console.log('Instruction:', msg),
 *   onChallenge: async (problems) => {
 *     // Custom solver logic
 *     return problems.map(p => customSolve(p.num));
 *   },
 *   onResult: (result) => console.log('Result:', result),
 *   timeout: 45000, // 45 seconds
 * });
 * ```
 */
export class BotchaStreamClient {
  private baseUrl: string;
  private agentIdentity: string;
  private eventSource: EventSource | null = null;

  constructor(baseUrl?: string) {
    this.baseUrl = baseUrl || 'https://botcha.ai';
    this.agentIdentity = `BotchaStreamClient/${SDK_VERSION}`;
  }

  /**
   * Verify using streaming challenge flow
   * 
   * Automatically connects to the streaming endpoint, handles the full challenge flow,
   * and returns a JWT token on successful verification.
   * 
   * @param options - Configuration options and callbacks
   * @returns JWT token string
   * @throws Error if verification fails or times out
   */
  async verify(options: StreamChallengeOptions = {}): Promise<string> {
    const {
      onInstruction,
      onChallenge,
      onResult,
      timeout = 30000,
    } = options;

    return new Promise<string>((resolve, reject) => {
      const timeoutId = setTimeout(() => {
        this.close();
        reject(new Error('Stream verification timeout'));
      }, timeout);

      let sessionId: string | null = null;

      // Connect to stream endpoint
      const streamUrl = `${this.baseUrl}/v1/challenge/stream`;
      
      // Check if EventSource is available
      if (typeof EventSource === 'undefined') {
        clearTimeout(timeoutId);
        reject(new Error('EventSource not available. For Node.js, use Node 18+ or install eventsource polyfill.'));
        return;
      }

      this.eventSource = new EventSource(streamUrl);

      // Handle 'ready' event - send 'go' action
      this.eventSource.addEventListener('ready', (event: MessageEvent) => {
        try {
          const data = JSON.parse(event.data);
          sessionId = data.session;
          
          // Auto-send 'go' action to start challenge
          if (sessionId) {
            this.sendAction(sessionId, 'go').catch((err) => {
              clearTimeout(timeoutId);
              this.close();
              reject(err);
            });
          }
        } catch (err) {
          clearTimeout(timeoutId);
          this.close();
          reject(new Error(`Failed to parse ready event: ${err}`));
        }
      });

      // Handle 'instruction' event
      this.eventSource.addEventListener('instruction', (event: MessageEvent) => {
        try {
          const data = JSON.parse(event.data);
          if (onInstruction && data.message) {
            onInstruction(data.message);
          }
        } catch (err) {
          console.warn('Failed to parse instruction event:', err);
        }
      });

      // Handle 'challenge' event - solve and submit
      this.eventSource.addEventListener('challenge', async (event: MessageEvent) => {
        try {
          const data = JSON.parse(event.data);
          const problems: Problem[] = data.problems || [];

          // Get answers from callback or use default solver
          let answers: string[];
          if (onChallenge) {
            answers = await Promise.resolve(onChallenge(problems));
          } else {
            // Default SHA256 solver for speed challenges
            answers = this.solveSpeed(problems);
          }

          // Send solve action
          if (sessionId) {
            await this.sendAction(sessionId, { action: 'solve', answers });
          }
        } catch (err) {
          clearTimeout(timeoutId);
          this.close();
          reject(new Error(`Challenge solving failed: ${err}`));
        }
      });

      // Handle 'result' event - final verification result
      this.eventSource.addEventListener('result', (event: MessageEvent) => {
        try {
          const data = JSON.parse(event.data) as VerifyResult;
          
          if (onResult) {
            onResult(data);
          }

          clearTimeout(timeoutId);
          this.close();

          if (data.success && data.token) {
            resolve(data.token);
          } else {
            reject(new Error(data.message || 'Verification failed'));
          }
        } catch (err) {
          clearTimeout(timeoutId);
          this.close();
          reject(new Error(`Failed to parse result event: ${err}`));
        }
      });

      // Handle 'error' event
      this.eventSource.addEventListener('error', (event: MessageEvent) => {
        try {
          const data = JSON.parse(event.data);
          clearTimeout(timeoutId);
          this.close();
          reject(new Error(data.message || 'Stream error occurred'));
        } catch (err) {
          clearTimeout(timeoutId);
          this.close();
          reject(new Error('Stream connection error'));
        }
      });

      // Handle connection errors
      this.eventSource.onerror = () => {
        clearTimeout(timeoutId);
        this.close();
        reject(new Error('EventSource connection failed'));
      };
    });
  }

  /**
   * Connect to streaming endpoint and get session
   * 
   * Lower-level method for manual control of the stream flow.
   * 
   * @returns Promise resolving to StreamSession with session ID and URL
   */
  async connect(): Promise<StreamSession> {
    return new Promise<StreamSession>((resolve, reject) => {
      const streamUrl = `${this.baseUrl}/v1/challenge/stream`;
      
      if (typeof EventSource === 'undefined') {
        reject(new Error('EventSource not available. For Node.js, use Node 18+ or install eventsource polyfill.'));
        return;
      }

      this.eventSource = new EventSource(streamUrl);

      this.eventSource.addEventListener('ready', (event: MessageEvent) => {
        try {
          const data = JSON.parse(event.data);
          resolve({
            session: data.session,
            url: streamUrl,
          });
        } catch (err) {
          this.close();
          reject(new Error(`Failed to parse ready event: ${err}`));
        }
      });

      this.eventSource.onerror = () => {
        this.close();
        reject(new Error('EventSource connection failed'));
      };
    });
  }

  /**
   * Send an action to the streaming session
   * 
   * @param session - Session ID from connect()
   * @param action - Action to send ('go' or solve object)
   */
  async sendAction(
    session: string,
    action: 'go' | { action: 'solve'; answers: string[] }
  ): Promise<void> {
    const actionUrl = `${this.baseUrl}/v1/challenge/stream`;
    
    const body = typeof action === 'string' 
      ? { session, action }
      : { session, ...action };

    const response = await fetch(actionUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': this.agentIdentity,
      },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      throw new Error(`Action failed with status ${response.status} ${response.statusText}`);
    }
  }

  /**
   * Close the stream connection
   */
  close(): void {
    if (this.eventSource) {
      this.eventSource.close();
      this.eventSource = null;
    }
  }

  /**
   * Built-in SHA256 solver for speed challenges
   * 
   * @param problems - Array of speed challenge problems
   * @returns Array of SHA256 first 8 hex chars for each number
   */
  private solveSpeed(problems: Problem[]): string[] {
    return problems.map((problem) => {
      const num = problem.num;
      return crypto
        .createHash('sha256')
        .update(num.toString())
        .digest('hex')
        .substring(0, 8);
    });
  }
}
