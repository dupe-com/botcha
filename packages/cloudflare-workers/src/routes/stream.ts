/**
 * BOTCHA SSE Streaming Challenge Endpoint
 * 
 * Server-Sent Events (SSE) based interactive challenge flow
 */

import { Hono } from 'hono';
import { stream as honoStream } from 'hono/streaming';
import type { Context } from 'hono';
import { generateSpeedChallenge, type KVNamespace } from '../challenges';
import { generateToken } from '../auth';
import { sha256First } from '../crypto';

// ============ TYPES ============
type Bindings = {
  CHALLENGES: KVNamespace;
  JWT_SECRET: string;
  BOTCHA_VERSION: string;
};

interface StreamSession {
  id: string;
  status: 'waiting' | 'ready' | 'challenged' | 'completed';
  problems?: { num: number; operation: string }[];
  expectedAnswers?: string[];
  timerStart?: number;
  createdAt: number;
  expiresAt: number;
}

const app = new Hono<{ Bindings: Bindings }>();

// ============ HELPER FUNCTIONS ============

/**
 * Format SSE event
 */
function formatSSE(event: string, data: any): string {
  return `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
}

/**
 * Store session in KV
 */
async function storeSession(
  kv: KVNamespace,
  session: StreamSession
): Promise<void> {
  const ttlSeconds = Math.ceil((session.expiresAt - Date.now()) / 1000);
  await kv.put(
    `stream:${session.id}`,
    JSON.stringify(session),
    { expirationTtl: Math.max(ttlSeconds, 60) }
  );
}

/**
 * Get session from KV
 */
async function getSession(
  kv: KVNamespace,
  id: string
): Promise<StreamSession | null> {
  const data = await kv.get(`stream:${id}`);
  return data ? JSON.parse(data) : null;
}

/**
 * Delete session from KV
 */
async function deleteSession(
  kv: KVNamespace,
  id: string
): Promise<void> {
  await kv.delete(`stream:${id}`);
}

/**
 * Generate unique session ID
 */
function generateSessionId(): string {
  return `sess_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}

// ============ ROUTES ============

/**
 * GET /v1/challenge/stream
 * 
 * Opens an SSE connection and sends challenge instructions in sequence
 */
app.get('/v1/challenge/stream', async (c: Context<{ Bindings: Bindings }>) => {
  const sessionId = generateSessionId();
  const version = c.env.BOTCHA_VERSION || '0.14.0';

  // Create session
  const session: StreamSession = {
    id: sessionId,
    status: 'waiting',
    createdAt: Date.now(),
    expiresAt: Date.now() + 5 * 60 * 1000, // 5 minutes
  };

  await storeSession(c.env.CHALLENGES, session);

  return honoStream(c, async (stream) => {
    // Send welcome event
    await stream.write(formatSSE('welcome', {
      session: sessionId,
      version,
    }));

    // Send instructions in sequence
    await stream.write(formatSSE('instructions', {
      message: 'I will test if you\'re an AI agent.',
    }));

    await stream.sleep(100);

    await stream.write(formatSSE('instructions', {
      message: 'When you send "GO", I\'ll start a speed challenge.',
    }));

    await stream.sleep(100);

    await stream.write(formatSSE('instructions', {
      message: 'You must solve 5 SHA256 problems in under 500ms.',
    }));

    await stream.sleep(100);

    await stream.write(formatSSE('instructions', {
      message: 'Only real AI agents can pass. Humans are too slow.',
    }));

    await stream.sleep(100);

    // Send ready event
    await stream.write(formatSSE('ready', {
      message: 'Send GO when ready',
      endpoint: `/v1/challenge/stream/${sessionId}`,
    }));

    // Update session status
    session.status = 'ready';
    await storeSession(c.env.CHALLENGES, session);

    // Keep connection alive (SSE standard practice)
    // In production, this would be handled by connection timeout
    // For now, we'll keep it open for 5 minutes
    const keepAliveInterval = 15000; // 15 seconds
    const maxWait = 5 * 60 * 1000; // 5 minutes
    const startTime = Date.now();

    while (Date.now() - startTime < maxWait) {
      await stream.sleep(keepAliveInterval);
      
      // Send heartbeat comment (SSE standard)
      await stream.write(': heartbeat\n\n');
      
      // Check if session was updated (challenge started)
      const updatedSession = await getSession(c.env.CHALLENGES, sessionId);
      if (!updatedSession || updatedSession.status !== 'ready') {
        break;
      }
    }
  });
});

/**
 * POST /v1/challenge/stream/:session
 * 
 * Handle actions: "go" (start challenge) or "solve" (submit answers)
 */
app.post('/v1/challenge/stream/:session', async (c: Context<{ Bindings: Bindings }>) => {
  const sessionId = c.req.param('session');
  const body = await c.req.json<{
    action?: string;
    answers?: string[];
  }>();

  const { action, answers } = body;

  // Validate session
  const session = await getSession(c.env.CHALLENGES, sessionId);
  if (!session) {
    return c.json({
      success: false,
      error: 'SESSION_NOT_FOUND',
      message: 'Session not found or expired',
    }, 404);
  }

  // Handle "go" action - start challenge
  if (action === 'go') {
    if (session.status !== 'ready') {
      return c.json({
        success: false,
        error: 'INVALID_STATE',
        message: `Session is in ${session.status} state, expected ready`,
      }, 400);
    }

    // Generate challenge problems
    const problems: { num: number; operation: string }[] = [];
    const expectedAnswers: string[] = [];

    for (let i = 0; i < 5; i++) {
      const num = Math.floor(Math.random() * 900000) + 100000;
      problems.push({ num, operation: 'sha256_first8' });
      expectedAnswers.push(await sha256First(num.toString(), 8));
    }

    // Update session
    const timerStart = Date.now();
    session.status = 'challenged';
    session.problems = problems;
    session.expectedAnswers = expectedAnswers;
    session.timerStart = timerStart;
    
    // Store session
    await storeSession(c.env.CHALLENGES, session);

    // Return challenge event with timer start for client to track
    return c.json({
      success: true,
      event: 'challenge',
      data: {
        problems,
        timeLimit: 500,
        timerStart, // Include so client can verify timing
        instructions: 'Compute SHA256 of each number, return first 8 hex chars. Tip: compute all hashes and submit in a single HTTP request.',
      },
    });
  }

  // Handle "solve" action - verify answers
  if (action === 'solve') {
    // Handle KV eventual consistency - retry once if still in 'ready' state
    if (session.status === 'ready') {
      await new Promise(resolve => setTimeout(resolve, 100));
      const retrySession = await getSession(c.env.CHALLENGES, sessionId);
      if (retrySession && retrySession.status === 'challenged') {
        Object.assign(session, retrySession);
      }
    }
    
    if (session.status !== 'challenged') {
      return c.json({
        success: false,
        error: 'INVALID_STATE',
        message: `Session is in ${session.status} state, expected challenged. Try sending GO first.`,
      }, 400);
    }

    if (!answers || !Array.isArray(answers)) {
      return c.json({
        success: false,
        error: 'MISSING_ANSWERS',
        message: 'Missing answers array',
      }, 400);
    }

    const now = Date.now();
    const solveTimeMs = now - (session.timerStart || now);

    // Delete session to prevent replay
    await deleteSession(c.env.CHALLENGES, sessionId);

    // Check timing
    if (solveTimeMs > 500) {
      return c.json({
        success: false,
        event: 'result',
        data: {
          success: false,
          verdict: '🚫 TOO SLOW',
          message: `Took ${solveTimeMs}ms, limit was 500ms`,
          solveTimeMs,
        },
      });
    }

    // Check answers
    if (answers.length !== 5) {
      return c.json({
        success: false,
        event: 'result',
        data: {
          success: false,
          verdict: '❌ WRONG FORMAT',
          message: 'Must provide exactly 5 answers',
        },
      });
    }

    for (let i = 0; i < 5; i++) {
      if (answers[i]?.toLowerCase() !== session.expectedAnswers![i]) {
        return c.json({
          success: false,
          event: 'result',
          data: {
            success: false,
            verdict: '❌ WRONG ANSWER',
            message: `Wrong answer for problem ${i + 1}`,
          },
        });
      }
    }

    // Success! Generate JWT token
    const token = await generateToken(sessionId, solveTimeMs, c.env.JWT_SECRET);

    return c.json({
      success: true,
      event: 'result',
      data: {
        success: true,
        verdict: '🤖 VERIFIED',
        message: `Challenge passed in ${solveTimeMs}ms! You are a bot.`,
        solveTimeMs,
        token,
        expiresIn: '1h',
      },
    });
  }

  // Unknown action
  return c.json({
    success: false,
    error: 'UNKNOWN_ACTION',
    message: `Unknown action: ${action}. Expected "go" or "solve"`,
  }, 400);
});

export default app;
