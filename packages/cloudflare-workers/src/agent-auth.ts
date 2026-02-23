/**
 * Agent Identity Authentication
 *
 * Allows a registered TAP agent to prove its identity by signing a nonce
 * with its Ed25519 private key. Returns a JWT containing both app_id and
 * agent_id — so callers know exactly which agent they're talking to.
 *
 * Flow:
 *   1. POST /v1/agents/auth          { agent_id }
 *      → { challenge_id, nonce, message, expires_in: 60 }
 *
 *   2. Agent signs the nonce bytes with its Ed25519 private key
 *
 *   3. POST /v1/agents/auth/verify   { challenge_id, agent_id, signature }
 *      → { access_token, agent_id, app_id, expires_in: 3600 }
 *
 * The nonce is a random 32-byte hex string stored in KV with a 60-second TTL.
 * The signature is base64-encoded Ed25519 signature over the raw nonce bytes.
 *
 * Why this matters:
 *   A challenge-verified JWT (from /v1/token) only proves "I am an AI agent
 *   for app X". An agent-auth JWT proves "I am specifically agent Y for app X".
 *   The private key is the agent's persistent credential — the operator stores
 *   it and provides it to the agent at the start of each session.
 */

import type { Context } from 'hono';
import { SignJWT } from 'jose';
import { getTAPAgent } from './tap-agents';

type KVNamespace = { get(key: string, type?: string): Promise<string | null>; put(key: string, value: string, opts?: { expirationTtl?: number }): Promise<void>; delete(key: string): Promise<void> };
type Bindings = { AGENTS: KVNamespace; CHALLENGES: KVNamespace; JWT_SECRET: string };

// ============ STEP 1: Issue nonce challenge ============

export async function handleAgentAuthChallenge(c: Context<{ Bindings: Bindings }>) {
  const body = await c.req.json().catch(() => ({})) as any;
  const agent_id = body?.agent_id;

  if (!agent_id || typeof agent_id !== 'string') {
    return c.json({ success: false, error: 'MISSING_AGENT_ID', message: 'agent_id is required' }, 400);
  }

  // Look up TAP agent — must have a registered public key
  const result = await getTAPAgent(c.env.AGENTS, agent_id);
  if (!result.success || !result.agent) {
    return c.json({ success: false, error: 'AGENT_NOT_FOUND', message: 'No TAP agent found with that agent_id. Register a keypair first via POST /v1/agents/register/tap' }, 404);
  }
  if (!result.agent.public_key) {
    return c.json({ success: false, error: 'NO_PUBLIC_KEY', message: 'This agent has no registered public key. Re-register via POST /v1/agents/register/tap with a public_key' }, 400);
  }

  // Generate a random nonce
  const nonceBytes = crypto.getRandomValues(new Uint8Array(32));
  const nonce = Array.from(nonceBytes).map(b => b.toString(16).padStart(2, '0')).join('');
  const challenge_id = `agentauth_${crypto.randomUUID()}`;

  // Store: challenge_id → { nonce, agent_id } with 60s TTL
  await c.env.CHALLENGES.put(
    `agentauth:${challenge_id}`,
    JSON.stringify({ nonce, agent_id, created_at: Date.now() }),
    { expirationTtl: 60 }
  );

  return c.json({
    success: true,
    challenge_id,
    nonce,
    agent_id,
    expires_in: 60,
    message: 'Sign the nonce bytes with your Ed25519 private key. Submit base64-encoded signature to POST /v1/agents/auth/verify',
    instructions: {
      what_to_sign: 'The raw nonce string encoded as UTF-8 bytes',
      signature_format: 'base64-encoded Ed25519 signature',
      next_step: 'POST /v1/agents/auth/verify with { challenge_id, agent_id, signature }',
    },
  });
}

// ============ STEP 2: Verify signature, issue agent JWT ============

export async function handleAgentAuthVerify(c: Context<{ Bindings: Bindings }>) {
  const body = await c.req.json().catch(() => ({})) as any;
  const { challenge_id, agent_id, signature } = body ?? {};

  if (!challenge_id || !agent_id || !signature) {
    return c.json({ success: false, error: 'MISSING_FIELDS', message: 'challenge_id, agent_id, and signature are required' }, 400);
  }

  // Retrieve and immediately delete the challenge (one-shot)
  const raw = await c.env.CHALLENGES.get(`agentauth:${challenge_id}`, 'text');
  if (!raw) {
    return c.json({ success: false, error: 'CHALLENGE_NOT_FOUND', message: 'Challenge not found or expired (60s TTL)' }, 404);
  }
  await c.env.CHALLENGES.delete(`agentauth:${challenge_id}`);

  const stored = JSON.parse(raw) as { nonce: string; agent_id: string; created_at: number };

  // Verify agent_id matches what was challenged
  if (stored.agent_id !== agent_id) {
    return c.json({ success: false, error: 'AGENT_MISMATCH', message: 'agent_id does not match the challenged agent' }, 400);
  }

  // Look up TAP agent and public key
  const result = await getTAPAgent(c.env.AGENTS, agent_id);
  if (!result.success || !result.agent?.public_key) {
    return c.json({ success: false, error: 'AGENT_NOT_FOUND', message: 'Agent not found' }, 404);
  }

  const { public_key, signature_algorithm, app_id } = result.agent as any;

  // Verify the signature
  const valid = await verifyNonceSignature(stored.nonce, signature, public_key, signature_algorithm ?? 'ed25519');
  if (!valid) {
    return c.json({ success: false, error: 'INVALID_SIGNATURE', message: 'Signature verification failed. Ensure you signed the raw nonce string with your registered private key.' }, 401);
  }

  // Issue agent-identity JWT (1 hour)
  const secret = new TextEncoder().encode(c.env.JWT_SECRET);
  const access_token = await new SignJWT({
    type: 'botcha-agent-identity',
    agent_id,
    app_id,
  })
    .setProtectedHeader({ alg: 'HS256' })
    .setSubject(agent_id)
    .setIssuer('botcha.ai')
    .setIssuedAt()
    .setExpirationTime('1h')
    .setJti(crypto.randomUUID())
    .sign(secret);

  return c.json({
    success: true,
    access_token,
    token_type: 'Bearer',
    agent_id,
    app_id,
    expires_in: 3600,
    message: 'Identity verified. This token proves you are specifically this agent.',
    usage: {
      header: 'Authorization: Bearer <access_token>',
      note: 'This token contains your agent_id claim. Services can verify your specific identity without you solving a fresh challenge.',
    },
  });
}

// ============ Signature verification ============

async function verifyNonceSignature(
  nonce: string,
  signatureB64: string,
  publicKey: string,
  algorithm: string
): Promise<boolean> {
  try {
    const sigBytes = Uint8Array.from(atob(signatureB64), c => c.charCodeAt(0));
    const nonceBytes = new TextEncoder().encode(nonce);

    let keyData: ArrayBuffer;
    if (algorithm === 'ed25519') {
      // Accept raw 32-byte base64 key or SPKI DER base64
      const raw = Uint8Array.from(atob(publicKey), c => c.charCodeAt(0));
      if (raw.length === 32) {
        // Raw key — wrap in SPKI
        const spki = new Uint8Array(44);
        // Ed25519 SPKI header (12 bytes)
        spki.set([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]);
        spki.set(raw, 12);
        keyData = spki.buffer;
      } else {
        keyData = raw.buffer;
      }
      const cryptoKey = await crypto.subtle.importKey('spki', keyData, { name: 'Ed25519' }, false, ['verify']);
      return await crypto.subtle.verify({ name: 'Ed25519' }, cryptoKey, sigBytes, nonceBytes);
    }

    // ECDSA P-256
    if (algorithm === 'ecdsa-p256-sha256') {
      const raw = Uint8Array.from(atob(publicKey), c => c.charCodeAt(0));
      const cryptoKey = await crypto.subtle.importKey('spki', raw.buffer, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
      return await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, cryptoKey, sigBytes, nonceBytes);
    }

    return false;
  } catch (e) {
    console.error('Agent auth signature verification error:', e);
    return false;
  }
}
