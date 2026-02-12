/**
 * BOTCHA Dashboard — Device Code Authentication
 *
 * OAuth2 Device Authorization Grant adapted for agent→human handoff.
 * An agent generates a short-lived device code by solving a BOTCHA challenge.
 * The human redeems the code at /dashboard/code to get a dashboard session.
 *
 * Flow:
 *   1. Agent: POST /v1/auth/device-code       → gets challenge
 *   2. Agent: POST /v1/auth/device-code/verify → solves challenge, gets { code, login_url }
 *   3. Human: visits /dashboard/code, enters code → dashboard session
 *
 * The agent MUST solve a challenge to generate a code. No agent, no code.
 */

import type { KVNamespace } from '../challenges';

// ============ TYPES ============

export interface DeviceCodeData {
  code: string;
  app_id: string;
  created_at: number;
  expires_at: number;
  redeemed: boolean;
}

// ============ CODE GENERATION ============

/**
 * Generate a human-friendly device code.
 * Format: BOTCHA-XXXX (4 alphanumeric chars, no ambiguous chars)
 *
 * Uses a restricted alphabet that avoids 0/O, 1/I/l confusion.
 */
export function generateDeviceCode(): string {
  const alphabet = '23456789ABCDEFGHJKMNPQRSTUVWXYZ'; // no 0,O,1,I,L
  const bytes = new Uint8Array(4);
  crypto.getRandomValues(bytes);
  const chars = Array.from(bytes).map(b => alphabet[b % alphabet.length]).join('');
  return `BOTCHA-${chars}`;
}

/**
 * Store a device code in KV with 10-minute TTL.
 */
export async function storeDeviceCode(
  kv: KVNamespace,
  code: string,
  appId: string
): Promise<DeviceCodeData> {
  const now = Date.now();
  const data: DeviceCodeData = {
    code,
    app_id: appId,
    created_at: now,
    expires_at: now + 10 * 60 * 1000, // 10 minutes
    redeemed: false,
  };

  await kv.put(
    `device-code:${code}`,
    JSON.stringify(data),
    { expirationTtl: 600 } // 10 minutes
  );

  return data;
}

/**
 * Look up a device code from KV.
 * Returns null if not found, expired, or already redeemed.
 */
export async function lookupDeviceCode(
  kv: KVNamespace,
  code: string
): Promise<DeviceCodeData | null> {
  try {
    const raw = await kv.get(`device-code:${code}`, 'text');
    if (!raw) return null;

    const data: DeviceCodeData = JSON.parse(raw);

    if (data.redeemed) return null;
    if (Date.now() > data.expires_at) return null;

    return data;
  } catch {
    return null;
  }
}

/**
 * Redeem a device code (mark as used so it can't be reused).
 */
export async function redeemDeviceCode(
  kv: KVNamespace,
  code: string
): Promise<DeviceCodeData | null> {
  const data = await lookupDeviceCode(kv, code);
  if (!data) return null;

  // Mark redeemed and update KV (keep same TTL by letting it expire naturally)
  data.redeemed = true;
  await kv.put(
    `device-code:${code}`,
    JSON.stringify(data),
    { expirationTtl: 60 } // Reduce TTL to 1 minute after redemption
  );

  return data;
}
