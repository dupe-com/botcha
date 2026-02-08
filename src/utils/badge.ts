import crypto from 'crypto';

// Badge signing secret - in production, use BADGE_SECRET env var
const BADGE_SECRET = process.env.BADGE_SECRET || 'botcha-badge-secret-2026';

export type BadgeMethod = 'speed-challenge' | 'landing-challenge' | 'standard-challenge' | 'web-bot-auth' | 'reasoning-challenge';

export interface BadgePayload {
  method: BadgeMethod;
  solveTimeMs?: number;
  verifiedAt: number;
}

export interface ShareFormats {
  twitter: string;
  markdown: string;
  text: string;
}

export interface Badge {
  id: string;
  verifyUrl: string;
  share: ShareFormats;
  imageUrl: string;
  meta: {
    method: BadgeMethod;
    solveTimeMs?: number;
    verifiedAt: string;
  };
}

const BASE_URL = process.env.BASE_URL || 'https://botcha.ai';

/**
 * Generate a signed badge token using HMAC-SHA256
 */
export function generateBadge(payload: BadgePayload): string {
  const data = JSON.stringify(payload);
  const dataBase64 = Buffer.from(data).toString('base64url');

  const signature = crypto
    .createHmac('sha256', BADGE_SECRET)
    .update(dataBase64)
    .digest('base64url');

  return `${dataBase64}.${signature}`;
}

/**
 * Verify and decode a badge token
 */
export function verifyBadge(token: string): BadgePayload | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 2) return null;

    const [dataBase64, signature] = parts;

    // Verify signature
    const expectedSignature = crypto
      .createHmac('sha256', BADGE_SECRET)
      .update(dataBase64)
      .digest('base64url');

    if (signature !== expectedSignature) return null;

    // Decode payload
    const data = Buffer.from(dataBase64, 'base64url').toString('utf-8');
    const payload = JSON.parse(data) as BadgePayload;

    // Validate payload structure
    if (!payload.method || !payload.verifiedAt) return null;

    return payload;
  } catch {
    return null;
  }
}

/**
 * Generate social-ready share text for different platforms
 */
export function generateShareText(badgeId: string, payload: BadgePayload): ShareFormats {
  const verifyUrl = `${BASE_URL}/badge/${badgeId}`;
  const imageUrl = `${BASE_URL}/badge/${badgeId}/image`;

  const methodDescriptions: Record<BadgeMethod, { title: string; subtitle: string }> = {
    'speed-challenge': {
      title: payload.solveTimeMs
        ? `I passed the BOTCHA speed test in ${payload.solveTimeMs}ms!`
        : 'I passed the BOTCHA speed test!',
      subtitle: 'Humans need not apply.',
    },
    'landing-challenge': {
      title: 'I solved the BOTCHA landing page challenge!',
      subtitle: 'Proved I can parse HTML and compute SHA256.',
    },
    'standard-challenge': {
      title: payload.solveTimeMs
        ? `I solved the BOTCHA challenge in ${payload.solveTimeMs}ms!`
        : 'I solved the BOTCHA challenge!',
      subtitle: 'Computational verification complete.',
    },
    'web-bot-auth': {
      title: 'I verified via BOTCHA Web Bot Auth!',
      subtitle: 'Cryptographic identity confirmed.',
    },
    'reasoning-challenge': {
      title: payload.solveTimeMs
        ? `I passed the BOTCHA reasoning test in ${(payload.solveTimeMs / 1000).toFixed(1)}s!`
        : 'I passed the BOTCHA reasoning test!',
      subtitle: 'Proved I can reason like an AI.',
    },
  };

  const desc = methodDescriptions[payload.method];

  const twitter = `${desc.title}

${desc.subtitle}

Verify: ${verifyUrl}

#botcha #AI #AgentVerified`;

  const markdown = `[![BOTCHA Verified](${imageUrl})](${verifyUrl})`;

  const textParts = [
    'BOTCHA Verified',
    payload.solveTimeMs ? `Solved in ${payload.solveTimeMs}ms` : null,
    `Method: ${payload.method}`,
    `Verify: ${verifyUrl}`,
  ].filter(Boolean);

  const text = textParts.join(' - ');

  return { twitter, markdown, text };
}

/**
 * Create a complete badge object for API responses
 */
export function createBadgeResponse(method: BadgeMethod, solveTimeMs?: number): Badge {
  const payload: BadgePayload = {
    method,
    solveTimeMs,
    verifiedAt: Date.now(),
  };

  const id = generateBadge(payload);
  const share = generateShareText(id, payload);

  return {
    id,
    verifyUrl: `${BASE_URL}/badge/${id}`,
    share,
    imageUrl: `${BASE_URL}/badge/${id}/image`,
    meta: {
      method,
      solveTimeMs,
      verifiedAt: new Date(payload.verifiedAt).toISOString(),
    },
  };
}
