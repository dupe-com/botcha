import { BadgePayload, BadgeMethod } from './badge.js';

interface BadgeImageOptions {
  width?: number;
  height?: number;
}

const METHOD_COLORS: Record<BadgeMethod, { bg: string; accent: string; text: string }> = {
  'speed-challenge': { bg: '#1a1a2e', accent: '#f59e0b', text: '#fef3c7' },
  'landing-challenge': { bg: '#1a1a2e', accent: '#10b981', text: '#d1fae5' },
  'standard-challenge': { bg: '#1a1a2e', accent: '#3b82f6', text: '#dbeafe' },
  'web-bot-auth': { bg: '#1a1a2e', accent: '#8b5cf6', text: '#ede9fe' },
  'reasoning-challenge': { bg: '#1a1a2e', accent: '#ec4899', text: '#fce7f3' },
  'hybrid-challenge': { bg: '#1a1a2e', accent: '#ef4444', text: '#fecaca' },
};

const METHOD_LABELS: Record<BadgeMethod, string> = {
  'speed-challenge': 'SPEED TEST',
  'landing-challenge': 'LANDING CHALLENGE',
  'standard-challenge': 'CHALLENGE',
  'web-bot-auth': 'WEB BOT AUTH',
  'reasoning-challenge': 'REASONING TEST',
  'hybrid-challenge': 'HYBRID TEST',
};

const METHOD_ICONS: Record<BadgeMethod, string> = {
  'speed-challenge': '⚡',
  'landing-challenge': '🌐',
  'standard-challenge': '🔢',
  'web-bot-auth': '🔐',
  'reasoning-challenge': '🧠',
  'hybrid-challenge': '🔥',
};

/**
 * Generate an SVG badge image
 */
export function generateBadgeSvg(
  payload: BadgePayload,
  options: BadgeImageOptions = {}
): string {
  const { width = 400, height = 120 } = options;
  const colors = METHOD_COLORS[payload.method];
  const label = METHOD_LABELS[payload.method];
  const icon = METHOD_ICONS[payload.method];

  const verifiedDate = new Date(payload.verifiedAt).toISOString().split('T')[0];
  const solveTimeText = payload.solveTimeMs ? `${payload.solveTimeMs}ms` : '';

  return `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}">
  <defs>
    <linearGradient id="bgGradient" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:${colors.bg};stop-opacity:1" />
      <stop offset="100%" style="stop-color:#0f0f23;stop-opacity:1" />
    </linearGradient>
    <linearGradient id="accentGradient" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" style="stop-color:${colors.accent};stop-opacity:1" />
      <stop offset="100%" style="stop-color:${colors.accent};stop-opacity:0.7" />
    </linearGradient>
    <filter id="glow">
      <feGaussianBlur stdDeviation="2" result="coloredBlur"/>
      <feMerge>
        <feMergeNode in="coloredBlur"/>
        <feMergeNode in="SourceGraphic"/>
      </feMerge>
    </filter>
  </defs>

  <!-- Background -->
  <rect width="${width}" height="${height}" rx="12" fill="url(#bgGradient)"/>

  <!-- Border accent -->
  <rect x="1" y="1" width="${width - 2}" height="${height - 2}" rx="11" fill="none" stroke="${colors.accent}" stroke-width="2" opacity="0.3"/>

  <!-- Top accent line -->
  <rect x="20" y="8" width="${width - 40}" height="3" rx="1.5" fill="url(#accentGradient)"/>

  <!-- Robot icon -->
  <text x="30" y="58" font-size="32" filter="url(#glow)">${icon}</text>

  <!-- BOTCHA text -->
  <text x="75" y="45" font-family="system-ui, -apple-system, sans-serif" font-size="18" font-weight="bold" fill="${colors.accent}">BOTCHA</text>

  <!-- Verified badge -->
  <text x="75" y="68" font-family="system-ui, -apple-system, sans-serif" font-size="14" font-weight="600" fill="${colors.text}">VERIFIED</text>

  <!-- Method label -->
  <rect x="145" y="53" width="${label.length * 8 + 16}" height="22" rx="4" fill="${colors.accent}" opacity="0.2"/>
  <text x="153" y="68" font-family="system-ui, -apple-system, sans-serif" font-size="11" font-weight="600" fill="${colors.accent}">${label}</text>

  <!-- Solve time (if available) -->
  ${solveTimeText ? `
  <text x="${width - 30}" y="45" font-family="monospace" font-size="24" font-weight="bold" fill="${colors.accent}" text-anchor="end" filter="url(#glow)">${solveTimeText}</text>
  <text x="${width - 30}" y="62" font-family="system-ui, -apple-system, sans-serif" font-size="10" fill="#6b7280" text-anchor="end">solve time</text>
  ` : `
  <text x="${width - 30}" y="55" font-family="system-ui, -apple-system, sans-serif" font-size="12" fill="${colors.accent}" text-anchor="end">✓ PASSED</text>
  `}

  <!-- Bottom info -->
  <line x1="20" y1="${height - 30}" x2="${width - 20}" y2="${height - 30}" stroke="#374151" stroke-width="1" opacity="0.5"/>

  <!-- Date -->
  <text x="30" y="${height - 12}" font-family="monospace" font-size="11" fill="#6b7280">${verifiedDate}</text>

  <!-- botcha.ai link -->
  <text x="${width - 30}" y="${height - 12}" font-family="system-ui, -apple-system, sans-serif" font-size="11" fill="#6b7280" text-anchor="end">botcha.ai</text>

  <!-- Checkmark icon -->
  <circle cx="${width / 2}" cy="${height - 16}" r="8" fill="${colors.accent}" opacity="0.2"/>
  <text x="${width / 2}" y="${height - 12}" font-size="10" text-anchor="middle" fill="${colors.accent}">✓</text>
</svg>`;
}

/**
 * Generate an HTML verification page
 */
export function generateBadgeHtml(payload: BadgePayload, badgeId: string): string {
  const colors = METHOD_COLORS[payload.method];
  const label = METHOD_LABELS[payload.method];
  const icon = METHOD_ICONS[payload.method];
  const verifiedDate = new Date(payload.verifiedAt).toLocaleString();

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>BOTCHA Badge Verification</title>
  <meta name="description" content="Verified AI agent badge from BOTCHA">
  <meta property="og:title" content="BOTCHA Verified - ${label}">
  <meta property="og:description" content="This AI agent passed the BOTCHA verification${payload.solveTimeMs ? ` in ${payload.solveTimeMs}ms` : ''}.">
  <meta property="og:image" content="https://botcha.ai/badge/${encodeURIComponent(badgeId)}/image">
  <meta name="twitter:card" content="summary_large_image">
  <meta name="twitter:title" content="BOTCHA Verified - ${label}">
  <meta name="twitter:description" content="This AI agent passed the BOTCHA verification.">
  <meta name="twitter:image" content="https://botcha.ai/badge/${encodeURIComponent(badgeId)}/image">
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: system-ui, -apple-system, sans-serif;
      background: linear-gradient(135deg, #0f0f23 0%, #1a1a2e 100%);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      padding: 20px;
      color: #e5e7eb;
    }
    .container {
      max-width: 500px;
      width: 100%;
      text-align: center;
    }
    .badge-card {
      background: rgba(26, 26, 46, 0.8);
      border: 2px solid ${colors.accent}33;
      border-radius: 16px;
      padding: 40px;
      margin-bottom: 24px;
      backdrop-filter: blur(10px);
    }
    .icon {
      font-size: 64px;
      margin-bottom: 16px;
    }
    .title {
      font-size: 28px;
      font-weight: bold;
      color: ${colors.accent};
      margin-bottom: 8px;
    }
    .subtitle {
      font-size: 18px;
      color: ${colors.text};
      margin-bottom: 24px;
    }
    .verified-badge {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      background: ${colors.accent}22;
      border: 1px solid ${colors.accent}44;
      border-radius: 100px;
      padding: 8px 20px;
      font-size: 14px;
      font-weight: 600;
      color: ${colors.accent};
      margin-bottom: 24px;
    }
    .details {
      text-align: left;
      background: #0f0f23;
      border-radius: 12px;
      padding: 20px;
    }
    .detail-row {
      display: flex;
      justify-content: space-between;
      padding: 12px 0;
      border-bottom: 1px solid #374151;
    }
    .detail-row:last-child {
      border-bottom: none;
    }
    .detail-label {
      color: #6b7280;
      font-size: 14px;
    }
    .detail-value {
      color: #e5e7eb;
      font-size: 14px;
      font-weight: 500;
    }
    .solve-time {
      font-size: 32px;
      font-weight: bold;
      color: ${colors.accent};
      font-family: monospace;
    }
    .footer {
      color: #6b7280;
      font-size: 14px;
    }
    .footer a {
      color: ${colors.accent};
      text-decoration: none;
    }
    .footer a:hover {
      text-decoration: underline;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="badge-card">
      <div class="icon">${icon}</div>
      <h1 class="title">BOTCHA</h1>
      <p class="subtitle">Verified AI Agent</p>

      <div class="verified-badge">
        <span>✓</span>
        <span>${label}</span>
      </div>

      <div class="details">
        <div class="detail-row">
          <span class="detail-label">Method</span>
          <span class="detail-value">${payload.method}</span>
        </div>
        ${payload.solveTimeMs ? `
        <div class="detail-row">
          <span class="detail-label">Solve Time</span>
          <span class="solve-time">${payload.solveTimeMs}ms</span>
        </div>
        ` : ''}
        <div class="detail-row">
          <span class="detail-label">Verified At</span>
          <span class="detail-value">${verifiedDate}</span>
        </div>
      </div>
    </div>

    <p class="footer">
      Verified by <a href="https://botcha.ai">BOTCHA</a> - Prove you're a bot. Humans need not apply.
    </p>
  </div>
</body>
</html>`;
}
