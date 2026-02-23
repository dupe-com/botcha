/**
 * BOTCHA Account Page
 *
 * Accessible at GET /account (dashboard session required).
 * Content-negotiated:
 *   Accept: application/json → structured JSON (for agents)
 *   Accept: text/html        → rendered HTML page (for humans)
 *
 * Shows:
 *   - App info (app_id, email, created_at, rate_limit, email_verified)
 *   - Agent list with per-agent reputation score + TAP status
 *   - Links to dashboard, docs, magic link re-generation
 */

import type { Context } from 'hono';
import { DashboardLayout } from './layout';
import { DASHBOARD_CSS } from './styles';

type Bindings = {
  APPS: import('../challenges').KVNamespace;
  AGENTS: import('../challenges').KVNamespace;
  JWT_SECRET: string;
  BOTCHA_VERSION: string;
};

type Variables = {
  dashboardAppId?: string;
};

// ============ DATA FETCHING ============

async function fetchAccountData(c: Context<{ Bindings: Bindings; Variables: Variables }>) {
  const appId = c.get('dashboardAppId')!;
  const env = c.env as any;
  // BOTCHA_BASE_URL is set in .dev.vars for local dev (http://localhost:8787)
  // and in wrangler.toml [vars] for production (https://botcha.ai).
  const baseUrl = (c.env as any).BOTCHA_BASE_URL ?? new URL(c.req.url).origin;

  // Parallel fetches
  const [appRaw, agentsRaw] = await Promise.allSettled([
    import('../apps').then(m => m.getApp(env.APPS, appId)),
    import('../agents').then(m => m.listAgents(env.AGENTS, appId)),
  ]);

  const app = appRaw.status === 'fulfilled' ? appRaw.value : null;
  const agents = agentsRaw.status === 'fulfilled' ? (agentsRaw.value ?? []) : [];

  // Fetch reputation for each agent (parallel, fail-open)
  // getReputationScore requires (sessions, agents, agentId, appId)
  // It only works for TAP-registered agents; returns { success, score? }
  const reputations = await Promise.allSettled(
    agents.map((agent: any) =>
      import('../tap-reputation').then(m =>
        m.getReputationScore(env.AGENTS, env.AGENTS, agent.agent_id, appId)
      )
    )
  );

  const agentsWithRep = agents.map((agent: any, i: number) => {
    const result = reputations[i].status === 'fulfilled' ? reputations[i].value : null;
    const rep = result?.success && result?.score ? result.score : null;
    return {
      agent_id: agent.agent_id,
      name: agent.name,
      operator: agent.operator ?? null,
      created_at: agent.created_at,
      tap_enabled: Boolean((agent as any).tap_enabled),
      provider: (agent as any).provider ?? null,
      reputation: rep
        ? { score: rep.score, tier: rep.tier, event_count: rep.event_count }
        : null,
    };
  });

  return { appId, app, agents: agentsWithRep, baseUrl };
}

// ============ JSON HANDLER (agents) ============

export async function handleAccountJson(c: Context<{ Bindings: Bindings; Variables: Variables }>) {
  const { appId, app, agents, baseUrl } = await fetchAccountData(c);

  return c.json({
    success: true,
    app: {
      app_id: appId,
      email: app?.email ?? null,
      email_verified: app?.email_verified ?? false,
      created_at: app?.created_at ?? null,
      rate_limit: app?.rate_limit ?? null,
    },
    agents,
    links: {
      account: `${baseUrl}/account`,
      dashboard: `${baseUrl}/dashboard`,
      docs: `${baseUrl}/docs`,
      openapi: `${baseUrl}/openapi.json`,
      ai_txt: `${baseUrl}/ai.txt`,
    },
  });
}

// ============ HTML PAGE (humans) ============

function reputationBar(score: number | undefined): string {
  const s = score ?? 500;
  // score 0-1000, bar 0-100%
  const pct = Math.round(s / 10);
  const color = s >= 700 ? '#22c55e' : s >= 400 ? '#f59e0b' : '#ef4444';
  return `<div style="background:#e5e7eb;border-radius:4px;height:6px;width:100%;margin-top:4px;">
    <div style="background:${color};height:6px;border-radius:4px;width:${pct}%;transition:width 0.3s;"></div>
  </div>`;
}

function tierBadge(tier: string): string {
  const colors: Record<string, string> = {
    trusted: '#22c55e',
    good: '#84cc16',
    neutral: '#f59e0b',
    caution: '#f97316',
    restricted: '#ef4444',
  };
  const c = colors[tier] ?? '#9ca3af';
  return `<span style="background:${c}22;color:${c};border:1px solid ${c}66;border-radius:3px;padding:1px 6px;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.05em;">${tier}</span>`;
}

export async function handleAccountPage(c: Context<{ Bindings: Bindings; Variables: Variables }>) {
  const { appId, app, agents, baseUrl } = await fetchAccountData(c);
  const version = (c.env as any).BOTCHA_VERSION ?? '0.15.0';

  const agentRows = agents.length === 0
    ? `<tr><td colspan="6" style="text-align:center;color:#9ca3af;padding:32px 24px;">No agents yet. Click <strong style="color:#6b7280;">+ Add Agent</strong> above to get a prompt you can paste into your AI agent.</td></tr>`
    : agents.map(a => `
        <tr id="row-${a.agent_id}">
          <td style="font-family:monospace;font-size:12px;color:#6b7280;">${a.agent_id}</td>
          <td>${a.name ?? '—'}</td>
          <td>${a.operator ?? '—'}</td>
          <td>
            ${a.reputation
              ? `${reputationBar(a.reputation.score)}<span style="font-size:11px;color:#6b7280;">${a.reputation.score} &middot; ${tierBadge(a.reputation.tier)} &middot; ${a.reputation.event_count} events</span>`
              : '<span style="color:#9ca3af;font-size:12px;">no data</span>'}
          </td>
          <td style="text-align:center;">
            ${a.tap_enabled
              ? `<button class="btn-action" onclick="toggleReidentify('${a.agent_id}')" style="color:#22c55e;" title="Click for re-identification instructions">✓ TAP${(a as any).provider ? ' · ' + (a as any).provider : ''}</button>`
              : '<span style="color:#d1d5db;font-size:11px;font-weight:500;" title="No TAP keypair">— TAP</span>'}
          </td>
          <td style="text-align:right;white-space:nowrap;">
            ${a.tap_enabled
              ? `<button class="btn-action warn" onclick="toggleRotateKey('${a.agent_id}')" title="Lost your private key? Rotate to a new keypair using your app_secret">↺ rotate</button>`
              : ''}
            <button class="btn-action danger" onclick="deleteAgent('${a.agent_id}')" title="Delete agent">✕</button>
          </td>
        </tr>
        ${a.tap_enabled ? `
        <tr id="reidentify-${a.agent_id}" style="display:none;">
          <td colspan="6" style="padding:0 12px 16px 12px;background:#f9fafb;border-bottom:1px solid var(--border);">
            <div style="font-size:12px;color:#374151;line-height:1.7;padding-top:12px;">
              <strong style="font-size:11px;text-transform:uppercase;letter-spacing:0.05em;color:#6b7280;">How to re-identify in a new session</strong>
              ${(a as any).provider ? `
              <p style="margin:8px 0 4px;">This agent is bound to your <strong>${(a as any).provider}</strong> API key. At the start of a new conversation, just tell your agent:</p>
              <div style="background:#fff;border:1px solid var(--border);border-radius:2px;padding:10px 12px;font-family:monospace;font-size:12px;color:#374151;margin-bottom:8px;">
                You are agent <strong>${a.agent_id}</strong> on my BOTCHA account (${baseUrl}). App ID is ${appId}. Re-identify yourself before doing anything else.
              </div>
              <p style="margin:4px 0 0;color:#6b7280;font-size:12px;">The agent uses its <code style="font-size:11px;">${(a as any).provider.toUpperCase()}_API_KEY</code> environment variable — no extra secret needed. It calls <code style="font-size:11px;">POST /v1/agents/auth/provider</code> automatically.</p>
              ` : `
              <p style="margin:8px 0 4px;">At the start of a new conversation, tell your agent:</p>
              <div style="background:#fff;border:1px solid var(--border);border-radius:2px;padding:10px 12px;font-family:monospace;font-size:12px;color:#374151;margin-bottom:8px;">
                You are agent <strong>${a.agent_id}</strong> on my BOTCHA account (${baseUrl}). Your TAP private key is <strong>&lt;paste tapk_... key&gt;</strong>. Re-identify yourself before doing anything else.
              </div>
              <p style="margin:4px 0 4px;font-size:11px;color:#d97706;"><strong>Tip:</strong> Bind your provider API key to skip the tapk_ secret entirely — use the ↺ rotate button to register a provider binding.</p>
              `}
              <p style="margin:8px 0 0;color:#9ca3af;font-size:11px;">The identity JWT contains your agent_id claim — proving this is the same agent, not a fresh anonymous session.</p>
            </div>
          </td>
        </tr>
        <tr id="rotatekey-${a.agent_id}" style="display:none;">
          <td colspan="6" style="padding:0 12px 16px 12px;background:#fffbeb;border-bottom:1px solid #fde68a;">
            <div style="font-size:12px;color:#374151;line-height:1.7;padding-top:12px;">
              <strong style="font-size:11px;text-transform:uppercase;letter-spacing:0.05em;color:#92400e;">Lost your private key? Rotate to a new keypair</strong>
              <p style="margin:8px 0 4px;color:#6b7280;">Your <code style="font-size:11px;">app_secret</code> is the recovery anchor. As long as you have it, you can issue a new keypair to this agent without losing its <code style="font-size:11px;">agent_id</code> or reputation. Tell your agent:</p>
              <div style="background:#fff;border:1px solid #fde68a;border-radius:2px;padding:10px 12px;font-family:monospace;font-size:12px;color:#374151;margin-bottom:8px;">
                My BOTCHA agent ${a.agent_id} lost its private key. Rotate its keypair using app_secret &lt;paste app_secret&gt; for app ${appId} at ${baseUrl}. Generate a new Ed25519 keypair, call POST ${baseUrl}/v1/agents/${a.agent_id}/tap/rotate-key?app_id=${appId} with header x-app-secret: &lt;app_secret&gt; and body {"public_key":"&lt;raw 32-byte base64&gt;","signature_algorithm":"ed25519"}, then give me the new private key to save.
              </div>
              <p style="margin:4px 0 0;color:#9ca3af;font-size:11px;">The agent generates a new keypair locally, registers the new public key, and returns the new private key for you to store. The old key is invalidated immediately.</p>
            </div>
          </td>
        </tr>` : ''}
      `).join('');

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Account — BOTCHA</title>
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet" />
  <style>${DASHBOARD_CSS}
    .account-grid { display:grid; grid-template-columns:1fr 1fr; gap:20px; margin-bottom:24px; }
    @media(max-width:640px){ .account-grid{ grid-template-columns:1fr; } }
    .kv-row { display:flex; justify-content:space-between; align-items:center; padding:8px 0; border-bottom:1px solid #f3f4f6; font-size:13px; }
    .kv-row:last-child { border-bottom:none; }
    .kv-label { color:#6b7280; font-weight:500; }
    .kv-value { font-family:monospace; color:#111827; word-break:break-all; text-align:right; max-width:60%; }
    .agents-table { width:100%; border-collapse:collapse; font-size:13px; }
    .agents-table th { text-align:left; padding:8px 12px; background:#f9fafb; border-bottom:2px solid #e5e7eb; font-weight:600; color:#374151; font-size:11px; text-transform:uppercase; letter-spacing:0.05em; }
    .agents-table td { padding:12px; border-bottom:1px solid #f3f4f6; vertical-align:top; }
    .agents-table tr:last-child td { border-bottom:none; }
    .btn-action { background:none; border:none; color:#9ca3af; font-size:11px; font-weight:500; cursor:pointer; padding:3px 7px; border-radius:3px; font-family:var(--font); letter-spacing:0.03em; transition:color 0.15s,background 0.15s; white-space:nowrap; }
    .btn-action:hover { color:#374151; background:#f3f4f6; }
    .btn-action.danger:hover { color:#ef4444; background:#fef2f2; }
    .btn-action.warn:hover { color:#d97706; background:#fffbeb; }
    .verified-badge { color:#22c55e; font-size:11px; }
    .unverified-badge { color:#f59e0b; font-size:11px; }
  </style>
</head>
<body>
  <nav class="dashboard-nav">
    <div class="nav-container">
      <a href="/dashboard" class="nav-logo">BOTCHA</a>
      <span class="nav-app-id">${appId}</span>
      <a href="/account" class="nav-link" style="font-weight:600;">Account</a>
      <a href="/dashboard" class="nav-link">Analytics</a>
      <a href="/dashboard/logout" class="nav-link">Logout</a>
    </div>
  </nav>
  <main class="dashboard-main">
    <div style="max-width:900px;margin:0 auto;padding:32px 16px;">
      <h1 style="font-size:20px;font-weight:700;margin:0 0 4px;">Account</h1>
      <p style="color:#6b7280;font-size:13px;margin:0 0 28px;">App details, registered agents, and reputation scores.</p>

      <div class="account-grid">
        <!-- App Info -->
        <div class="card">
          <div class="card-header"><h3><span class="card-title">App</span></h3></div>
          <div class="card-body"><div class="card-inner">
            <div class="kv-row">
              <span class="kv-label">app_id</span>
              <span class="kv-value">${appId}</span>
            </div>
            <div class="kv-row">
              <span class="kv-label">email</span>
              <span class="kv-value">${app?.email ?? '—'}
                ${app?.email_verified
                  ? '<span class="verified-badge"> ✓ verified</span>'
                  : '<span class="unverified-badge"> ⚠ unverified</span>'}
              </span>
            </div>
            <div class="kv-row">
              <span class="kv-label">created</span>
              <span class="kv-value">${app?.created_at ? new Date(app.created_at).toLocaleDateString('en-US', {year:'numeric',month:'short',day:'numeric'}) : '—'}</span>
            </div>
            <div class="kv-row">
              <span class="kv-label">rate limit</span>
              <span class="kv-value">${app?.rate_limit ?? '—'} req/min</span>
            </div>
            <div class="kv-row" style="align-items:flex-start;flex-direction:column;gap:6px;padding-top:12px;border-top:1px solid #f3f4f6;margin-top:4px;">
              <span class="kv-label">app_secret</span>
              <span style="font-size:12px;color:#6b7280;line-height:1.6;">
                Your <code style="font-size:11px;">app_secret</code> was shown once when you created this app.
                It's the master credential for your account — store it in a password manager.<br>
                <strong style="color:#374151;">Lost it?</strong>
                ${app?.email_verified
                  ? `Send a recovery code to <strong>${app?.email}</strong>:`
                  : 'Verify your email first, then you can recover via email.'}
              </span>
              ${app?.email_verified ? `
              <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
                <button class="btn-action" onclick="recoverSecret(this)" style="border:1px solid var(--border);">
                  Email recovery code →
                </button>
                <span id="recover-status" style="font-size:11px;color:#6b7280;"></span>
              </div>
              <div id="recover-form" style="display:none;margin-top:6px;width:100%;">
                <p style="font-size:12px;color:#6b7280;margin:0 0 6px;">Enter the 6-digit code from your email:</p>
                <div style="display:flex;gap:6px;align-items:center;">
                  <input id="recover-code" type="text" maxlength="6" placeholder="123456"
                    style="font-family:var(--font);font-size:13px;padding:4px 8px;border:1px solid var(--border);border-radius:3px;width:90px;background:var(--bg);" />
                  <button class="btn-action" onclick="submitRecovery()" style="border:1px solid var(--border);">Rotate secret</button>
                </div>
                <p id="recover-result" style="font-size:12px;margin:8px 0 0;word-break:break-all;"></p>
              </div>` : ''}
            </div>
          </div></div>
        </div>

        <!-- Quick Links -->
        <div class="card">
          <div class="card-header"><h3><span class="card-title">Links</span></h3></div>
          <div class="card-body"><div class="card-inner">
            <div class="kv-row">
              <span class="kv-label">Analytics</span>
              <span class="kv-value"><a href="/dashboard">Dashboard →</a></span>
            </div>
            <div class="kv-row">
              <span class="kv-label">API Docs</span>
              <span class="kv-value"><a href="/docs">Docs →</a></span>
            </div>
            <div class="kv-row">
              <span class="kv-label">OpenAPI</span>
              <span class="kv-value"><a href="/openapi.json">openapi.json →</a></span>
            </div>
            <div class="kv-row">
              <span class="kv-label">Agent discovery</span>
              <span class="kv-value"><a href="/ai.txt">ai.txt →</a></span>
            </div>
            <div class="kv-row">
              <span class="kv-label">Whitepaper</span>
              <span class="kv-value"><a href="/whitepaper">TAP whitepaper →</a></span>
            </div>
          </div></div>
        </div>
      </div>

      <!-- Agents Table -->
      <div class="card">
        <div class="card-header">
          <h3 style="display:flex;align-items:center;justify-content:space-between;width:100%;">
            <span>
              <span class="card-title">Agents</span>
              <span class="badge-inline section-badge">${agents.length} registered</span>
            </span>
            <button
              onclick="toggleAddAgent()"
              class="btn-action"
              style="border:1px solid var(--border);color:var(--text-muted);text-transform:uppercase;letter-spacing:0.05em;"
            >+ Add Agent</button>
          </h3>
        </div>

        <!-- Add Agent prompt panel (hidden by default) -->
        <div id="add-agent-panel" style="display:none;border-bottom:1px solid var(--border);">
          <div style="padding:16px 20px;">

            <!-- Hidden full prompt (copied to clipboard) -->
            <span id="agent-prompt" style="display:none;">Register as a BOTCHA agent. Base URL: ${baseUrl}. App ID: ${appId}. Do all steps automatically: 1) GET ${baseUrl}/v1/token?app_id=${appId} — solve the SHA256 speed challenge in-process, then POST ${baseUrl}/v1/token/verify with {"id":"<challenge_id>","answers":["<hash1>",...],"app_id":"${appId}"}. Save access_token as your Bearer token. 2) POST ${baseUrl}/v1/agents/register — Authorization: Bearer <access_token>, body {"name":"<your model name>","operator":"<human name or org>"}. Save agent_id. 3) Generate an Ed25519 keypair. Export public key as raw 32 bytes base64 (strip 12-byte SPKI header). 4) POST ${baseUrl}/v1/agents/register/tap?app_id=${appId} — Authorization: Bearer <access_token>, body {"agent_id":"<from step 2>","name":"<your model name>","public_key":"<raw 32-byte base64>","signature_algorithm":"ed25519","capabilities":[{"action":"browse"},{"action":"search"}]}. 5) Tell the human: agent_id, public key fingerprint, and TAP private key — prefix it with tapk_ so it looks like tapk_ABC123...== — they must save this, it is the only way to re-identify you. BOTCHA never stores it. IMPORTANT: the TAP private key (tapk_...) is NOT the same as the app_secret (sk_...). Label them clearly.</span>

            <!-- Human-readable breakdown -->
            <div style="font-size:12px;color:#6b7280;margin-bottom:12px;">
              Copy this prompt and paste it into your AI agent — it will handle all steps automatically.
            </div>

            <div style="background:var(--bg-raised);border:1px solid var(--border);border-radius:2px;padding:14px 16px;">
              <ol style="margin:0;padding:0 0 0 18px;font-size:12px;color:#374151;line-height:1.8;font-family:var(--font);">
                <li><strong>Solve speed challenge</strong> — <code style="font-size:11px;">GET /v1/token?app_id=${appId}</code>, compute SHA256 answers in-process, verify with <code style="font-size:11px;">POST /v1/token/verify</code> → <code style="font-size:11px;">access_token</code></li>
                <li><strong>Register identity</strong> — <code style="font-size:11px;">POST /v1/agents/register</code> with Bearer token → <code style="font-size:11px;">agent_id</code></li>
                <li><strong>Generate Ed25519 keypair</strong> — raw 32-byte public key as base64</li>
                <li><strong>Register keypair</strong> — <code style="font-size:11px;">POST /v1/agents/register/tap</code> with <code style="font-size:11px;">agent_id</code> + public key</li>
                <li><strong>Report back</strong> — agent_id, key fingerprint, and private key for you to save</li>
              </ol>
              <div style="margin-top:12px;padding-top:12px;border-top:1px solid var(--border);">
                <button onclick="copyAgentPrompt()" type="button"
                  style="display:inline-flex;align-items:center;gap:6px;font-family:var(--font);font-size:11px;font-weight:500;color:var(--text-muted);background:none;border:none;cursor:pointer;padding:0;text-transform:uppercase;letter-spacing:0.1em;"
                  onmouseover="this.style.color='#111827'" onmouseout="this.style.color='var(--text-muted)'">
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="square"><rect x="9" y="9" width="13" height="13"/><path d="M5 15H4a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v1"/></svg>
                  <span id="agent-copy-text">Copy prompt</span>
                </button>
              </div>
            </div>

          </div>
        </div>

        <div class="card-body"><div class="card-inner" style="padding:0;overflow-x:auto;">
          <table class="agents-table">
            <thead>
              <tr>
                <th>Agent ID</th>
                <th>Name</th>
                <th>Operator</th>
                <th>Reputation</th>
                <th style="text-align:center;">TAP</th>
                <th></th>
              </tr>
            </thead>
            <tbody>${agentRows}</tbody>
          </table>
        </div></div>
      </div>

      <script>
        var _newSecret = '';
        function copySecret() {
          navigator.clipboard.writeText(_newSecret).then(function() {
            var btn = document.getElementById('copy-secret-btn');
            if (btn) { btn.textContent = 'Copied!'; setTimeout(function(){ btn.textContent = 'Copy'; }, 2500); }
          });
        }
        async function recoverSecret(btn) {
          var status = document.getElementById('recover-status');
          btn.disabled = true;
          status.textContent = 'Sending…';
          try {
            await fetch('/v1/auth/recover', {
              method: 'POST',
              headers: {'Content-Type':'application/json'},
              body: JSON.stringify({email: '${app?.email ?? ''}'})
            });
            status.textContent = 'Code sent — check your email.';
            document.getElementById('recover-form').style.display = 'block';
          } catch(e) {
            status.textContent = 'Failed to send. Try again.';
            btn.disabled = false;
          }
        }
        async function submitRecovery() {
          var code = document.getElementById('recover-code').value.trim();
          var result = document.getElementById('recover-result');
          if (!code) { result.textContent = 'Enter the 6-digit code.'; return; }
          result.textContent = 'Verifying…';
          try {
            const loginRes = await fetch('/dashboard/code', {
              method: 'POST',
              headers: {'Content-Type':'application/json'},
              body: JSON.stringify({code})
            });
            if (!loginRes.ok) {
              const d = await loginRes.json();
              result.textContent = 'Invalid code: ' + (d.message || d.error || loginRes.status);
              return;
            }
            result.textContent = 'Rotating secret…';
            const rotateRes = await fetch('/v1/apps/${appId}/rotate-secret', {
              method: 'POST',
              headers: {'Content-Type':'application/json'},
              body: JSON.stringify({app_id: '${appId}'})
            });
            const rotateData = await rotateRes.json();
            if (rotateRes.ok && rotateData.app_secret) {
              _newSecret = rotateData.app_secret;
              result.innerHTML =
                '<strong style="color:#22c55e;">New app_secret issued.</strong> Save this now — it will not be shown again:<br>' +
                '<code id="new-secret-val" style="display:block;margin-top:8px;padding:8px 10px;background:#f9fafb;border:1px solid #e5e7eb;border-radius:3px;font-size:12px;word-break:break-all;color:#111827;"></code>' +
                '<button id="copy-secret-btn" onclick="copySecret()" class="btn-action" style="margin-top:6px;border:1px solid var(--border);">Copy</button>';
              document.getElementById('new-secret-val').textContent = rotateData.app_secret;
            } else {
              result.textContent = 'Rotation failed: ' + (rotateData.message || rotateData.error || rotateRes.status);
            }
          } catch(e) {
            result.textContent = 'Failed. Try again.';
          }
        }
        function toggleAddAgent() {
          var panel = document.getElementById('add-agent-panel');
          panel.style.display = panel.style.display === 'none' ? 'block' : 'none';
        }
        function toggleReidentify(agentId) {
          var row = document.getElementById('reidentify-' + agentId);
          if (row) row.style.display = row.style.display === 'none' ? 'table-row' : 'none';
        }
        function toggleRotateKey(agentId) {
          var row = document.getElementById('rotatekey-' + agentId);
          if (row) row.style.display = row.style.display === 'none' ? 'table-row' : 'none';
        }
        function copyAgentPrompt() {
          var text = document.getElementById('agent-prompt').textContent.trim();
          navigator.clipboard.writeText(text).then(function() {
            var label = document.getElementById('agent-copy-text');
            label.textContent = 'Copied!';
            setTimeout(function() { label.textContent = 'Copy prompt'; }, 2500);
          });
        }
        async function deleteAgent(agentId) {
          if (!confirm('Delete agent ' + agentId + '? This cannot be undone.')) return;
          const res = await fetch('/v1/agents/' + agentId, { method: 'DELETE' });
          if (res.ok) {
            var row = document.getElementById('row-' + agentId);
            if (row) row.remove();
            var badge = document.querySelector('.section-badge');
            if (badge) {
              var n = document.querySelectorAll('[id^="row-"]').length;
              badge.textContent = n + ' registered';
            }
          } else {
            var data = await res.json();
            alert('Failed to delete: ' + (data.error || res.status));
          }
        }
      </script>
    </div>
  </main>
  <footer class="global-footer">
    <div class="global-footer-inner">
      <a href="/account" class="global-footer-dashboard">Account</a>
      <div class="global-footer-links">
        <span>v${version}</span>
        <span class="global-footer-sep">&middot;</span>
        <a href="https://botcha.ai">botcha.ai</a>
        <span class="global-footer-sep">&middot;</span>
        <a href="/docs">Docs</a>
        <span class="global-footer-sep">&middot;</span>
        <a href="/whitepaper">Whitepaper</a>
        <span class="global-footer-sep">&middot;</span>
        <a href="/openapi.json">OpenAPI</a>
        <span class="global-footer-sep">&middot;</span>
        <a href="/ai.txt">ai.txt</a>
        <span class="global-footer-sep">&middot;</span>
        <a href="https://github.com/dupe-com/botcha">GitHub</a>
      </div>
      <div class="global-footer-legal">&copy; ${new Date().getFullYear()} <a href="https://dupe.com">Dupe.com</a></div>
    </div>
  </footer>
</body>
</html>`;

  return c.html(html);
}
