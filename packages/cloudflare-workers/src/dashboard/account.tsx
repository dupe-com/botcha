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
  const baseUrl = new URL(c.req.url).origin;

  // Parallel fetches
  const [appRaw, agentsRaw, tapAgentsRaw] = await Promise.allSettled([
    import('../apps').then(m => m.getApp(env.APPS, appId)),
    import('../agents').then(m => m.listAgents(env.AGENTS, appId)),
    import('../tap-agents').then(m => m.listTAPAgents(env.AGENTS, appId)),
  ]);

  const app = appRaw.status === 'fulfilled' ? appRaw.value : null;
  const agents = agentsRaw.status === 'fulfilled' ? (agentsRaw.value ?? []) : [];
  const tapAgents = tapAgentsRaw.status === 'fulfilled' ? (tapAgentsRaw.value?.agents ?? []) : [];

  const tapAgentIds = new Set(tapAgents.map((a: any) => a.agent_id));

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
      tap_enabled: tapAgentIds.has(agent.agent_id),
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
  const { appId, app, agents } = await fetchAccountData(c);
  const version = (c.env as any).BOTCHA_VERSION ?? '0.15.0';

  const agentRows = agents.length === 0
    ? `<tr><td colspan="5" style="text-align:center;color:#9ca3af;padding:24px;">No agents registered yet. Your agent can register via <code>POST /v1/agents/register</code>.</td></tr>`
    : agents.map(a => `
        <tr>
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
              ? '<span style="color:#22c55e;font-size:13px;" title="TAP keypair registered">✓ TAP</span>'
              : '<span style="color:#d1d5db;font-size:13px;" title="No TAP keypair">— TAP</span>'}
          </td>
        </tr>`).join('');

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
          <h3>
            <span class="card-title">Agents</span>
            <span class="badge-inline">${agents.length} registered</span>
          </h3>
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
              </tr>
            </thead>
            <tbody>${agentRows}</tbody>
          </table>
        </div></div>
      </div>

      <p style="margin-top:20px;font-size:12px;color:#9ca3af;text-align:center;">
        Agents: <code>GET /account</code> with <code>Accept: application/json</code> + Bearer token for structured data.
      </p>
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
