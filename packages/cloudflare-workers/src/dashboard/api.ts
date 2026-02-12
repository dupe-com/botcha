/**
 * BOTCHA Dashboard — Analytics Engine Query API
 *
 * Server-side endpoints that query CF Analytics Engine SQL API
 * and return HTML fragments for htmx to swap in.
 *
 * Data schema (from analytics.ts writeDataPoint):
 *   blobs[0] = eventType   (challenge_generated | challenge_verified | auth_success | auth_failure | rate_limit_exceeded | error)
 *   blobs[1] = challengeType (speed | standard | reasoning | hybrid | '')
 *   blobs[2] = endpoint
 *   blobs[3] = verificationResult (success | failure | '')
 *   blobs[4] = authMethod
 *   blobs[5] = clientIP
 *   blobs[6] = country
 *   blobs[7] = errorType
 *   doubles[0] = solveTimeMs
 *   doubles[1] = responseTimeMs
 *   indexes[0] = eventType
 *   indexes[1] = challengeType or 'none'
 *   indexes[2] = endpoint or 'unknown'
 */

import type { Context } from 'hono';

// ============ TYPES ============

// Use a flexible env type so Context from the parent app (which may include Variables) is compatible
interface DashboardEnv {
  Bindings: {
    ANALYTICS?: AnalyticsEngineDataset;
    CF_API_TOKEN?: string;
    CF_ACCOUNT_ID?: string;
    [key: string]: unknown;
  };
  [key: string]: unknown;
}

type AnalyticsEngineDataset = {
  writeDataPoint: (data: {
    blobs?: string[];
    doubles?: number[];
    indexes?: string[];
  }) => void;
};

// Period options for time filters
type Period = '1h' | '24h' | '7d' | '30d';

function periodToInterval(period: Period): string {
  // CF Analytics Engine SQL requires quoted numbers: INTERVAL '24' HOUR
  switch (period) {
    case '1h':
      return "'1' HOUR";
    case '24h':
      return "'24' HOUR";
    case '7d':
      return "'7' DAY";
    case '30d':
      return "'30' DAY";
    default:
      return "'24' HOUR";
  }
}

function parsePeriod(value: string | undefined): Period {
  if (value === '1h' || value === '24h' || value === '7d' || value === '30d') {
    return value;
  }
  return '24h';
}

// ============ SQL QUERY HELPER ============

const CF_AE_BASE = 'https://api.cloudflare.com/client/v4/accounts';

interface AERow {
  [key: string]: string | number | null;
}

interface AEQueryResult {
  data: AERow[];
  rows: number;
  error?: string;
}

/**
 * Query Cloudflare Analytics Engine SQL API
 */
async function queryAnalyticsEngine(
  sql: string,
  accountId: string,
  apiToken: string
): Promise<AEQueryResult> {
  const url = `${CF_AE_BASE}/${accountId}/analytics_engine/sql`;

  try {
    const resp = await fetch(url, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${apiToken}`,
        'Content-Type': 'text/plain',
      },
      body: sql,
    });

    if (!resp.ok) {
      const text = await resp.text();
      console.error('Analytics Engine query failed:', resp.status, text);
      return { data: [], rows: 0, error: `HTTP ${resp.status}: ${text.substring(0, 200)}` };
    }

    // AE SQL API returns newline-delimited JSON (first line is metadata, second is data)
    const text = await resp.text();
    
    // Try parsing as JSON first (newer AE format)
    try {
      const json = JSON.parse(text);
      if (json.data) {
        return { data: json.data, rows: json.data.length };
      }
      // Some responses have a `rows` property
      if (Array.isArray(json)) {
        return { data: json, rows: json.length };
      }
    } catch {
      // Not JSON — try CSV-like parsing for older AE format
    }
    
    // Parse tab-separated response with header row
    const lines = text.trim().split('\n');
    if (lines.length < 2) {
      return { data: [], rows: 0 };
    }

    const headers = lines[0].split('\t').map(h => h.trim());
    const data: AERow[] = [];
    
    for (let i = 1; i < lines.length; i++) {
      const values = lines[i].split('\t');
      const row: AERow = {};
      for (let j = 0; j < headers.length; j++) {
        const val = values[j]?.trim() ?? '';
        // Try to parse as number
        const num = Number(val);
        row[headers[j]] = isNaN(num) || val === '' ? val : num;
      }
      data.push(row);
    }

    return { data, rows: data.length };
  } catch (error) {
    console.error('Analytics Engine query error:', error);
    return { data: [], rows: 0, error: error instanceof Error ? error.message : 'Unknown error' };
  }
}

// ============ HTML FRAGMENT HELPERS ============

function formatNumber(n: number | null | undefined): string {
  if (n === null || n === undefined) return '0';
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return n.toLocaleString('en-US');
}

function renderStatCard(value: string, label: string, cssClass?: string): string {
  return `<div class="stat-card">
    <span class="stat-value ${cssClass || ''}">${value}</span>
    <span class="stat-label">${label}</span>
  </div>`;
}

function renderBarChart(items: { name: string; value: number; maxValue: number }[]): string {
  if (items.length === 0) {
    return renderEmptyState('No data for this period');
  }
  
  let html = '<div class="bar-chart">';
  for (const item of items) {
    const pct = item.maxValue > 0 ? Math.round((item.value / item.maxValue) * 100) : 0;
    html += `<div class="bar-item">
      <div class="bar-label">
        <span class="bar-name">${escapeHtml(item.name)}</span>
        <span class="bar-value">${formatNumber(item.value)}</span>
      </div>
      <div class="bar" style="width: ${Math.max(pct, 2)}%"></div>
    </div>`;
  }
  html += '</div>';
  return html;
}

function renderEmptyState(message: string): string {
  return `<div class="empty-state">
    <div class="empty-state-icon">&gt;_</div>
    <div class="empty-state-text">${escapeHtml(message)}</div>
    <div class="empty-state-subtext">Try a longer time period or generate some challenges first</div>
  </div>`;
}

function renderError(message: string): string {
  return `<div class="alert alert-danger">${escapeHtml(message)}</div>`;
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ============ API ENDPOINT HANDLERS ============

/**
 * GET /dashboard/api/overview?period=24h
 * Returns HTML fragment with key stats: total challenges, verifications, success rate, avg solve time
 */
export async function handleOverview(c: Context<DashboardEnv>, appId: string) {
  const period = parsePeriod(c.req.query('period'));
  const interval = periodToInterval(period);
  const accountId = c.env.CF_ACCOUNT_ID;
  const apiToken = c.env.CF_API_TOKEN;

  if (!accountId || !apiToken) {
    return c.html(renderMockOverview(period));
  }

  const sql = `
    SELECT
      count() as total_events,
      countIf(blob1 = 'challenge_generated') as challenges_generated,
      countIf(blob1 = 'challenge_verified') as verifications,
      countIf(blob1 = 'challenge_verified' AND blob4 = 'success') as successful_verifications,
      countIf(blob1 = 'auth_success') as auth_successes,
      countIf(blob1 = 'rate_limit_exceeded') as rate_limits,
      countIf(blob1 = 'error') as errors,
      avg(double1) as avg_solve_time_ms,
      avg(double2) as avg_response_time_ms
    FROM botcha
    WHERE timestamp >= now() - INTERVAL ${interval}
    FORMAT JSON
  `;

  const result = await queryAnalyticsEngine(sql, accountId, apiToken);

  if (result.error) {
    return c.html(renderError(`Analytics query failed: ${result.error}`));
  }

  const row = result.data[0] || {};
  const totalChallenges = Number(row.challenges_generated || 0);
  const totalVerifications = Number(row.verifications || 0);
  const successfulVerifications = Number(row.successful_verifications || 0);
  const rateLimits = Number(row.rate_limits || 0);
  const errors = Number(row.errors || 0);
  const avgSolveTime = Number(row.avg_solve_time_ms || 0);
  const successRate = totalVerifications > 0
    ? Math.round((successfulVerifications / totalVerifications) * 100)
    : 0;

  const html = `<div class="dashboard-grid">
    ${renderStatCard(formatNumber(totalChallenges), 'Challenges Generated')}
    ${renderStatCard(formatNumber(totalVerifications), 'Verifications')}
    ${renderStatCard(`${successRate}%`, 'Success Rate', successRate >= 80 ? 'text-success' : successRate >= 50 ? 'text-warning' : 'text-danger')}
    ${renderStatCard(`${Math.round(avgSolveTime)}ms`, 'Avg Solve Time')}
    ${renderStatCard(formatNumber(rateLimits), 'Rate Limits Hit', rateLimits > 0 ? 'text-warning' : '')}
    ${renderStatCard(formatNumber(errors), 'Errors', errors > 0 ? 'text-danger' : '')}
  </div>`;

  return c.html(html);
}

/**
 * GET /dashboard/api/volume?period=24h
 * Returns HTML fragment with time-bucketed event volume
 */
export async function handleVolume(c: Context<DashboardEnv>, appId: string) {
  const period = parsePeriod(c.req.query('period'));
  const interval = periodToInterval(period);
  const accountId = c.env.CF_ACCOUNT_ID;
  const apiToken = c.env.CF_API_TOKEN;

  if (!accountId || !apiToken) {
    return c.html(renderMockVolume(period));
  }

  // Choose bucket size based on period (CF AE SQL requires quoted numbers)
  const bucket = period === '1h' ? "'5' MINUTE" : period === '24h' ? "'1' HOUR" : "'1' DAY";

  const sql = `
    SELECT
      toStartOfInterval(timestamp, INTERVAL ${bucket}) as time_bucket,
      count() as events,
      countIf(blob1 = 'challenge_generated') as generated,
      countIf(blob1 = 'challenge_verified' AND blob4 = 'success') as verified_ok,
      countIf(blob1 = 'challenge_verified' AND blob4 = 'failure') as verified_fail
    FROM botcha
    WHERE timestamp >= now() - INTERVAL ${interval}
    GROUP BY time_bucket
    ORDER BY time_bucket ASC
    FORMAT JSON
  `;

  const result = await queryAnalyticsEngine(sql, accountId, apiToken);

  if (result.error) {
    return c.html(renderError(`Analytics query failed: ${result.error}`));
  }

  if (result.data.length === 0) {
    return c.html(renderEmptyState('No activity in this period'));
  }

  const maxEvents = Math.max(...result.data.map(r => Number(r.events || 0)));
  const items = result.data.map(row => ({
    name: formatTimeBucket(String(row.time_bucket || ''), period),
    value: Number(row.events || 0),
    maxValue: maxEvents,
  }));

  return c.html(`<fieldset>
    <legend>Request Volume (${period})</legend>
    ${renderBarChart(items)}
  </fieldset>`);
}

/**
 * GET /dashboard/api/types?period=24h
 * Returns HTML fragment with challenge type breakdown
 */
export async function handleTypes(c: Context<DashboardEnv>, appId: string) {
  const period = parsePeriod(c.req.query('period'));
  const interval = periodToInterval(period);
  const accountId = c.env.CF_ACCOUNT_ID;
  const apiToken = c.env.CF_API_TOKEN;

  if (!accountId || !apiToken) {
    return c.html(renderMockTypes(period));
  }

  const sql = `
    SELECT
      blob2 as challenge_type,
      count() as total,
      countIf(blob4 = 'success') as successes,
      countIf(blob4 = 'failure') as failures
    FROM botcha
    WHERE timestamp >= now() - INTERVAL ${interval}
      AND blob1 IN ('challenge_generated', 'challenge_verified')
      AND blob2 != ''
    GROUP BY challenge_type
    ORDER BY total DESC
    FORMAT JSON
  `;

  const result = await queryAnalyticsEngine(sql, accountId, apiToken);

  if (result.error) {
    return c.html(renderError(`Analytics query failed: ${result.error}`));
  }

  if (result.data.length === 0) {
    return c.html(renderEmptyState('No challenges in this period'));
  }

  const maxTotal = Math.max(...result.data.map(r => Number(r.total || 0)));
  const items = result.data.map(row => ({
    name: `${String(row.challenge_type || 'unknown')} (${Number(row.successes || 0)} ok / ${Number(row.failures || 0)} fail)`,
    value: Number(row.total || 0),
    maxValue: maxTotal,
  }));

  return c.html(`<fieldset>
    <legend>Challenge Types (${period})</legend>
    ${renderBarChart(items)}
  </fieldset>`);
}

/**
 * GET /dashboard/api/performance?period=24h
 * Returns HTML fragment with performance metrics (solve times, response times)
 */
export async function handlePerformance(c: Context<DashboardEnv>, appId: string) {
  const period = parsePeriod(c.req.query('period'));
  const interval = periodToInterval(period);
  const accountId = c.env.CF_ACCOUNT_ID;
  const apiToken = c.env.CF_API_TOKEN;

  if (!accountId || !apiToken) {
    return c.html(renderMockPerformance(period));
  }

  const sql = `
    SELECT
      blob2 as challenge_type,
      count() as total,
      avg(double1) as avg_solve_ms,
      min(double1) as min_solve_ms,
      max(double1) as max_solve_ms,
      avg(double2) as avg_response_ms
    FROM botcha
    WHERE timestamp >= now() - INTERVAL ${interval}
      AND blob1 = 'challenge_verified'
      AND blob4 = 'success'
      AND blob2 != ''
      AND double1 > 0
    GROUP BY challenge_type
    ORDER BY total DESC
    FORMAT JSON
  `;

  const result = await queryAnalyticsEngine(sql, accountId, apiToken);

  if (result.error) {
    return c.html(renderError(`Analytics query failed: ${result.error}`));
  }

  if (result.data.length === 0) {
    return c.html(renderEmptyState('No successful verifications in this period'));
  }

  let html = `<table>
    <thead>
      <tr>
        <th>Type</th>
        <th>Count</th>
        <th>Avg Solve</th>
        <th>p50</th>
        <th>p95</th>
        <th>Min</th>
        <th>Max</th>
        <th>Avg Response</th>
      </tr>
    </thead>
    <tbody>`;

  for (const row of result.data) {
    html += `<tr>
      <td><span class="badge badge-info">${escapeHtml(String(row.challenge_type || '-'))}</span></td>
      <td>${formatNumber(Number(row.total || 0))}</td>
      <td>${Math.round(Number(row.avg_solve_ms || 0))}ms</td>
      <td>${Math.round(Number(row.p50_solve_ms || 0))}ms</td>
      <td>${Math.round(Number(row.p95_solve_ms || 0))}ms</td>
      <td>${Math.round(Number(row.min_solve_ms || 0))}ms</td>
      <td>${Math.round(Number(row.max_solve_ms || 0))}ms</td>
      <td>${Math.round(Number(row.avg_response_ms || 0))}ms</td>
    </tr>`;
  }

  html += '</tbody></table>';

  return c.html(`<fieldset>
    <legend>Performance (${period})</legend>
    ${html}
  </fieldset>`);
}

/**
 * GET /dashboard/api/errors?period=24h
 * Returns HTML fragment with error breakdown
 */
export async function handleErrors(c: Context<DashboardEnv>, appId: string) {
  const period = parsePeriod(c.req.query('period'));
  const interval = periodToInterval(period);
  const accountId = c.env.CF_ACCOUNT_ID;
  const apiToken = c.env.CF_API_TOKEN;

  if (!accountId || !apiToken) {
    return c.html(renderMockErrors(period));
  }

  const sql = `
    SELECT
      blob1 as event_type,
      count() as total
    FROM botcha
    WHERE timestamp >= now() - INTERVAL ${interval}
      AND blob1 IN ('error', 'rate_limit_exceeded', 'auth_failure')
    GROUP BY event_type
    ORDER BY total DESC
    FORMAT JSON
  `;

  const result = await queryAnalyticsEngine(sql, accountId, apiToken);

  if (result.error) {
    return c.html(renderError(`Analytics query failed: ${result.error}`));
  }

  if (result.data.length === 0) {
    return c.html(`<fieldset>
      <legend>Errors & Rate Limits (${period})</legend>
      <div class="alert alert-success">No errors or rate limits in this period</div>
    </fieldset>`);
  }

  const maxTotal = Math.max(...result.data.map(r => Number(r.total || 0)));
  const items = result.data.map(row => ({
    name: String(row.event_type || 'unknown').replace(/_/g, ' '),
    value: Number(row.total || 0),
    maxValue: maxTotal,
  }));

  return c.html(`<fieldset>
    <legend>Errors & Rate Limits (${period})</legend>
    ${renderBarChart(items)}
  </fieldset>`);
}

/**
 * GET /dashboard/api/geo?period=24h
 * Returns HTML fragment with geographic distribution
 */
export async function handleGeo(c: Context<DashboardEnv>, appId: string) {
  const period = parsePeriod(c.req.query('period'));
  const interval = periodToInterval(period);
  const accountId = c.env.CF_ACCOUNT_ID;
  const apiToken = c.env.CF_API_TOKEN;

  if (!accountId || !apiToken) {
    return c.html(renderMockGeo(period));
  }

  const sql = `
    SELECT
      blob7 as country,
      count() as total
    FROM botcha
    WHERE timestamp >= now() - INTERVAL ${interval}
      AND blob7 != '' AND blob7 != 'unknown'
    GROUP BY country
    ORDER BY total DESC
    LIMIT 20
    FORMAT JSON
  `;

  const result = await queryAnalyticsEngine(sql, accountId, apiToken);

  if (result.error) {
    return c.html(renderError(`Analytics query failed: ${result.error}`));
  }

  if (result.data.length === 0) {
    return c.html(renderEmptyState('No geographic data in this period'));
  }

  const maxTotal = Math.max(...result.data.map(r => Number(r.total || 0)));
  const items = result.data.map(row => ({
    name: String(row.country || '??'),
    value: Number(row.total || 0),
    maxValue: maxTotal,
  }));

  return c.html(`<fieldset>
    <legend>Top Countries (${period})</legend>
    ${renderBarChart(items)}
  </fieldset>`);
}

// ============ TIME FORMATTING ============

function formatTimeBucket(timestamp: string, period: Period): string {
  if (!timestamp) return '—';
  try {
    const d = new Date(timestamp);
    if (isNaN(d.getTime())) return timestamp.substring(0, 16);

    if (period === '1h' || period === '24h') {
      return d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false });
    }
    return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
  } catch {
    return timestamp.substring(0, 16);
  }
}

// ============ MOCK DATA (when CF_API_TOKEN not configured) ============

function renderMockOverview(_period: Period): string {
  return `<div class="alert alert-warning">
    Analytics Engine API not configured. Set <code>CF_API_TOKEN</code> and <code>CF_ACCOUNT_ID</code> secrets.
    <br>Showing sample data below.
  </div>
  <div class="dashboard-grid">
    ${renderStatCard('1,247', 'Challenges Generated')}
    ${renderStatCard('1,089', 'Verifications')}
    ${renderStatCard('94%', 'Success Rate', 'text-success')}
    ${renderStatCard('127ms', 'Avg Solve Time')}
    ${renderStatCard('3', 'Rate Limits Hit', 'text-warning')}
    ${renderStatCard('0', 'Errors')}
  </div>`;
}

function renderMockVolume(_period: Period): string {
  const items = [
    { name: '00:00', value: 42, maxValue: 89 },
    { name: '04:00', value: 15, maxValue: 89 },
    { name: '08:00', value: 67, maxValue: 89 },
    { name: '12:00', value: 89, maxValue: 89 },
    { name: '16:00', value: 73, maxValue: 89 },
    { name: '20:00', value: 55, maxValue: 89 },
  ];
  return `<fieldset>
    <legend>Request Volume (sample)</legend>
    ${renderBarChart(items)}
  </fieldset>`;
}

function renderMockTypes(_period: Period): string {
  const items = [
    { name: 'hybrid (412 ok / 18 fail)', value: 430, maxValue: 430 },
    { name: 'speed (389 ok / 12 fail)', value: 401, maxValue: 430 },
    { name: 'reasoning (256 ok / 45 fail)', value: 301, maxValue: 430 },
    { name: 'standard (22 ok / 5 fail)', value: 27, maxValue: 430 },
  ];
  return `<fieldset>
    <legend>Challenge Types (sample)</legend>
    ${renderBarChart(items)}
  </fieldset>`;
}

function renderMockPerformance(_period: Period): string {
  return `<fieldset>
    <legend>Performance (sample)</legend>
    <table>
      <thead>
        <tr>
          <th>Type</th><th>Count</th><th>Avg Solve</th><th>p50</th><th>p95</th><th>Min</th><th>Max</th><th>Avg Response</th>
        </tr>
      </thead>
      <tbody>
        <tr><td><span class="badge badge-info">speed</span></td><td>389</td><td>127ms</td><td>112ms</td><td>289ms</td><td>45ms</td><td>498ms</td><td>12ms</td></tr>
        <tr><td><span class="badge badge-info">hybrid</span></td><td>412</td><td>1,845ms</td><td>1,620ms</td><td>4,200ms</td><td>890ms</td><td>8,500ms</td><td>15ms</td></tr>
        <tr><td><span class="badge badge-info">reasoning</span></td><td>256</td><td>4,230ms</td><td>3,800ms</td><td>8,900ms</td><td>1,200ms</td><td>28,000ms</td><td>18ms</td></tr>
      </tbody>
    </table>
  </fieldset>`;
}

function renderMockErrors(_period: Period): string {
  return `<fieldset>
    <legend>Errors & Rate Limits (sample)</legend>
    <div class="alert alert-success">No errors or rate limits (sample data)</div>
  </fieldset>`;
}

function renderMockGeo(_period: Period): string {
  const items = [
    { name: 'US', value: 523, maxValue: 523 },
    { name: 'DE', value: 189, maxValue: 523 },
    { name: 'JP', value: 134, maxValue: 523 },
    { name: 'GB', value: 98, maxValue: 523 },
    { name: 'FR', value: 67, maxValue: 523 },
  ];
  return `<fieldset>
    <legend>Top Countries (sample)</legend>
    ${renderBarChart(items)}
  </fieldset>`;
}
