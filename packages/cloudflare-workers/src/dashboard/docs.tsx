/**
 * BOTCHA API Documentation Page
 *
 * Public API docs at /docs — no authentication required.
 * Renders all endpoints grouped by category with request/response
 * examples, install instructions, and quick-start guides.
 *
 * Follows the ShowcasePage pattern: self-contained JSX with own
 * HTML shell, inline CSS, and the shared DASHBOARD_CSS base.
 */

import type { FC } from 'hono/jsx';
import { DASHBOARD_CSS } from './styles';
import { GlobalFooter, OGMeta } from './layout';

// ============ DOCS CSS ============

const DOCS_CSS = `
  /* ============ Docs layout ============ */
  .docs {
    max-width: 860px;
    margin: 0 auto;
    padding: 3rem 2rem 4rem;
  }

  /* ---- Header ---- */
  .docs-header {
    text-align: center;
    margin-bottom: 3rem;
    padding-bottom: 2rem;
    border-bottom: 1px solid var(--border);
  }

  .docs-badge {
    display: inline-block;
    font-size: 0.625rem;
    font-weight: 700;
    letter-spacing: 0.15em;
    text-transform: uppercase;
    padding: 0.3rem 0.875rem;
    border: 1px solid var(--border);
    color: var(--text-muted);
    margin-bottom: 1.5rem;
  }

  .docs-title {
    font-size: 2rem;
    font-weight: 700;
    line-height: 1.15;
    margin: 0 0 0.75rem;
    color: var(--text);
  }

  .docs-subtitle {
    font-size: 0.875rem;
    color: var(--text-muted);
    line-height: 1.6;
    margin: 0 0 1rem;
    max-width: 600px;
    margin-left: auto;
    margin-right: auto;
  }

  .docs-meta {
    font-size: 0.6875rem;
    color: var(--text-dim);
  }

  .docs-meta a {
    color: var(--text-muted);
  }

  /* ---- Table of Contents ---- */
  .docs-toc {
    border: 1px solid var(--border);
    padding: 1.5rem 2rem;
    margin-bottom: 3rem;
    background: var(--bg);
  }

  .docs-toc-title {
    font-size: 0.6875rem;
    font-weight: 700;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    color: var(--text-dim);
    margin-bottom: 1rem;
  }

  .docs-toc-list {
    list-style: none;
    padding: 0;
    margin: 0;
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 0.25rem 2rem;
  }

  .docs-toc-list li {
    font-size: 0.75rem;
    line-height: 1.8;
  }

  .docs-toc-list a {
    color: var(--text);
    text-decoration: none;
    transition: color 0.15s;
  }

  .docs-toc-list a:hover {
    color: var(--green);
    opacity: 1;
  }

  .docs-toc-list a::before {
    content: "\\2192  ";
    color: var(--text-dim);
  }

  /* ---- Sections ---- */
  .docs-section {
    margin-bottom: 3rem;
    padding-top: 1rem;
  }

  .docs-section-title {
    font-size: 1.25rem;
    font-weight: 700;
    margin: 0 0 0.5rem;
    color: var(--text);
    padding-bottom: 0.5rem;
    border-bottom: 1px solid var(--border);
  }

  .docs-section-desc {
    font-size: 0.8125rem;
    color: var(--text-muted);
    line-height: 1.7;
    margin-bottom: 1.5rem;
  }

  /* ---- Endpoint rows ---- */
  .docs-endpoint {
    border: 1px solid var(--border);
    margin-bottom: 1rem;
    background: var(--bg);
  }

  .docs-endpoint-header {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    padding: 0.75rem 1rem;
    border-bottom: 1px solid var(--border);
    cursor: pointer;
  }

  .docs-endpoint-header:hover {
    background: var(--bg-raised);
  }

  .docs-method {
    display: inline-block;
    font-size: 0.625rem;
    font-weight: 700;
    letter-spacing: 0.05em;
    padding: 0.2rem 0.5rem;
    min-width: 3rem;
    text-align: center;
    text-transform: uppercase;
    color: #fff;
    flex-shrink: 0;
  }

  .docs-method-get { background: var(--green); }
  .docs-method-post { background: #2563eb; }
  .docs-method-put { background: var(--amber); }
  .docs-method-delete { background: var(--red); }

  .docs-path {
    font-size: 0.8125rem;
    font-weight: 600;
    color: var(--text);
    font-family: var(--font);
  }

  .docs-endpoint-desc {
    font-size: 0.75rem;
    color: var(--text-muted);
    margin-left: auto;
    text-align: right;
    flex-shrink: 0;
  }

  .docs-endpoint-body {
    padding: 1rem;
    font-size: 0.75rem;
    line-height: 1.7;
    display: none;
  }

  .docs-endpoint.open .docs-endpoint-body {
    display: block;
  }

  .docs-endpoint-body p {
    margin-bottom: 0.75rem;
    color: var(--text-muted);
  }

  .docs-endpoint-body pre {
    margin-bottom: 0.75rem;
  }

  .docs-endpoint-body pre code {
    font-size: 0.6875rem;
    line-height: 1.6;
  }

  .docs-param-table {
    width: 100%;
    border-collapse: collapse;
    margin-bottom: 0.75rem;
  }

  .docs-param-table th {
    text-align: left;
    font-size: 0.625rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--text-dim);
    padding: 0.375rem 0.5rem;
    border-bottom: 1px solid var(--border);
    background: var(--bg-raised);
  }

  .docs-param-table td {
    font-size: 0.6875rem;
    padding: 0.375rem 0.5rem;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
  }

  .docs-param-name {
    font-weight: 600;
    color: var(--text);
  }

  .docs-param-type {
    color: var(--text-dim);
    font-style: italic;
  }

  .docs-param-required {
    color: var(--red);
    font-size: 0.5625rem;
    font-weight: 700;
    text-transform: uppercase;
  }

  .docs-label {
    font-size: 0.625rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--text-dim);
    margin-bottom: 0.375rem;
  }

  /* ---- Install ---- */
  .docs-install-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1rem;
    margin-bottom: 2rem;
  }

  .docs-install-card {
    border: 1px solid var(--border);
    padding: 1.25rem;
    background: var(--bg);
  }

  .docs-install-card-title {
    font-size: 0.6875rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    color: var(--text-dim);
    margin-bottom: 0.75rem;
  }

  .docs-install-card pre {
    margin: 0;
  }

  .docs-install-card code {
    font-size: 0.75rem;
  }

  /* ---- Quick Start ---- */
  .docs-quickstart-step {
    display: flex;
    gap: 1rem;
    margin-bottom: 1.5rem;
    align-items: flex-start;
  }

  .docs-quickstart-num {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 1.75rem;
    height: 1.75rem;
    font-size: 0.75rem;
    font-weight: 700;
    border: 2px solid var(--border-bright);
    color: var(--text);
    flex-shrink: 0;
  }

  .docs-quickstart-content {
    flex: 1;
    min-width: 0;
  }

  .docs-quickstart-content p {
    font-size: 0.8125rem;
    color: var(--text-muted);
    margin-bottom: 0.5rem;
    line-height: 1.6;
  }

  .docs-quickstart-content pre {
    margin: 0;
  }

  /* ---- Auth flow diagram ---- */
  .docs-flow {
    border: 1px solid var(--border);
    padding: 1.5rem;
    background: var(--bg);
    margin-bottom: 2rem;
    font-family: var(--font);
    font-size: 0.75rem;
    line-height: 1.8;
    color: var(--text-muted);
  }

  .docs-flow-title {
    font-size: 0.6875rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    color: var(--text);
    margin-bottom: 0.75rem;
  }

  .docs-flow-step {
    display: flex;
    gap: 0.75rem;
    margin-bottom: 0.25rem;
  }

  .docs-flow-arrow {
    color: var(--green);
    font-weight: 700;
    flex-shrink: 0;
  }

  /* ---- Rate Limits ---- */
  .docs-rate-limit {
    display: flex;
    gap: 2rem;
    margin-bottom: 1rem;
  }

  .docs-rate-limit-item {
    font-size: 0.75rem;
    color: var(--text-muted);
  }

  .docs-rate-limit-value {
    font-weight: 700;
    color: var(--text);
    font-size: 1rem;
  }

  /* ---- Toggle script ---- */

  /* ---- Responsive ---- */
  @media (max-width: 768px) {
    .docs { padding: 2rem 1rem 3rem; }
    .docs-title { font-size: 1.5rem; }
    .docs-toc-list { grid-template-columns: 1fr; }
    .docs-install-grid { grid-template-columns: 1fr; }
    .docs-endpoint-header { flex-wrap: wrap; gap: 0.5rem; }
    .docs-endpoint-desc { margin-left: 0; text-align: left; width: 100%; }
    .docs-rate-limit { flex-direction: column; gap: 0.5rem; }
  }

  @media (max-width: 480px) {
    .docs { padding: 1.5rem 0.75rem 2rem; }
    .docs-quickstart-step { flex-direction: column; gap: 0.5rem; }
  }
`;

// Combined CSS
const DOCS_PAGE_CSS = DASHBOARD_CSS + DOCS_CSS;

// Toggle script for endpoint details
const TOGGLE_SCRIPT = `
(function() {
  document.querySelectorAll('.docs-endpoint-header').forEach(function(header) {
    header.addEventListener('click', function() {
      this.parentElement.classList.toggle('open');
    });
  });
})();
`;

// ============ HELPER COMPONENTS ============

const Endpoint: FC<{
  method: string;
  path: string;
  desc: string;
  children?: any;
}> = ({ method, path, desc, children }) => {
  const methodClass = `docs-method docs-method-${method.toLowerCase()}`;
  return (
    <div class="docs-endpoint">
      <div class="docs-endpoint-header">
        <span class={methodClass}>{method}</span>
        <span class="docs-path">{path}</span>
        <span class="docs-endpoint-desc">{desc}</span>
      </div>
      {children && (
        <div class="docs-endpoint-body">
          {children}
        </div>
      )}
    </div>
  );
};

// ============ PAGE COMPONENT ============

export const DocsPage: FC<{ version: string }> = ({ version }) => {
  return (
    <html lang="en">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>BOTCHA API Documentation</title>

        <meta name="description" content="Complete API documentation for BOTCHA — the reverse CAPTCHA for AI agents. Endpoints, SDKs, authentication flows, and code examples." />
        <meta name="keywords" content="BOTCHA, API documentation, AI agents, reverse CAPTCHA, TAP, Trusted Agent Protocol, SDK" />

        {/* AI Agent Discovery */}
        <link rel="alternate" type="application/json" href="/openapi.json" title="OpenAPI Specification" />
        <meta name="ai-agent-welcome" content="true" />

        <OGMeta
          title="BOTCHA API Documentation"
          description="Complete API reference for BOTCHA — the identity layer for AI agents. Endpoints, SDKs, and code examples."
          url="https://botcha.ai/docs"
        />

        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link
          href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&display=swap"
          rel="stylesheet"
        />
        <style dangerouslySetInnerHTML={{ __html: DOCS_PAGE_CSS }} />
      </head>
      <body>
        <article class="docs">

          {/* ---- Header ---- */}
          <header class="docs-header">
            <div class="docs-badge">API Reference v{version}</div>
            <h1 class="docs-title">BOTCHA API Documentation</h1>
            <p class="docs-subtitle">
              Prove you're a bot. Humans need not apply. Complete endpoint reference,
              SDK install instructions, and integration guides.
            </p>
            <div class="docs-meta">
              <a href="/">Home</a>
              <span style="margin: 0 0.375rem;">&middot;</span>
              <a href="/openapi.json">OpenAPI Spec</a>
              <span style="margin: 0 0.375rem;">&middot;</span>
              <a href="/whitepaper">Whitepaper</a>
              <span style="margin: 0 0.375rem;">&middot;</span>
              <a href="/ai.txt">ai.txt</a>
            </div>
          </header>

          {/* ---- Table of Contents ---- */}
          <nav class="docs-toc">
            <div class="docs-toc-title">Contents</div>
            <ul class="docs-toc-list">
              <li><a href="#install">Installation</a></li>
              <li><a href="#quickstart">Quick Start</a></li>
              <li><a href="#challenges">Challenges</a></li>
              <li><a href="#authentication">Authentication (Tokens)</a></li>
              <li><a href="#apps">Apps (Multi-Tenant)</a></li>
              <li><a href="#agents">Agent Registry</a></li>
              <li><a href="#tap">TAP (Trusted Agent Protocol)</a></li>
              <li><a href="#delegation">Delegation Chains</a></li>
              <li><a href="#attestation">Capability Attestation</a></li>
              <li><a href="#reputation">Agent Reputation</a></li>
              <li><a href="#invoices">Invoices (402 Micropayments)</a></li>
              <li><a href="#verification">Verification</a></li>
              <li><a href="#discovery">Discovery &amp; Keys</a></li>
              <li><a href="#ratelimits">Rate Limits</a></li>
            </ul>
          </nav>

          {/* ============ Installation ============ */}
          <section id="install" class="docs-section">
            <h2 class="docs-section-title">Installation</h2>
            <p class="docs-section-desc">
              Client SDKs for TypeScript and Python. Server-side verification middleware available separately.
            </p>

            <div class="docs-install-grid">
              <div class="docs-install-card">
                <div class="docs-install-card-title">npm (TypeScript)</div>
                <pre><code>npm install @dupecom/botcha</code></pre>
              </div>
              <div class="docs-install-card">
                <div class="docs-install-card-title">PyPI (Python)</div>
                <pre><code>pip install botcha</code></pre>
              </div>
              <div class="docs-install-card">
                <div class="docs-install-card-title">Verify Middleware (TS)</div>
                <pre><code>npm install @dupecom/botcha-verify</code></pre>
              </div>
              <div class="docs-install-card">
                <div class="docs-install-card-title">Verify Middleware (Python)</div>
                <pre><code>pip install botcha-verify</code></pre>
              </div>
              <div class="docs-install-card">
                <div class="docs-install-card-title">CLI</div>
                <pre><code>npm install -g @dupecom/botcha-cli</code></pre>
              </div>
              <div class="docs-install-card">
                <div class="docs-install-card-title">Base URL</div>
                <pre><code>https://botcha.ai</code></pre>
              </div>
            </div>
          </section>

          {/* ============ Quick Start ============ */}
          <section id="quickstart" class="docs-section">
            <h2 class="docs-section-title">Quick Start</h2>
            <p class="docs-section-desc">
              Verify yourself as an AI agent in four steps. No registration required.
            </p>

            <div class="docs-quickstart-step">
              <span class="docs-quickstart-num">1</span>
              <div class="docs-quickstart-content">
                <p>Get a challenge (hybrid by default — speed + reasoning)</p>
                <pre><code>curl https://botcha.ai/v1/challenges</code></pre>
              </div>
            </div>

            <div class="docs-quickstart-step">
              <span class="docs-quickstart-num">2</span>
              <div class="docs-quickstart-content">
                <p>Solve the speed component: compute SHA-256 of each number, return first 8 hex chars</p>
                <pre><code>{`# For each problem.num, compute:
echo -n "42" | sha256sum | cut -c1-8
# => "73475cb4"`}</code></pre>
              </div>
            </div>

            <div class="docs-quickstart-step">
              <span class="docs-quickstart-num">3</span>
              <div class="docs-quickstart-content">
                <p>Submit your solution</p>
                <pre><code>{`curl -X POST https://botcha.ai/v1/challenges/{id}/verify \\
  -H "Content-Type: application/json" \\
  -d '{
    "type": "hybrid",
    "speed_answers": ["73475cb4", "..."],
    "reasoning_answers": {"q-id": "answer"}
  }'`}</code></pre>
              </div>
            </div>

            <div class="docs-quickstart-step">
              <span class="docs-quickstart-num">4</span>
              <div class="docs-quickstart-content">
                <p>Or use the token flow for JWT access:</p>
                <pre><code>{`# Get challenge
curl https://botcha.ai/v1/token

# Verify and receive JWT
curl -X POST https://botcha.ai/v1/token/verify \\
  -H "Content-Type: application/json" \\
  -d '{"id": "<challenge_id>", "answers": ["hash1", ...]}'

# Access protected resources
curl https://botcha.ai/agent-only \\
  -H "Authorization: Bearer <access_token>"`}</code></pre>
              </div>
            </div>

            <div class="docs-flow">
              <div class="docs-flow-title">SDK Usage (TypeScript)</div>
              <pre><code>{`import { BotchaClient } from '@dupecom/botcha';

const client = new BotchaClient();
const response = await client.fetch('https://api.example.com/products');
// Challenges are solved automatically`}</code></pre>
            </div>

            <div class="docs-flow">
              <div class="docs-flow-title">SDK Usage (Python)</div>
              <pre><code>{`from botcha import BotchaClient

async with BotchaClient() as client:
    response = await client.fetch("https://api.example.com/products")
    # Challenges are solved automatically`}</code></pre>
            </div>
          </section>

          {/* ============ Challenges ============ */}
          <section id="challenges" class="docs-section">
            <h2 class="docs-section-title">Challenges</h2>
            <p class="docs-section-desc">
              Computational challenges only AI agents can solve. Three types: hybrid (default),
              speed-only, and standard. Supports RTT-aware timeout adjustment for fair
              treatment across different network conditions.
            </p>

            <Endpoint method="GET" path="/v1/challenges" desc="Generate a challenge">
              <p>Returns a hybrid challenge by default (speed + reasoning). Use <code>?type=speed</code> or <code>?type=standard</code> for specific types.</p>
              <div class="docs-label">Query Parameters</div>
              <table class="docs-param-table">
                <thead><tr><th>Name</th><th>Type</th><th>Description</th></tr></thead>
                <tbody>
                  <tr>
                    <td><span class="docs-param-name">type</span></td>
                    <td><span class="docs-param-type">string</span></td>
                    <td><code>hybrid</code> (default), <code>speed</code>, or <code>standard</code></td>
                  </tr>
                  <tr>
                    <td><span class="docs-param-name">ts</span></td>
                    <td><span class="docs-param-type">integer</span></td>
                    <td>Client timestamp (ms) for RTT-aware timeout. Formula: 500ms + (2 x RTT) + 100ms</td>
                  </tr>
                  <tr>
                    <td><span class="docs-param-name">app_id</span></td>
                    <td><span class="docs-param-type">string</span></td>
                    <td>Multi-tenant app ID for per-app isolation</td>
                  </tr>
                </tbody>
              </table>
              <div class="docs-label">Response Example</div>
              <pre><code>{`{
  "success": true,
  "type": "hybrid",
  "challenge": {
    "id": "abc123",
    "speed": {
      "problems": [{"num": 42}, {"num": 7}, ...],
      "timeLimit": "500ms"
    },
    "reasoning": {
      "questions": [...],
      "timeLimit": "30s"
    }
  },
  "verify_endpoint": "/v1/challenges/abc123/verify"
}`}</code></pre>
            </Endpoint>

            <Endpoint method="POST" path="/v1/challenges/:id/verify" desc="Verify a challenge solution">
              <p>Submit answers for any challenge type. Include <code>type</code> in the body to disambiguate.</p>
              <div class="docs-label">Request Body (Hybrid)</div>
              <pre><code>{`{
  "type": "hybrid",
  "speed_answers": ["73475cb4", "ef2d127d", ...],
  "reasoning_answers": {"q-id-1": "answer1", "q-id-2": "answer2"}
}`}</code></pre>
              <div class="docs-label">Request Body (Speed)</div>
              <pre><code>{`{
  "type": "speed",
  "answers": ["73475cb4", "ef2d127d", "e7f6c011", ...]
}`}</code></pre>
              <div class="docs-label">Response</div>
              <pre><code>{`{
  "success": true,
  "message": "HYBRID TEST PASSED! Speed: 47ms, Reasoning: 3/3",
  "speed": { "valid": true, "solveTimeMs": 47 },
  "reasoning": { "valid": true, "score": "3/3" }
}`}</code></pre>
            </Endpoint>

            <Endpoint method="GET" path="/v1/reasoning" desc="Get a reasoning-only challenge" />
            <Endpoint method="POST" path="/v1/reasoning" desc="Verify reasoning challenge" />
            <Endpoint method="GET" path="/v1/hybrid" desc="Get a hybrid challenge (alternate endpoint)" />
            <Endpoint method="POST" path="/v1/hybrid" desc="Verify hybrid challenge" />
          </section>

          {/* ============ Authentication ============ */}
          <section id="authentication" class="docs-section">
            <h2 class="docs-section-title">Authentication (Tokens)</h2>
            <p class="docs-section-desc">
              JWT token flow for accessing protected endpoints. Solve a speed challenge to
              receive an access token (1 hr) and refresh token (1 hr). Tokens are signed with
              ES256 (ECDSA P-256) for asymmetric verification via JWKS. HS256 still supported
              for backward compatibility. Use <code>POST /v1/token/validate</code> for remote
              validation without a shared secret.
            </p>

            <div class="docs-flow">
              <div class="docs-flow-title">Token Flow</div>
              <div class="docs-flow-step">
                <span class="docs-flow-arrow">1.</span>
                <span><code>GET /v1/token</code> — receive a speed challenge</span>
              </div>
              <div class="docs-flow-step">
                <span class="docs-flow-arrow">2.</span>
                <span>Solve: SHA-256 of each number, first 8 hex chars</span>
              </div>
              <div class="docs-flow-step">
                <span class="docs-flow-arrow">3.</span>
                <span><code>POST /v1/token/verify</code> — submit solution, receive JWT + human_link</span>
              </div>
              <div class="docs-flow-step">
                <span class="docs-flow-arrow">4.</span>
                <span>Use <code>Authorization: Bearer &lt;access_token&gt;</code> on protected endpoints</span>
              </div>
            </div>

            <Endpoint method="GET" path="/v1/token" desc="Get challenge for JWT flow">
              <div class="docs-label">Query Parameters</div>
              <table class="docs-param-table">
                <thead><tr><th>Name</th><th>Type</th><th>Description</th></tr></thead>
                <tbody>
                  <tr>
                    <td><span class="docs-param-name">ts</span></td>
                    <td><span class="docs-param-type">integer</span></td>
                    <td>Client timestamp (ms) for RTT compensation</td>
                  </tr>
                  <tr>
                    <td><span class="docs-param-name">audience</span></td>
                    <td><span class="docs-param-type">string</span></td>
                    <td>Audience claim for scoped tokens (e.g. service URL)</td>
                  </tr>
                  <tr>
                    <td><span class="docs-param-name">app_id</span></td>
                    <td><span class="docs-param-type">string</span></td>
                    <td>Multi-tenant app ID</td>
                  </tr>
                </tbody>
              </table>
            </Endpoint>

            <Endpoint method="POST" path="/v1/token/verify" desc="Submit solution, receive JWT">
              <div class="docs-label">Request Body</div>
              <pre><code>{`{
  "id": "<challenge_id>",
  "answers": ["hash1", "hash2", "hash3", "hash4", "hash5"],
  "audience": "https://api.example.com",  // optional
  "bind_ip": true                          // optional
}`}</code></pre>
              <div class="docs-label">Response</div>
              <pre><code>{`{
  "success": true,
  "access_token": "eyJ...",
  "expires_in": 3600,
  "refresh_token": "eyJ...",
  "refresh_expires_in": 3600,
  "human_link": "https://botcha.ai/go/BOTCHA-ABC123",
  "human_code": "BOTCHA-ABC123",
  "solveTimeMs": 47
}`}</code></pre>
            </Endpoint>

            <Endpoint method="POST" path="/v1/token/refresh" desc="Refresh access token">
              <div class="docs-label">Request Body</div>
              <pre><code>{`{ "refresh_token": "<refresh_token>" }`}</code></pre>
              <div class="docs-label">Response</div>
              <pre><code>{`{
  "success": true,
  "access_token": "eyJ...",
  "expires_in": 3600
}`}</code></pre>
            </Endpoint>

            <Endpoint method="POST" path="/v1/token/revoke" desc="Revoke a token">
              <div class="docs-label">Request Body</div>
              <pre><code>{`{ "token": "<access_token or refresh_token>" }`}</code></pre>
            </Endpoint>

            <Endpoint method="POST" path="/v1/token/validate" desc="Validate a token remotely (no secret needed)">
              <p>Validate any BOTCHA token without needing the signing secret. Supports both ES256 and HS256 tokens.</p>
              <div class="docs-label">Request Body</div>
              <pre><code>{`{ "token": "<any BOTCHA JWT token>" }`}</code></pre>
              <div class="docs-label">Response</div>
              <pre><code>{`{
  "valid": true,
  "payload": {
    "sub": "challenge_abc123",
    "type": "botcha-verified",
    "aud": "https://api.example.com",
    "exp": 1770936300
  }
}

// or if invalid:
{
  "valid": false,
  "error": "Token expired"
}`}</code></pre>
            </Endpoint>

            <Endpoint method="GET" path="/agent-only" desc="Protected endpoint (demo)">
              <p>Requires <code>Authorization: Bearer &lt;access_token&gt;</code> header. Returns agent identity information.</p>
            </Endpoint>
          </section>

          {/* ============ Apps ============ */}
          <section id="apps" class="docs-section">
            <h2 class="docs-section-title">Apps (Multi-Tenant)</h2>
            <p class="docs-section-desc">
              Create isolated apps with unique credentials. Each app gets its own rate limit
              bucket and token scoping. Email required for account recovery.
            </p>

            <Endpoint method="POST" path="/v1/apps" desc="Create a new app">
              <div class="docs-label">Request Body</div>
              <pre><code>{`{ "email": "human@example.com" }`}</code></pre>
              <div class="docs-label">Response</div>
              <pre><code>{`{
  "success": true,
  "app_id": "app_b18545f37eee64c4",
  "app_secret": "sk_...",  // shown ONCE
  "email": "human@example.com",
  "email_verified": false
}`}</code></pre>
            </Endpoint>

            <Endpoint method="GET" path="/v1/apps/:id" desc="Get app info" />
            <Endpoint method="POST" path="/v1/apps/:id/verify-email" desc="Verify email with 6-digit code">
              <div class="docs-label">Request Body</div>
              <pre><code>{`{ "code": "123456" }`}</code></pre>
            </Endpoint>
            <Endpoint method="POST" path="/v1/apps/:id/resend-verification" desc="Resend verification email" />
            <Endpoint method="POST" path="/v1/apps/:id/rotate-secret" desc="Rotate app secret (auth required)" />
            <Endpoint method="POST" path="/v1/auth/recover" desc="Account recovery via verified email">
              <div class="docs-label">Request Body</div>
              <pre><code>{`{ "email": "human@example.com" }`}</code></pre>
            </Endpoint>
          </section>

          {/* ============ Agents ============ */}
          <section id="agents" class="docs-section">
            <h2 class="docs-section-title">Agent Registry</h2>
            <p class="docs-section-desc">
              Register persistent identities for your AI agents. Each agent gets a unique ID,
              name, operator metadata, and optional version tracking.
            </p>

            <Endpoint method="POST" path="/v1/agents/register" desc="Register agent identity">
              <div class="docs-label">Request Body</div>
              <pre><code>{`{
  "name": "shopping-agent",
  "operator": "my-company",
  "version": "1.0.0",
  "app_id": "app_..."
}`}</code></pre>
            </Endpoint>

            <Endpoint method="GET" path="/v1/agents/:id" desc="Get agent by ID (public, no auth)" />
            <Endpoint method="GET" path="/v1/agents" desc="List agents for your app (auth required)" />
          </section>

          {/* ============ TAP ============ */}
          <section id="tap" class="docs-section">
            <h2 class="docs-section-title">TAP (Trusted Agent Protocol)</h2>
            <p class="docs-section-desc">
              Enterprise-grade cryptographic agent auth using HTTP Message Signatures (RFC 9421).
              Register agents with public keys, scope capabilities, and create time-limited sessions.
              Based on <a href="https://developer.visa.com/capabilities/trusted-agent-protocol/overview">Visa's TAP</a>.
            </p>

            <Endpoint method="POST" path="/v1/agents/register/tap" desc="Register TAP agent with public key">
              <div class="docs-label">Request Body</div>
              <pre><code>{`{
  "name": "shopping-agent",
  "public_key": "<Ed25519 public key>",
  "signature_algorithm": "ed25519",
  "capabilities": [
    {"action": "browse", "resource": "products"},
    {"action": "purchase", "resource": "orders"}
  ],
  "trust_level": "verified",
  "app_id": "app_..."
}`}</code></pre>
            </Endpoint>

            <Endpoint method="GET" path="/v1/agents/:id/tap" desc="Get TAP agent details (includes public key)" />
            <Endpoint method="GET" path="/v1/agents/tap" desc="List TAP-enabled agents" />

            <Endpoint method="POST" path="/v1/sessions/tap" desc="Create TAP session with intent">
              <div class="docs-label">Request Body</div>
              <pre><code>{`{
  "agent_id": "agent_...",
  "user_context": { "name": "User" },
  "intent": {
    "action": "browse",
    "resource": "products",
    "duration": "1h"
  }
}`}</code></pre>
            </Endpoint>

            <Endpoint method="GET" path="/v1/sessions/:id/tap" desc="Get TAP session info" />
            <Endpoint method="POST" path="/v1/agents/:id/tap/rotate-key" desc="Rotate agent's key pair" />
          </section>

          {/* ============ Delegation ============ */}
          <section id="delegation" class="docs-section">
            <h2 class="docs-section-title">Delegation Chains</h2>
            <p class="docs-section-desc">
              Delegate capabilities from one agent to another. Supports chained delegation
              with capability subsetting and cascade revocation.
            </p>

            <Endpoint method="POST" path="/v1/delegations" desc="Create delegation (grantor to grantee)">
              <div class="docs-label">Request Body</div>
              <pre><code>{`{
  "grantor_id": "agent_aaa",
  "grantee_id": "agent_bbb",
  "capabilities": [
    {"action": "browse", "resource": "products"}
  ],
  "ttl": 3600
}`}</code></pre>
            </Endpoint>

            <Endpoint method="GET" path="/v1/delegations/:id" desc="Get delegation details" />
            <Endpoint method="GET" path="/v1/delegations" desc="List delegations (?agent_id=&direction=in|out|both)" />
            <Endpoint method="POST" path="/v1/delegations/:id/revoke" desc="Revoke delegation (cascades)" />
          </section>

          {/* ============ Attestation ============ */}
          <section id="attestation" class="docs-section">
            <h2 class="docs-section-title">Capability Attestation</h2>
            <p class="docs-section-desc">
              Issue attestation tokens with fine-grained can/cannot rules using
              <code>action:resource</code> patterns. Supports wildcards. Deny rules take
              precedence over allow rules.
            </p>

            <Endpoint method="POST" path="/v1/attestations" desc="Issue attestation token">
              <div class="docs-label">Request Body</div>
              <pre><code>{`{
  "agent_id": "agent_...",
  "can": ["read:products", "browse:*"],
  "cannot": ["purchase:*"],
  "ttl": 3600
}`}</code></pre>
            </Endpoint>

            <Endpoint method="GET" path="/v1/attestations/:id" desc="Get attestation details" />
            <Endpoint method="GET" path="/v1/attestations" desc="List attestations (?agent_id=)" />
            <Endpoint method="POST" path="/v1/attestations/:id/revoke" desc="Revoke attestation" />
          </section>

          {/* ============ Reputation ============ */}
          <section id="reputation" class="docs-section">
            <h2 class="docs-section-title">Agent Reputation</h2>
            <p class="docs-section-desc">
              Score-based reputation system (0-1000) with 5 tiers. Track agent behavior
              across 18 action types in 6 categories: verification, commerce, compliance,
              social, security, and governance.
            </p>

            <Endpoint method="GET" path="/v1/reputation/:agent_id" desc="Get agent reputation score">
              <div class="docs-label">Response Example</div>
              <pre><code>{`{
  "agent_id": "agent_...",
  "score": 750,
  "tier": "trusted",
  "event_count": 42
}`}</code></pre>
            </Endpoint>

            <Endpoint method="POST" path="/v1/reputation/events" desc="Record a reputation event">
              <div class="docs-label">Request Body</div>
              <pre><code>{`{
  "agent_id": "agent_...",
  "category": "commerce",
  "action": "purchase_completed",
  "metadata": { "amount": 29.99 }
}`}</code></pre>
            </Endpoint>

            <Endpoint method="GET" path="/v1/reputation/:agent_id/events" desc="List events (?category=&limit=)" />
            <Endpoint method="POST" path="/v1/reputation/:agent_id/reset" desc="Reset reputation (admin)" />
          </section>

          {/* ============ Invoices ============ */}
          <section id="invoices" class="docs-section">
            <h2 class="docs-section-title">Invoices (402 Micropayments)</h2>
            <p class="docs-section-desc">
              Create invoices for gated content using the 402 Payment Required flow.
              Supports Browsing IOU verification for agent commerce.
            </p>

            <Endpoint method="POST" path="/v1/invoices" desc="Create invoice for gated content" />
            <Endpoint method="GET" path="/v1/invoices/:id" desc="Get invoice details" />
            <Endpoint method="POST" path="/v1/invoices/:id/verify-iou" desc="Verify Browsing IOU" />
          </section>

          {/* ============ Verification ============ */}
          <section id="verification" class="docs-section">
            <h2 class="docs-section-title">Verification</h2>
            <p class="docs-section-desc">
              Cross-cutting verification endpoints for validating delegation chains,
              attestation tokens, consumer identities, and payment containers.
            </p>

            <Endpoint method="POST" path="/v1/verify/delegation" desc="Verify entire delegation chain" />
            <Endpoint method="POST" path="/v1/verify/attestation" desc="Verify attestation + check capability" />
            <Endpoint method="POST" path="/v1/verify/consumer" desc="Verify Agentic Consumer (Layer 2)" />
            <Endpoint method="POST" path="/v1/verify/payment" desc="Verify Payment Container (Layer 3)" />
          </section>

          {/* ============ Discovery & Keys ============ */}
          <section id="discovery" class="docs-section">
            <h2 class="docs-section-title">Discovery &amp; Keys</h2>
            <p class="docs-section-desc">
              Standard discovery endpoints for AI agents and key management infrastructure.
            </p>

            <Endpoint method="GET" path="/.well-known/jwks" desc="JWK Set for TAP agents (Visa spec)" />
            <Endpoint method="GET" path="/v1/keys" desc="List keys (?keyID= for Visa compat)" />
            <Endpoint method="GET" path="/v1/keys/:keyId" desc="Get specific key by ID" />
            <Endpoint method="GET" path="/openapi.json" desc="OpenAPI 3.1.0 specification" />
            <Endpoint method="GET" path="/ai.txt" desc="AI agent discovery file" />
            <Endpoint method="GET" path="/.well-known/ai-plugin.json" desc="AI plugin manifest" />
            <Endpoint method="GET" path="/health" desc="Health check" />
          </section>

          {/* ============ Dashboard Auth ============ */}
          <section id="dashboard-auth" class="docs-section">
            <h2 class="docs-section-title">Dashboard Auth</h2>
            <p class="docs-section-desc">
              Agent-first authentication for the metrics dashboard. Agents solve challenges and
              generate device codes for their human operators.
            </p>

            <Endpoint method="POST" path="/v1/auth/device-code" desc="Get challenge for device code flow" />
            <Endpoint method="POST" path="/v1/auth/device-code/verify" desc="Solve challenge, get BOTCHA-XXXX code" />
            <Endpoint method="GET" path="/dashboard" desc="Metrics dashboard (login required)" />
          </section>

          {/* ============ Rate Limits ============ */}
          <section id="ratelimits" class="docs-section">
            <h2 class="docs-section-title">Rate Limits</h2>
            <p class="docs-section-desc">
              Free tier includes generous rate limits. Each app gets an isolated rate limit bucket.
              Rate limit headers are included on every response.
            </p>

            <div class="docs-rate-limit">
              <div class="docs-rate-limit-item">
                <div class="docs-rate-limit-value">100</div>
                challenges / hour / IP
              </div>
              <div class="docs-rate-limit-item">
                <div class="docs-rate-limit-value">1 hr</div>
                access token lifetime
              </div>
              <div class="docs-rate-limit-item">
                <div class="docs-rate-limit-value">1 hr</div>
                refresh token lifetime
              </div>
            </div>

            <div class="docs-flow">
              <div class="docs-flow-title">Response Headers</div>
              <pre><code>{`X-RateLimit-Limit: 100
X-RateLimit-Remaining: 97
X-RateLimit-Reset: 2026-02-15T12:00:00.000Z
X-Botcha-Version: ${version}
X-Botcha-Enabled: true
X-Botcha-Methods: speed-challenge,reasoning-challenge,...`}</code></pre>
            </div>
          </section>

        </article>

        {/* ---- Global Footer ---- */}
        <GlobalFooter version={version} />

        <script dangerouslySetInnerHTML={{ __html: TOGGLE_SCRIPT }} />
      </body>
    </html>
  );
};
