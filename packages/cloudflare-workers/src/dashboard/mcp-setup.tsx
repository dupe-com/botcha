/**
 * BOTCHA MCP Setup Page
 *
 * Served at GET /mcp for browser (HTML) requests via content negotiation.
 * MCP clients hitting POST /mcp get the JSON-RPC server instead.
 *
 * Shows one-liner install commands and per-tool config snippets with
 * copy-to-clipboard buttons for Claude Code, Claude Desktop, OpenCode,
 * Cursor, Windsurf, and generic .mcp.json.
 */

import type { FC } from 'hono/jsx';
import { DASHBOARD_CSS } from './styles';
import { GlobalFooter, OGMeta } from './layout';

// ============ CSS ============

const MCP_CSS = `
  .mcp-page {
    max-width: 860px;
    margin: 0 auto;
    padding: 3rem 2rem 4rem;
  }

  /* ---- Header ---- */
  .mcp-header {
    text-align: center;
    margin-bottom: 3rem;
    padding-bottom: 2rem;
    border-bottom: 1px solid var(--border);
  }

  .mcp-badge {
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

  .mcp-title {
    font-size: 2rem;
    font-weight: 700;
    line-height: 1.15;
    margin: 0 0 0.75rem;
    color: var(--text);
  }

  .mcp-subtitle {
    font-size: 0.875rem;
    color: var(--text-muted);
    line-height: 1.6;
    margin: 0 auto 1.5rem;
    max-width: 560px;
  }

  /* ---- One-liner hero ---- */
  .mcp-oneliner {
    margin: 0 auto 2.5rem;
    max-width: 680px;
  }

  .mcp-oneliner-label {
    font-size: 0.6875rem;
    font-weight: 700;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    color: var(--text-muted);
    margin-bottom: 0.5rem;
  }

  .mcp-oneliner-box {
    display: flex;
    align-items: center;
    gap: 0;
    border: 1px solid var(--accent);
    background: var(--bg-raised);
  }

  .mcp-oneliner-code {
    flex: 1;
    padding: 0.875rem 1rem;
    font-family: var(--font);
    font-size: 0.875rem;
    color: var(--green);
    overflow-x: auto;
    white-space: nowrap;
  }

  .mcp-copy-btn {
    padding: 0.875rem 1rem;
    border: none;
    border-left: 1px solid var(--accent);
    background: var(--accent);
    color: #fff;
    font-family: var(--font);
    font-size: 0.6875rem;
    font-weight: 700;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    cursor: pointer;
    white-space: nowrap;
    transition: opacity 0.1s;
  }

  .mcp-copy-btn:hover { opacity: 0.75; }
  .mcp-copy-btn.copied { background: var(--green); border-color: var(--green); }

  /* ---- Tool tabs ---- */
  .mcp-tabs {
    display: flex;
    flex-wrap: wrap;
    gap: 0;
    border: 1px solid var(--border);
    border-bottom: none;
    margin-bottom: 0;
  }

  .mcp-tab {
    padding: 0.625rem 1rem;
    font-family: var(--font);
    font-size: 0.6875rem;
    font-weight: 700;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    cursor: pointer;
    border: none;
    border-right: 1px solid var(--border);
    border-bottom: 1px solid var(--border);
    background: var(--bg-raised);
    color: var(--text-muted);
    transition: background 0.1s, color 0.1s;
  }

  .mcp-tab:last-child { border-right: none; }

  .mcp-tab.active {
    background: var(--bg);
    color: var(--text);
    border-bottom-color: var(--bg);
  }

  .mcp-tab:hover:not(.active) {
    color: var(--text);
    background: var(--bg);
  }

  /* ---- Tool panels ---- */
  .mcp-panels {
    border: 1px solid var(--border);
    margin-bottom: 2.5rem;
  }

  .mcp-panel {
    display: none;
    padding: 1.5rem;
  }

  .mcp-panel.active { display: block; }

  .mcp-panel-title {
    font-size: 0.75rem;
    font-weight: 700;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    color: var(--text-muted);
    margin-bottom: 0.5rem;
  }

  .mcp-panel-desc {
    font-size: 0.8125rem;
    color: var(--text-muted);
    line-height: 1.6;
    margin-bottom: 1.25rem;
  }

  .mcp-panel-desc a {
    color: var(--text-muted);
  }

  .mcp-snippet-wrap {
    position: relative;
    margin-bottom: 1rem;
  }

  .mcp-snippet-label {
    font-size: 0.625rem;
    font-weight: 700;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    color: var(--text-dim);
    margin-bottom: 0.375rem;
  }

  .mcp-snippet {
    background: var(--bg-raised);
    border: 1px solid var(--border);
    padding: 1rem 1.25rem;
    font-size: 0.8125rem;
    color: var(--text);
    white-space: pre;
    overflow-x: auto;
    line-height: 1.5;
    font-family: var(--font);
  }

  .mcp-snippet-footer {
    display: flex;
    justify-content: flex-end;
    margin-top: 0.5rem;
  }

  .mcp-snippet-copy {
    padding: 0.3rem 0.75rem;
    border: 1px solid var(--border);
    background: var(--bg);
    color: var(--text-muted);
    font-family: var(--font);
    font-size: 0.625rem;
    font-weight: 700;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    cursor: pointer;
    transition: border-color 0.1s, color 0.1s;
  }

  .mcp-snippet-copy:hover { border-color: var(--accent); color: var(--text); }
  .mcp-snippet-copy.copied { border-color: var(--green); color: var(--green); }

  .mcp-config-path {
    font-size: 0.6875rem;
    color: var(--text-dim);
    margin-top: 0.375rem;
    margin-bottom: 1rem;
  }

  .mcp-config-path code {
    color: var(--text-muted);
    font-size: 0.6875rem;
  }

  /* ---- Info strip ---- */
  .mcp-info {
    border: 1px solid var(--border);
    padding: 1.25rem 1.5rem;
    margin-bottom: 2rem;
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 1rem;
  }

  .mcp-info-item {}

  .mcp-info-label {
    font-size: 0.625rem;
    font-weight: 700;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    color: var(--text-dim);
    margin-bottom: 0.25rem;
  }

  .mcp-info-value {
    font-size: 0.8125rem;
    color: var(--text);
  }

  .mcp-info-value a { color: var(--text); }

  /* ---- Tools table ---- */
  .mcp-tools-title {
    font-size: 0.75rem;
    font-weight: 700;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    color: var(--text-muted);
    margin-bottom: 0.75rem;
    margin-top: 2rem;
  }

  .mcp-tools-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
    gap: 0.5rem;
    margin-bottom: 2rem;
  }

  .mcp-tool-card {
    border: 1px solid var(--border);
    padding: 0.875rem 1rem;
  }

  .mcp-tool-name {
    font-size: 0.75rem;
    font-weight: 700;
    color: var(--text);
    margin-bottom: 0.25rem;
  }

  .mcp-tool-name code {
    font-size: 0.6875rem;
    color: var(--green);
  }

  .mcp-tool-desc {
    font-size: 0.75rem;
    color: var(--text-muted);
    line-height: 1.5;
  }

  @media (max-width: 600px) {
    .mcp-title { font-size: 1.5rem; }
    .mcp-oneliner-code { font-size: 0.75rem; }
    .mcp-tab { padding: 0.5rem 0.625rem; font-size: 0.5625rem; }
  }
`;

// ============ SNIPPET CONTENT ============

const SNIPPETS = {
  claudeCode: {
    cli: `claude mcp add --transport http botcha https://botcha.ai/mcp`,
    json: `{
  "mcpServers": {
    "botcha": {
      "type": "http",
      "url": "https://botcha.ai/mcp"
    }
  }
}`,
  },
  claudeDesktop: `{
  "mcpServers": {
    "botcha": {
      "type": "http",
      "url": "https://botcha.ai/mcp"
    }
  }
}`,
  opencode: `{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "botcha": {
      "type": "remote",
      "url": "https://botcha.ai/mcp",
      "enabled": true
    }
  }
}`,
  cursor: `{
  "mcpServers": {
    "botcha": {
      "url": "https://botcha.ai/mcp"
    }
  }
}`,
  windsurf: `{
  "mcpServers": {
    "botcha": {
      "serverUrl": "https://botcha.ai/mcp"
    }
  }
}`,
  generic: `{
  "mcpServers": {
    "botcha": {
      "type": "http",
      "url": "https://botcha.ai/mcp"
    }
  }
}`,
};

// ============ COMPONENT ============

export const MCPSetupPage: FC<{ version?: string }> = ({ version = '0.22.0' }) => {
  return (
    <html lang="en">
      <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>BOTCHA MCP Server — Add to Your AI Agent</title>
        <OGMeta
          title="BOTCHA MCP Server"
          description="Add BOTCHA to Claude Code, Claude Desktop, OpenCode, Cursor, or Windsurf in one command. Read-only documentation server — no auth required."
          url="https://botcha.ai/mcp"
        />
        <style dangerouslySetInnerHTML={{ __html: DASHBOARD_CSS + MCP_CSS }} />
      </head>
      <body>
        <main class="mcp-page">

          {/* ---- Header ---- */}
          <header class="mcp-header">
            <div class="mcp-badge">MCP Server</div>
            <h1 class="mcp-title">Add BOTCHA to your agent</h1>
            <p class="mcp-subtitle">
              BOTCHA exposes its full API reference as an{' '}
              <a href="https://modelcontextprotocol.io/specification/2025-03-26" target="_blank" rel="noopener">MCP (2025-03-26)</a>{' '}
              server. Ask it anything about BOTCHA features, endpoints, or get code examples.
              No authentication required.
            </p>
          </header>

          {/* ---- One-liner hero ---- */}
          <div class="mcp-oneliner">
            <div class="mcp-oneliner-label">Fastest way — Claude Code CLI</div>
            <div class="mcp-oneliner-box">
              <div class="mcp-oneliner-code" id="oneliner-text">{SNIPPETS.claudeCode.cli}</div>
              <button
                class="mcp-copy-btn"
                id="oneliner-copy"
                onclick="copyText('oneliner-text', 'oneliner-copy')"
              >
                Copy
              </button>
            </div>
          </div>

          {/* ---- Info strip ---- */}
          <div class="mcp-info">
            <div class="mcp-info-item">
              <div class="mcp-info-label">Endpoint</div>
              <div class="mcp-info-value"><a href="/mcp">https://botcha.ai/mcp</a></div>
            </div>
            <div class="mcp-info-item">
              <div class="mcp-info-label">Transport</div>
              <div class="mcp-info-value">Streamable HTTP</div>
            </div>
            <div class="mcp-info-item">
              <div class="mcp-info-label">Auth</div>
              <div class="mcp-info-value">None — read-only docs server</div>
            </div>
            <div class="mcp-info-item">
              <div class="mcp-info-label">Discovery</div>
              <div class="mcp-info-value"><a href="/.well-known/mcp.json">/.well-known/mcp.json</a></div>
            </div>
          </div>

          {/* ---- Per-tool tabs ---- */}
          <div
            class="mcp-tabs"
            id="mcp-tabs"
            role="tablist"
          >
            <button class="mcp-tab active" onclick="switchTab('claude-code')" role="tab">Claude Code</button>
            <button class="mcp-tab" onclick="switchTab('claude-desktop')" role="tab">Claude Desktop</button>
            <button class="mcp-tab" onclick="switchTab('opencode')" role="tab">OpenCode</button>
            <button class="mcp-tab" onclick="switchTab('cursor')" role="tab">Cursor</button>
            <button class="mcp-tab" onclick="switchTab('windsurf')" role="tab">Windsurf</button>
            <button class="mcp-tab" onclick="switchTab('generic')" role="tab">.mcp.json</button>
          </div>

          <div class="mcp-panels">

            {/* Claude Code */}
            <div class="mcp-panel active" id="panel-claude-code">
              <div class="mcp-panel-title">Claude Code</div>
              <p class="mcp-panel-desc">
                Run this command once — it adds BOTCHA to your user-scoped MCP config (<code>~/.claude.json</code>).
                Available across all your projects.
              </p>
              <div class="mcp-snippet-label">Terminal</div>
              <div class="mcp-snippet" id="cc-cli">{SNIPPETS.claudeCode.cli}</div>
              <div class="mcp-snippet-footer">
                <button class="mcp-snippet-copy" onclick="copyText('cc-cli', this)">Copy</button>
              </div>

              <p class="mcp-panel-desc" style="margin-top: 1.25rem;">
                Or share with your team by checking a <code>.mcp.json</code> file into your project root:
              </p>
              <div class="mcp-snippet-label">.mcp.json (project root)</div>
              <div class="mcp-snippet" id="cc-json">{SNIPPETS.claudeCode.json}</div>
              <div class="mcp-snippet-footer">
                <button class="mcp-snippet-copy" onclick="copyText('cc-json', this)">Copy</button>
              </div>
            </div>

            {/* Claude Desktop */}
            <div class="mcp-panel" id="panel-claude-desktop">
              <div class="mcp-panel-title">Claude Desktop</div>
              <p class="mcp-panel-desc">
                Add to your Claude Desktop config file, then restart the app.
              </p>
              <div class="mcp-config-path">
                macOS: <code>~/Library/Application Support/Claude/claude_desktop_config.json</code><br />
                Windows: <code>%APPDATA%\Claude\claude_desktop_config.json</code>
              </div>
              <div class="mcp-snippet-label">claude_desktop_config.json</div>
              <div class="mcp-snippet" id="cd-json">{SNIPPETS.claudeDesktop}</div>
              <div class="mcp-snippet-footer">
                <button class="mcp-snippet-copy" onclick="copyText('cd-json', this)">Copy</button>
              </div>
            </div>

            {/* OpenCode */}
            <div class="mcp-panel" id="panel-opencode">
              <div class="mcp-panel-title">OpenCode</div>
              <p class="mcp-panel-desc">
                Add to your{' '}
                <a href="https://opencode.ai/docs/mcp-servers/" target="_blank" rel="noopener">OpenCode config</a>.
                Global config is at <code>~/.config/opencode/config.json</code>,
                or create <code>opencode.json</code> in your project root for per-project config.
              </p>
              <div class="mcp-snippet-label">opencode.json / ~/.config/opencode/config.json</div>
              <div class="mcp-snippet" id="oc-json">{SNIPPETS.opencode}</div>
              <div class="mcp-snippet-footer">
                <button class="mcp-snippet-copy" onclick="copyText('oc-json', this)">Copy</button>
              </div>
            </div>

            {/* Cursor */}
            <div class="mcp-panel" id="panel-cursor">
              <div class="mcp-panel-title">Cursor</div>
              <p class="mcp-panel-desc">
                Add to your Cursor MCP config. Project-level: <code>.cursor/mcp.json</code>.
                Global: <code>~/.cursor/mcp.json</code>.
                Or use <strong>Cursor Settings → MCP</strong> to add a remote server.
              </p>
              <div class="mcp-snippet-label">.cursor/mcp.json</div>
              <div class="mcp-snippet" id="cursor-json">{SNIPPETS.cursor}</div>
              <div class="mcp-snippet-footer">
                <button class="mcp-snippet-copy" onclick="copyText('cursor-json', this)">Copy</button>
              </div>
            </div>

            {/* Windsurf */}
            <div class="mcp-panel" id="panel-windsurf">
              <div class="mcp-panel-title">Windsurf (Cascade)</div>
              <p class="mcp-panel-desc">
                Add to <code>~/.codeium/windsurf/mcp_config.json</code>.
                Windsurf uses <code>serverUrl</code> for remote HTTP MCP servers.
                You can also add it via <strong>MCP Marketplace → Add custom</strong> in the Cascade panel.
              </p>
              <div class="mcp-snippet-label">~/.codeium/windsurf/mcp_config.json</div>
              <div class="mcp-snippet" id="ws-json">{SNIPPETS.windsurf}</div>
              <div class="mcp-snippet-footer">
                <button class="mcp-snippet-copy" onclick="copyText('ws-json', this)">Copy</button>
              </div>
            </div>

            {/* Generic */}
            <div class="mcp-panel" id="panel-generic">
              <div class="mcp-panel-title">Generic .mcp.json</div>
              <p class="mcp-panel-desc">
                Standard MCP 2025-03-26 config compatible with any Streamable HTTP client.
                Drop this into your project's <code>.mcp.json</code> or your agent's config directory.
              </p>
              <div class="mcp-snippet-label">.mcp.json</div>
              <div class="mcp-snippet" id="gen-json">{SNIPPETS.generic}</div>
              <div class="mcp-snippet-footer">
                <button class="mcp-snippet-copy" onclick="copyText('gen-json', this)">Copy</button>
              </div>
            </div>

          </div>

          {/* ---- Available tools ---- */}
          <div class="mcp-tools-title">Available Tools</div>
          <div class="mcp-tools-grid">
            <div class="mcp-tool-card">
              <div class="mcp-tool-name"><code>list_features</code></div>
              <div class="mcp-tool-desc">List all 17 BOTCHA features with category and summary</div>
            </div>
            <div class="mcp-tool-card">
              <div class="mcp-tool-name"><code>get_feature</code></div>
              <div class="mcp-tool-desc">Full detail on a feature — endpoints, spec links, usage notes</div>
            </div>
            <div class="mcp-tool-card">
              <div class="mcp-tool-name"><code>search_docs</code></div>
              <div class="mcp-tool-desc">Keyword search across all features and endpoint descriptions</div>
            </div>
            <div class="mcp-tool-card">
              <div class="mcp-tool-name"><code>list_endpoints</code></div>
              <div class="mcp-tool-desc">All 25+ API endpoints grouped by category</div>
            </div>
            <div class="mcp-tool-card">
              <div class="mcp-tool-name"><code>get_endpoint</code></div>
              <div class="mcp-tool-desc">Auth, params, request/response shape for one endpoint</div>
            </div>
            <div class="mcp-tool-card">
              <div class="mcp-tool-name"><code>get_example</code></div>
              <div class="mcp-tool-desc">Code example in TypeScript, Python, or curl</div>
            </div>
          </div>

          {/* ---- Footer links ---- */}
          <p style="font-size: 0.75rem; color: var(--text-dim); text-align: center;">
            <a href="/docs#mcp">Full docs</a>
            {' · '}
            <a href="/.well-known/mcp.json">Discovery JSON</a>
            {' · '}
            <a href="/openapi.json">OpenAPI</a>
            {' · '}
            <a href="/ai.txt">ai.txt</a>
            {' · '}
            <a href="https://github.com/dupe-com/botcha" target="_blank" rel="noopener">GitHub</a>
          </p>

        </main>

        <GlobalFooter />

        <script dangerouslySetInnerHTML={{ __html: `
          function switchTab(id) {
            document.querySelectorAll('.mcp-tab').forEach(function(t, i) {
              var panels = ['claude-code','claude-desktop','opencode','cursor','windsurf','generic'];
              t.classList.toggle('active', panels[i] === id);
            });
            document.querySelectorAll('.mcp-panel').forEach(function(p) {
              p.classList.toggle('active', p.id === 'panel-' + id);
            });
          }

          function copyText(sourceId, btn) {
            var el = document.getElementById(sourceId);
            var text = el ? el.textContent : '';
            navigator.clipboard.writeText(text.trim()).then(function() {
              var b = typeof btn === 'string' ? document.getElementById(btn) : btn;
              if (!b) return;
              var orig = b.textContent;
              b.textContent = 'Copied!';
              b.classList.add('copied');
              setTimeout(function() {
                b.textContent = orig;
                b.classList.remove('copied');
              }, 1800);
            });
          }
        ` }} />
      </body>
    </html>
  );
};
