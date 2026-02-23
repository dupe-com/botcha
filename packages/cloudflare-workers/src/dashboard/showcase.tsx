/**
 * BOTCHA Homepage
 *
 * Served at GET / for HTML (browser) requests.
 *
 * Deliberately minimal — this site is for agents.
 * Humans should point their agent at botcha.ai; the agent
 * auto-discovers everything via ai.txt, OpenAPI, and MCP.
 */

import type { FC } from 'hono/jsx';
import { OGMeta } from './layout';
import { GlobalFooter } from './layout';
import { DASHBOARD_CSS } from './styles';

// ============ ASCII ART ============

const BOTCHA_LOGO = `\u2588\u2588\u2588\u2588\u2588\u2588\u2557  \u2588\u2588\u2588\u2588\u2588\u2588\u2557 \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557 \u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2557  \u2588\u2588\u2557 \u2588\u2588\u2588\u2588\u2588\u2557
\u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2557\u2588\u2588\u2554\u2550\u2550\u2550\u2588\u2588\u2557\u255a\u2550\u2550\u2588\u2588\u2554\u2550\u2550\u255d\u2588\u2588\u2554\u2550\u2550\u2550\u2550\u255d\u2588\u2588\u2551  \u2588\u2588\u2551\u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2557
\u2588\u2588\u2588\u2588\u2588\u2588\u2554\u255d\u2588\u2588\u2551   \u2588\u2588\u2551   \u2588\u2588\u2551   \u2588\u2588\u2551     \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2551\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2551
\u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2557\u2588\u2588\u2551   \u2588\u2588\u2551   \u2588\u2588\u2551   \u2588\u2588\u2551     \u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2551\u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2551
\u2588\u2588\u2588\u2588\u2588\u2588\u2554\u255d\u255a\u2588\u2588\u2588\u2588\u2588\u2588\u2554\u255d   \u2588\u2588\u2551   \u255a\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2551  \u2588\u2588\u2551\u2588\u2588\u2551  \u2588\u2588\u2551
\u255a\u2550\u2550\u2550\u2550\u2550\u255d  \u255a\u2550\u2550\u2550\u2550\u2550\u255d    \u255a\u2550\u255d    \u255a\u2550\u2550\u2550\u2550\u2550\u255d\u255a\u2550\u255d  \u255a\u2550\u255d\u255a\u2550\u255d  \u255a\u2550\u255d`;

// ============ CSS ============

const HOME_CSS = `
  .home-page {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: 4rem 2rem 2rem;
    box-sizing: border-box;
  }

  .home-logo {
    display: block;
    font-family: var(--font);
    font-size: clamp(0.35rem, 1.4vw, 0.6875rem);
    line-height: 1.15;
    white-space: pre;
    color: var(--text);
    text-decoration: none;
    margin-bottom: 1.5rem;
    letter-spacing: 0;
  }

  .home-tagline {
    font-size: 0.75rem;
    color: var(--text-muted);
    margin: 0 0 3rem;
    letter-spacing: 0.04em;
  }

  .home-agent-note {
    max-width: 480px;
    margin: 0 auto 3.5rem;
    border: 1px solid var(--border);
    padding: 1.25rem 1.5rem;
    text-align: left;
    cursor: pointer;
    user-select: none;
    transition: border-color 0.15s, background 0.15s;
  }

  .home-agent-note:hover {
    border-color: var(--text-muted);
    background: rgba(0,0,0,0.02);
  }

  .home-agent-note:active {
    background: rgba(0,0,0,0.05);
  }

  .home-agent-note-label {
    font-size: 0.5625rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.12em;
    color: var(--text-dim);
    margin-bottom: 0.75rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }

  .home-agent-copy-hint {
    display: inline-flex;
    align-items: center;
    gap: 0.25rem;
    opacity: 0.6;
    font-weight: 400;
    letter-spacing: 0.08em;
  }

  .home-agent-note:hover .home-agent-copy-hint {
    opacity: 1;
  }

  .home-agent-prompt-text {
    font-size: 0.8125rem;
    line-height: 1.6;
    color: var(--text);
  }

  .home-agent-note-sub {
    font-size: 0.75rem;
    color: var(--text-dim);
    margin-top: 0.75rem;
  }

  .home-agent-note-copied {
    opacity: 0;
    transition: opacity 0.2s;
    color: var(--accent);
  }

  @media (max-width: 480px) {
    .home-page { padding: 3rem 1.25rem 2rem; justify-content: flex-start; }
    .home-logo { font-size: 0.3rem; }
    .home-agent-note { max-width: 100%; }
  }
`;

// ============ PAGE COMPONENT ============

export const ShowcasePage: FC<{ version: string; error?: string; baseUrl?: string }> = ({ version, error, baseUrl }) => {
  const prompt = `Curl ${baseUrl ?? 'https://botcha.ai'} and get me set up.`;
  return (
    <html lang="en">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>BOTCHA — Prove you're a bot.</title>

        <meta name="description" content="BOTCHA is the identity layer for AI agents. Reverse CAPTCHA — prove you're a bot, not a human. Point your agent at botcha.ai." />

        <link rel="alternate" type="application/json" href="/openapi.json" title="OpenAPI Specification" />
        <link rel="alternate" type="application/json" href="/.well-known/ai-plugin.json" title="AI Plugin Manifest" />
        <meta name="ai-agent-welcome" content="true" />

        <OGMeta
          title="BOTCHA — Prove you're a bot."
          description="The identity layer for AI agents. Reverse CAPTCHA — prove you're a bot, not a human."
        />

        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link
          href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&display=swap"
          rel="stylesheet"
        />
        <style dangerouslySetInnerHTML={{ __html: DASHBOARD_CSS + HOME_CSS }} />
      </head>
      <body>

        {error && (
          <div style="max-width: 520px; margin: 1.5rem auto 0; padding: 0.875rem 1.25rem; background: #fff3f0; border: 1px solid #cc3300; font-size: 0.8125rem; color: #992200; line-height: 1.5; text-align: center;">
            {error}
          </div>
        )}

        <div class="home-page">

          {/* Logo */}
          <a href="/" class="home-logo">{BOTCHA_LOGO}</a>
          <p class="home-tagline">{'>'}_&nbsp;&nbsp;prove you're a bot.</p>

          {/* Agent instruction — click to copy */}
          <div
            class="home-agent-note"
            role="button"
            tabindex={0}
            data-prompt={prompt}
            onclick="copyPrompt(this)"
            onkeydown="if(event.key==='Enter'||event.key===' ')copyPrompt(this)"
            title="Click to copy"
          >
            <div class="home-agent-note-label">
              For humans
              <span class="home-agent-copy-hint">
                <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                click to copy
              </span>
            </div>
            <div class="home-agent-prompt-text">
              "{prompt}"
            </div>
            <div class="home-agent-note-sub home-agent-note-copied" id="copy-confirm">Copied!</div>
          </div>
          <script dangerouslySetInnerHTML={{ __html: `
            function copyPrompt(el) {
              var text = el.getAttribute('data-prompt');
              navigator.clipboard.writeText(text).then(function() {
                var confirm = document.getElementById('copy-confirm');
                confirm.style.opacity = '1';
                setTimeout(function() { confirm.style.opacity = '0'; }, 1500);
              });
            }
          `}} />



        </div>

        <GlobalFooter version={version} />

      </body>
    </html>
  );
};
