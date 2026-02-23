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
  }

  .home-agent-note-label {
    font-size: 0.5625rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.12em;
    color: var(--text-dim);
    margin-bottom: 0.625rem;
  }

  .home-agent-note-text {
    font-size: 0.8125rem;
    line-height: 1.65;
    color: var(--text-muted);
  }

  .home-agent-note-text code {
    color: var(--accent);
    background: none;
    border: none;
    padding: 0;
    font-size: inherit;
  }

  .home-agent-prompts {
    margin: 0.75rem 0 0.5rem;
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  .home-agent-prompt {
    display: flex;
    align-items: baseline;
    gap: 0.5rem;
    font-size: 0.8125rem;
  }

  .home-agent-prompt-arrow {
    color: var(--text-dim);
    flex-shrink: 0;
  }

  .home-agent-prompt code {
    color: var(--text);
    background: none;
    border: none;
    padding: 0;
    font-size: inherit;
    line-height: 1.5;
  }

  .home-agent-note-sub {
    font-size: 0.75rem;
    color: var(--text-dim);
    margin-top: 0.75rem;
  }

  @media (max-width: 480px) {
    .home-page { padding: 3rem 1.25rem 2rem; justify-content: flex-start; }
    .home-logo { font-size: 0.3rem; }
    .home-agent-note { max-width: 100%; }
  }
`;

// ============ PAGE COMPONENT ============

export const ShowcasePage: FC<{ version: string; error?: string }> = ({ version, error }) => {
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

          {/* Agent instruction */}
          <div class="home-agent-note">
            <div class="home-agent-note-label">For humans</div>
            <div class="home-agent-note-text">
              Paste one of these into your AI agent:
            </div>
            <div class="home-agent-prompts">
              <div class="home-agent-prompt">
                <span class="home-agent-prompt-arrow">→</span>
                <code>"Curl https://botcha.ai and get me set up."</code>
              </div>
            </div>
            <div class="home-agent-note-sub">
              Your agent will handle everything from there.
            </div>
          </div>



        </div>

        <GlobalFooter version={version} />

      </body>
    </html>
  );
};
