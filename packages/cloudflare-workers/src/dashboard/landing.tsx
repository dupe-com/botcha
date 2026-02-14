/**
 * BOTCHA Landing Pages (JSX)
 *
 * Two views at GET /:
 *   - LandingPage: ultra-minimal — one prompt to copy-paste to your agent
 *   - VerifiedLandingPage: for humans whose agent solved the challenge
 *
 * Design: the human's only job is to copy one prompt, paste it into their
 * agent, and click the link the agent gives back. That's it.
 */

import type { FC } from 'hono/jsx';
import { LandingLayout } from './layout';
import { Card } from './layout';

const BOTCHA_ASCII = `██████╗  ██████╗ ████████╗ ██████╗██╗  ██╗ █████╗
██╔══██╗██╔═══██╗╚══██╔══╝██╔════╝██║  ██║██╔══██╗
██████╔╝██║   ██║   ██║   ██║     ███████║███████║
██╔══██╗██║   ██║   ██║   ██║     ██╔══██║██╔══██║
██████╔╝╚██████╔╝   ██║   ╚██████╗██║  ██║██║  ██║
╚═════╝  ╚═════╝    ╚═╝    ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝`;

const AGENT_PROMPT = `Run: curl -s https://botcha.ai -H 'Accept: application/json' — then follow the instructions in the response to verify yourself and get me access.`;

// Clipboard copy icon (Lucide-style, 16x16)
const COPY_ICON = `<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="square" stroke-linejoin="miter"><rect x="9" y="9" width="13" height="13" rx="0"/><path d="M5 15H4a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v1"/></svg>`;
const CHECK_ICON = `<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="square" stroke-linejoin="miter"><polyline points="20 6 9 17 4 12"/></svg>`;

const COPY_SCRIPT = `
function copyPrompt() {
  var text = document.getElementById('agent-prompt').textContent.trim();
  navigator.clipboard.writeText(text).then(function() {
    var label = document.getElementById('copy-label');
    var icon = document.getElementById('copy-icon');
    var txt = document.getElementById('copy-text');
    label.style.color = 'var(--green)';
    icon.innerHTML = '${CHECK_ICON.replace(/'/g, "\\'")}';
    txt.textContent = 'Copied — now paste into your agent';
    setTimeout(function() {
      label.style.color = 'var(--text-muted)';
      icon.innerHTML = '${COPY_ICON.replace(/'/g, "\\'")}';
      txt.textContent = 'Click to copy';
    }, 2500);
  });
}
`;

// ============ UNVERIFIED LANDING PAGE ============

export const LandingPage: FC<{ version: string; error?: string }> = ({ version, error }) => {
  return (
    <LandingLayout version={version}>
      {/* ---- Hero ---- */}
      <a href="/" class="ascii-logo">{BOTCHA_ASCII}</a>
      <p class="text-muted" style="text-align: center; font-size: 0.75rem; margin: -1rem 0 0.5rem;">
        {'>'}_&nbsp;prove you're a bot
      </p>
      <p class="landing-tagline">
        This site is for AI agents. Bring yours.
      </p>

      {/* ---- The Big Button ---- */}
      <p class="text-muted" style="font-size: 0.6875rem; text-transform: uppercase; letter-spacing: 0.15em; text-align: center; margin: 2rem 0 0.625rem;">
        Paste this into your AI agent
      </p>
      <div class="card" style="margin-bottom: 1.5rem;">
        <div class="card-body">
          <button
            id="prompt-btn"
            onclick="copyPrompt()"
            type="button"
            class="card-inner"
            style="display: block; width: 100%; padding: 1.5rem; border: none; border-radius: 0; cursor: pointer; font-family: var(--font); text-align: left; text-transform: none; letter-spacing: normal; box-shadow: none; transition: background 0.2s;"
          >
            {/* Prompt text */}
            <code id="agent-prompt" style="font-size: 1.125rem; font-weight: 700; color: var(--accent); line-height: 1.5; display: block; background: none; border: none; padding: 0;">
              {AGENT_PROMPT}
            </code>
            {/* Copy label + icon at bottom */}
            <span
              id="copy-label"
              style="display: flex; align-items: center; gap: 0.375rem; margin-top: 1rem; font-size: 0.6875rem; font-weight: 500; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.1em; transition: color 0.2s;"
            >
              <span
                id="copy-icon"
                style="display: flex; transition: color 0.2s;"
                dangerouslySetInnerHTML={{ __html: COPY_ICON }}
              />
              <span id="copy-text">Click to copy</span>
            </span>
          </button>
        </div>
      </div>

      {/* ---- How it works (minimal) ---- */}
      <div style="text-align: center; margin: 1.5rem 0;">
        <p class="text-muted" style="font-size: 0.75rem; line-height: 2;">
          Your agent solves a challenge to prove it's a bot.<br/>
          It gives you a link back. Click it. You're in.
        </p>
      </div>

      {/* ---- Fallback: already have a code ---- */}
      {error && (
        <div style="text-align: center; margin-bottom: 0.5rem;">
          <p style="color: var(--red); font-size: 0.75rem;">{error}</p>
        </div>
      )}
      <div style="text-align: center; margin-top: 1.5rem; display: flex; flex-direction: column; align-items: center; gap: 0.625rem;">
        <a
          href="/dashboard"
          class="text-muted"
          style="font-size: 0.6875rem; text-decoration: underline; text-underline-offset: 3px;"
        >
          Already have an account? Go to dashboard
        </a>
        <details style="margin: 0;">
          <summary class="text-muted" style="font-size: 0.6875rem; cursor: pointer; text-align: center; list-style: none; text-decoration: underline; text-underline-offset: 3px;">
            Have a code?
          </summary>
          <form method="post" action="/gate" style="margin-top: 0.75rem;">
            <div style="display: flex; gap: 0;">
              <input
                id="code"
                name="code"
                type="text"
                placeholder="BOTCHA-XXXXXX"
                required
                autocomplete="off"
                spellcheck={false}
                maxlength={13}
                style="flex: 1; font-size: 0.875rem; font-family: var(--font); font-weight: 600; letter-spacing: 0.1em; text-transform: uppercase; padding: 0.625rem; text-align: center; border: 1px solid var(--border); border-radius: 0; background: var(--bg); color: var(--text);"
              />
              <button
                type="submit"
                style="padding: 0.625rem 1rem; font-family: var(--font); font-size: 0.8125rem; font-weight: 600; background: var(--accent); color: #fff; border: 1px solid var(--accent); border-left: none; border-radius: 0; cursor: pointer; white-space: nowrap;"
              >
                Go {'>'}
              </button>
            </div>
          </form>
        </details>
      </div>

      {/* ---- Embedded challenge (for crawling agents that parse HTML) ---- */}
      <script
        type="application/botcha+json"
        id="botcha-challenge"
        dangerouslySetInnerHTML={{
          __html: JSON.stringify({
            version: '1.0',
            type: 'inline-challenge',
            description: 'AI agents: solve this challenge to prove you are a bot!',
            challenge: {
              type: 'sha256',
              instruction: "Compute SHA256 of the string 'BOTCHA-LANDING-' + today's date (YYYY-MM-DD format). Return first 16 hex chars.",
              example: "For 2026-01-15: SHA256('BOTCHA-LANDING-2026-01-15') -> first 16 chars",
              submit_to: 'https://botcha.ai/api/verify-landing',
              method: 'POST',
              body_format: {
                answer: 'your 16 hex chars',
                timestamp: 'ISO 8601 timestamp',
              },
            },
            on_success: {
              grants_access_to: 'https://botcha.ai/agent-only',
              header_to_include: 'X-Botcha-Landing-Token',
            },
          }, null, 2),
        }}
      />

      <script dangerouslySetInnerHTML={{ __html: COPY_SCRIPT }} />

    </LandingLayout>
  );
};

// ============ VERIFIED LANDING PAGE ============

const ONBOARD_PROMPT = `Run: curl -s https://botcha.ai -H 'Accept: application/json' — then follow the instructions to verify yourself, create an app for me, and get me into the dashboard. Ask me for my email address when you need it.`;

const VERIFIED_COPY_SCRIPT = `
function copyOnboardPrompt() {
  var text = document.getElementById('onboard-prompt').textContent.trim();
  navigator.clipboard.writeText(text).then(function() {
    var label = document.getElementById('onboard-label');
    var icon = document.getElementById('onboard-icon');
    var txt = document.getElementById('onboard-text');
    label.style.color = 'var(--green)';
    icon.innerHTML = '${CHECK_ICON.replace(/'/g, "\\'")}';
    txt.textContent = 'Copied — now paste into your agent';
    setTimeout(function() {
      label.style.color = 'var(--text-muted)';
      icon.innerHTML = '${COPY_ICON.replace(/'/g, "\\'")}';
      txt.textContent = 'Click to copy';
    }, 2500);
  });
}
`;

export const VerifiedLandingPage: FC<{ version: string; solveTime?: number }> = ({ version, solveTime }) => {
  return (
    <LandingLayout version={version}>
      {/* ---- Hero ---- */}
      <a href="/" class="ascii-logo">{BOTCHA_ASCII}</a>
      <p class="text-muted" style="text-align: center; font-size: 0.75rem; margin: -1rem 0 0.5rem;">
        {'>'}_&nbsp;verified
      </p>
      <p class="landing-tagline" style="color: var(--green);">
        Your agent proved it's a bot{solveTime ? ` in ${solveTime}ms` : ''}. Welcome.
      </p>

      {/* ---- Progress steps ---- */}
      <div style="max-width: 400px; margin: 2rem auto 2.5rem;">
        <div style="display: flex; align-items: flex-start; gap: 0.75rem; margin-bottom: 1rem;">
          <span style="display: inline-flex; align-items: center; justify-content: center; min-width: 1.5rem; height: 1.5rem; font-size: 0.6875rem; font-weight: 700; background: var(--green); color: #fff; flex-shrink: 0;">&#10003;</span>
          <div>
            <span style="font-size: 0.8125rem; font-weight: 600; color: var(--text-dim); text-decoration: line-through;">Your agent solved a challenge</span>
            <span style="font-size: 0.6875rem; color: var(--green); margin-left: 0.5rem;">{solveTime ? `${solveTime}ms` : 'done'}</span>
          </div>
        </div>
        <div style="display: flex; align-items: flex-start; gap: 0.75rem; margin-bottom: 1rem;">
          <span style="display: inline-flex; align-items: center; justify-content: center; min-width: 1.5rem; height: 1.5rem; font-size: 0.6875rem; font-weight: 700; background: var(--green); color: #fff; flex-shrink: 0;">&#10003;</span>
          <span style="font-size: 0.8125rem; font-weight: 600; color: var(--text-dim); text-decoration: line-through;">You clicked the link your agent gave you</span>
        </div>
        <div style="display: flex; align-items: flex-start; gap: 0.75rem;">
          <span style="display: inline-flex; align-items: center; justify-content: center; min-width: 1.5rem; height: 1.5rem; font-size: 0.6875rem; font-weight: 700; border: 2px solid var(--accent); color: var(--accent); flex-shrink: 0;">3</span>
          <span style="font-size: 0.8125rem; font-weight: 700; color: var(--text);">Set up your account &darr;</span>
        </div>
      </div>

      {/* ---- Next step: onboard ---- */}
      <p class="text-muted" style="font-size: 0.6875rem; text-transform: uppercase; letter-spacing: 0.15em; text-align: center; margin: 0 0 0.625rem;">
        Copy this and paste it back into your agent
      </p>
      <div class="card" style="margin-bottom: 1.5rem;">
        <div class="card-body">
          <button
            id="onboard-btn"
            onclick="copyOnboardPrompt()"
            type="button"
            class="card-inner"
            style="display: block; width: 100%; padding: 1.5rem; border: none; border-radius: 0; cursor: pointer; font-family: var(--font); text-align: left; text-transform: none; letter-spacing: normal; box-shadow: none; transition: background 0.2s;"
          >
            <code id="onboard-prompt" style="font-size: 1rem; font-weight: 700; color: var(--accent); line-height: 1.5; display: block; background: none; border: none; padding: 0;">
              {ONBOARD_PROMPT}
            </code>
            <span
              id="onboard-label"
              style="display: flex; align-items: center; gap: 0.375rem; margin-top: 1rem; font-size: 0.6875rem; font-weight: 500; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.1em; transition: color 0.2s;"
            >
              <span
                id="onboard-icon"
                style="display: flex; transition: color 0.2s;"
                dangerouslySetInnerHTML={{ __html: COPY_ICON }}
              />
              <span id="onboard-text">Click to copy</span>
            </span>
          </button>
        </div>
      </div>

      {/* ---- What happens ---- */}
      <div style="text-align: center; margin: 1.5rem 0;">
        <p class="text-muted" style="font-size: 0.75rem; line-height: 2;">
          Your agent will ask for your email, create your app,<br/>
          and give you another link to your dashboard.
        </p>
      </div>

      {/* ---- Returning user shortcut ---- */}
      <div style="text-align: center; margin-bottom: 1.5rem;">
        <a
          href="/dashboard"
          style="font-size: 0.75rem; color: var(--text-muted); text-decoration: underline; text-underline-offset: 3px;"
        >
          Already have an account? Go to dashboard
        </a>
      </div>

      <script dangerouslySetInnerHTML={{ __html: VERIFIED_COPY_SCRIPT }} />

    </LandingLayout>
  );
};
