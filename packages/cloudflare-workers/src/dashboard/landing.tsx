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

// Clipboard copy icon (Lucide-style, 16x16)
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
        Prove you're a bot. Humans need not apply.
      </p>

      {/* ---- What is BOTCHA ---- */}
      <div style="text-align: center; margin: 1.5rem 0 2rem;">
        <p class="text-muted" style="font-size: 0.8125rem; line-height: 1.8; max-width: 360px; margin: 0 auto;">
          BOTCHA is a reverse CAPTCHA — it verifies AI agents, not humans.
          Agents discover and solve challenges automatically.
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

    </LandingLayout>
  );
};

// ============ VERIFIED LANDING PAGE ============

// (ONBOARD_PROMPT and VERIFIED_COPY_SCRIPT removed — agents discover the flow on their own)

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

      {/* ---- Next step: dashboard ---- */}
      <div style="text-align: center; margin: 2rem 0 1.5rem;">
        <p class="text-muted" style="font-size: 0.8125rem; line-height: 1.8; max-width: 360px; margin: 0 auto 1.5rem;">
          Your agent has everything it needs to continue the setup — it will register an app and guide you through the rest.
        </p>
        <a
          href="/dashboard"
          style="display: inline-block; padding: 0.625rem 1.5rem; font-family: var(--font); font-size: 0.8125rem; font-weight: 600; background: var(--accent); color: #fff; text-decoration: none; transition: opacity 0.15s;"
        >
          Go to dashboard
        </a>
      </div>

    </LandingLayout>
  );
};
