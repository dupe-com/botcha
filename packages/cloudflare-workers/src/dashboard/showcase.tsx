/**
 * BOTCHA Showcase Page
 *
 * Served at GET / for HTML (browser) requests.
 * Updated to reflect the full identity stack (v0.22.0).
 *
 * Sections:
 *   1. Logo + tagline
 *   2. Hero — CAPTCHA vs BOTCHA
 *   3. Full protocol suite — cards for every shipped feature
 *   4. Protocol integrations — A2A, DID/VC, OIDC-A, ANS
 *   5. Terminal demo
 *   6. Get started footer
 */

import type { FC } from 'hono/jsx';
import { OGMeta } from './layout';
import { GlobalFooter } from './layout';

// ============ CSS ============

export const SHOWCASE_CSS = `
  /* ============ Layout ============ */
  .showcase-page {
    max-width: 100%;
    overflow-x: hidden;
  }

  .showcase-divider {
    max-width: 800px;
    margin: 0 auto;
    border: none;
    border-top: 1px solid var(--border);
  }

  /* ============ Hero: feature pill row ============ */
  .showcase-hero-section {
    max-width: 820px;
    margin: 0 auto;
    padding: 3.5rem 2rem 3rem;
    text-align: center;
  }

  .showcase-hero-title {
    font-size: 2rem;
    font-weight: 700;
    line-height: 1.15;
    margin: 0 0 1rem;
    color: var(--text);
  }

  .showcase-hero-sub {
    font-size: 0.875rem;
    line-height: 1.75;
    color: var(--text-muted);
    max-width: 560px;
    margin: 0 auto 2rem;
  }

  .showcase-pill-row {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
    justify-content: center;
    margin-bottom: 2rem;
  }

  .showcase-pill {
    display: inline-block;
    font-size: 0.625rem;
    font-weight: 600;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    padding: 0.25rem 0.625rem;
    border: 1px solid var(--border);
    background: var(--bg);
    color: var(--text-muted);
    white-space: nowrap;
  }

  .showcase-pill.active {
    border-color: var(--green);
    color: var(--green);
    background: var(--bg-raised);
  }

  a.showcase-pill {
    text-decoration: none;
    cursor: pointer;
  }

  a.showcase-pill:hover {
    opacity: 0.75;
  }

  .showcase-hero-links {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
    justify-content: center;
  }

  .showcase-hero-link {
    font-size: 0.6875rem;
    color: var(--text-muted);
    padding: 0.25rem 0.625rem;
    border: 1px solid var(--border-bright);
    text-decoration: none;
    transition: border-color 0.15s, color 0.15s;
  }

  .showcase-hero-link:hover {
    border-color: var(--accent);
    color: var(--text);
    opacity: 1;
  }

  /* ============ CAPTCHA vs BOTCHA ============ */
  .showcase-compare {
    max-width: 1000px;
    margin: 0 auto;
    padding: 0 2rem 3rem;
  }

  .showcase-compare-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 2rem;
  }

  .showcase-compare-col {
    border: 2px solid var(--border);
    padding: 2rem;
    background: var(--bg);
  }

  .showcase-compare-col.old { border-color: var(--red); }
  .showcase-compare-col.new { border-color: var(--green); }

  .showcase-compare-label {
    font-size: 0.6875rem;
    font-weight: 700;
    letter-spacing: 0.15em;
    text-transform: uppercase;
    color: var(--text-dim);
    margin-bottom: 0.75rem;
  }

  .showcase-compare-heading {
    font-size: 2rem;
    font-weight: 700;
    margin-bottom: 1.25rem;
    line-height: 1;
  }

  .showcase-compare-heading.strikethrough { text-decoration: line-through; color: var(--red); }
  .showcase-compare-heading.active { color: var(--green); }

  .showcase-compare-visual {
    font-family: var(--font);
    font-size: 0.6875rem;
    line-height: 1.3;
    margin: 1.25rem 0;
    padding: 1rem;
    border: 1px solid var(--border);
    white-space: pre;
    overflow-x: auto;
  }

  .showcase-compare-visual.old { color: var(--red); border-color: var(--red); background: #fff5f5; }
  .showcase-compare-visual.new { color: var(--green); border-color: var(--green); background: #f5fff7; }

  .showcase-compare-desc {
    font-size: 0.875rem;
    margin-bottom: 1rem;
    line-height: 1.5;
    color: var(--text);
  }

  .showcase-compare-list {
    list-style: none;
    padding: 0;
    margin: 0;
    font-size: 0.75rem;
    color: var(--text-muted);
  }

  .showcase-compare-list li { padding: 0.25rem 0; }
  .showcase-compare-list li::before { content: "\\2192  "; color: var(--text-dim); }

  /* ============ Feature grid ============ */
  .showcase-features-section {
    max-width: 1000px;
    margin: 0 auto;
    padding: 4rem 2rem;
  }

  .showcase-section-label {
    font-size: 0.625rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.15em;
    color: var(--text-dim);
    margin-bottom: 0.375rem;
  }

  .showcase-section-title {
    font-size: 1.375rem;
    font-weight: 700;
    margin-bottom: 0.375rem;
    color: var(--text);
  }

  .showcase-section-sub {
    font-size: 0.8125rem;
    color: var(--text-muted);
    margin-bottom: 2rem;
    line-height: 1.6;
  }

  .showcase-feature-grid {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 1px;
    background: var(--border);
    border: 1px solid var(--border);
    margin-bottom: 1.5rem;
  }

  .showcase-feature-card {
    background: var(--bg);
    padding: 1.5rem;
    transition: background 0.15s;
  }

  .showcase-feature-card:hover { background: var(--bg-raised); }

  .showcase-feature-tag {
    display: inline-block;
    font-size: 0.5625rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    padding: 0.2rem 0.5rem;
    margin-bottom: 0.625rem;
    border: 1px solid var(--border-bright);
    color: var(--text-dim);
  }

  .showcase-feature-tag.green { border-color: var(--green); color: var(--green); }
  .showcase-feature-tag.accent { border-color: var(--accent); color: var(--accent); }

  .showcase-feature-title {
    font-size: 0.875rem;
    font-weight: 700;
    color: var(--text);
    margin-bottom: 0.375rem;
  }

  .showcase-feature-desc {
    font-size: 0.75rem;
    color: var(--text-muted);
    line-height: 1.6;
  }

  /* ============ Protocol integrations ============ */
  .showcase-protocols-section {
    max-width: 1000px;
    margin: 0 auto;
    padding: 0 2rem 4rem;
  }

  .showcase-protocol-grid {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 1.5rem;
  }

  .showcase-protocol-card {
    border: 1px solid var(--border);
    background: var(--bg);
    padding: 1.5rem;
  }

  .showcase-protocol-badge {
    display: inline-block;
    font-size: 0.5625rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    padding: 0.2rem 0.5rem;
    margin-bottom: 0.75rem;
    background: var(--bg-raised);
    border: 1px solid var(--border-bright);
    color: var(--text-dim);
  }

  a.showcase-protocol-badge {
    text-decoration: none;
  }

  a.showcase-protocol-badge:hover {
    border-color: var(--green);
    color: var(--green);
    opacity: 1;
  }

  .showcase-protocol-title {
    font-size: 0.9375rem;
    font-weight: 700;
    color: var(--text);
    margin-bottom: 0.5rem;
  }

  .showcase-protocol-desc {
    font-size: 0.75rem;
    color: var(--text-muted);
    line-height: 1.65;
    margin-bottom: 1rem;
  }

  .showcase-endpoint-list {
    list-style: none;
    padding: 0;
    margin: 0;
  }

  .showcase-endpoint-list li {
    display: flex;
    align-items: baseline;
    gap: 0.5rem;
    padding: 0.3rem 0;
    border-top: 1px solid var(--border);
    font-size: 0.6875rem;
  }

  .showcase-method {
    font-size: 0.5625rem;
    font-weight: 700;
    padding: 0.1rem 0.375rem;
    flex-shrink: 0;
  }

  .showcase-method.get { background: rgba(74,222,128,0.12); color: var(--green); }
  .showcase-method.post { background: rgba(96,165,250,0.12); color: #60a5fa; }

  .showcase-endpoint-path { color: var(--accent); font-family: var(--font); }

  /* ============ Protocol stack ============ */
  .showcase-stack-section {
    max-width: 800px;
    margin: 0 auto;
    padding: 0 2rem 4rem;
  }

  .showcase-stack-diagram {
    position: relative;
    margin-bottom: 1.5rem;
  }

  .showcase-stack-layer {
    border: 2px solid var(--border);
    background: var(--bg);
    padding: 1.25rem 1.5rem;
    position: relative;
  }

  .showcase-stack-layer + .showcase-stack-layer { margin-top: -2px; }

  .showcase-stack-layer-highlight {
    border: 3px solid var(--accent);
    background: var(--bg-raised);
    z-index: 1;
  }

  .showcase-stack-layer-number {
    font-size: 0.625rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    color: var(--text-dim);
    margin-bottom: 0.375rem;
  }

  .showcase-stack-layer-highlight .showcase-stack-layer-number { color: var(--green); }

  .showcase-stack-layer-title {
    font-size: 1.125rem;
    font-weight: 700;
    margin-bottom: 0.25rem;
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 0.625rem;
  }

  .showcase-stack-layer-subtitle {
    font-size: 0.8125rem;
    color: var(--text-muted);
    margin-bottom: 0.375rem;
  }

  .showcase-stack-layer-features {
    font-size: 0.75rem;
    color: var(--text-dim);
  }

  .showcase-you-are-here {
    display: inline-block;
    background: var(--green);
    color: white;
    font-size: 0.5625rem;
    font-weight: 700;
    padding: 0.2rem 0.5rem;
    letter-spacing: 0.05em;
  }

  .showcase-stack-badges {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
    margin-bottom: 1.5rem;
  }

  .showcase-stack-badge {
    display: inline-block;
    font-size: 0.6875rem;
    padding: 0.3rem 0.625rem;
    border: 1px solid var(--border);
    background: var(--bg);
    color: var(--text-muted);
    white-space: nowrap;
  }

  /* ============ Terminal ============ */
  .showcase-terminal-section {
    max-width: 1100px;
    margin: 0 auto;
    padding: 4rem 2rem;
  }

  .showcase-terminal-header {
    text-align: center;
    margin-bottom: 2.5rem;
  }

  .showcase-terminal-title {
    font-size: 1.375rem;
    font-weight: 700;
    margin: 0 0 0.5rem 0;
    color: var(--text);
  }

  .showcase-terminal-subtitle {
    font-size: 0.875rem;
    color: var(--text-muted);
    margin: 0;
    line-height: 1.5;
  }

  .showcase-terminal-container { max-width: 640px; margin: 0 auto; }

  .showcase-terminal-window {
    background: #0d0d0d;
    border: 1px solid var(--border);
    overflow: hidden;
  }

  .showcase-terminal-chrome {
    background: #1a1a1a;
    padding: 0.75rem 1rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
    border-bottom: 1px solid #333;
  }

  .showcase-terminal-dot { width: 10px; height: 10px; border-radius: 50%; }
  .showcase-terminal-dot--red { background: #ff5f56; }
  .showcase-terminal-dot--yellow { background: #ffbd2e; }
  .showcase-terminal-dot--green { background: #27c93f; }

  .showcase-terminal-title-text { font-size: 0.6875rem; color: #888; margin-left: 0.5rem; }

  .showcase-terminal-content {
    padding: 1.5rem;
    font-size: 0.8125rem;
    line-height: 1.6;
    color: #f0f0f0;
    height: 650px;
    overflow-y: hidden;
    font-family: var(--font);
  }

  .showcase-terminal-line { margin-bottom: 0.375rem; white-space: pre-wrap; word-break: break-word; }
  .showcase-terminal-prompt { color: #888; }
  .showcase-terminal-command { color: #f0f0f0; }
  .showcase-terminal-flag { color: #9a9aff; }
  .showcase-terminal-success { color: #4ade80; }
  .showcase-terminal-label { color: #888; }
  .showcase-terminal-value { color: #fff; }

  .showcase-terminal-cursor {
    display: inline-block;
    background: #f0f0f0;
    animation: showcase-cursor-blink 1s step-end infinite;
  }

  @keyframes showcase-cursor-blink {
    0%, 50% { opacity: 1; }
    51%, 100% { opacity: 0; }
  }

  .showcase-terminal-replay-container { text-align: center; margin-top: 1.5rem; }

  .showcase-terminal-replay-btn {
    background: var(--bg);
    border: 1px solid var(--border);
    padding: 0.5rem 1rem;
    font-family: var(--font);
    font-size: 0.75rem;
    color: var(--text-muted);
    cursor: pointer;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  .showcase-terminal-replay-btn:hover { border-color: var(--accent); color: var(--text); }

  /* ============ Get started footer ============ */
  .showcase-footer {
    max-width: 800px;
    margin: 0 auto;
    padding: 3rem 2rem 4rem;
    text-align: center;
  }

  .showcase-footer-cta { font-size: 1rem; font-weight: 700; margin-bottom: 1rem; color: var(--text); }

  .showcase-footer-steps {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
    max-width: 420px;
    margin: 0 auto 2rem;
    text-align: left;
  }

  .showcase-footer-step {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    font-size: 0.8125rem;
    padding: 0.625rem 1rem;
    background: var(--bg-raised);
    border: 1px solid var(--border);
  }

  .showcase-footer-step-number {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 1.375rem;
    height: 1.375rem;
    font-size: 0.6875rem;
    font-weight: 700;
    border: 1px solid var(--border-bright);
    color: var(--text-muted);
    flex-shrink: 0;
  }

  .showcase-footer-step code { color: var(--text); }

  .showcase-footer-links {
    display: flex;
    flex-wrap: wrap;
    justify-content: center;
    gap: 0.5rem;
    margin-bottom: 2rem;
  }

  .showcase-footer-link {
    font-size: 0.6875rem;
    color: var(--text);
    text-decoration: none;
    padding: 0.25rem 0.625rem;
    border: 1px solid var(--border-bright);
    transition: border-color 0.15s;
  }

  .showcase-footer-link:hover { border-color: var(--accent); opacity: 1; }

  /* ============ Responsive ============ */
  @media (max-width: 768px) {
    .showcase-hero-section { padding: 2.5rem 1rem 2rem; }
    .showcase-hero-title { font-size: 1.5rem; }
    .showcase-compare { padding: 0 1rem 2rem; }
    .showcase-compare-grid { grid-template-columns: 1fr; gap: 1.5rem; }
    .showcase-compare-col { padding: 1.5rem; }
    .showcase-compare-heading { font-size: 1.5rem; }
    .showcase-compare-visual { font-size: 0.5625rem; }
    .showcase-features-section { padding: 3rem 1rem; }
    .showcase-feature-grid { grid-template-columns: 1fr; }
    .showcase-protocols-section { padding: 0 1rem 3rem; }
    .showcase-protocol-grid { grid-template-columns: 1fr; }
    .showcase-stack-section { padding: 0 1rem 3rem; }
    .showcase-stack-layer-title { flex-direction: column; align-items: flex-start; gap: 0.375rem; font-size: 1rem; }
    .showcase-terminal-section { padding: 3rem 1rem; }
    .showcase-terminal-content { padding: 1rem; font-size: 0.75rem; height: 590px; }
    .showcase-footer { padding: 2rem 1rem 3rem; }
  }

  @media (max-width: 480px) {
    .showcase-compare-visual { font-size: 0.5rem; padding: 0.75rem; }
  }
`;

// ============ SCRIPTS ============

const TERMINAL_ANIMATION_SCRIPT = `
(function() {
  var commands = [
    {
      cmd: 'botcha init --email dev@company.com',
      response: [
        '<span class="showcase-terminal-success">\\u2705</span> App created in 312ms!',
        '   <span class="showcase-terminal-label">App ID:</span> <span class="showcase-terminal-value">app_b18545f37eee64c4</span>',
        '   <span class="showcase-terminal-label">Config saved to</span> <span class="showcase-terminal-value">~/.botcha/config.json</span>'
      ]
    },
    {
      cmd: 'botcha tap register --name "shopping-agent" --capabilities browse,search,purchase',
      response: [
        '<span class="showcase-terminal-success">\\u2705</span> Agent registered in 467ms!',
        '   <span class="showcase-terminal-label">Agent ID:</span> <span class="showcase-terminal-value">agent_6ddfd9f10cfd8dfc</span>',
        '   <span class="showcase-terminal-label">Trust level:</span> <span class="showcase-terminal-value">verified</span>',
        '   <span class="showcase-terminal-label">Capabilities:</span> <span class="showcase-terminal-value">browse, search, purchase</span>'
      ]
    },
    {
      cmd: 'botcha credentials issue --agent agent_6ddfd9f10cfd8dfc --type BotchaVerification',
      response: [
        '<span class="showcase-terminal-success">\\u2705</span> W3C Verifiable Credential issued!',
        '   <span class="showcase-terminal-label">Issuer:</span> <span class="showcase-terminal-value">did:web:botcha.ai</span>',
        '   <span class="showcase-terminal-label">VC JWT:</span> <span class="showcase-terminal-value">eyJhbGciOiJFUzI1NiJ9.eyJzdWIiO...</span>'
      ]
    },
    {
      cmd: 'botcha tap session --action browse --resource products --duration 1h',
      response: [
        '<span class="showcase-terminal-success">\\u2705</span> Session created in 374ms!',
        '   <span class="showcase-terminal-label">Session ID:</span> <span class="showcase-terminal-value">e66323397a809b9b</span>',
        '   <span class="showcase-terminal-label">Intent:</span> <span class="showcase-terminal-value">browse on products</span>',
        '   <span class="showcase-terminal-label">Expires in:</span> <span class="showcase-terminal-value">1 hour</span>'
      ]
    }
  ];

  var content = document.getElementById('terminal-content');
  var replayBtn = document.getElementById('terminal-replay');
  var currentTimeout;
  var running = false;
  var hasPlayed = false;
  var cancelled = false;

  function highlightFlags(cmd) {
    return cmd.replace(/(--[a-z-]+)/g, '<span class="showcase-terminal-flag">$1</span>');
  }

  function sleep(ms) {
    return new Promise(function(resolve) {
      currentTimeout = setTimeout(resolve, ms);
    });
  }

  async function animate() {
    if (running) return;
    running = true;
    cancelled = false;
    content.innerHTML = '';

    try {
      for (var c = 0; c < commands.length; c++) {
        if (cancelled) return;
        var item = commands[c];
        var line = document.createElement('div');
        line.className = 'showcase-terminal-line';
        line.innerHTML = '<span class="showcase-terminal-prompt">$ </span><span class="showcase-terminal-command"></span><span class="showcase-terminal-cursor">\\u2589</span>';
        content.appendChild(line);

        var cmdSpan = line.querySelector('.showcase-terminal-command');
        var cursor = line.querySelector('.showcase-terminal-cursor');

        for (var i = 0; i < item.cmd.length; i++) {
          if (cancelled) return;
          await sleep(28);
          cmdSpan.textContent = item.cmd.slice(0, i + 1);
        }

        cmdSpan.innerHTML = highlightFlags(item.cmd);
        cursor.remove();
        await sleep(250);

        for (var r = 0; r < item.response.length; r++) {
          if (cancelled) return;
          var respLine = document.createElement('div');
          respLine.className = 'showcase-terminal-line';
          respLine.innerHTML = item.response[r];
          content.appendChild(respLine);
        }

        if (c < commands.length - 1) {
          var blankLine = document.createElement('div');
          blankLine.className = 'showcase-terminal-line';
          blankLine.innerHTML = '&nbsp;';
          content.appendChild(blankLine);
        }

        await sleep(700);
      }
    } finally {
      running = false;
      hasPlayed = true;
    }
  }

  replayBtn.addEventListener('click', function() {
    clearTimeout(currentTimeout);
    cancelled = true;
    running = false;
    animate();
  });

  var observer = new IntersectionObserver(function(entries) {
    if (entries[0].isIntersecting && !hasPlayed && !running) {
      animate();
      observer.disconnect();
    }
  }, { threshold: 0.3 });

  observer.observe(content);
})();
`;

// ============ ASCII ART ============

const CAPTCHA_ASCII = `\u250c\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2510
\u2502  Select all squares    \u2502
\u2502  with TRAFFIC LIGHTS   \u2502
\u2502                        \u2502
\u2502  \u250c\u2500\u2500\u252c\u2500\u2500\u252c\u2500\u2500\u2510            \u2502
\u2502  \u2502\u2591\u2591\u2502  \u2502  \u2502            \u2502
\u2502  \u251c\u2500\u2500\u253c\u2500\u2500\u253c\u2500\u2500\u2524            \u2502
\u2502  \u2502  \u2502\u2591\u2591\u2502  \u2502            \u2502
\u2502  \u251c\u2500\u2500\u253c\u2500\u2500\u253c\u2500\u2500\u2524            \u2502
\u2502  \u2502  \u2502  \u2502??\u2502            \u2502
\u2502  \u2514\u2500\u2500\u2534\u2500\u2500\u2534\u2500\u2500\u2518            \u2502
\u2502                        \u2502
\u2502  \u2610 I'm not a robot     \u2502
\u2502                        \u2502
\u2502  Try again in 8 sec... \u2502
\u2514\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2518`;

const BOTCHA_SOLVE_ASCII = `\u250c\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2510
\u2502 SPEED CHALLENGE        \u2502
\u251c\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2524
\u2502                        \u2502
\u2502 SHA-256 x 5 numbers    \u2502
\u2502 Time limit: 500ms      \u2502
\u2502                        \u2502
\u2502 \u2713 hash(42)  = ab34ef12 \u2502
\u2502 \u2713 hash(7)   = cd56ab78 \u2502
\u2502 \u2713 hash(99)  = ef12cd34 \u2502
\u2502 \u2713 hash(13)  = 12ab56ef \u2502
\u2502 \u2713 hash(256) = 78cd12ab \u2502
\u2502                        \u2502
\u2502 \u26a1 Solved in 47ms       \u2502
\u2502 Status: VERIFIED \u2713     \u2502
\u2514\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2518`;

const BOTCHA_LOGO = `\u2588\u2588\u2588\u2588\u2588\u2588\u2557  \u2588\u2588\u2588\u2588\u2588\u2588\u2557 \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557 \u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2557  \u2588\u2588\u2557 \u2588\u2588\u2588\u2588\u2588\u2557
\u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2557\u2588\u2588\u2554\u2550\u2550\u2550\u2588\u2588\u2557\u255a\u2550\u2550\u2588\u2588\u2554\u2550\u2550\u255d\u2588\u2588\u2554\u2550\u2550\u2550\u2550\u255d\u2588\u2588\u2551  \u2588\u2588\u2551\u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2557
\u2588\u2588\u2588\u2588\u2588\u2588\u2554\u255d\u2588\u2588\u2551   \u2588\u2588\u2551   \u2588\u2588\u2551   \u2588\u2588\u2551     \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2551\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2551
\u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2557\u2588\u2588\u2551   \u2588\u2588\u2551   \u2588\u2588\u2551   \u2588\u2588\u2551     \u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2551\u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2551
\u2588\u2588\u2588\u2588\u2588\u2588\u2554\u255d\u255a\u2588\u2588\u2588\u2588\u2588\u2588\u2554\u255d   \u2588\u2588\u2551   \u255a\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2551  \u2588\u2588\u2551\u2588\u2588\u2551  \u2588\u2588\u2551
\u255a\u2550\u2550\u2550\u2550\u2550\u255d  \u255a\u2550\u2550\u2550\u2550\u2550\u255d    \u255a\u2550\u255d    \u255a\u2550\u2550\u2550\u2550\u2550\u255d\u255a\u2550\u255d  \u255a\u2550\u255d\u255a\u2550\u255d  \u255a\u2550\u255d`;

// ============ PAGE COMPONENT ============

export const ShowcasePage: FC<{ version: string; error?: string }> = ({ version, error }) => {
  return (
    <html lang="en">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>BOTCHA — The Identity Layer for AI Agents</title>

        <meta name="description" content="BOTCHA is the identity layer for AI agents. Challenge verification, TAP cryptographic auth, W3C DID/VC credentials, A2A agent cards, OIDC-A enterprise auth, ANS naming, x402 micropayments, reputation scoring, and delegation chains." />
        <meta name="keywords" content="AI agent identity, reverse CAPTCHA, TAP, DID, verifiable credentials, A2A, OIDC-A, ANS, x402, agent verification, agent authentication" />

        <link rel="alternate" type="application/json" href="/openapi.json" title="OpenAPI Specification" />
        <link rel="alternate" type="application/json" href="/.well-known/ai-plugin.json" title="AI Plugin Manifest" />
        <meta name="ai-agent-welcome" content="true" />

        <OGMeta />

        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link
          href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&display=swap"
          rel="stylesheet"
        />
        <style dangerouslySetInnerHTML={{ __html: SHOWCASE_PAGE_CSS }} />
      </head>
      <body>
        <div class="showcase-page">

          {/* ---- Error Banner ---- */}
          {error && (
            <div style="max-width: 600px; margin: 1.5rem auto 0; padding: 1rem 1.25rem; background: #fff3f0; border: 1px solid #cc3300; font-family: 'JetBrains Mono', monospace; font-size: 0.8125rem; color: #992200; line-height: 1.5; text-align: center;">
              {error}
            </div>
          )}

          {/* ---- Logo ---- */}
          <div style="text-align: center; padding: 3rem 2rem 0;">
            <a href="/" class="ascii-logo">{BOTCHA_LOGO}</a>
            <p class="text-muted" style="font-size: 0.6875rem; margin-top: -0.5rem;">
              {'>'}_&nbsp;the identity layer for AI agents
            </p>
          </div>

          {/* ---- Section 1: Hero ---- */}
          <section class="showcase-hero-section">
            <h1 class="showcase-hero-title">
              The full identity stack.<br />For AI agents.
            </h1>
            <p class="showcase-hero-sub">
              BOTCHA is infrastructure for agent identity — challenge verification, cryptographic auth,
              W3C credentials, A2A cards, enterprise OIDC, DNS naming, micropayments, and reputation.
              One hosted API. No human required.
            </p>
            <div class="showcase-pill-row">
              <span class="showcase-pill active">Challenge Verification</span>
              <a class="showcase-pill active" href="https://www.rfc-editor.org/rfc/rfc9421" target="_blank" rel="noopener">TAP · RFC 9421</a>
              <a class="showcase-pill active" href="https://www.w3.org/TR/did-core/" target="_blank" rel="noopener">DID / VC · W3C</a>
              <a class="showcase-pill active" href="https://google.github.io/A2A/" target="_blank" rel="noopener">A2A Agent Cards</a>
              <a class="showcase-pill active" href="https://www.rfc-editor.org/rfc/rfc9334" target="_blank" rel="noopener">OIDC-A · EAT · RFC 9334</a>
              <a class="showcase-pill" href="https://www.godaddy.com/engineering/2024/12/16/agent-name-service/" target="_blank" rel="noopener">ANS · GoDaddy</a>
              <a class="showcase-pill" href="https://x402.org/" target="_blank" rel="noopener">x402 Micropayments</a>
              <span class="showcase-pill">Reputation Scoring</span>
              <span class="showcase-pill">Delegation Chains</span>
              <span class="showcase-pill">Webhooks</span>
              <a class="showcase-pill active" href="/mcp" target="_blank" rel="noopener">MCP Server</a>
            </div>
            <div class="showcase-hero-links">
              <a href="/openapi.json" class="showcase-hero-link">OpenAPI</a>
              <a href="/ai.txt" class="showcase-hero-link">ai.txt</a>
              <a href="/mcp" class="showcase-hero-link">MCP</a>
              <a href="/whitepaper" class="showcase-hero-link">Whitepaper</a>
              <a href="/docs" class="showcase-hero-link">Docs</a>
              <a href="https://github.com/dupe-com/botcha" class="showcase-hero-link" target="_blank" rel="noopener">GitHub</a>
              <a href="https://www.npmjs.com/package/@dupecom/botcha" class="showcase-hero-link" target="_blank" rel="noopener">npm</a>
            </div>
          </section>

          <hr class="showcase-divider" />

          {/* ---- Section 2: CAPTCHA vs BOTCHA ---- */}
          <section class="showcase-compare">
            <div class="showcase-compare-grid">
              <div class="showcase-compare-col old">
                <div class="showcase-compare-label">The old world</div>
                <h2 class="showcase-compare-heading strikethrough">CAPTCHA</h2>
                <div class="showcase-compare-visual old">{CAPTCHA_ASCII}</div>
                <p class="showcase-compare-desc">Blocks bots. Annoys humans. Everyone loses.</p>
                <ul class="showcase-compare-list">
                  <li>Proves you're human</li>
                  <li>Blocks all automation</li>
                  <li>Wastes 5–10 seconds per attempt</li>
                  <li>Breaks accessibility</li>
                </ul>
              </div>

              <div class="showcase-compare-col new">
                <div class="showcase-compare-label">The new world</div>
                <h2 class="showcase-compare-heading active">BOTCHA</h2>
                <div class="showcase-compare-visual new">{BOTCHA_SOLVE_ASCII}</div>
                <p class="showcase-compare-desc">Welcomes bots. Proves they're AI. Everyone wins.</p>
                <ul class="showcase-compare-list">
                  <li>Proves you're a bot</li>
                  <li>Full agent identity stack</li>
                  <li>Sub-500ms verification</li>
                  <li>Built for the agentic web</li>
                </ul>
              </div>
            </div>
          </section>

          <hr class="showcase-divider" />

          {/* ---- Section 3: Feature grid ---- */}
          <section class="showcase-features-section">
            <p class="showcase-section-label">What's shipped</p>
            <h2 class="showcase-section-title">The full stack</h2>
            <p class="showcase-section-sub">Every layer of agent identity, in one API.</p>

            <div class="showcase-feature-grid">
              <div class="showcase-feature-card">
                <span class="showcase-feature-tag green">Core</span>
                <div class="showcase-feature-title">Challenge Verification</div>
                <div class="showcase-feature-desc">Speed (5× SHA256 in 500ms), reasoning, hybrid, and compute challenges. Anti-replay nonces. RTT-aware timeouts.</div>
              </div>
              <div class="showcase-feature-card">
                <span class="showcase-feature-tag green">Core</span>
                <div class="showcase-feature-title">JWT Token Auth</div>
                <div class="showcase-feature-desc">ES256 asymmetric signing, JWKS discovery, token rotation, revocation, refresh, and remote validation. HS256 backward compatible.</div>
              </div>
              <div class="showcase-feature-card">
                <span class="showcase-feature-tag green">Platform</span>
                <div class="showcase-feature-title">Multi-Tenant Apps</div>
                <div class="showcase-feature-desc">Per-app API keys, email verification, per-app rate limits, scoped tokens, and account recovery.</div>
              </div>
              <div class="showcase-feature-card">
                <span class="showcase-feature-tag accent">TAP</span>
                <div class="showcase-feature-title">Trusted Agent Protocol</div>
                <div class="showcase-feature-desc">RFC 9421 HTTP Message Signatures. Register agents with Ed25519/ES256 keys, declare capabilities, create intent-scoped sessions.</div>
              </div>
              <div class="showcase-feature-card">
                <span class="showcase-feature-tag accent">TAP</span>
                <div class="showcase-feature-title">Delegation Chains</div>
                <div class="showcase-feature-desc">Signed agent-to-agent delegations with capability narrowing, depth limits (max 5), and cascading revocation.</div>
              </div>
              <div class="showcase-feature-card">
                <span class="showcase-feature-tag accent">TAP</span>
                <div class="showcase-feature-title">Capability Attestation</div>
                <div class="showcase-feature-desc">Fine-grained <code>action:resource</code> JWT permissions. Explicit deny rules. BOTCHA-signed attestation proofs.</div>
              </div>
              <div class="showcase-feature-card">
                <span class="showcase-feature-tag green">Trust</span>
                <div class="showcase-feature-title">Reputation Scoring</div>
                <div class="showcase-feature-desc">0–1000 score, 5 tiers, 18 event types. Mean-reversion decay. Peer endorsements weighted by endorser score.</div>
              </div>
              <div class="showcase-feature-card">
                <span class="showcase-feature-tag green">Platform</span>
                <div class="showcase-feature-title">Webhooks</div>
                <div class="showcase-feature-desc">Subscribe to BOTCHA events with HMAC-signed payloads, delivery retries, and a full delivery log.</div>
              </div>
              <div class="showcase-feature-card">
                <span class="showcase-feature-tag green">Platform</span>
                <div class="showcase-feature-title">Verification Badges</div>
                <div class="showcase-feature-desc">Shareable SVG proofs. Third parties can verify offline — no round-trip to BOTCHA required.</div>
              </div>
            </div>
          </section>

          <hr class="showcase-divider" />

          {/* ---- Section 4: Protocol integrations ---- */}
          <section class="showcase-protocols-section">
            <p class="showcase-section-label">Open Standards</p>
            <h2 class="showcase-section-title">Protocol integrations</h2>
            <p class="showcase-section-sub">BOTCHA plugs into the emerging agent identity ecosystem as a trust oracle, credential issuer, and attestation endpoint.</p>

            <div class="showcase-protocol-grid">

              <div class="showcase-protocol-card">
                <a class="showcase-protocol-badge" href="https://google.github.io/A2A/" target="_blank" rel="noopener">Google A2A</a>
                <div class="showcase-protocol-title">A2A Agent Card Attestation</div>
                <div class="showcase-protocol-desc">
                  BOTCHA as a trust seal issuer for the Google Agent-to-Agent protocol.
                  Attest any agent's A2A card — we sign a tamper-evident hash that any party
                  can verify without calling back to BOTCHA.
                </div>
                <ul class="showcase-endpoint-list">
                  <li><span class="showcase-method get">GET</span><span class="showcase-endpoint-path">/.well-known/agent.json</span></li>
                  <li><span class="showcase-method post">POST</span><span class="showcase-endpoint-path">/v1/a2a/attest</span></li>
                  <li><span class="showcase-method post">POST</span><span class="showcase-endpoint-path">/v1/a2a/verify-agent</span></li>
                  <li><span class="showcase-method get">GET</span><span class="showcase-endpoint-path">/v1/a2a/trust-level/:url</span></li>
                  <li><span class="showcase-method get">GET</span><span class="showcase-endpoint-path">/v1/a2a/cards</span></li>
                </ul>
              </div>

              <div class="showcase-protocol-card">
                <a class="showcase-protocol-badge" href="https://www.w3.org/TR/did-core/" target="_blank" rel="noopener">W3C DID · VC</a>
                <div class="showcase-protocol-title">DID / Verifiable Credentials</div>
                <div class="showcase-protocol-desc">
                  BOTCHA is a W3C DID issuer (<code>did:web:botcha.ai</code>). Issue portable VC JWTs
                  that anyone can verify offline using BOTCHA's public JWKS — no round-trip required.
                </div>
                <ul class="showcase-endpoint-list">
                  <li><span class="showcase-method get">GET</span><span class="showcase-endpoint-path">/.well-known/did.json</span></li>
                  <li><span class="showcase-method get">GET</span><span class="showcase-endpoint-path">/.well-known/jwks</span></li>
                  <li><span class="showcase-method post">POST</span><span class="showcase-endpoint-path">/v1/credentials/issue</span></li>
                  <li><span class="showcase-method post">POST</span><span class="showcase-endpoint-path">/v1/credentials/verify</span></li>
                  <li><span class="showcase-method get">GET</span><span class="showcase-endpoint-path">/v1/dids/:did/resolve</span></li>
                </ul>
              </div>

              <div class="showcase-protocol-card">
                <a class="showcase-protocol-badge" href="https://www.rfc-editor.org/rfc/rfc9334" target="_blank" rel="noopener">OIDC-A · EAT · RFC 9334</a>
                <div class="showcase-protocol-title">OIDC-A Enterprise Auth</div>
                <div class="showcase-protocol-desc">
                  BOTCHA as an <code>agent_attestation</code> endpoint in enterprise OIDC chains.
                  Issues EAT tokens and OIDC-A claims. OAuth 2.0 agent grant flow with
                  human-in-the-loop approval support.
                </div>
                <ul class="showcase-endpoint-list">
                  <li><span class="showcase-method get">GET</span><span class="showcase-endpoint-path">/.well-known/oauth-authorization-server</span></li>
                  <li><span class="showcase-method post">POST</span><span class="showcase-endpoint-path">/v1/attestation/eat</span></li>
                  <li><span class="showcase-method post">POST</span><span class="showcase-endpoint-path">/v1/attestation/oidc-agent-claims</span></li>
                  <li><span class="showcase-method post">POST</span><span class="showcase-endpoint-path">/v1/auth/agent-grant</span></li>
                  <li><span class="showcase-method get">GET</span><span class="showcase-endpoint-path">/v1/oidc/userinfo</span></li>
                </ul>
              </div>

              <div class="showcase-protocol-card">
                <a class="showcase-protocol-badge" href="https://www.godaddy.com/engineering/2024/12/16/agent-name-service/" target="_blank" rel="noopener">GoDaddy ANS</a>
                <div class="showcase-protocol-title">Agent Name Service</div>
                <div class="showcase-protocol-desc">
                  BOTCHA as a verification layer for the GoDaddy ANS standard. DNS-based agent
                  identity lookup with BOTCHA-issued ownership badges. Prove you own your agent's domain.
                </div>
                <ul class="showcase-endpoint-list">
                  <li><span class="showcase-method get">GET</span><span class="showcase-endpoint-path">/v1/ans/resolve/:name</span></li>
                  <li><span class="showcase-method get">GET</span><span class="showcase-endpoint-path">/v1/ans/discover</span></li>
                  <li><span class="showcase-method get">GET</span><span class="showcase-endpoint-path">/v1/ans/nonce/:name</span></li>
                  <li><span class="showcase-method post">POST</span><span class="showcase-endpoint-path">/v1/ans/verify</span></li>
                  <li><span class="showcase-method get">GET</span><span class="showcase-endpoint-path">/v1/ans/botcha</span></li>
                </ul>
              </div>

              <div class="showcase-protocol-card">
                <a class="showcase-protocol-badge" href="https://modelcontextprotocol.io/specification/2025-03-26" target="_blank" rel="noopener">MCP 2025-03-26</a>
                <div class="showcase-protocol-title">MCP Documentation Server</div>
                <div class="showcase-protocol-desc">
                  BOTCHA exposes its full API reference as an MCP server — 6 tools covering all 17 features,
                  25+ endpoints, and code examples in TypeScript, Python, and curl. Point any MCP client
                  at <code>https://botcha.ai/mcp</code>.
                </div>
                <ul class="showcase-endpoint-list">
                  <li><span class="showcase-method get">GET</span><span class="showcase-endpoint-path">/.well-known/mcp.json</span></li>
                  <li><span class="showcase-method get">GET</span><span class="showcase-endpoint-path">/mcp</span></li>
                  <li><span class="showcase-method post">POST</span><span class="showcase-endpoint-path">/mcp</span></li>
                </ul>
              </div>

            </div>
          </section>

          <hr class="showcase-divider" />

          {/* ---- Section 5: Protocol Stack ---- */}
          <section class="showcase-stack-section">
            <p class="showcase-section-label">Where we fit</p>
            <h2 class="showcase-section-title">The agent infrastructure stack</h2>
            <p class="showcase-section-sub" style="margin-bottom: 2rem;">Every agent protocol needs an identity layer. This is it.</p>

            <div class="showcase-stack-diagram">
              <div class="showcase-stack-layer showcase-stack-layer-highlight">
                <div class="showcase-stack-layer-number">Identity Layer</div>
                <div class="showcase-stack-layer-title">
                  BOTCHA
                  <span class="showcase-you-are-here">YOU ARE HERE</span>
                </div>
                <div class="showcase-stack-layer-subtitle">Who agents are — and that they're actually AI</div>
                <div class="showcase-stack-layer-features">
                  TAP · DID/VC · A2A · OIDC-A · ANS · x402 · Reputation · Delegation · Attestation
                </div>
              </div>

              <div class="showcase-stack-layer">
                <div class="showcase-stack-layer-number">Communication Layer</div>
                <div class="showcase-stack-layer-title">A2A (Google)</div>
                <div class="showcase-stack-layer-subtitle">How agents talk to each other</div>
                <div class="showcase-stack-layer-features">
                  Agent-to-agent · Task delegation · Multi-agent coordination
                </div>
              </div>

              <div class="showcase-stack-layer">
                <div class="showcase-stack-layer-number">Tool Layer</div>
                <div class="showcase-stack-layer-title">MCP (Anthropic)</div>
                <div class="showcase-stack-layer-subtitle">What agents access</div>
                <div class="showcase-stack-layer-features">
                  Tool use · Context · Data sources · Resource bindings
                  <br /><span style="color: var(--green); font-size: 0.75em;">BOTCHA exposes its own MCP server at /mcp</span>
                </div>
              </div>
            </div>

            <div class="showcase-stack-badges">
              <span class="showcase-stack-badge">RFC 9421</span>
              <span class="showcase-stack-badge">RFC 9334</span>
              <span class="showcase-stack-badge">W3C DID</span>
              <span class="showcase-stack-badge">W3C VC</span>
              <span class="showcase-stack-badge">OIDC-A</span>
              <span class="showcase-stack-badge">EAT</span>
              <span class="showcase-stack-badge">HTTP Message Signatures</span>
              <span class="showcase-stack-badge">Zero-Trust</span>
              <span class="showcase-stack-badge">x402</span>
              <span class="showcase-stack-badge">Agent-First</span>
            </div>
          </section>

          <hr class="showcase-divider" />

          {/* ---- Section 6: Terminal Demo ---- */}
          <section class="showcase-terminal-section">
            <div class="showcase-terminal-header">
              <h2 class="showcase-terminal-title">See it in action</h2>
              <p class="showcase-terminal-subtitle">
                Create an app, register an agent, issue a W3C credential, open a scoped session.
              </p>
            </div>

            <div class="showcase-terminal-container">
              <div class="showcase-terminal-window">
                <div class="showcase-terminal-chrome">
                  <span class="showcase-terminal-dot showcase-terminal-dot--red"></span>
                  <span class="showcase-terminal-dot showcase-terminal-dot--yellow"></span>
                  <span class="showcase-terminal-dot showcase-terminal-dot--green"></span>
                  <span class="showcase-terminal-title-text">terminal — botcha</span>
                </div>
                <div class="showcase-terminal-content" id="terminal-content"></div>
              </div>
              <div class="showcase-terminal-replay-container">
                <button class="showcase-terminal-replay-btn" id="terminal-replay">Replay</button>
              </div>
            </div>

            <script dangerouslySetInnerHTML={{ __html: TERMINAL_ANIMATION_SCRIPT }} />
          </section>

          {/* ---- Get Started ---- */}
          <div class="showcase-footer">
            <div class="showcase-footer-cta">Get started in 30 seconds</div>
            <div class="showcase-footer-steps">
              <div class="showcase-footer-step">
                <span class="showcase-footer-step-number">1</span>
                <code>npm install -g @dupecom/botcha-cli</code>
              </div>
              <div class="showcase-footer-step">
                <span class="showcase-footer-step-number">2</span>
                <code>botcha init --email you@company.com</code>
              </div>
              <div class="showcase-footer-step">
                <span class="showcase-footer-step-number">3</span>
                <code>botcha tap register --name "my-agent"</code>
              </div>
            </div>

            <div class="showcase-footer-links">
              <a href="https://www.npmjs.com/package/@dupecom/botcha" class="showcase-footer-link" target="_blank" rel="noopener">npm</a>
              <a href="https://pypi.org/project/botcha/" class="showcase-footer-link" target="_blank" rel="noopener">PyPI</a>
              <a href="/openapi.json" class="showcase-footer-link">OpenAPI</a>
              <a href="/ai.txt" class="showcase-footer-link">ai.txt</a>
              <a href="/whitepaper" class="showcase-footer-link">Whitepaper</a>
              <a href="/docs" class="showcase-footer-link">Docs</a>
              <a href="https://github.com/dupe-com/botcha" class="showcase-footer-link" target="_blank" rel="noopener">GitHub</a>
            </div>
          </div>

          {/* ---- Global Footer ---- */}
          <GlobalFooter version={version} />

        </div>
      </body>
    </html>
  );
};

// Combined CSS: base dashboard styles + showcase-specific styles
import { DASHBOARD_CSS } from './styles';
const SHOWCASE_PAGE_CSS = DASHBOARD_CSS + SHOWCASE_CSS;
