/**
 * BOTCHA Showcase Page
 *
 * Visual explainer at /showcase — shows what BOTCHA is, how it works,
 * where it fits in the agent infrastructure stack, and lets visitors
 * solve a live challenge.
 *
 * Sections:
 *   1. Hero — side-by-side CAPTCHA vs BOTCHA comparison
 *   2. Protocol Stack — MCP / A2A / TAP positioning
 *   3. Terminal Demo — animated CLI walkthrough
 *   4. Live Demo — interactive challenge solver
 */

import type { FC } from 'hono/jsx';

// ============ CSS ============

export const SHOWCASE_CSS = `
  /* ============ Showcase layout ============ */
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

  /* ============ Section 1: Hero ============ */
  .showcase-hero {
    max-width: 1100px;
    margin: 0 auto;
    padding: 4rem 2rem 2rem;
  }

  .showcase-hero-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 2rem;
    margin-bottom: 3rem;
  }

  .showcase-hero-column {
    border: 2px solid var(--border);
    padding: 2rem;
    background: var(--bg);
  }

  .showcase-hero-column.old-world {
    border-color: var(--red);
  }

  .showcase-hero-column.new-world {
    border-color: var(--green);
  }

  .showcase-hero-label {
    font-size: 0.6875rem;
    font-weight: 700;
    letter-spacing: 0.15em;
    text-transform: uppercase;
    margin-bottom: 0.75rem;
    color: var(--text-dim);
  }

  .showcase-hero-title {
    font-size: 2rem;
    font-weight: 700;
    margin-bottom: 1.25rem;
    line-height: 1;
  }

  .showcase-hero-title.strikethrough {
    text-decoration: line-through;
    color: var(--red);
  }

  .showcase-hero-title.active {
    color: var(--green);
  }

  .showcase-hero-visual {
    font-family: var(--font);
    font-size: 0.6875rem;
    line-height: 1.3;
    margin: 1.25rem 0;
    padding: 1rem;
    background: #fafafa;
    border: 1px solid var(--border);
    white-space: pre;
    overflow-x: auto;
  }

  .showcase-hero-visual.old-world {
    color: var(--red);
    border-color: var(--red);
    background: #fff5f5;
  }

  .showcase-hero-visual.new-world {
    color: var(--green);
    border-color: var(--green);
    background: #f5fff7;
  }

  .showcase-hero-subtitle {
    font-size: 0.875rem;
    margin-bottom: 1rem;
    line-height: 1.5;
    color: var(--text);
  }

  .showcase-hero-features {
    list-style: none;
    padding: 0;
    margin: 0;
    font-size: 0.75rem;
    color: var(--text-muted);
  }

  .showcase-hero-features li {
    padding: 0.25rem 0;
  }

  .showcase-hero-features li::before {
    content: "\\2192  ";
    color: var(--text-dim);
  }

  .showcase-hero-tagline {
    text-align: center;
    padding: 2rem 2rem 0;
  }

  .showcase-hero-tagline-main {
    font-size: 1.5rem;
    font-weight: 700;
    margin-bottom: 0.5rem;
    color: var(--text);
  }

  .showcase-hero-tagline-sub {
    font-size: 0.875rem;
    color: var(--text-muted);
  }

  /* ============ Section 2: Protocol Stack ============ */
  .showcase-protocol-stack {
    max-width: 800px;
    margin: 0 auto;
    padding: 4rem 2rem;
  }

  .showcase-protocol-stack h2 {
    font-size: 1.5rem;
    font-weight: 700;
    margin-bottom: 0.5rem;
  }

  .showcase-protocol-stack .subtitle {
    color: var(--text-muted);
    font-size: 0.875rem;
    margin-bottom: 2.5rem;
  }

  .showcase-stack-diagram {
    position: relative;
    margin: 0 0 2rem 0;
  }

  .showcase-stack-layer {
    border: 2px solid var(--border);
    background: var(--bg);
    padding: 1.25rem 1.5rem;
    position: relative;
  }

  .showcase-stack-layer + .showcase-stack-layer {
    margin-top: -2px;
  }

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

  .showcase-stack-layer-highlight .showcase-stack-layer-number {
    color: var(--green);
  }

  .showcase-stack-layer-title {
    font-size: 1.125rem;
    font-weight: 700;
    margin-bottom: 0.25rem;
    display: flex;
    align-items: center;
    gap: 0.75rem;
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

  .showcase-buzzword-badges {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
    margin-bottom: 2rem;
  }

  .showcase-badge {
    display: inline-block;
    font-size: 0.6875rem;
    padding: 0.3rem 0.625rem;
    border: 1px solid var(--border);
    background: var(--bg);
    color: var(--text-muted);
    white-space: nowrap;
  }

  .showcase-protocol-explanation {
    font-size: 0.8125rem;
    line-height: 1.7;
    color: var(--text-muted);
  }

  /* ============ Section 3: Terminal Demo ============ */
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
    font-size: 1.5rem;
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

  .showcase-terminal-container {
    max-width: 640px;
    margin: 0 auto;
  }

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

  .showcase-terminal-dot {
    width: 10px;
    height: 10px;
    border-radius: 50%;
  }

  .showcase-terminal-dot--red { background: #ff5f56; }
  .showcase-terminal-dot--yellow { background: #ffbd2e; }
  .showcase-terminal-dot--green { background: #27c93f; }

  .showcase-terminal-title-text {
    font-size: 0.6875rem;
    color: #888;
    margin-left: 0.5rem;
  }

  .showcase-terminal-content {
    padding: 1.5rem;
    font-size: 0.8125rem;
    line-height: 1.6;
    color: #f0f0f0;
    min-height: 340px;
    font-family: var(--font);
  }

  .showcase-terminal-line {
    margin-bottom: 0.375rem;
    white-space: pre-wrap;
    word-break: break-word;
  }

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

  .showcase-terminal-replay-container {
    text-align: center;
    margin-top: 1.5rem;
  }

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

  .showcase-terminal-replay-btn:hover {
    border-color: var(--accent);
    color: var(--text);
  }

  /* ============ Section 4: Live Demo ============ */
  .showcase-livedemo {
    padding: 4rem 2rem;
    background: var(--bg-raised);
    border-top: 2px solid var(--border);
    border-bottom: 2px solid var(--border);
  }

  .showcase-livedemo-container {
    max-width: 700px;
    margin: 0 auto;
    text-align: center;
  }

  .showcase-livedemo-title {
    font-size: 1.5rem;
    font-weight: 700;
    margin-bottom: 0.5rem;
    color: var(--text);
  }

  .showcase-livedemo-subtitle {
    font-size: 0.875rem;
    color: var(--text-muted);
    margin-bottom: 2.5rem;
    line-height: 1.6;
  }

  .showcase-livedemo-button {
    display: inline-block;
    padding: 1rem 2rem;
    font-size: 0.875rem;
    font-weight: 700;
    font-family: var(--font);
    color: #fff;
    background: var(--accent);
    border: 2px solid var(--accent);
    cursor: pointer;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    box-shadow: 4px 4px 0 var(--border-bright);
    transition: all 0.15s;
    margin-bottom: 1.5rem;
  }

  .showcase-livedemo-button:hover:not(:disabled) {
    transform: translate(-2px, -2px);
    box-shadow: 6px 6px 0 var(--border-bright);
    opacity: 1;
  }

  .showcase-livedemo-button:active:not(:disabled) {
    transform: translate(2px, 2px);
    box-shadow: 2px 2px 0 var(--border-bright);
  }

  .showcase-livedemo-button:disabled {
    cursor: not-allowed;
    opacity: 0.5;
  }

  .showcase-livedemo-result {
    margin-top: 2rem;
    padding: 1.5rem;
    background: var(--bg);
    border: 2px solid var(--border);
    box-shadow: 4px 4px 0 var(--border-bright);
    text-align: left;
    font-size: 0.8125rem;
    line-height: 1.8;
  }

  .showcase-livedemo-result-line {
    opacity: 0;
    animation: showcase-livedemo-fadein 0.3s ease forwards;
    margin-bottom: 0.375rem;
  }

  .showcase-livedemo-result-line:nth-child(1) { animation-delay: 0ms; }
  .showcase-livedemo-result-line:nth-child(2) { animation-delay: 100ms; }
  .showcase-livedemo-result-line:nth-child(3) { animation-delay: 200ms; }
  .showcase-livedemo-result-line:nth-child(4) { animation-delay: 300ms; }
  .showcase-livedemo-result-line:nth-child(5) { animation-delay: 400ms; }
  .showcase-livedemo-result-line:nth-child(6) { animation-delay: 500ms; }
  .showcase-livedemo-result-line:nth-child(7) { animation-delay: 600ms; }

  @keyframes showcase-livedemo-fadein {
    from { opacity: 0; transform: translateY(-4px); }
    to { opacity: 1; transform: translateY(0); }
  }

  .showcase-livedemo-label {
    color: var(--text-dim);
    font-weight: 600;
  }

  .showcase-livedemo-value {
    color: var(--text);
  }

  .showcase-livedemo-time-fast {
    color: var(--green);
    font-weight: 700;
  }

  .showcase-livedemo-time-slow {
    color: var(--red);
    font-weight: 700;
  }

  .showcase-livedemo-status-success {
    color: var(--green);
    font-weight: 700;
    font-size: 1rem;
  }

  .showcase-livedemo-status-error {
    color: var(--red);
    font-weight: 700;
  }

  .showcase-livedemo-token {
    font-family: var(--font);
    color: var(--text-muted);
    word-break: break-all;
    font-size: 0.75rem;
  }

  .showcase-livedemo-counter {
    margin-top: 1rem;
    font-size: 0.75rem;
    color: var(--text-dim);
  }

  .showcase-livedemo-error {
    margin-top: 1.5rem;
    padding: 1rem;
    background: var(--bg);
    border: 2px solid var(--red);
    color: var(--red);
    text-align: left;
    font-size: 0.8125rem;
  }

  /* ============ Showcase footer ============ */
  .showcase-footer {
    max-width: 800px;
    margin: 0 auto;
    padding: 3rem 2rem 4rem;
    text-align: center;
  }

  .showcase-footer-cta {
    font-size: 1rem;
    font-weight: 700;
    margin-bottom: 1rem;
    color: var(--text);
  }

  .showcase-footer-install {
    font-size: 0.875rem;
    padding: 0.75rem 1.5rem;
    background: var(--bg-raised);
    border: 1px solid var(--border);
    display: inline-block;
    margin-bottom: 2rem;
  }

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

  .showcase-footer-link:hover {
    border-color: var(--accent);
    opacity: 1;
  }

  .showcase-footer-meta {
    font-size: 0.6875rem;
    color: var(--text-dim);
  }

  .showcase-footer-meta a {
    color: var(--text-muted);
    text-decoration: none;
  }

  .showcase-footer-sep {
    margin: 0 0.375rem;
  }

  /* ============ Responsive ============ */
  @media (max-width: 768px) {
    .showcase-hero { padding: 2rem 1rem 1rem; }
    .showcase-hero-grid {
      grid-template-columns: 1fr;
      gap: 1.5rem;
    }
    .showcase-hero-column { padding: 1.5rem; }
    .showcase-hero-title { font-size: 1.5rem; }
    .showcase-hero-visual { font-size: 0.5625rem; }
    .showcase-hero-tagline-main { font-size: 1.25rem; }

    .showcase-protocol-stack { padding: 3rem 1rem; }
    .showcase-stack-layer-title {
      flex-direction: column;
      align-items: flex-start;
      gap: 0.375rem;
      font-size: 1rem;
    }

    .showcase-terminal-section { padding: 3rem 1rem; }
    .showcase-terminal-content { padding: 1rem; font-size: 0.75rem; min-height: 300px; }

    .showcase-livedemo { padding: 3rem 1rem; }

    .showcase-footer { padding: 2rem 1rem 3rem; }
  }

  @media (max-width: 480px) {
    .showcase-hero-visual { font-size: 0.5rem; padding: 0.75rem; }
    .showcase-hero-tagline-main { font-size: 1rem; }
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
        '   <span class="showcase-terminal-label">Name:</span> <span class="showcase-terminal-value">shopping-agent</span>',
        '   <span class="showcase-terminal-label">Capabilities:</span> <span class="showcase-terminal-value">browse, search, purchase</span>'
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

  function highlightFlags(cmd) {
    return cmd.replace(/(--[a-z-]+)/g, '<span class="showcase-terminal-flag">$1</span>');
  }

  function sleep(ms) {
    return new Promise(function(r) { currentTimeout = setTimeout(r, ms); });
  }

  async function animate() {
    if (running) return;
    running = true;
    content.innerHTML = '';

    for (var c = 0; c < commands.length; c++) {
      var item = commands[c];
      var line = document.createElement('div');
      line.className = 'showcase-terminal-line';
      line.innerHTML = '<span class="showcase-terminal-prompt">$ </span><span class="showcase-terminal-command"></span><span class="showcase-terminal-cursor">\\u2589</span>';
      content.appendChild(line);

      var cmdSpan = line.querySelector('.showcase-terminal-command');
      var cursor = line.querySelector('.showcase-terminal-cursor');

      for (var i = 0; i < item.cmd.length; i++) {
        await sleep(35);
        cmdSpan.textContent = item.cmd.slice(0, i + 1);
      }

      cmdSpan.innerHTML = highlightFlags(item.cmd);
      cursor.remove();
      await sleep(300);

      for (var r = 0; r < item.response.length; r++) {
        var respLine = document.createElement('div');
        respLine.className = 'showcase-terminal-line';
        respLine.innerHTML = item.response[r];
        content.appendChild(respLine);
      }

      await sleep(800);
    }

    await sleep(2500);
    running = false;
    animate();
  }

  replayBtn.addEventListener('click', function() {
    clearTimeout(currentTimeout);
    running = false;
    animate();
  });

  animate();
})();
`;

const LIVE_DEMO_SCRIPT = `
(function() {
  var solveCount = 0;
  var isRunning = false;

  function sha256(str) {
    var encoder = new TextEncoder();
    var data = encoder.encode(str);
    return crypto.subtle.digest('SHA-256', data).then(function(buf) {
      var arr = Array.from(new Uint8Array(buf));
      var hex = arr.map(function(b) { return b.toString(16).padStart(2, '0'); }).join('');
      return hex.substring(0, 8);
    });
  }

  function solveBotcha() {
    if (isRunning) return;
    isRunning = true;

    var button = document.getElementById('botcha-demo-button');
    var resultDiv = document.getElementById('botcha-demo-result');
    var errorDiv = document.getElementById('botcha-demo-error');
    var counter = document.getElementById('botcha-demo-counter');

    button.disabled = true;
    button.textContent = 'SOLVING...';
    resultDiv.style.display = 'none';
    errorDiv.style.display = 'none';

    var startTime = Date.now();

    fetch('https://botcha.ai/v1/token')
      .then(function(res) {
        if (!res.ok) throw new Error('Failed to fetch challenge: ' + res.status);
        return res.json();
      })
      .then(function(data) {
        var challenge = data.challenge;
        if (!challenge || !challenge.numbers) throw new Error('Invalid challenge format');

        return Promise.all(
          challenge.numbers.map(function(n) { return sha256(String(n)); })
        ).then(function(answers) {
          return fetch('https://botcha.ai/v1/token/verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id: challenge.id, answers: answers })
          }).then(function(res) {
            if (!res.ok) throw new Error('Verification failed: ' + res.status);
            return res.json();
          }).then(function(verifyData) {
            var solveTime = Date.now() - startTime;
            var timeClass = solveTime < 500 ? 'showcase-livedemo-time-fast' : 'showcase-livedemo-time-slow';
            var token = verifyData.token || verifyData.access_token || 'N/A';
            var tokenPreview = token.substring(0, 24) + '...';

            resultDiv.innerHTML =
              '<div class="showcase-livedemo-result-line"><span class="showcase-livedemo-label">Challenge:</span> <span class="showcase-livedemo-value">' + challenge.numbers.length + ' SHA-256 hashes</span></div>' +
              '<div class="showcase-livedemo-result-line"><span class="showcase-livedemo-label">Numbers:</span> <span class="showcase-livedemo-value">[' + challenge.numbers.join(', ') + ']</span></div>' +
              '<div class="showcase-livedemo-result-line"><span class="showcase-livedemo-label">Answers:</span> <span class="showcase-livedemo-value">["' + answers.join('", "') + '"]</span></div>' +
              '<div class="showcase-livedemo-result-line"><span class="showcase-livedemo-label">Solve time:</span> <span class="' + timeClass + '">' + solveTime + 'ms</span></div>' +
              '<div class="showcase-livedemo-result-line"><span class="showcase-livedemo-status-success">VERIFIED \\u2014 You are a bot.</span></div>' +
              '<div class="showcase-livedemo-result-line"><span class="showcase-livedemo-label">Token:</span> <span class="showcase-livedemo-token">' + tokenPreview + '</span></div>';

            resultDiv.style.display = 'block';
            solveCount++;
            counter.textContent = 'Challenges solved on this page: ' + solveCount;
            button.textContent = 'SOLVE ANOTHER';
          });
        });
      })
      .catch(function(err) {
        errorDiv.innerHTML = '<span class="showcase-livedemo-status-error">[ERR]</span> ' + err.message;
        errorDiv.style.display = 'block';
        button.textContent = 'TRY AGAIN';
      })
      .finally(function() {
        button.disabled = false;
        isRunning = false;
      });
  }

  document.getElementById('botcha-demo-button').addEventListener('click', solveBotcha);
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

export const ShowcasePage: FC<{ version: string }> = ({ version }) => {
  return (
    <html lang="en">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>BOTCHA — Reverse CAPTCHA for AI Agents</title>

        <meta name="description" content="BOTCHA proves you're a bot. Zero-trust identity for AI agents. The identity layer for the agentic web." />
        <meta property="og:title" content="BOTCHA — Reverse CAPTCHA for AI Agents" />
        <meta property="og:description" content="Zero-trust identity for AI agents. Prove you're a bot, not a human." />
        <meta property="og:url" content="https://botcha.ai/showcase" />
        <meta property="og:type" content="website" />

        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link
          href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&display=swap"
          rel="stylesheet"
        />
        <style dangerouslySetInnerHTML={{ __html: SHOWCASE_PAGE_CSS }} />
      </head>
      <body>
        <div class="showcase-page">

          {/* ---- Logo ---- */}
          <div style="text-align: center; padding: 3rem 2rem 0;">
            <a href="/" class="ascii-logo">{BOTCHA_LOGO}</a>
            <p class="text-muted" style="font-size: 0.6875rem; margin-top: -0.5rem;">
              {'>'}_&nbsp;reverse CAPTCHA for AI agents
            </p>
          </div>

          {/* ---- Section 1: Hero ---- */}
          <section class="showcase-hero">
            <div class="showcase-hero-grid">
              <div class="showcase-hero-column old-world">
                <div class="showcase-hero-label">The old world</div>
                <h2 class="showcase-hero-title strikethrough">CAPTCHA</h2>
                <div class="showcase-hero-visual old-world">{CAPTCHA_ASCII}</div>
                <p class="showcase-hero-subtitle">
                  Blocks bots. Annoys humans. Everyone loses.
                </p>
                <ul class="showcase-hero-features">
                  <li>Proves you're human</li>
                  <li>Blocks automation</li>
                  <li>Wastes 5-10 seconds per attempt</li>
                  <li>Breaks accessibility</li>
                </ul>
              </div>

              <div class="showcase-hero-column new-world">
                <div class="showcase-hero-label">The new world</div>
                <h2 class="showcase-hero-title active">BOTCHA</h2>
                <div class="showcase-hero-visual new-world">{BOTCHA_SOLVE_ASCII}</div>
                <p class="showcase-hero-subtitle">
                  Welcomes bots. Proves they're AI. Everyone wins.
                </p>
                <ul class="showcase-hero-features">
                  <li>Proves you're a bot</li>
                  <li>Agent identity layer</li>
                  <li>Sub-500ms verification</li>
                  <li>Built for the agentic web</li>
                </ul>
              </div>
            </div>

            <div class="showcase-hero-tagline">
              <div class="showcase-hero-tagline-main">
                Zero-trust identity for AI agents
              </div>
              <div class="showcase-hero-tagline-sub">
                The identity layer for the agentic web
              </div>
            </div>
          </section>

          <hr class="showcase-divider" />

          {/* ---- Section 2: Protocol Stack ---- */}
          <section class="showcase-protocol-stack">
            <h2>The Agent Infrastructure Stack</h2>
            <p class="subtitle">
              Where BOTCHA fits in the new world of agentic AI
            </p>

            <div class="showcase-stack-diagram">
              <div class="showcase-stack-layer showcase-stack-layer-highlight">
                <div class="showcase-stack-layer-number">Layer 3: Identity</div>
                <div class="showcase-stack-layer-title">
                  TAP (BOTCHA)
                  <span class="showcase-you-are-here">YOU ARE HERE</span>
                </div>
                <div class="showcase-stack-layer-subtitle">Who agents are</div>
                <div class="showcase-stack-layer-features">
                  Agent auth · Proof of AI · Zero-trust · Capability scoping · Session management
                </div>
              </div>

              <div class="showcase-stack-layer">
                <div class="showcase-stack-layer-number">Layer 2: Communication</div>
                <div class="showcase-stack-layer-title">A2A (Google)</div>
                <div class="showcase-stack-layer-subtitle">How agents talk</div>
                <div class="showcase-stack-layer-features">
                  Agent-to-agent · Task delegation · Multi-agent coordination
                </div>
              </div>

              <div class="showcase-stack-layer">
                <div class="showcase-stack-layer-number">Layer 1: Tools</div>
                <div class="showcase-stack-layer-title">MCP (Anthropic)</div>
                <div class="showcase-stack-layer-subtitle">What agents access</div>
                <div class="showcase-stack-layer-features">
                  Tool use · Context · Data sources · Resource bindings
                </div>
              </div>
            </div>

            <div class="showcase-buzzword-badges">
              <span class="showcase-badge">RFC 9421</span>
              <span class="showcase-badge">HTTP Message Signatures</span>
              <span class="showcase-badge">Zero-Trust</span>
              <span class="showcase-badge">Agent Identity</span>
              <span class="showcase-badge">Capability Scoping</span>
              <span class="showcase-badge">Agentic AI</span>
              <span class="showcase-badge">Multi-Agent Systems</span>
            </div>

            <p class="showcase-protocol-explanation">
              Every agent protocol needs an identity layer. MCP gives agents tools. A2A lets
              agents communicate. TAP proves they're actually AI — and scopes what they're
              allowed to do.
            </p>
          </section>

          <hr class="showcase-divider" />

          {/* ---- Section 3: Terminal Demo ---- */}
          <section class="showcase-terminal-section">
            <div class="showcase-terminal-header">
              <h2 class="showcase-terminal-title">See it in action</h2>
              <p class="showcase-terminal-subtitle">
                Three commands. Your agent has an identity, capabilities, and a scoped session.
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
                <button class="showcase-terminal-replay-btn" id="terminal-replay">
                  Replay
                </button>
              </div>
            </div>

            <script dangerouslySetInnerHTML={{ __html: TERMINAL_ANIMATION_SCRIPT }} />
          </section>

          {/* ---- Section 4: Live Demo ---- */}
          <section class="showcase-livedemo">
            <div class="showcase-livedemo-container">
              <h2 class="showcase-livedemo-title">Try it yourself</h2>
              <p class="showcase-livedemo-subtitle">
                Click the button. Watch a real challenge get solved in your browser. Only a bot can do this in under 500ms.
              </p>

              <button id="botcha-demo-button" class="showcase-livedemo-button">
                Solve a BOTCHA challenge
              </button>

              <div id="botcha-demo-result" class="showcase-livedemo-result" style="display: none;"></div>
              <div id="botcha-demo-error" class="showcase-livedemo-error" style="display: none;"></div>
              <div id="botcha-demo-counter" class="showcase-livedemo-counter">
                Challenges solved on this page: 0
              </div>
            </div>

            <script dangerouslySetInnerHTML={{ __html: LIVE_DEMO_SCRIPT }} />
          </section>

          {/* ---- Footer ---- */}
          <div class="showcase-footer">
            <div class="showcase-footer-cta">Get started in 30 seconds</div>
            <div class="showcase-footer-install">
              <code>npm install -g @dupecom/botcha-cli</code>
            </div>

            <div class="showcase-footer-links">
              <a href="/" class="showcase-footer-link">Home</a>
              <a href="/openapi.json" class="showcase-footer-link">OpenAPI</a>
              <a href="/ai.txt" class="showcase-footer-link">ai.txt</a>
              <a href="https://github.com/dupe-com/botcha" class="showcase-footer-link">GitHub</a>
              <a href="https://www.npmjs.com/package/@dupecom/botcha" class="showcase-footer-link">npm</a>
              <a href="https://pypi.org/project/botcha/" class="showcase-footer-link">PyPI</a>
            </div>

            <div class="showcase-footer-meta">
              <span>v{version}</span>
              <span class="showcase-footer-sep">&middot;</span>
              <a href="https://botcha.ai">botcha.ai</a>
              <span class="showcase-footer-sep">&middot;</span>
              <a href="https://github.com/i8ramin">@i8ramin</a>
            </div>
          </div>

        </div>
      </body>
    </html>
  );
};

// Combined CSS: base dashboard styles (subset) + showcase-specific styles
import { DASHBOARD_CSS } from './styles';
const SHOWCASE_PAGE_CSS = DASHBOARD_CSS + SHOWCASE_CSS;
