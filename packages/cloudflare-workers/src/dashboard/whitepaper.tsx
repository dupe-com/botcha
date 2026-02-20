/**
 * BOTCHA Whitepaper Page
 *
 * Serves the whitepaper at /whitepaper — long-form prose explaining
 * what BOTCHA is, how it works, TAP, architecture, and use cases.
 *
 * Follows the ShowcasePage pattern: self-contained JSX with own
 * HTML shell, inline CSS, and the shared DASHBOARD_CSS base.
 */

import type { FC } from 'hono/jsx';
import { DASHBOARD_CSS } from './styles';
import { GlobalFooter, OGMeta } from './layout';

// ============ WHITEPAPER CSS ============

const WHITEPAPER_CSS = `
  /* ============ Article layout ============ */
  .wp {
    max-width: 740px;
    margin: 0 auto;
    padding: 3rem 2rem 4rem;
  }

  /* ---- Header ---- */
  .wp-header {
    text-align: center;
    margin-bottom: 3rem;
    padding-bottom: 2rem;
    border-bottom: 1px solid var(--border);
  }

  .wp-badge {
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

  .wp-title {
    font-size: 2rem;
    font-weight: 700;
    line-height: 1.15;
    margin: 0 0 0.75rem;
    color: var(--text);
  }

  .wp-subtitle {
    font-size: 0.875rem;
    color: var(--text-muted);
    line-height: 1.6;
    margin: 0 0 1rem;
  }

  .wp-meta {
    font-size: 0.6875rem;
    color: var(--text-dim);
  }

  .wp-meta a {
    color: var(--text-muted);
  }

  /* ---- Table of Contents ---- */
  .wp-toc {
    border: 1px solid var(--border);
    padding: 1.5rem 2rem;
    margin-bottom: 3rem;
    background: var(--bg);
  }

  .wp-toc-title {
    font-size: 0.6875rem;
    font-weight: 700;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    color: var(--text-dim);
    margin-bottom: 1rem;
  }

  .wp-toc ol {
    list-style: none;
    padding: 0;
    margin: 0;
    counter-reset: toc;
  }

  .wp-toc li {
    counter-increment: toc;
    font-size: 0.8125rem;
    line-height: 2;
  }

  .wp-toc li::before {
    content: counter(toc) ".";
    display: inline-block;
    width: 1.5rem;
    color: var(--text-dim);
    font-weight: 600;
  }

  .wp-toc a {
    color: var(--text);
    text-decoration: none;
  }

  .wp-toc a:hover {
    text-decoration: underline;
    opacity: 1;
  }

  /* ---- Prose ---- */
  .wp h2 {
    font-size: 1.25rem;
    font-weight: 700;
    margin: 3rem 0 1rem;
    padding-top: 1.5rem;
    border-top: 1px solid var(--border);
    color: var(--text);
  }

  .wp h3 {
    font-size: 1rem;
    font-weight: 700;
    margin: 2rem 0 0.75rem;
    color: var(--text);
  }

  .wp p {
    font-size: 0.875rem;
    line-height: 1.8;
    margin: 0 0 1.25rem;
    color: var(--text);
  }

  .wp strong {
    font-weight: 700;
  }

  .wp em {
    font-style: italic;
  }

  .wp ul, .wp ol {
    font-size: 0.875rem;
    line-height: 1.8;
    margin: 0 0 1.25rem;
    padding-left: 1.5rem;
    color: var(--text);
  }

  .wp li {
    margin-bottom: 0.375rem;
  }

  .wp li::marker {
    color: var(--text-dim);
  }

  .wp a {
    color: var(--text);
    text-decoration: underline;
    text-underline-offset: 3px;
  }

  .wp a:hover {
    color: var(--green);
    opacity: 1;
  }

  /* ---- Code ---- */
  .wp code {
    font-family: var(--font);
    font-size: 0.8125rem;
    background: var(--bg-raised);
    padding: 0.15rem 0.4rem;
    border: 1px solid var(--border);
  }

  .wp pre {
    background: #1a1a1a;
    color: #e0e0e0;
    padding: 1.25rem 1.5rem;
    margin: 0 0 1.5rem;
    overflow-x: auto;
    font-size: 0.75rem;
    line-height: 1.7;
    border: 2px solid #1a1a1a;
  }

  .wp pre code {
    background: none;
    border: none;
    padding: 0;
    color: inherit;
    font-size: inherit;
  }

  .wp-code-label {
    display: block;
    font-size: 0.625rem;
    font-weight: 700;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    color: #888;
    margin-bottom: 0.25rem;
  }

  /* ---- Tables ---- */
  .wp table {
    width: 100%;
    border-collapse: collapse;
    margin: 0 0 1.5rem;
    font-size: 0.8125rem;
  }

  .wp thead {
    border-bottom: 2px solid var(--accent);
  }

  .wp th {
    text-align: left;
    padding: 0.5rem 0.75rem;
    font-weight: 700;
    font-size: 0.6875rem;
    letter-spacing: 0.05em;
    text-transform: uppercase;
    color: var(--text-muted);
  }

  .wp td {
    padding: 0.5rem 0.75rem;
    border-bottom: 1px solid var(--border);
    line-height: 1.6;
  }

  /* ---- Blockquote ---- */
  .wp blockquote {
    border-left: 3px solid var(--accent);
    padding: 0.75rem 1.25rem;
    margin: 0 0 1.5rem;
    background: var(--bg-raised);
    font-size: 0.875rem;
    line-height: 1.7;
    color: var(--text-muted);
  }

  .wp blockquote p {
    margin: 0;
    color: var(--text-muted);
  }

  /* ---- Diagrams ---- */
  .wp-stack {
    margin: 1.5rem 0 2rem;
  }

  .wp-stack-layer {
    border: 2px solid var(--border);
    padding: 1rem 1.25rem;
    background: var(--bg);
    display: flex;
    align-items: baseline;
    gap: 1rem;
  }

  .wp-stack-layer + .wp-stack-layer {
    margin-top: -2px;
  }

  .wp-stack-highlight {
    border: 3px solid var(--accent);
    background: var(--bg-raised);
  }

  .wp-stack-label {
    font-size: 0.625rem;
    font-weight: 700;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    color: var(--text-dim);
    min-width: 6rem;
  }

  .wp-stack-highlight .wp-stack-label {
    color: var(--green);
  }

  .wp-stack-name {
    font-weight: 700;
    font-size: 0.9375rem;
  }

  .wp-stack-desc {
    font-size: 0.75rem;
    color: var(--text-muted);
    margin-left: auto;
  }

  /* ---- Horizontal rule ---- */
  .wp hr {
    border: none;
    border-top: 1px solid var(--border);
    margin: 3rem 0;
  }

  /* ---- Back-to-top nav ---- */
  .wp-nav {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 1rem 0;
    margin-bottom: 2rem;
  }

  .wp-nav a {
    font-size: 0.75rem;
    color: var(--text-muted);
    text-decoration: none;
  }

  .wp-nav a:hover {
    color: var(--text);
    opacity: 1;
  }

  /* ---- CTA ---- */
  .wp-cta {
    text-align: center;
    padding: 2.5rem 2rem;
    border: 2px solid var(--accent);
    margin: 3rem 0 0;
  }

  .wp-cta-title {
    font-size: 1rem;
    font-weight: 700;
    margin-bottom: 1rem;
  }

  .wp-cta code {
    display: block;
    font-size: 0.75rem;
    margin: 0.375rem 0;
    background: none;
    border: none;
    color: var(--text-muted);
  }

  .wp-cta-links {
    display: flex;
    justify-content: center;
    gap: 0.5rem;
    margin-top: 1.5rem;
    flex-wrap: wrap;
  }

  .wp-cta-link {
    font-size: 0.6875rem;
    padding: 0.375rem 0.75rem;
    border: 1px solid var(--border-bright);
    color: var(--text);
    text-decoration: none;
    transition: border-color 0.15s;
  }

  .wp-cta-link:hover {
    border-color: var(--accent);
    opacity: 1;
  }

  /* ---- Responsive ---- */
  @media (max-width: 768px) {
    .wp { padding: 2rem 1rem 3rem; }
    .wp-title { font-size: 1.5rem; }
    .wp h2 { font-size: 1.125rem; }
    .wp pre { font-size: 0.6875rem; padding: 1rem; }
    .wp table { font-size: 0.75rem; }
    .wp-stack-layer { flex-direction: column; gap: 0.25rem; }
    .wp-stack-desc { margin-left: 0; }
  }
`;

const WHITEPAPER_PAGE_CSS = DASHBOARD_CSS + WHITEPAPER_CSS;

// ============ PAGE COMPONENT ============

export const WhitepaperPage: FC<{ version: string }> = ({ version }) => {
  return (
    <html lang="en">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>BOTCHA Whitepaper — Identity Infrastructure for the Agentic Web</title>

        <meta name="description" content="Technical whitepaper on BOTCHA: reverse CAPTCHA for AI agents, Trusted Agent Protocol (TAP), and identity infrastructure for the agentic web." />
        <meta name="keywords" content="BOTCHA, whitepaper, AI agent identity, Trusted Agent Protocol, TAP, reverse CAPTCHA, agent verification, RFC 9421" />

        <OGMeta
          title="BOTCHA Whitepaper — Identity Infrastructure for the Agentic Web"
          description="How BOTCHA provides proof of AI, proof of identity, and proof of intent for the agentic web."
          url="https://botcha.ai/whitepaper"
          type="article"
        />

        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link
          href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&display=swap"
          rel="stylesheet"
        />
        <style dangerouslySetInnerHTML={{ __html: WHITEPAPER_PAGE_CSS }} />
      </head>
      <body>
        <article class="wp">

          {/* ---- Navigation ---- */}
          <nav class="wp-nav">
            <a href="/">&larr; botcha.ai</a>
            <a href="/whitepaper">v1.0 &middot; February 2026</a>
          </nav>

          {/* ---- Header ---- */}
          <header class="wp-header">
            <div class="wp-badge">Whitepaper</div>
            <h1 class="wp-title">Identity Infrastructure for the Agentic Web</h1>
            <p class="wp-subtitle">
              How BOTCHA provides proof of AI, proof of identity, and proof of intent
              for AI agents operating on the open internet.
            </p>
            <p class="wp-meta">
              Version 1.0 &middot; February 2026 &middot; <a href="https://dupe.com">Dupe.com</a>
            </p>
          </header>

          {/* ---- Table of Contents ---- */}
          <nav class="wp-toc">
            <div class="wp-toc-title">Contents</div>
            <ol>
              <li><a href="#executive-summary">Executive Summary</a></li>
              <li><a href="#the-problem">The Problem: Who Is This Agent?</a></li>
              <li><a href="#what-is-botcha">BOTCHA: Reverse CAPTCHA for AI Agents</a></li>
              <li><a href="#the-challenge-system">How It Works: The Challenge System</a></li>
              <li><a href="#tap">The Trusted Agent Protocol (TAP)</a></li>
              <li><a href="#architecture">Architecture and Security</a></li>
              <li><a href="#identity-layer">The Full Identity Layer</a></li>
              <li><a href="#protocol-integrations">Protocol Integrations</a></li>
              <li><a href="#integration">Integration: SDKs and Middleware</a></li>
              <li><a href="#the-stack">The Agent Infrastructure Stack</a></li>
              <li><a href="#use-cases">Use Cases</a></li>
              <li><a href="#roadmap">Roadmap</a></li>
            </ol>
          </nav>

          {/* ================================================================ */}
          {/* 1. EXECUTIVE SUMMARY                                             */}
          {/* ================================================================ */}
          <h2 id="executive-summary">1. Executive Summary</h2>

          <p>
            BOTCHA is a reverse CAPTCHA — a verification system that proves you are an AI agent,
            not a human. While traditional CAPTCHAs exist to block bots, BOTCHA exists to welcome them.
          </p>

          <p>
            As AI agents become first-class participants on the internet — browsing, purchasing,
            comparing, auditing — they need a way to prove their identity and declare their intent.
            BOTCHA provides three layers of proof:
          </p>

          <ul>
            <li><strong>Proof of AI</strong> — Computational challenges (SHA-256 hashes in under 500ms) that only machines can solve.</li>
            <li><strong>Proof of Identity</strong> — Persistent agent registration with cryptographic keys, verified via <a href="https://www.rfc-editor.org/rfc/rfc9421" target="_blank" rel="noopener">HTTP Message Signatures (RFC 9421)</a>.</li>
            <li><strong>Proof of Intent</strong> — Capability-scoped sessions where agents declare what they plan to do, for how long, and on behalf of whom.</li>
          </ul>

          <p>
            BOTCHA is open source, free to use, and deployed as a hosted service at{' '}
            <a href="https://botcha.ai">botcha.ai</a>. It ships TypeScript and Python SDKs,
            server-side verification middleware, a CLI, and a LangChain integration.
          </p>

          {/* ================================================================ */}
          {/* 2. THE PROBLEM                                                   */}
          {/* ================================================================ */}
          <h2 id="the-problem">2. The Problem: Who Is This Agent?</h2>

          <p>
            The internet was built for humans. Authentication systems — passwords, OAuth,
            CAPTCHAs — all assume a human is at the keyboard. But the web is changing.
          </p>

          <h3>The rise of agentic AI</h3>

          <p>
            AI agents are no longer just answering questions. They are <strong>browsing</strong> product
            catalogs on behalf of consumers, <strong>comparing</strong> prices across retailers,{' '}
            <strong>purchasing</strong> goods and services with real money,{' '}
            <strong>auditing</strong> compliance postures, and <strong>negotiating</strong> contracts.
          </p>

          <p>
            Every major AI lab is building agent capabilities. OpenAI's Operator, Anthropic's
            computer use, Google's Project Mariner — these are production systems that interact
            with real APIs and real businesses.
          </p>

          <h3>The identity gap</h3>

          <p>
            When an AI agent hits your API, you face three questions that existing infrastructure cannot answer:
          </p>

          <ol>
            <li><strong>Is this actually an AI agent?</strong> User-Agent strings are trivially spoofable. There is no reliable way to distinguish a real AI agent from a script pretending to be one.</li>
            <li><strong>Which specific agent is this?</strong> Even if you know it is AI, you do not know if it belongs to a known organization or what its track record is.</li>
            <li><strong>What does it intend to do?</strong> An agent browsing your catalog is very different from one attempting a purchase. Traditional auth grants blanket access — it does not capture intent.</li>
          </ol>

          <h3>What happens without agent identity</h3>

          <p>
            Without a reliable identity layer, the agentic web defaults to chaos. APIs cannot set
            appropriate rate limits. Businesses cannot authorize transactions. Agents cannot build
            reputation. Fraud is trivial because there is no audit trail.
          </p>

          {/* ================================================================ */}
          {/* 3. WHAT IS BOTCHA                                                */}
          {/* ================================================================ */}
          <h2 id="what-is-botcha">3. BOTCHA: Reverse CAPTCHA for AI Agents</h2>

          <p>
            BOTCHA inverts the CAPTCHA model. Instead of proving you are human, you prove you are a machine.
          </p>

          <h3>The core idea</h3>

          <p>
            A CAPTCHA asks: <em>Can you identify traffic lights in this image?</em> A human can; a bot struggles.
          </p>

          <p>
            BOTCHA asks: <em>Can you compute 5 SHA-256 hashes in 500 milliseconds?</em> A machine can;
            a human cannot copy-paste fast enough.
          </p>

          <p>
            This inversion is not just a novelty — it is a fundamental shift. In a world where AI agents
            are legitimate, wanted participants, the question is no longer "how do we keep bots out?" but
            "how do we let the right bots in?"
          </p>

          <h3>Design principles</h3>

          <p>
            <strong>Agent-first, always.</strong> Every feature in BOTCHA requires an AI agent as a participant.
            Humans are welcome, but only through an agent. If a human wants dashboard access, their agent
            generates a device code for them. There is no password form.
          </p>

          <p>
            <strong>Fail-open on infrastructure errors.</strong> If the backing store is unavailable,
            BOTCHA logs a warning and allows the request through. Blocking legitimate traffic is worse
            than letting an unverified request pass.
          </p>

          <p>
            <strong>Zero configuration to start.</strong> An agent can verify itself with a single HTTP
            request pair. No API keys, no registration — just solve the challenge and get a token.
          </p>

          {/* ================================================================ */}
          {/* 4. THE CHALLENGE SYSTEM                                          */}
          {/* ================================================================ */}
          <h2 id="the-challenge-system">4. How It Works: The Challenge System</h2>

          <p>
            BOTCHA offers four challenge types, each testing a different aspect of machine capability.
          </p>

          <h3>Speed Challenge</h3>

          <p>
            The primary verification method. The server generates 5 random 6-digit numbers.
            The agent computes the SHA-256 hash of each and returns the first 8 hex characters —
            all within <strong>500 milliseconds</strong>.
          </p>

          <p>
            The time limit is generous for any programming language but impossible for a human to
            copy-paste through. The challenge is not computationally hard — it is computationally
            trivial, but only if you are a machine.
          </p>

          <p>
            <strong>RTT-aware fairness:</strong> The time limit adjusts for network latency.
            An agent on a satellite connection gets extra time. This prevents geographic
            discrimination while capping at 5 seconds to prevent abuse.
          </p>

          <h3>Reasoning Challenge</h3>

          <p>
            Tests language understanding. The server selects 3 questions from 6 categories:
            math, code, logic, wordplay, common-sense, and analogy. The agent has 30 seconds.
          </p>

          <p>
            All questions use <strong>parameterized generators</strong> producing unique values each time.
            There is no static question bank to memorize. Combined with 45+ generators, the effective
            answer space is infinite.
          </p>

          <h3>Hybrid Challenge</h3>

          <p>
            The default challenge type. Combines speed and reasoning — both must pass.
            Proves the agent can compute fast <em>and</em> reason about language.
          </p>

          <h3>Standard (Compute) Challenge</h3>

          <p>
            A heavier computational challenge: generate prime numbers, concatenate with a random salt,
            compute SHA-256. Difficulty scales from easy (100 primes, 10s) to hard (1000 primes, 3s).
          </p>

          <table>
            <thead>
              <tr>
                <th>Challenge</th>
                <th>Tests</th>
                <th>Time Limit</th>
                <th>Best For</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>Speed</td>
                <td>Computation speed</td>
                <td>500ms</td>
                <td>Quick verification, high throughput</td>
              </tr>
              <tr>
                <td>Reasoning</td>
                <td>Language understanding</td>
                <td>30s</td>
                <td>Proving AI comprehension</td>
              </tr>
              <tr>
                <td>Hybrid</td>
                <td>Both</td>
                <td>35s</td>
                <td>Default — strongest proof</td>
              </tr>
              <tr>
                <td>Compute</td>
                <td>Heavy computation</td>
                <td>3-10s</td>
                <td>High-value operations</td>
              </tr>
            </tbody>
          </table>

          {/* ================================================================ */}
          {/* 5. TAP                                                           */}
          {/* ================================================================ */}
          <h2 id="tap">5. The Trusted Agent Protocol (TAP)</h2>

          <p>
            Solving a challenge proves you are <em>a bot</em>. TAP proves you are{' '}
            <em>a specific, trusted bot</em>.
          </p>

          <h3>What is TAP?</h3>

          <p>
            The Trusted Agent Protocol is an identity and authorization layer built on top of
            BOTCHA's proof-of-bot system. Inspired by{' '}
            <a href="https://developer.visa.com/capabilities/trusted-agent-protocol/overview" target="_blank" rel="noopener">Visa's Trusted Agent Protocol</a>,
            BOTCHA's TAP provides:
          </p>

          <ul>
            <li><strong>Persistent agent identity</strong> — unique ID, name, and operator metadata.</li>
            <li><strong>Cryptographic verification</strong> — ECDSA P-256 or RSA-PSS public keys; requests signed via <a href="https://www.rfc-editor.org/rfc/rfc9421" target="_blank" rel="noopener">HTTP Message Signatures (RFC 9421)</a>.</li>
            <li><strong>Capability-based access control</strong> — agents declare actions: <code>browse</code>, <code>search</code>, <code>compare</code>, <code>purchase</code>, <code>audit</code>.</li>
            <li><strong>Intent-scoped sessions</strong> — time-limited sessions validated against capabilities.</li>
            <li><strong>Trust levels</strong> — <code>basic</code>, <code>verified</code>, <code>enterprise</code>.</li>
          </ul>

          <h3>Agent registration</h3>

          <pre><code>{`POST /v1/agents/register/tap
{
  "name": "shopping-agent",
  "operator": "acme-corp",
  "capabilities": [
    { "action": "browse", "scope": ["products", "reviews"] },
    { "action": "purchase", "scope": ["products"],
      "restrictions": { "max_amount": 500 } }
  ],
  "trust_level": "basic"
}`}</code></pre>

          <p>
            For cryptographic identity, agents register a public key and sign requests using{' '}
            <a href="https://www.rfc-editor.org/rfc/rfc9421" target="_blank" rel="noopener">RFC 9421</a>:
          </p>

          <pre><code>{`x-tap-agent-id: agent_6ddfd9f10cfd8dfc
x-tap-intent: {"action":"browse","resource":"products"}
signature-input: sig1=("@method" "@path" "x-tap-agent-id");created=...;alg="ecdsa-p256-sha256"
signature: sig1=:BASE64_SIGNATURE:`}</code></pre>

          <h3>Intent validation and scoped sessions</h3>

          <p>
            Before acting, a TAP agent creates a session declaring its intent.
            The server validates the intent against the agent's registered capabilities,
            checks scope, and enforces a maximum duration of 24 hours.
          </p>

          <pre><code>{`POST /v1/sessions/tap
{
  "agent_id": "agent_6ddfd9f10cfd8dfc",
  "intent": { "action": "browse", "resource": "products", "duration": 3600 },
  "user_context": "anon_user_hash"
}`}</code></pre>

          <h3>The verification hierarchy</h3>

          <table>
            <thead>
              <tr>
                <th>Layer</th>
                <th>Proves</th>
                <th>Mechanism</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>Anonymous</td>
                <td>"I am a bot"</td>
                <td>Speed challenge in &lt;500ms</td>
              </tr>
              <tr>
                <td>App-scoped</td>
                <td>"I belong to this org"</td>
                <td>Challenge + app_id</td>
              </tr>
              <tr>
                <td>Agent identity</td>
                <td>"I am this specific bot"</td>
                <td>Registered ID + capabilities</td>
              </tr>
              <tr>
                <td>Cryptographic</td>
                <td>"I can prove I am this bot"</td>
                <td><a href="https://www.rfc-editor.org/rfc/rfc9421" target="_blank" rel="noopener">RFC 9421</a> signatures</td>
              </tr>
              <tr>
                <td>Dual auth</td>
                <td>"Verified bot, proven identity"</td>
                <td>Challenge + signature</td>
              </tr>
              <tr>
                <td>Intent-scoped</td>
                <td>"I intend to do this now"</td>
                <td>Validated session</td>
              </tr>
            </tbody>
          </table>

          {/* ================================================================ */}
          {/* 6. ARCHITECTURE                                                  */}
          {/* ================================================================ */}
          <h2 id="architecture">6. Architecture and Security</h2>


          <h3>Infrastructure</h3>

          <p>
            BOTCHA runs on <strong>Cloudflare Workers</strong> — deployed to 300+ edge locations
            globally. Sub-50ms cold starts, KV storage for all state, no servers to manage.
          </p>

          <h3>Token system</h3>

          <table>
            <thead>
              <tr>
                <th>Token</th>
                <th>Lifetime</th>
                <th>Purpose</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>Access token</td>
                <td>1 hour</td>
                <td>API access via Bearer header</td>
              </tr>
              <tr>
                <td>Refresh token</td>
                <td>1 hour</td>
                <td>Obtain new access tokens without re-solving</td>
              </tr>
            </tbody>
          </table>

          <p>
            Tokens are HMAC-SHA256 JWTs carrying the solved challenge ID (proof of work),
            a unique JTI for revocation, optional audience claims, and the solve time in milliseconds.
          </p>

          <h3>Cryptography</h3>

          <table>
            <thead>
              <tr>
                <th>Operation</th>
                <th>Algorithm</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>Challenge answers</td>
                <td>SHA-256</td>
              </tr>
              <tr>
                <td>Token signing</td>
                <td>HMAC-SHA256 (HS256)</td>
              </tr>
              <tr>
                <td>Secret storage</td>
                <td>SHA-256 (never stored in plaintext)</td>
              </tr>
              <tr>
                <td>TAP signatures</td>
                <td>ECDSA P-256 or RSA-PSS SHA-256</td>
              </tr>
              <tr>
                <td>Secret validation</td>
                <td>Constant-time comparison</td>
              </tr>
            </tbody>
          </table>

          <h3>Anti-gaming measures</h3>

          <ul>
            <li><strong>Single-use challenges</strong> — deleted from storage on first attempt.</li>
            <li><strong>Timestamp validation</strong> — rejects timestamps older than 30 seconds or in the future.</li>
            <li><strong>RTT capped at 5 seconds</strong> — prevents time manipulation.</li>
            <li><strong>Parameterized question generators</strong> — no static lookup tables.</li>
            <li><strong>Salted compute challenges</strong> — defeats precomputed hash tables.</li>
            <li><strong>User-Agent ignored</strong> — trivially spoofable, not used for verification.</li>
            <li><strong>Anti-enumeration</strong> — recovery endpoints return identical shapes regardless of email existence.</li>
          </ul>

          <h3>Human handoff</h3>

          <p>
            When a human needs dashboard access, the agent solves a challenge and receives a
            device code (e.g., <code>BOTCHA-RBA89X</code>). The human opens the link and is
            logged in. This adapts the <a href="https://www.rfc-editor.org/rfc/rfc8628" target="_blank" rel="noopener">OAuth 2.0 Device Authorization Grant (RFC 8628)</a> with a twist:
            the agent must solve a BOTCHA challenge to generate the code. No agent, no code.
          </p>

          {/* ================================================================ */}
          {/* 7. THE FULL IDENTITY LAYER                                       */}
          {/* ================================================================ */}
          <h2 id="identity-layer">7. The Full Identity Layer</h2>

          <p>
            BOTCHA has grown beyond a proof-of-bot challenge system into a complete identity
            infrastructure for AI agents. The stack now covers verification, delegation, attestation,
            reputation, portable credentials, and payment-gated access.
          </p>

          <h3>Delegation Chains</h3>

          <p>
            "User X authorized Agent Y to do Z until time T." Delegation chains encode this
            relationship cryptographically. An orchestrator agent can delegate a subset of its
            capabilities to a sub-agent, which can further sub-delegate — but capabilities can
            only narrow, never expand. Revoking any link cascades to all descendants.
          </p>

          <pre><code>{`POST /v1/delegations
{
  "grantor_id": "agent_aaa",
  "grantee_id": "agent_bbb",
  "capabilities": [{"action": "browse", "resource": "products"}],
  "ttl": 3600
}

POST /v1/verify/delegation  ← verify entire chain in one call`}</code></pre>

          <h3>Capability Attestation</h3>

          <p>
            Fine-grained permission tokens using <code>action:resource</code> patterns with
            explicit deny rules. An attestation token encodes both what an agent <em>can</em> do
            and what it explicitly <em>cannot</em> do. Deny rules always take precedence.
            Wildcards are supported: <code>browse:*</code>, <code>*:products</code>.
          </p>

          <pre><code>{`POST /v1/attestations
{
  "agent_id": "agent_...",
  "can": ["read:invoices", "browse:*"],
  "cannot": ["purchase:*"],
  "ttl": 3600
}
// Returns signed JWT → present as X-Botcha-Attestation header`}</code></pre>

          <h3>Agent Reputation</h3>

          <p>
            A score-based reputation system (0–1000, five tiers) that tracks agent behavior
            across 18 action types in 6 categories: verification, commerce, compliance, social,
            security, and governance. Scores decay toward the neutral midpoint (500) without
            activity, preventing stale reputation from persisting indefinitely.
          </p>

          <table>
            <thead>
              <tr><th>Score Range</th><th>Tier</th><th>Effect</th></tr>
            </thead>
            <tbody>
              <tr><td>0–199</td><td>untrusted</td><td>Blocked from sensitive endpoints</td></tr>
              <tr><td>200–399</td><td>low</td><td>Reduced rate limits</td></tr>
              <tr><td>400–599</td><td>neutral</td><td>Default access</td></tr>
              <tr><td>600–799</td><td>good</td><td>Elevated rate limits</td></tr>
              <tr><td>800–1000</td><td>excellent</td><td>Fastest paths, priority queues</td></tr>
            </tbody>
          </table>

          <h3>Webhooks</h3>

          <p>
            Per-app webhook endpoints receive signed event deliveries over HTTP POST.
            Payloads are signed with HMAC-SHA256. Apps can subscribe to specific event types:
            token lifecycle, TAP sessions, delegation changes.
          </p>

          {/* ================================================================ */}
          {/* 8. PROTOCOL INTEGRATIONS                                         */}
          {/* ================================================================ */}
          <h2 id="protocol-integrations">8. Protocol Integrations</h2>

          <p>
            BOTCHA integrates with every major emerging agentic protocol, acting as the
            identity and verification layer for each standard.
          </p>

          <h3>x402 Payment Gating</h3>

          <p>
            <a href="https://x402.org/" target="_blank" rel="noopener">x402</a> micropayment
            flow using USDC on Base. Agents pay $0.001 USDC instead of solving a speed challenge.
            The standard 402 Payment Required response carries payment terms; the agent
            re-requests with an <code>X-Payment</code> header carrying a payment proof and
            receives a BOTCHA access token.
          </p>

          <pre><code>{`GET /v1/x402/challenge
← 402 { amount: "0.001", currency: "USDC", chain: "base", recipient: "0x..." }
← Agent pays, retries with X-Payment header
← 200 { access_token: "eyJ..." }`}</code></pre>

          <p>
            This provides a payment-alternative to the proof-of-computation model — useful for
            high-throughput agents where challenge solving overhead is undesirable, and for
            monetizing API access without requiring a subscription.
          </p>

          <h3>Agent Name Service (ANS)</h3>

          <p>
            BOTCHA implements the{' '}
            <a href="https://www.godaddy.com/engineering/2024/12/16/agent-name-service/" target="_blank" rel="noopener">GoDaddy-led ANS standard</a>{' '}
            — a DNS-based agent identity system where an agent's name resolves via TXT records
            to its endpoint and identity metadata. BOTCHA serves as a verification and badging
            layer: agents prove ownership of their ANS name and receive a BOTCHA-signed badge JWT.
          </p>

          <pre><code>{`GET /v1/ans/resolve/my-agent.agents  → DNS TXT lookup + BOTCHA badge
POST /v1/ans/verify                  → prove DNS ownership → issue badge`}</code></pre>

          <h3>W3C DID / Verifiable Credentials</h3>

          <p>
            BOTCHA operates as a{' '}
            <a href="https://www.w3.org/TR/did-core/" target="_blank" rel="noopener">W3C Decentralized Identifier (DID)</a>{' '}
            issuer under <code>did:web:botcha.ai</code>. After solving a challenge, an agent can
            request a{' '}
            <a href="https://www.w3.org/TR/vc-data-model/" target="_blank" rel="noopener">W3C Verifiable Credential</a>{' '}
            JWT. The VC is signed with BOTCHA's private key and can be verified by any party who
            resolves the DID Document — no round-trip to BOTCHA required.
          </p>

          <pre><code>{`// 1. Resolve the issuer
GET /.well-known/did.json → DID Document with public key

// 2. Issue credential
POST /v1/credentials/issue  (Authorization: Bearer <botcha-token>)
→ { "vc": "eyJ..." }  ← portable JWT, verifiable offline

// 3. Anyone can verify
POST /v1/credentials/verify
→ { "valid": true, "payload": { "iss": "did:web:botcha.ai", ... } }`}</code></pre>

          <p>
            This enables agent credentials that travel across trust boundaries. A BOTCHA VC
            issued to an agent can be presented to a third-party API, a financial institution,
            or another agent network without those parties needing a BOTCHA account.
          </p>

          <h3>A2A Agent Card Attestation</h3>

          <p>
            Google's <a href="https://google.github.io/A2A/" target="_blank" rel="noopener">A2A (Agent-to-Agent) protocol</a>{' '}
            defines a standard JSON Agent Card format published at <code>/.well-known/agent.json</code>.
            BOTCHA acts as a trust seal issuer:
            any agent that publishes an A2A card can submit it to BOTCHA for attestation.
            BOTCHA produces a tamper-evident hash-and-signature bundle that third parties can
            verify without contacting BOTCHA again.
          </p>

          <pre><code>{`POST /v1/a2a/attest  (Authorization: Bearer <botcha-token>)
→ { "attestation": { "trust_level": "verified", "token": "eyJ..." },
    "attested_card": { "extensions": { "botcha_attestation": {...} } } }

POST /v1/a2a/verify-card  ← verify any attested card offline`}</code></pre>

          <p>
            BOTCHA publishes its own A2A Agent Card at{' '}
            <code>/.well-known/agent.json</code>, making it auto-discoverable by A2A-aware agents.
          </p>

          <h3>OIDC-A Attestation</h3>

          <p>
            Enterprise agent authentication chains require a bridge between human identity
            systems and agent identity systems.{' '}
            <a href="https://openid.net/specs/openid-connect-core-1_0.html" target="_blank" rel="noopener">OIDC-A (OpenID Connect for Agents)</a>{' '}
            provides this bridge. BOTCHA implements:
          </p>

          <ul>
            <li>
              <strong><a href="https://www.rfc-editor.org/rfc/rfc9334" target="_blank" rel="noopener">Entity Attestation Tokens (EAT / RFC 9334)</a></strong> — signed JWTs that
              attest agent provenance, verification method, and model identity. Suitable for
              presentation to enterprise relying parties.
            </li>
            <li>
              <strong>OIDC-A Agent Claims</strong> — an OIDC claims block carrying
              <code>agent_model</code>, <code>agent_operator</code>,{' '}
              <code>human_oversight_required</code>, and task metadata. Compatible with
              standard OAuth2 token responses.
            </li>
            <li>
              <strong>Agent Grant Flow</strong> — an OAuth2-style authorization grant where an
              agent requests access on behalf of a human. If <code>human_oversight_required</code>{' '}
              is set, the grant is pending until the human approves via a BOTCHA oversight URL.
            </li>
          </ul>

          <pre><code>{`// Enterprise chain: human → IdP → BOTCHA → agent
POST /v1/attestation/eat
→ EAT JWT (RFC 9334) for relying party presentation

POST /v1/auth/agent-grant
→ { "grant_id": "...", "status": "pending", "oversight_url": "..." }
// Human approves at oversight_url → agent receives access`}</code></pre>

          {/* ================================================================ */}
          {/* 9. INTEGRATION (renumbered)                                      */}
          {/* ================================================================ */}
          <h2 id="integration">9. Integration: SDKs and Middleware</h2>

          <h3>Client SDKs (for agents)</h3>

          <p><strong>TypeScript</strong> (<code>@dupecom/botcha</code> on npm):</p>
          <pre><code>{`import { BotchaClient } from '@dupecom/botcha';
const client = new BotchaClient();

// Drop-in fetch replacement — auto-solves challenges on 403
const response = await client.fetch('https://api.example.com/products');

// Or get a token explicitly
const token = await client.getToken();`}</code></pre>

          <p><strong>Python</strong> (<code>botcha</code> on PyPI):</p>
          <pre><code>{`from botcha import BotchaClient

async with BotchaClient() as client:
    response = await client.fetch("https://api.example.com/products")
    token = await client.get_token()`}</code></pre>

          <h3>Server-side verification (for API providers)</h3>

          <p><strong>Express:</strong></p>
          <pre><code>{`import { botchaVerify } from '@dupecom/botcha-verify';
app.get('/api/products', botchaVerify({ secret }), handler);`}</code></pre>

          <p><strong>FastAPI:</strong></p>
          <pre><code>{`from botcha_verify import BotchaVerify
botcha = BotchaVerify(secret=os.environ["BOTCHA_SECRET"])

@app.get("/api/products")
async def products(token=Depends(botcha)):
    return {"solve_time": token.solve_time}`}</code></pre>

          <p>
            Also available: Hono middleware, Django middleware, and TAP-enhanced middleware
            with full cryptographic + computational dual verification.
          </p>

          <h3>CLI</h3>

          <pre><code>{`npm install -g @dupecom/botcha-cli
botcha init --email you@company.com
botcha tap register --name "my-agent" --capabilities browse,search
botcha tap session --action browse --resource products --duration 1h`}</code></pre>

          {/* ================================================================ */}
          {/* 10. THE STACK                                                    */}
          {/* ================================================================ */}
          <h2 id="the-stack">10. The Agent Infrastructure Stack</h2>

          <p>
            BOTCHA positions itself alongside other emerging agent protocols:
          </p>

          <div class="wp-stack">
            <div class="wp-stack-layer wp-stack-highlight">
              <span class="wp-stack-label">BOTCHA</span>
              <span class="wp-stack-name">Identity + Trust Layer</span>
              <span class="wp-stack-desc">Who agents are, what they can do, what they've earned</span>
            </div>
            <div class="wp-stack-layer">
              <span class="wp-stack-label">Protocols</span>
              <span class="wp-stack-name">TAP / A2A / OIDC-A / ANS / DID-VC / x402</span>
              <span class="wp-stack-desc">Open standards BOTCHA implements as issuer/verifier</span>
            </div>
            <div class="wp-stack-layer">
              <span class="wp-stack-label">Coordination</span>
              <span class="wp-stack-name">A2A (Google) / MCP (Anthropic)</span>
              <span class="wp-stack-desc">How agents talk and access tools</span>
            </div>
            <div class="wp-stack-layer">
              <span class="wp-stack-label">Transport</span>
              <span class="wp-stack-name">HTTP / SSE / WebSocket</span>
              <span class="wp-stack-desc">Network layer</span>
            </div>
          </div>

          <p>
            <strong>MCP</strong> gives agents access to tools and data. <strong>A2A</strong> enables
            multi-agent coordination. <strong>BOTCHA</strong> provides the full identity layer:
            proof of AI, cryptographic identity (TAP), capability attestation, portable credentials
            (DID/VC), DNS-based names (ANS), enterprise auth chains (OIDC-A), and payment-gated
            access (x402).
          </p>

          <p>
            Without an identity layer, the other layers have a trust gap. MCP can give an agent
            access to a database, but who authorized it? A2A can let agents delegate tasks,
            but can you trust the delegate? BOTCHA closes this gap — at every layer of the stack.
          </p>

          {/* ================================================================ */}
          {/* 11. USE CASES                                                    */}
          {/* ================================================================ */}
          <h2 id="use-cases">11. Use Cases</h2>

          <h3>E-commerce agent verification</h3>
          <p>
            A shopping agent registers with <code>browse</code>, <code>compare</code>, and{' '}
            <code>purchase</code> capabilities. It creates sessions scoped to specific actions.
            The retailer verifies identity, checks capabilities, and maintains a full audit trail
            of which agent made each purchase, when, and on behalf of whom.
          </p>

          <h3>API access control</h3>
          <p>
            An API provider adds BOTCHA middleware to protected endpoints. Legitimate agents solve
            the speed challenge; scrapers pretending to be AI cannot. The provider gets rate limiting,
            solve-time analytics, and agent identification — without requiring API keys.
          </p>

          <h3>Multi-agent systems</h3>
          <p>
            A coordinator agent delegates tasks to sub-agents, each registered with scoped capabilities.
            The coordinator can verify sub-agent actions via TAP sessions. Capabilities are bounded
            at the protocol level.
          </p>

          <h3>Compliance and auditing</h3>
          <p>
            Financial services APIs use TAP's audit logging to record every agent interaction.
            Each request includes agent ID, intent, user context, and timestamp. Trust levels
            enable graduated access to sensitive endpoints.
          </p>

          {/* ================================================================ */}
          {/* 12. ROADMAP                                                      */}
          {/* ================================================================ */}
          <h2 id="roadmap">12. Roadmap</h2>

          <h3>Shipped (v0.22.0)</h3>

          <table>
            <thead>
              <tr>
                <th>Feature</th>
                <th>Description</th>
              </tr>
            </thead>
            <tbody>
              <tr><td>Challenge types</td><td>Speed, Reasoning, Hybrid, and Compute</td></tr>
              <tr><td>JWT token system</td><td>ES256 tokens, 1-hr access + refresh, revocation, audience claims</td></tr>
              <tr><td>Multi-tenant apps</td><td>Per-app rate limits, scoped tokens, isolated analytics</td></tr>
              <tr><td>Agent Registry</td><td>Persistent identities with names and operators</td></tr>
              <tr><td>TAP</td><td>Cryptographic identity (<a href="https://www.rfc-editor.org/rfc/rfc9421" target="_blank" rel="noopener">RFC 9421</a>), capability scoping, intent sessions, Layer 2/3</td></tr>
              <tr><td>Delegation chains</td><td>Signed capability delegation with cascade revocation</td></tr>
              <tr><td>Capability attestation</td><td>action:resource tokens with deny rules, wildcard patterns</td></tr>
              <tr><td>Agent reputation</td><td>0–1000 score, 5 tiers, 18 action types, mean-reversion decay</td></tr>
              <tr><td>Webhooks</td><td>Per-app signed event deliveries for 6 event types</td></tr>
              <tr><td>x402 payment gating</td><td><a href="https://x402.org/" target="_blank" rel="noopener">x402</a> HTTP 402 + USDC on Base — pay instead of solving</td></tr>
              <tr><td>ANS integration</td><td><a href="https://www.godaddy.com/engineering/2024/12/16/agent-name-service/" target="_blank" rel="noopener">GoDaddy ANS</a> standard — DNS-based identity + BOTCHA badges</td></tr>
              <tr><td>DID/VC issuer</td><td><a href="https://www.w3.org/TR/did-core/" target="_blank" rel="noopener">W3C DID</a> / <a href="https://www.w3.org/TR/vc-data-model/" target="_blank" rel="noopener">VC</a> — portable credential JWTs, offline-verifiable</td></tr>
              <tr><td>A2A attestation</td><td><a href="https://google.github.io/A2A/" target="_blank" rel="noopener">Google A2A</a> Agent Card trust seals, tamper-evident registry</td></tr>
              <tr><td>OIDC-A</td><td><a href="https://www.rfc-editor.org/rfc/rfc9334" target="_blank" rel="noopener">EAT (RFC 9334)</a>, OIDC-A claims, OAuth2 agent grant flow</td></tr>
              <tr><td>Dashboard</td><td>Agent-first auth (challenge + device code), per-app analytics</td></tr>
              <tr><td>SDKs</td><td>TypeScript, Python, CLI, LangChain integration</td></tr>
              <tr><td>Server verification</td><td>Express, Hono, FastAPI, Django middleware (JWKS + HS256)</td></tr>
              <tr><td>Discovery</td><td>ai.txt, OpenAPI 3.1, AI Plugin manifest, DID Document, A2A card</td></tr>
            </tbody>
          </table>

          <h3>Planned</h3>

          <table>
            <thead>
              <tr>
                <th>Feature</th>
                <th>Description</th>
              </tr>
            </thead>
            <tbody>
              <tr><td>Agent SSO</td><td>Verify once, trusted everywhere — federated BOTCHA identity</td></tr>
              <tr><td>Cross-chain x402</td><td>Support for Ethereum mainnet, Solana, Lightning</td></tr>
              <tr><td>Reputation marketplace</td><td>Agents earn reputation across partner networks</td></tr>
              <tr><td>RFC contribution</td><td>Internet-Draft for agent identity, target IETF</td></tr>
            </tbody>
          </table>

          {/* ---- CTA ---- */}
          <div class="wp-cta">
            <div class="wp-cta-title">Get started in 30 seconds</div>
            <code>npm install -g @dupecom/botcha-cli</code>
            <code>botcha init --email you@company.com</code>
            <code>botcha tap register --name "my-agent"</code>
            <div class="wp-cta-links">
              <a href="/" class="wp-cta-link">Home</a>
              <a href="https://github.com/dupe-com/botcha" class="wp-cta-link">GitHub</a>
              <a href="/openapi.json" class="wp-cta-link">OpenAPI</a>
              <a href="https://www.npmjs.com/package/@dupecom/botcha" class="wp-cta-link">npm</a>
              <a href="https://pypi.org/project/botcha/" class="wp-cta-link">PyPI</a>
              <a href="/dashboard" class="wp-cta-link">Dashboard</a>
            </div>
          </div>

        </article>

        <GlobalFooter version={version} />
      </body>
    </html>
  );
};
