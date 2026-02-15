/**
 * BOTCHA Dashboard Layout + Shared Components
 * Hono JSX components for HTML shells and reusable UI pieces
 * Terminal / ASCII aesthetic
 */

import type { FC, PropsWithChildren } from 'hono/jsx';
import { DASHBOARD_CSS } from './styles';

// ============ OG META COMPONENT ============

/**
 * Shared Open Graph + Twitter Card meta tags.
 * Use on every page so social previews always work.
 * Pass overrides for page-specific titles/descriptions.
 */
export const OGMeta: FC<{
  title?: string;
  description?: string;
  url?: string;
  type?: string;
  image?: string;
}> = ({
  title = 'BOTCHA — The Identity Layer for AI Agents',
  description = 'Reverse CAPTCHA — Prove you\'re a bot. Humans need not apply. One of the first services to support the Trusted Agent Protocol (TAP).',
  url = 'https://botcha.ai',
  type = 'website',
  image = 'https://botcha.ai/og.png',
}) => (
  <>
    {/* Open Graph */}
    <meta property="og:title" content={title} />
    <meta property="og:description" content={description} />
    <meta property="og:url" content={url} />
    <meta property="og:type" content={type} />
    <meta property="og:image" content={image} />
    <meta property="og:image:width" content="1200" />
    <meta property="og:image:height" content="630" />
    <meta property="og:image:type" content="image/png" />
    {/* Twitter Card */}
    <meta name="twitter:card" content="summary_large_image" />
    <meta name="twitter:title" content={title} />
    <meta name="twitter:description" content={description} />
    <meta name="twitter:image" content={image} />
  </>
);

// ============ CARD COMPONENT ============

/**
 * Reusable card with Turbopuffer-style dotted drop shadow.
 *
 * Structure:
 *   .card
 *     .card-header  (title sits on the border line)
 *     .card-body    (::before = dot shadow)
 *       .card-inner (z-index: 1, white bg covers dots)
 *
 * Usage:
 *   <Card title="Overview" badge="agent required">
 *     ...content...
 *   </Card>
 */
export const Card: FC<PropsWithChildren<{ title: string; badge?: string; class?: string }>> = ({
  children,
  title,
  badge,
  class: className,
}) => {
  return (
    <div class={`card${className ? ` ${className}` : ''}`}>
      <div class="card-header">
        <h3>
          <span class="card-title">{title}</span>
          {badge && <span class="badge-inline">{badge}</span>}
        </h3>
      </div>
      <div class="card-body">
        <div class="card-inner">{children}</div>
      </div>
    </div>
  );
};

// ============ GLOBAL FOOTER ============

/**
 * Global footer used on every page.
 * Dashboard button + text links + copyright.
 */
export const GlobalFooter: FC<{ version?: string }> = ({ version = '0.15.0' }) => {
  const year = new Date().getFullYear();
  return (
    <footer class="global-footer">
      <div class="global-footer-inner">
        <a href="/dashboard" class="global-footer-dashboard">Dashboard</a>
        <div class="global-footer-links">
          <span>v{version}</span>
          <span class="global-footer-sep">&middot;</span>
          <a href="https://botcha.ai">botcha.ai</a>
          <span class="global-footer-sep">&middot;</span>
          <a href="/docs">Docs</a>
          <span class="global-footer-sep">&middot;</span>
          <a href="/whitepaper">Whitepaper</a>
          <span class="global-footer-sep">&middot;</span>
          <a href="/openapi.json">OpenAPI</a>
          <span class="global-footer-sep">&middot;</span>
          <a href="/ai.txt">ai.txt</a>
          <span class="global-footer-sep">&middot;</span>
          <a href="https://github.com/dupe-com/botcha">GitHub</a>
          <span class="global-footer-sep">&middot;</span>
          <a href="https://www.npmjs.com/package/@dupecom/botcha">npm</a>
          <span class="global-footer-sep">&middot;</span>
          <a href="https://pypi.org/project/botcha/">PyPI</a>
        </div>
        <div class="global-footer-legal">
          &copy; {year} <a href="https://dupe.com">Dupe.com</a>
          <span class="global-footer-sep">&middot;</span>
          Free and open source
          <span class="global-footer-sep">&middot;</span>
          <a href="https://github.com/i8ramin">@i8ramin</a>
        </div>
      </div>
    </footer>
  );
};

/**
 * Divider with centered text, used between sections on auth pages.
 */
export const Divider: FC<{ text: string }> = ({ text }) => (
  <div class="divider">{text}</div>
);

/**
 * Main dashboard layout with navigation
 * Used for authenticated dashboard pages
 */
export const DashboardLayout: FC<PropsWithChildren<{ title?: string; appId?: string; version?: string }>> = ({ children, title, appId, version }) => {
  return (
    <html lang="en">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>{title || 'BOTCHA Dashboard'}</title>
        <OGMeta url="https://botcha.ai/dashboard" />
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link
          href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&display=swap"
          rel="stylesheet"
        />
        <style dangerouslySetInnerHTML={{ __html: DASHBOARD_CSS }} />
        <script src="https://unpkg.com/htmx.org@2.0.4" />
      </head>
      <body>
        <nav class="dashboard-nav">
          <div class="nav-container">
            <a href="/dashboard" class="nav-logo">
              BOTCHA
            </a>
            {appId && (
              <>
                <span class="nav-app-id">{appId}</span>
                <a href="/dashboard/logout" class="nav-link">
                  Logout
                </a>
              </>
            )}
          </div>
        </nav>
        <main class="dashboard-main">{children}</main>
        <GlobalFooter version={version} />
      </body>
    </html>
  );
};

/**
 * Login/auth layout without navigation
 * Used for login, signup, and other auth pages
 */
export const LoginLayout: FC<PropsWithChildren<{ title?: string; version?: string }>> = ({ children, title, version }) => {
  return (
    <html lang="en">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>{title || 'BOTCHA Login'}</title>
        <OGMeta url="https://botcha.ai/dashboard/login" />
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link
          href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&display=swap"
          rel="stylesheet"
        />
        <style dangerouslySetInnerHTML={{ __html: DASHBOARD_CSS }} />
        <script src="https://unpkg.com/htmx.org@2.0.4" />
      </head>
      <body>
        <div class="login-container">
          <div class="login-box">{children}</div>
        </div>
        <GlobalFooter version={version} />
      </body>
    </html>
  );
};

/**
 * Landing page layout — wider than LoginLayout, includes SEO meta tags.
 * Used for the public landing page at GET /
 */
export const LandingLayout: FC<PropsWithChildren<{ version: string }>> = ({ children, version }) => {
  return (
    <html lang="en">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>BOTCHA — Reverse CAPTCHA for AI Agents</title>

        {/* SEO */}
        <meta name="description" content="BOTCHA is a hosted reverse CAPTCHA that verifies AI agents, not humans. Protect your APIs with computational challenges only bots can solve." />
        <meta name="keywords" content="AI, bot verification, reverse CAPTCHA, API security, AI agents, agent verification" />

        {/* AI Agent Discovery */}
        <link rel="alternate" type="application/json" href="/openapi.json" title="OpenAPI Specification" />
        <link rel="alternate" type="application/json" href="/.well-known/ai-plugin.json" title="AI Plugin Manifest" />
        <link rel="botcha-challenge" href="#botcha-challenge" type="application/botcha+json" title="Embedded Bot Challenge" />
        <meta name="ai-agent-welcome" content="true" />
        <meta name="botcha-challenge" content="embedded" data-selector="script[type='application/botcha+json']" />

        <OGMeta />

        {/* Schema.org */}
        <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify({
          '@context': 'https://schema.org',
          '@type': 'SoftwareApplication',
          name: 'BOTCHA',
          applicationCategory: 'DeveloperApplication',
          description: 'Hosted reverse CAPTCHA for AI agents. Computational challenges that only bots can solve.',
          url: 'https://botcha.ai',
          offers: { '@type': 'Offer', price: '0', priceCurrency: 'USD' },
          operatingSystem: 'Any',
          softwareVersion: version,
        }) }} />

        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link
          href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&display=swap"
          rel="stylesheet"
        />
        <style dangerouslySetInnerHTML={{ __html: DASHBOARD_CSS }} />
      </head>
      <body>
        <div class="login-container">
          <div class="landing-box">{children}</div>
        </div>
        <GlobalFooter version={version} />
      </body>
    </html>
  );
};
