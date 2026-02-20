// Shared app-gate path rules for /v1/* middleware.

// App gate open paths that do not require app_id.
export const APP_GATE_OPEN_PATHS = [
  '/v1/apps',                       // POST: create app (registration)
  '/v1/auth/recover',               // POST: account recovery
  '/v1/token/validate',             // POST: public token validation — token is credential
  // x402 endpoints: payment is the credential
  '/v1/x402/challenge',
  '/v1/x402/verify-payment',
  '/v1/x402/webhook',
  '/v1/x402/info',
  // Public ANS + DID/VC endpoints under /v1/*
  '/v1/ans/discover',
  '/v1/ans/botcha',
  '/v1/ans/resolve/lookup',
  '/v1/credentials/verify',
  // OIDC-A UserInfo accepts BOTCHA access tokens OR EAT bearer tokens.
  // EAT tokens are not app-gate tokens, so this route must bypass app-gate
  // and perform its own auth checks in the route handler.
  '/v1/oidc/userinfo',
  // Public A2A verification and discovery endpoints
  '/v1/a2a/agent-card',
  '/v1/a2a/verify-card',
  '/v1/a2a/verify-agent',
  '/v1/a2a/cards',
];

// Pattern-match paths that start with /v1/apps/:id/ (verify-email, resend-verification, etc.)
export function isAppManagementPath(path: string): boolean {
  return /^\/v1\/apps\/[^/]+\/(verify-email|resend-verification)$/.test(path);
}

export function isPublicV1Path(path: string): boolean {
  // Public ANS resolution paths: /v1/ans/resolve/:name
  if (path.startsWith('/v1/ans/resolve/')) return true;

  // Public DID resolution path: /v1/dids/:did/resolve
  if (/^\/v1\/dids\/[^/]+\/resolve$/.test(path)) return true;

  // Public A2A routes with dynamic path params
  if (path.startsWith('/v1/a2a/cards/')) return true;
  if (path.startsWith('/v1/a2a/trust-level/')) return true;

  return false;
}

export function shouldBypassAppGate(path: string): boolean {
  return APP_GATE_OPEN_PATHS.includes(path) || isAppManagementPath(path) || isPublicV1Path(path);
}
