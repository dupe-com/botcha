/**
 * BOTCHA Dashboard — Hono Sub-Application
 *
 * Mounts at /dashboard on the main worker.
 * Routes:
 *   GET  /dashboard           → main dashboard (auth required)
 *   GET  /dashboard/login     → login page
 *   POST /dashboard/login     → login handler
 *   GET  /dashboard/logout    → logout handler
 *   GET  /dashboard/api/*     → htmx data endpoints (auth required)
 */

import { Hono } from 'hono';
import {
  requireDashboardAuth,
  handleLogin,
  handleLogout,
  handleEmailLogin,
  renderLoginPage,
  renderDeviceCodePage,
  handleDeviceCodeRedeem,
} from './auth';
import { DashboardPage } from './pages';
import {
  handleOverview,
  handleVolume,
  handleTypes,
  handlePerformance,
  handleErrors,
  handleGeo,
} from './api';

// Types matching the main app
type Bindings = {
  CHALLENGES: import('../challenges').KVNamespace;
  RATE_LIMITS: import('../challenges').KVNamespace;
  APPS: import('../challenges').KVNamespace;
  ANALYTICS?: import('../analytics').AnalyticsEngineDataset;
  JWT_SECRET: string;
  BOTCHA_VERSION: string;
  CF_API_TOKEN?: string;
  CF_ACCOUNT_ID?: string;
};

type Variables = {
  dashboardAppId?: string;
};

const dashboard = new Hono<{ Bindings: Bindings; Variables: Variables }>();

// ============ PUBLIC ROUTES (no auth) ============

// Login page
dashboard.get('/login', renderLoginPage);

// Login handler
dashboard.post('/login', handleLogin);

// Email login handler (sends device code to email)
dashboard.post('/email-login', handleEmailLogin);

// Logout handler
dashboard.get('/logout', handleLogout);

// Device code pages (human enters code here)
dashboard.get('/code', renderDeviceCodePage);
dashboard.get('/code/:code', renderDeviceCodePage); // Pre-filled code from URL
dashboard.post('/code', handleDeviceCodeRedeem);

// ============ PROTECTED ROUTES (auth required) ============

// Apply auth middleware to all routes below
dashboard.use('/*', requireDashboardAuth);

// Main dashboard page
dashboard.get('/', (c) => {
  const appId = c.get('dashboardAppId') || 'unknown';
  return c.html(<DashboardPage appId={appId} />);
});

// API endpoints (return HTML fragments for htmx)
// Note: cast context to `any` because api.ts uses a flexible DashboardEnv type
dashboard.get('/api/overview', (c) => {
  const appId = c.get('dashboardAppId') || '';
  return handleOverview(c as any, appId);
});

dashboard.get('/api/volume', (c) => {
  const appId = c.get('dashboardAppId') || '';
  return handleVolume(c as any, appId);
});

dashboard.get('/api/types', (c) => {
  const appId = c.get('dashboardAppId') || '';
  return handleTypes(c as any, appId);
});

dashboard.get('/api/performance', (c) => {
  const appId = c.get('dashboardAppId') || '';
  return handlePerformance(c as any, appId);
});

dashboard.get('/api/errors', (c) => {
  const appId = c.get('dashboardAppId') || '';
  return handleErrors(c as any, appId);
});

dashboard.get('/api/geo', (c) => {
  const appId = c.get('dashboardAppId') || '';
  return handleGeo(c as any, appId);
});

export default dashboard;
