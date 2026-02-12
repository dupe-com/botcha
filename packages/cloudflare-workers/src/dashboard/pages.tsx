/**
 * BOTCHA Dashboard Pages — Hono JSX + htmx
 *
 * Server-rendered pages with htmx for dynamic data loading.
 * Each section uses hx-get to fetch HTML fragments from /dashboard/api/*.
 */

import type { FC } from 'hono/jsx';
import { DashboardLayout } from './layout';

// ============ PERIOD SELECTOR ============

const PeriodSelector: FC<{ currentPeriod?: string; targetId: string; endpoint: string }> = ({
  currentPeriod = '24h',
  targetId,
  endpoint,
}) => {
  const periods = [
    { value: '1h', label: '1H' },
    { value: '24h', label: '24H' },
    { value: '7d', label: '7D' },
    { value: '30d', label: '30D' },
  ];

  return (
    <div class="period-selector" style="display: flex; gap: 0.5rem; margin-bottom: 1rem;">
      {periods.map((p) => (
        <button
          class={p.value === currentPeriod ? '' : 'secondary'}
          hx-get={`${endpoint}?period=${p.value}`}
          hx-target={`#${targetId}`}
          hx-swap="innerHTML"
          style="padding: 0.4rem 0.8rem; font-size: 0.75rem;"
        >
          {p.label}
        </button>
      ))}
    </div>
  );
};

// ============ LOADING SKELETON ============

const LoadingSkeleton: FC = () => (
  <div>
    <div class="skeleton skeleton-heading" />
    <div class="skeleton skeleton-text" style="width: 80%;" />
    <div class="skeleton skeleton-text" style="width: 60%;" />
    <div class="skeleton skeleton-text" style="width: 90%;" />
  </div>
);

// ============ MAIN DASHBOARD PAGE ============

export const DashboardPage: FC<{ appId: string }> = ({ appId }) => {
  return (
    <DashboardLayout title="BOTCHA Dashboard" appId={appId}>
      <h1 style="font-size: 1.25rem; font-weight: 700; margin-bottom: 0.5rem; text-transform: uppercase; letter-spacing: 0.08em;">
        Dashboard
      </h1>
      <p class="text-muted mb-3" style="font-size: 0.8125rem;">
        Per-app metrics for <code>{appId}</code>
      </p>

      {/* Overview Stats */}
      <div class="card">
        <div class="card-header"><h3><span>Overview</span></h3></div>
        <div class="card-body"><div class="card-inner">
          <PeriodSelector targetId="overview-content" endpoint="/dashboard/api/overview" />
          <div
            id="overview-content"
            hx-get="/dashboard/api/overview?period=24h"
            hx-trigger="load"
            hx-swap="innerHTML"
          >
            <LoadingSkeleton />
          </div>
        </div></div>
      </div>

      {/* Two-column grid for charts */}
      <div class="dashboard-grid">
        {/* Volume */}
        <div>
          <PeriodSelector targetId="volume-content" endpoint="/dashboard/api/volume" />
          <div
            id="volume-content"
            hx-get="/dashboard/api/volume?period=24h"
            hx-trigger="load"
            hx-swap="innerHTML"
          >
            <LoadingSkeleton />
          </div>
        </div>

        {/* Challenge Types */}
        <div>
          <PeriodSelector targetId="types-content" endpoint="/dashboard/api/types" />
          <div
            id="types-content"
            hx-get="/dashboard/api/types?period=24h"
            hx-trigger="load"
            hx-swap="innerHTML"
          >
            <LoadingSkeleton />
          </div>
        </div>
      </div>

      {/* Performance Table */}
      <PeriodSelector targetId="performance-content" endpoint="/dashboard/api/performance" />
      <div
        id="performance-content"
        hx-get="/dashboard/api/performance?period=24h"
        hx-trigger="load"
        hx-swap="innerHTML"
      >
        <LoadingSkeleton />
      </div>

      {/* Two-column grid: Errors + Geo */}
      <div class="dashboard-grid">
        {/* Errors */}
        <div>
          <PeriodSelector targetId="errors-content" endpoint="/dashboard/api/errors" />
          <div
            id="errors-content"
            hx-get="/dashboard/api/errors?period=24h"
            hx-trigger="load"
            hx-swap="innerHTML"
          >
            <LoadingSkeleton />
          </div>
        </div>

        {/* Geographic Distribution */}
        <div>
          <PeriodSelector targetId="geo-content" endpoint="/dashboard/api/geo" />
          <div
            id="geo-content"
            hx-get="/dashboard/api/geo?period=24h"
            hx-trigger="load"
            hx-swap="innerHTML"
          >
            <LoadingSkeleton />
          </div>
        </div>
      </div>

      {/* Footer */}
      <div class="text-center text-dim mt-4" style="font-size: 0.6875rem; padding-bottom: 2rem; letter-spacing: 0.02em;">
        BOTCHA &middot; Cloudflare Analytics Engine &middot;{' '}
        <a href="/" style="font-size: 0.6875rem; color: #555555;">
          API Docs
        </a>
      </div>
    </DashboardLayout>
  );
};
