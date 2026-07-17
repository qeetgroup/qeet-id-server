// Dashboard analytics data layer. One round-trip per render —
// /v1/tenants/{tenantID}/analytics/overview returns every KPI + chart
// in a single payload so the dashboard doesn't ladder 8 requests at
// first paint. If the endpoint 404s (e.g. an older backend without
// IMPROVEMENTS §4.8), the hook falls back to a stable empty shape so
// the dashboard renders skeletons instead of crashing.

import { useQuery } from "@tanstack/react-query";

import { ApiError, api } from "./api";
import { useTenantId } from "./auth";

export interface Metric {
  value: number;
  delta_pct: number;
}

export interface TrendPoint {
  date: string;
  value: number;
}

export interface ActivityPoint {
  date: string;
  password: number;
  passkey: number;
  social: number;
  saml: number;
  oidc: number;
}

export interface MethodSlice {
  method: string;
  value: number;
}

export interface MethodCount {
  method: string;
  users: number;
}

export interface HourlyPoint {
  hour: string;
  attempts: number;
}

export interface WeeklyActivityPoint {
  week: string;
  wau: number;
  dau: number;
}

export interface AnalyticsOverview {
  generated_at: string;
  kpis: {
    mau: Metric;
    logins_today: Metric;
    mfa_adoption_pct: Metric;
    failed_logins_24h: Metric;
    dau: Metric;
    total_users: Metric;
    avg_sessions_per_user: Metric;
    stickiness_pct: Metric;
  };
  weekly_activity_8w: WeeklyActivityPoint[];
  user_trend_14d: TrendPoint[];
  login_trend_14d: TrendPoint[];
  mfa_trend_14d: TrendPoint[];
  failed_trend_14d: TrendPoint[];
  login_activity_14d: ActivityPoint[];
  login_methods_mix: MethodSlice[];
  mfa_methods_adoption: MethodCount[];
  failed_logins_hourly_24h: HourlyPoint[];
}

const EMPTY_METRIC: Metric = { value: 0, delta_pct: 0 };

export const EMPTY_OVERVIEW: AnalyticsOverview = {
  generated_at: new Date(0).toISOString(),
  kpis: {
    mau: EMPTY_METRIC,
    logins_today: EMPTY_METRIC,
    mfa_adoption_pct: EMPTY_METRIC,
    failed_logins_24h: EMPTY_METRIC,
    dau: EMPTY_METRIC,
    total_users: EMPTY_METRIC,
    avg_sessions_per_user: EMPTY_METRIC,
    stickiness_pct: EMPTY_METRIC,
  },
  weekly_activity_8w: [],
  user_trend_14d: [],
  login_trend_14d: [],
  mfa_trend_14d: [],
  failed_trend_14d: [],
  login_activity_14d: [],
  login_methods_mix: [],
  mfa_methods_adoption: [],
  failed_logins_hourly_24h: [],
};

/**
 * Fetches the dashboard overview for the current tenant. Stale-time is
 * 60s — KPI cards don't need to be real-time, and the dashboard already
 * polls activity-feed components individually for fresher signals.
 */
export function useAnalyticsOverview(enabled = true) {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: ["analytics", "overview", tenantId],
    enabled: !!tenantId && enabled,
    staleTime: 60_000,
    queryFn: async (): Promise<AnalyticsOverview> => {
      try {
        return await api<AnalyticsOverview>(`/v1/tenants/${tenantId}/analytics/overview`);
      } catch (err) {
        // Backend without §4.8: surface empty data instead of an error
        // page. Anything else (auth, server error) bubbles up so the
        // user sees the real problem.
        if (err instanceof ApiError && (err.status === 404 || err.status === 501)) {
          return EMPTY_OVERVIEW;
        }
        throw err;
      }
    },
    meta: { silent: true },
  });
}

/**
 * Friendly short label for a date string ("2026-05-26" → "May 26"). The
 * recharts axis is tight on space; full ISO labels stack vertically.
 */
export function formatShortDate(iso: string): string {
  const d = new Date(`${iso}T00:00:00Z`);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    timeZone: "UTC",
  });
}
