// Shared contract types for the Enterprise Live Activity Center.
// Must be kept in sync with the backend's /v1/activity API.

export type Severity = "info" | "success" | "warning" | "error" | "critical";

export type ConnectionStatus = "connected" | "reconnecting" | "disconnected" | "paused";

export interface ActivityEvent {
  id: string;
  type: string;
  category: string;
  severity: Severity;
  title: string;
  description?: string;
  actor?: { id?: string; name?: string; type?: string };
  target?: { type?: string; id?: string; label?: string };
  /** RFC3339 timestamp */
  at: string;
  source?: string;
  ip?: string;
  location?: string;
  device?: string;
  browser?: string;
  status?: string;
  metadata?: Record<string, unknown>;
}

export interface ActivityFilters {
  types: string[];
  severity: Severity[];
  category: string[];
  actor: string;
  q: string;
  from: string;
  to: string;
  source: string;
  status: string;
}

export const DEFAULT_FILTERS: ActivityFilters = {
  types: [],
  severity: [],
  category: [],
  actor: "",
  q: "",
  from: "",
  to: "",
  source: "",
  status: "",
};

export interface DateGroup {
  label: string;
  events: ActivityEvent[];
}
