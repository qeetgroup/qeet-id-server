export interface QeetIDUser {
  id?: string;
  sub?: string;
  email?: string;
  displayName?: string;
  tenantId?: string;
  [key: string]: unknown;
}

export interface QeetIDState {
  /** False during the brief window before the provider mounts. */
  isLoaded: boolean;
  isAuthenticated: boolean;
  userId?: string;
  tenantId?: string;
  sessionId?: string;
  user?: QeetIDUser | null;
}
