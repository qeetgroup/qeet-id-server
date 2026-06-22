export interface QeetidUser {
  id?: string;
  sub?: string;
  email?: string;
  displayName?: string;
  tenantId?: string;
  [key: string]: unknown;
}

export interface QeetidState {
  /** False during the brief window before the provider mounts. */
  isLoaded: boolean;
  isAuthenticated: boolean;
  userId?: string;
  tenantId?: string;
  sessionId?: string;
  user?: QeetidUser | null;
}
