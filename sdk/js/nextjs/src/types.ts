/** What the encrypted session cookie holds. */
export interface SessionData {
  accessToken: string;
  refreshToken?: string;
  idToken?: string;
  /** Access-token expiry, unix seconds. */
  expiresAt: number;
  userId: string;
  tenantId?: string;
  sessionId?: string;
}

/** Result of auth(). */
export interface AuthState {
  isAuthenticated: boolean;
  userId?: string;
  tenantId?: string;
  sessionId?: string;
  accessToken?: string;
}
