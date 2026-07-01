// Public types for the browser client. Well-known auth flows are mapped to
// camelCase result types; pass-through resources (sessions, passkeys, me) keep
// the backend's own field names under an index signature so the client stays a
// thin, forward-compatible wrapper.

export type Branding = {
  logoUrl?: string;
  primaryColor?: string;
  secondaryColor?: string;
};

/** The hosted-login UI context for a given OAuth client_id. */
export type LoginContext = {
  clientName: string;
  tenantId: string;
  providers: string[];
  selfRegistrationEnabled: boolean;
  rememberDeviceEnabled: boolean;
  branding?: Branding;
};

/**
 * The outcome of a password sign-in: either the session is established
 * ("complete") or a second factor is required ("needs_mfa"), in which case the
 * caller collects a code and calls `verifyMfa` with the returned `mfaToken`.
 */
export type SignInResult =
  | { status: "complete"; userId?: string }
  | { status: "needs_mfa"; mfaToken: string; methods: string[] };

export type SignInParams = { email: string; password: string };
export type SignUpParams = {
  tenantId: string;
  email: string;
  password: string;
  displayName?: string;
};
export type VerifyMfaParams = { mfaToken: string; code: string; remember?: boolean };
export type ForgotPasswordParams = { email: string; tenantId?: string };
export type ResetPasswordParams = { token: string; newPassword: string };
export type MagicLinkStartParams = { email: string; tenantId?: string };
export type SocialStartParams = { provider: string; tenantId: string; returnTo: string };

export type CurrentUser = {
  sub?: string;
  userId?: string;
  tenantId?: string;
  email?: string;
  displayName?: string;
  [key: string]: unknown;
};

export type Session = {
  id: string;
  current?: boolean;
  [key: string]: unknown;
};

export type Passkey = {
  id: string;
  name?: string;
  [key: string]: unknown;
};
