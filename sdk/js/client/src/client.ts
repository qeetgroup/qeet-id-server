import { Http } from "./http.js";
import type {
  CurrentUser,
  ForgotPasswordParams,
  LoginContext,
  MagicLinkStartParams,
  Passkey,
  ResetPasswordParams,
  Session,
  SignInParams,
  SignInResult,
  SignUpParams,
  SocialStartParams,
  VerifyMfaParams,
} from "./types.js";
import { QeetIDApiError } from "./errors.js";
import { createCredential, getAssertion } from "./webauthn.js";

export type QeetIDClientOptions = {
  /** Base URL of the Qeet ID API, e.g. "https://api.id.qeet.in". */
  apiUrl: string;
};

// Backend response shapes (snake_case) we map from.
type SessionResponse = {
  user_id?: string;
  mfa_required?: boolean;
  mfa_token?: string;
  methods?: string[];
};
type LoginContextResponse = {
  client_name?: string;
  tenant_id?: string;
  providers?: string[];
  self_registration_enabled?: boolean;
  remember_device_enabled?: boolean;
  branding?: { logo_url?: string; primary_color?: string; secondary_color?: string } | null;
};

/**
 * QeetIDClient is the browser-side client for the Qeet ID auth flows. It is
 * cookie-based (the backend sets the HttpOnly SSO cookie), framework-agnostic,
 * and dependency-free — it powers both the hosted login app and the embedded
 * @qeet-id/react components/hooks.
 */
export class QeetIDClient {
  private readonly http: Http;
  readonly passkeys: PasskeysResource;
  readonly magicLink: MagicLinkResource;
  readonly sessions: SessionsResource;

  constructor(opts: QeetIDClientOptions) {
    this.http = new Http(opts.apiUrl);
    this.passkeys = new PasskeysResource(this.http);
    this.magicLink = new MagicLinkResource(this.http);
    this.sessions = new SessionsResource(this.http);
  }

  /** Fetch the hosted-login UI context (client name, providers, branding) for an
   * OAuth client_id. Returns sensible empty defaults when the id is unknown. */
  async loginContext(clientId: string): Promise<LoginContext> {
    const r = await this.http.get<LoginContextResponse>(
      `/v1/oauth/login-context?client_id=${encodeURIComponent(clientId)}`,
    );
    return {
      clientName: r.client_name ?? "",
      tenantId: r.tenant_id ?? "",
      providers: r.providers ?? [],
      selfRegistrationEnabled: r.self_registration_enabled ?? false,
      rememberDeviceEnabled: r.remember_device_enabled ?? false,
      branding: r.branding
        ? {
            logoUrl: r.branding.logo_url,
            primaryColor: r.branding.primary_color,
            secondaryColor: r.branding.secondary_color,
          }
        : undefined,
    };
  }

  /** Password sign-in. Establishes the session cookie, or reports that a second
   * factor is required (pass the returned mfaToken to `verifyMfa`). */
  async signIn({ email, password }: SignInParams): Promise<SignInResult> {
    const r = await this.http.post<SessionResponse>("/v1/auth/session", { email, password });
    if (r.mfa_required && r.mfa_token) {
      return { status: "needs_mfa", mfaToken: r.mfa_token, methods: r.methods ?? [] };
    }
    return { status: "complete", userId: r.user_id };
  }

  /** Complete a pending second-factor challenge (TOTP or recovery code). */
  async verifyMfa({ mfaToken, code, remember }: VerifyMfaParams): Promise<void> {
    await this.http.post("/v1/auth/session/mfa", {
      mfa_token: mfaToken,
      code,
      remember: remember ?? false,
    });
  }

  /** Tenant-scoped self-registration; establishes the session cookie on success. */
  async signUp({ tenantId, email, password, displayName }: SignUpParams): Promise<void> {
    await this.http.post("/v1/auth/register", {
      tenant_id: tenantId,
      email,
      password,
      display_name: displayName,
    });
  }

  /** Sign the current user out (clears the session server-side). */
  async signOut(): Promise<void> {
    await this.http.post("/v1/auth/logout");
  }

  /** Start a password-reset flow (enumeration-safe; tenant_id optional). */
  async forgotPassword({ email, tenantId }: ForgotPasswordParams): Promise<void> {
    const body: Record<string, string> = { email };
    if (tenantId) body.tenant_id = tenantId;
    await this.http.post("/v1/auth/forgot-password", body);
  }

  /** Complete a password reset with the emailed token. */
  async resetPassword({ token, newPassword }: ResetPasswordParams): Promise<void> {
    await this.http.post("/v1/auth/reset-password", { token, new_password: newPassword });
  }

  /** The current signed-in user, or null when there's no session. */
  async currentUser(): Promise<CurrentUser | null> {
    try {
      return await this.http.get<CurrentUser>("/v1/auth/me");
    } catch (e) {
      if (e instanceof QeetIDApiError && e.isUnauthorized) return null;
      throw e;
    }
  }

  /** Switch the active tenant for the current principal. */
  async switchTenant(tenantId: string): Promise<void> {
    await this.http.post("/v1/auth/switch-tenant", { tenant_id: tenantId });
  }

  /** Full-page redirect URL that starts a social (OAuth) sign-in. */
  socialStartUrl({ provider, tenantId, returnTo }: SocialStartParams): string {
    const q = new URLSearchParams({ tenant_id: tenantId, return_to: returnTo });
    return this.http.url(`/v1/social/${encodeURIComponent(provider)}/start?${q.toString()}`);
  }
}

// Begin responses for the WebAuthn ceremonies carry a session_id + JSON options.
type PasskeyBegin = { session_id: string; publicKey: unknown };

class PasskeysResource {
  constructor(private readonly http: Http) {}

  /** Passwordless passkey sign-in: begins the ceremony, prompts the
   * authenticator, and finishes — establishing the session cookie. */
  async login(): Promise<void> {
    const begin = await this.http.post<PasskeyBegin>("/v1/passkeys/login/begin", {});
    const credential = await getAssertion(begin.publicKey);
    await this.http.post("/v1/passkeys/login/finish", {
      session_id: begin.session_id,
      credential,
    });
  }

  /** Enroll a new passkey for the signed-in user. */
  async register(): Promise<void> {
    const begin = await this.http.post<PasskeyBegin>("/v1/passkeys/register/begin", {});
    const credential = await createCredential(begin.publicKey);
    await this.http.post("/v1/passkeys/register/finish", {
      session_id: begin.session_id,
      credential,
    });
  }

  /** List the signed-in user's registered passkeys. */
  list(): Promise<Passkey[]> {
    return this.http.get<Passkey[]>("/v1/passkeys");
  }

  /** Delete one of the user's passkeys. */
  delete(id: string): Promise<void> {
    return this.http.del(`/v1/passkeys/${encodeURIComponent(id)}`);
  }
}

class MagicLinkResource {
  constructor(private readonly http: Http) {}

  /** Send a passwordless magic link to the given email. */
  async start({ email, tenantId }: MagicLinkStartParams): Promise<void> {
    const body: Record<string, string> = { email };
    if (tenantId) body.tenant_id = tenantId;
    await this.http.post("/v1/auth/magic-link/start", body);
  }

  /** Consume a magic-link token, establishing the session cookie. */
  async consume(token: string): Promise<void> {
    await this.http.post("/v1/auth/magic-link/consume", { token });
  }
}

class SessionsResource {
  constructor(private readonly http: Http) {}

  /** List the current user's active sessions. */
  list(): Promise<Session[]> {
    return this.http.get<Session[]>("/v1/auth/sessions");
  }

  /** Revoke a session by id. */
  revoke(id: string): Promise<void> {
    return this.http.del(`/v1/auth/sessions/${encodeURIComponent(id)}`);
  }
}
