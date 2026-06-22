"use client";

import { QeetLogo } from "@qeetrix/brand";
import { Button, Card, CardContent, Input } from "@qeetrix/ui";
import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";

import { ProviderIcon } from "@/components/social-providers";
import { API_BASE_URL, ApiError, apiPost } from "@/lib/api";

type LoginFormProps = {
  returnTo: string;
  clientName: string;
  tenantId: string;
  providers: string[];
  selfRegistrationEnabled: boolean;
  // rememberDeviceEnabled gates the "remember this device" option on the MFA
  // step (adaptive MFA); true only when the tenant has opted in.
  rememberDeviceEnabled: boolean;
  // errorCode seeds the error banner from a redirect (e.g. a failed social
  // ceremony bounced back as ?error=social); empty when there's nothing to show.
  errorCode: string;
};

// safeReturnTo guards against open redirects: we only ever bounce back to our
// own backend's /oauth/authorize endpoint.
function safeReturnTo(returnTo: string): string | null {
  if (!returnTo) return null;
  try {
    const u = new URL(returnTo);
    const base = new URL(API_BASE_URL);
    if (u.origin === base.origin && u.pathname.endsWith("/oauth/authorize")) {
      return u.toString();
    }
  } catch {
    /* malformed — fall through */
  }
  return null;
}

function titleCase(s: string) {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

// The hosted-login session endpoint returns either the user id (cookie set) or,
// when a second factor is enrolled, a pending MFA challenge to complete.
type SessionResponse = {
  user_id?: string;
  mfa_required?: boolean;
  mfa_token?: string;
  methods?: string[];
};

export function LoginForm({
  returnTo,
  clientName,
  tenantId,
  providers,
  selfRegistrationEnabled,
  rememberDeviceEnabled,
  errorCode,
}: LoginFormProps) {
  const { t } = useTranslation("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(
    errorCode ? t(`errors.${errorCode}`, { defaultValue: t("common:errors.generic") }) : null,
  );
  const [loading, setLoading] = useState(false);
  const [passkeyBusy, setPasskeyBusy] = useState(false);
  // The pending MFA challenge token is held only in memory (never the URL) and,
  // when set, swaps the credential form for the second-factor step.
  const [mfaToken, setMfaToken] = useState<string | null>(null);

  function continueToApp() {
    const dest = safeReturnTo(returnTo);
    window.location.href = dest ?? "/login";
  }

  async function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const res = await apiPost<SessionResponse>("/v1/auth/session", { email, password });
      if (res.mfa_required && res.mfa_token) {
        setMfaToken(res.mfa_token);
        setLoading(false);
        return;
      }
      continueToApp();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t("common:errors.generic"));
      setLoading(false);
    }
  }

  if (mfaToken) {
    return (
      <MfaChallenge
        mfaToken={mfaToken}
        rememberDeviceEnabled={rememberDeviceEnabled}
        onVerified={continueToApp}
        onBack={() => {
          setMfaToken(null);
          setError(null);
        }}
      />
    );
  }

  // Social: a full-page redirect into the hosted social flow, which sets the SSO
  // cookie on the provider callback and returns to the authorize URL.
  function socialStart(provider: string) {
    const q = new URLSearchParams({ tenant_id: tenantId, return_to: returnTo });
    window.location.href = `${API_BASE_URL}/v1/social/${provider}/start?${q.toString()}`;
  }

  async function passkeyLogin() {
    setError(null);
    setPasskeyBusy(true);
    try {
      const PK = window.PublicKeyCredential as
        | (typeof window.PublicKeyCredential & {
            parseRequestOptionsFromJSON?: (o: unknown) => PublicKeyCredentialRequestOptions;
          })
        | undefined;
      if (!PK || !navigator.credentials) {
        throw new Error(t("errors.passkeyUnsupported"));
      }
      const begin = await apiPost<{ session_id: string; publicKey: unknown }>(
        "/v1/passkeys/login/begin",
        {},
      );
      const options = PK.parseRequestOptionsFromJSON
        ? PK.parseRequestOptionsFromJSON(begin.publicKey)
        : (begin.publicKey as PublicKeyCredentialRequestOptions);
      const assertion = (await navigator.credentials.get({
        publicKey: options,
      })) as PublicKeyCredential & {
        toJSON?: () => unknown;
      };
      if (!assertion) throw new Error(t("errors.noPasskeySelected"));
      const credential = assertion.toJSON ? assertion.toJSON() : assertion;
      await apiPost("/v1/passkeys/login/finish", { session_id: begin.session_id, credential });
      continueToApp();
    } catch (err) {
      setError(
        err instanceof ApiError ? err.message : (err as Error).message || t("errors.passkeyFailed"),
      );
      setPasskeyBusy(false);
    }
  }

  const busy = loading || passkeyBusy;
  const showSocial = providers.length > 0 && tenantId !== "" && returnTo !== "";

  return (
    <Card className="w-full max-w-sm">
      <CardContent className="space-y-6 pt-6">
        <div className="space-y-2 text-center">
          <QeetLogo size={40} className="mx-auto" />
          <h1 className="text-xl font-semibold tracking-tight">
            {clientName ? t("titleTo", { client: clientName }) : t("title")}
          </h1>
          <p className="text-muted-foreground text-sm">{t("subtitle")}</p>
        </div>

        <form onSubmit={onSubmit} className="space-y-4">
          <div className="space-y-1.5">
            <label htmlFor="email" className="text-sm font-medium">
              {t("fields.email")}
            </label>
            <Input
              id="email"
              type="email"
              autoComplete="email webauthn"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="you@example.com"
            />
          </div>
          <div className="space-y-1.5">
            <label htmlFor="password" className="text-sm font-medium">
              {t("fields.password")}
            </label>
            <Input
              id="password"
              type="password"
              autoComplete="current-password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
            <div className="text-right">
              <a
                href={`/forgot-password${returnTo ? `?return_to=${encodeURIComponent(returnTo)}` : ""}`}
                className="text-muted-foreground hover:text-foreground text-xs underline"
              >
                {t("forgotPassword")}
              </a>
            </div>
          </div>

          {error && (
            <p role="alert" className="text-destructive text-sm">
              {error}
            </p>
          )}

          <Button type="submit" className="w-full" disabled={busy}>
            {loading ? t("submit.busy") : t("submit.idle")}
          </Button>
        </form>

        <Button
          type="button"
          variant="outline"
          className="w-full"
          disabled={busy}
          onClick={passkeyLogin}
        >
          {passkeyBusy ? t("passkey.busy") : t("passkey.idle")}
        </Button>

        {showSocial && (
          <div className="space-y-3">
            <div className="flex items-center gap-3">
              <span className="bg-border h-px flex-1" />
              <span className="text-muted-foreground text-xs">{t("social.divider")}</span>
              <span className="bg-border h-px flex-1" />
            </div>
            <div className="grid gap-2">
              {providers.map((p) => (
                <Button
                  key={p}
                  type="button"
                  variant="outline"
                  className="w-full justify-center gap-2"
                  disabled={busy}
                  onClick={() => socialStart(p)}
                >
                  <ProviderIcon provider={p} />
                  {t(`common:providers.${p}`, { defaultValue: titleCase(p) })}
                </Button>
              ))}
            </div>
          </div>
        )}

        {selfRegistrationEnabled && (
          <p className="text-muted-foreground text-center text-sm">
            {t("noAccount")}{" "}
            <a
              href={`/signup${returnTo ? `?return_to=${encodeURIComponent(returnTo)}` : ""}`}
              className="hover:text-foreground underline"
            >
              {t("signUp")}
            </a>
          </p>
        )}
      </CardContent>
    </Card>
  );
}

// MfaChallenge is the second step of a hosted login: the password was accepted
// but the user has a second factor enrolled. It exchanges the in-memory
// mfa_token plus a TOTP or recovery code for the SSO cookie.
function MfaChallenge({
  mfaToken,
  rememberDeviceEnabled,
  onVerified,
  onBack,
}: {
  mfaToken: string;
  rememberDeviceEnabled: boolean;
  onVerified: () => void;
  onBack: () => void;
}) {
  const { t } = useTranslation("login");
  const [code, setCode] = useState("");
  const [remember, setRemember] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      await apiPost("/v1/auth/session/mfa", { mfa_token: mfaToken, code, remember });
      onVerified();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t("common:errors.generic"));
      setLoading(false);
    }
  }

  return (
    <Card className="w-full max-w-sm">
      <CardContent className="space-y-6 pt-6">
        <div className="space-y-1 text-center">
          <h1 className="text-xl font-semibold tracking-tight">{t("mfa.title")}</h1>
          <p className="text-muted-foreground text-sm">{t("mfa.subtitle")}</p>
        </div>

        <form onSubmit={onSubmit} className="space-y-4">
          <div className="space-y-1.5">
            <label htmlFor="mfa-code" className="text-sm font-medium">
              {t("mfa.label")}
            </label>
            <Input
              id="mfa-code"
              type="text"
              inputMode="numeric"
              autoComplete="one-time-code"
              autoFocus
              required
              value={code}
              onChange={(e) => setCode(e.target.value)}
              placeholder="123456"
            />
          </div>

          {rememberDeviceEnabled && (
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                className="size-4"
                checked={remember}
                onChange={(e) => setRemember(e.target.checked)}
              />
              {t("mfa.remember")}
            </label>
          )}

          {error && (
            <p role="alert" className="text-destructive text-sm">
              {error}
            </p>
          )}

          <Button type="submit" className="w-full" disabled={loading}>
            {loading ? t("mfa.submit.busy") : t("mfa.submit.idle")}
          </Button>
        </form>

        <Button
          type="button"
          variant="ghost"
          className="w-full"
          disabled={loading}
          onClick={onBack}
        >
          {t("mfa.back")}
        </Button>
      </CardContent>
    </Card>
  );
}
