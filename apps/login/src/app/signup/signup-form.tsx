"use client";

import { Button, Input, PasswordStrengthMeter, Spinner } from "@qeetrix/ui";
import { IconPasskey } from "@qeetrix/ui/brand";
import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";

import { AuthCard } from "@/components/auth-card";
import { FormAlert } from "@/components/form-alert";
import type { Branding } from "@/lib/branding";
import { API_BASE_URL, ApiError, apiPost } from "@/lib/api";

type SignupFormProps = {
  returnTo: string;
  clientName: string;
  tenantId: string;
  selfRegistrationEnabled: boolean;
  branding?: Branding;
};

// safeReturnTo guards against open redirects: we only ever bounce back to our
// own backend's /oauth/authorize endpoint (mirrors the sign-in form).
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

export function SignupForm({
  returnTo,
  clientName,
  tenantId,
  selfRegistrationEnabled,
  branding,
}: SignupFormProps) {
  const { t } = useTranslation("signup");
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [passkeyBusy, setPasskeyBusy] = useState(false);
  // Passkeys-first: the primary path is a passkey with no password field at
  // all; "Use a password instead" reveals the fallback form below.
  const [usePassword, setUsePassword] = useState(false);

  const loginHref = `/login${returnTo ? `?return_to=${encodeURIComponent(returnTo)}` : ""}`;
  const busy = loading || passkeyBusy;

  function continueToApp() {
    const dest = safeReturnTo(returnTo);
    window.location.href = dest ?? "/login";
  }

  async function passkeySignup() {
    setError(null);
    setPasskeyBusy(true);
    try {
      const PK = window.PublicKeyCredential as
        | (typeof window.PublicKeyCredential & {
            parseCreationOptionsFromJSON?: (o: unknown) => PublicKeyCredentialCreationOptions;
          })
        | undefined;
      if (!PK || !navigator.credentials) {
        throw new Error(t("errors.passkeyUnsupported"));
      }
      const begin = await apiPost<{ session_id: string; publicKey: unknown }>(
        "/v1/register/passkey/begin",
        { tenant_id: tenantId, email, display_name: name },
      );
      const options = PK.parseCreationOptionsFromJSON
        ? PK.parseCreationOptionsFromJSON(begin.publicKey)
        : (begin.publicKey as PublicKeyCredentialCreationOptions);
      const created = (await navigator.credentials.create({
        publicKey: options,
      })) as PublicKeyCredential & { toJSON?: () => unknown };
      if (!created) throw new Error(t("errors.passkeyFailed"));
      const credential = created.toJSON ? created.toJSON() : created;
      await apiPost("/v1/register/passkey/finish", {
        session_id: begin.session_id,
        credential,
        name: "",
      });
      continueToApp();
    } catch (err) {
      setError(
        err instanceof ApiError ? err.message : (err as Error).message || t("errors.passkeyFailed"),
      );
      setPasskeyBusy(false);
    }
  }

  async function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    if (password !== confirm) {
      setError(t("mismatch"));
      return;
    }
    setLoading(true);
    try {
      // Registration is tenant-scoped: the user is created in the client's
      // tenant and the SSO cookie is set, so we continue straight to the app.
      await apiPost("/v1/auth/register", {
        tenant_id: tenantId,
        email,
        password,
        display_name: name,
      });
      continueToApp();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t("common:errors.generic"));
      setLoading(false);
    }
  }

  return (
    <AuthCard
      branding={branding}
      title={clientName ? t("titleTo", { client: clientName }) : t("title")}
      subtitle={t("subtitle")}
    >
      {!selfRegistrationEnabled || !tenantId ? (
        <p role="status" className="text-muted-foreground text-center text-sm">
          {t("disabled")}
        </p>
      ) : (
        <div className="space-y-4">
          <div className="space-y-1.5">
            <label htmlFor="name" className="text-sm font-medium">
              {t("fields.name")}
            </label>
            <Input
              id="name"
              type="text"
              autoComplete="name"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          </div>
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

          {usePassword && (
            <form onSubmit={onSubmit} className="space-y-4">
              <div className="space-y-1.5">
                <label htmlFor="password" className="text-sm font-medium">
                  {t("fields.password")}
                </label>
                <Input
                  id="password"
                  type="password"
                  autoComplete="new-password"
                  required
                  minLength={8}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                />
                {password ? (
                  <PasswordStrengthMeter value={password} className="pt-1" />
                ) : (
                  <p className="text-muted-foreground text-xs">{t("hint")}</p>
                )}
              </div>
              <div className="space-y-1.5">
                <label htmlFor="confirm" className="text-sm font-medium">
                  {t("fields.confirm")}
                </label>
                <Input
                  id="confirm"
                  type="password"
                  autoComplete="new-password"
                  required
                  minLength={8}
                  value={confirm}
                  onChange={(e) => setConfirm(e.target.value)}
                  aria-invalid={confirm.length > 0 && confirm !== password}
                />
              </div>

              <FormAlert>{error}</FormAlert>

              <Button type="submit" size="lg" className="w-full" disabled={busy}>
                {loading ? (
                  <>
                    <Spinner size="sm" className="mr-2" /> {t("submit.busy")}
                  </>
                ) : (
                  t("submit.idle")
                )}
              </Button>
            </form>
          )}

          {!usePassword && (
            <>
              <Button
                type="button"
                size="lg"
                className="w-full"
                disabled={busy || !email}
                onClick={passkeySignup}
              >
                {passkeyBusy ? (
                  <>
                    <Spinner size="sm" className="mr-2" /> {t("passkey.busy")}
                  </>
                ) : (
                  <>
                    <IconPasskey className="mr-2 size-4" /> {t("passkey.idle")}
                  </>
                )}
              </Button>
              <FormAlert>{error}</FormAlert>
            </>
          )}

          <button
            type="button"
            className="text-muted-foreground hover:text-foreground w-full text-center text-sm underline-offset-2 hover:underline"
            disabled={busy}
            onClick={() => {
              setUsePassword((v) => !v);
              setError(null);
            }}
          >
            {usePassword ? t("usePasskey") : t("usePassword")}
          </button>
        </div>
      )}

      <p className="text-muted-foreground text-center text-sm">
        {t("haveAccount")}{" "}
        <a
          href={loginHref}
          className="text-foreground font-medium underline-offset-2 hover:underline"
        >
          {t("signIn")}
        </a>
      </p>
    </AuthCard>
  );
}
