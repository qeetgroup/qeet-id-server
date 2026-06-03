"use client";

import { Button, Card, CardContent, Input } from "@qeetrix/ui";
import { useState, type FormEvent } from "react";

import { API_BASE_URL, ApiError, apiPost } from "@/lib/api";

type LoginFormProps = {
  returnTo: string;
  clientName: string;
  tenantId: string;
  providers: string[];
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

const PROVIDER_LABELS: Record<string, string> = {
  google: "Google",
  github: "GitHub",
  microsoft: "Microsoft",
  apple: "Apple",
  gitlab: "GitLab",
};

function titleCase(s: string) {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

export function LoginForm({ returnTo, clientName, tenantId, providers }: LoginFormProps) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [passkeyBusy, setPasskeyBusy] = useState(false);

  function continueToApp() {
    const dest = safeReturnTo(returnTo);
    window.location.href = dest ?? "/login";
  }

  async function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      await apiPost("/v1/auth/session", { email, password });
      continueToApp();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Something went wrong. Please try again.");
      setLoading(false);
    }
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
        throw new Error("Passkeys aren't supported in this browser.");
      }
      const begin = await apiPost<{ session_id: string; publicKey: unknown }>(
        "/v1/passkeys/login/begin",
        {},
      );
      const options = PK.parseRequestOptionsFromJSON
        ? PK.parseRequestOptionsFromJSON(begin.publicKey)
        : (begin.publicKey as PublicKeyCredentialRequestOptions);
      const assertion = (await navigator.credentials.get({ publicKey: options })) as PublicKeyCredential & {
        toJSON?: () => unknown;
      };
      if (!assertion) throw new Error("No passkey was selected.");
      const credential = assertion.toJSON ? assertion.toJSON() : assertion;
      await apiPost("/v1/passkeys/login/finish", { session_id: begin.session_id, credential });
      continueToApp();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : (err as Error).message || "Passkey sign-in failed.");
      setPasskeyBusy(false);
    }
  }

  const busy = loading || passkeyBusy;
  const showSocial = providers.length > 0 && tenantId !== "" && returnTo !== "";

  return (
    <Card className="w-full max-w-sm">
      <CardContent className="space-y-6 pt-6">
        <div className="space-y-1 text-center">
          <h1 className="text-xl font-semibold tracking-tight">
            {clientName ? `Sign in to continue to ${clientName}` : "Sign in to continue"}
          </h1>
          <p className="text-muted-foreground text-sm">Use your Qeet ID account.</p>
        </div>

        <form onSubmit={onSubmit} className="space-y-4">
          <div className="space-y-1.5">
            <label htmlFor="email" className="text-sm font-medium">
              Email
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
              Password
            </label>
            <Input
              id="password"
              type="password"
              autoComplete="current-password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </div>

          {error && (
            <p role="alert" className="text-destructive text-sm">
              {error}
            </p>
          )}

          <Button type="submit" className="w-full" disabled={busy}>
            {loading ? "Signing in…" : "Sign in"}
          </Button>
        </form>

        <Button type="button" variant="outline" className="w-full" disabled={busy} onClick={passkeyLogin}>
          {passkeyBusy ? "Waiting for passkey…" : "Sign in with a passkey"}
        </Button>

        {showSocial && (
          <div className="space-y-3">
            <div className="flex items-center gap-3">
              <span className="bg-border h-px flex-1" />
              <span className="text-muted-foreground text-xs">or continue with</span>
              <span className="bg-border h-px flex-1" />
            </div>
            <div className="grid gap-2">
              {providers.map((p) => (
                <Button
                  key={p}
                  type="button"
                  variant="outline"
                  className="w-full"
                  disabled={busy}
                  onClick={() => socialStart(p)}
                >
                  {PROVIDER_LABELS[p] ?? titleCase(p)}
                </Button>
              ))}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
