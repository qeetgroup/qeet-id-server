"use client";

import { Button, Card, CardContent, Input } from "@qeetrix/ui";
import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";

import { ApiError, apiGet, apiPost } from "@/lib/api";

type DeviceContext = { client_name: string; scopes: string[] };

// Where the device-flow context lives on the backend, and where we bounce the
// user if they aren't signed in yet (so they land back here afterward).
function loginRedirect(code: string): string {
  const returnTo = `/device?user_code=${encodeURIComponent(code)}`;
  return `/login?return_to=${encodeURIComponent(returnTo)}`;
}

export function DeviceForm({ userCode }: { userCode: string }) {
  const { t } = useTranslation("device");
  const [code, setCode] = useState(userCode);
  const [ctx, setCtx] = useState<DeviceContext | null>(null);
  const [decision, setDecision] = useState<"authorized" | "denied" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function loadContext(e: FormEvent) {
    e.preventDefault();
    const trimmed = code.trim();
    if (!trimmed) {
      setError(t("errors.codeRequired"));
      return;
    }
    setError(null);
    setLoading(true);
    try {
      const res = await apiGet<DeviceContext>(
        "/v1/oauth/device?user_code=" + encodeURIComponent(trimmed),
      );
      setCtx(res);
      setLoading(false);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        // Not signed in: send them through login, then back to this page.
        window.location.href = loginRedirect(trimmed);
        return;
      }
      if (err instanceof ApiError && [400, 404, 409].includes(err.status)) {
        setError(t("errors.codeInvalid"));
      } else {
        setError(err instanceof ApiError ? err.message : t("common:errors.generic"));
      }
      setLoading(false);
    }
  }

  async function decide(approve: boolean) {
    setError(null);
    setLoading(true);
    try {
      const res = await apiPost<{ status: string }>("/v1/oauth/device/decision", {
        approve,
        user_code: code.trim(),
      });
      setDecision(res.status === "authorized" ? "authorized" : "denied");
      setLoading(false);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t("common:errors.generic"));
      setLoading(false);
    }
  }

  // Terminal state: the decision is recorded; the device polls for its token.
  if (decision) {
    return (
      <Card className="w-full max-w-md">
        <CardContent className="space-y-2 pt-6">
          <h1 className="text-xl font-semibold tracking-tight">
            {decision === "authorized" ? t("terminal.approvedTitle") : t("terminal.deniedTitle")}
          </h1>
          <p className="text-muted-foreground text-sm">
            {decision === "authorized" ? t("terminal.approvedBody") : t("terminal.deniedBody")}
          </p>
        </CardContent>
      </Card>
    );
  }

  // Approval step: we have the client + scopes, ask the user to approve or deny.
  if (ctx) {
    const scopes = ctx.scopes ?? [];
    return (
      <Card className="w-full max-w-md">
        <CardContent className="space-y-5 pt-6">
          <div className="space-y-1">
            <h1 className="text-xl font-semibold tracking-tight">{t("authorize.title")}</h1>
            <p className="text-muted-foreground text-sm">
              <span className="text-foreground font-medium">
                {ctx.client_name || t("common:fallbacks.application")}
              </span>{" "}
              {t("authorize.wantsPermission")}
            </p>
          </div>

          <ul className="space-y-2 text-sm">
            {scopes.length === 0 && (
              <li className="text-muted-foreground">{t("common:fallbacks.signYouIn")}</li>
            )}
            {scopes.map((s) => (
              <li key={s} className="flex gap-2">
                <span aria-hidden>•</span>
                <span>{t(`common:scopes.${s}`, { defaultValue: s })}</span>
              </li>
            ))}
          </ul>

          {error && (
            <p role="alert" className="text-destructive text-sm">
              {error}
            </p>
          )}

          <div className="flex gap-3">
            <Button variant="outline" className="flex-1" disabled={loading} onClick={() => decide(false)}>
              {t("authorize.deny")}
            </Button>
            <Button className="flex-1" disabled={loading} onClick={() => decide(true)}>
              {loading ? t("authorize.approving") : t("authorize.approve")}
            </Button>
          </div>
        </CardContent>
      </Card>
    );
  }

  // Entry step: enter or confirm the user code from the device.
  return (
    <Card className="w-full max-w-md">
      <CardContent className="space-y-5 pt-6">
        <div className="space-y-1">
          <h1 className="text-xl font-semibold tracking-tight">{t("entry.title")}</h1>
          <p className="text-muted-foreground text-sm">{t("entry.description")}</p>
        </div>

        <form onSubmit={loadContext} className="space-y-4">
          <div className="space-y-1.5">
            <label htmlFor="user_code" className="text-sm font-medium">
              {t("entry.codeLabel")}
            </label>
            <Input
              id="user_code"
              autoComplete="off"
              autoCapitalize="characters"
              required
              value={code}
              onChange={(e) => setCode(e.target.value.toUpperCase())}
              placeholder="XXXX-XXXX"
            />
          </div>

          {error && (
            <p role="alert" className="text-destructive text-sm">
              {error}
            </p>
          )}

          <Button type="submit" className="w-full" disabled={loading}>
            {loading ? t("entry.submitting") : t("entry.submit")}
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}
