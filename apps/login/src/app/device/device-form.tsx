"use client";

import { Button, Input, Spinner } from "@qeetrix/ui";
import { type FormEvent, useState } from "react";
import { useTranslation } from "react-i18next";

import { AuthCard } from "@/components/auth-card";
import { FormAlert } from "@/components/form-alert";
import { ScopeList } from "@/components/scope-list";
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
      <AuthCard
        className="max-w-md"
        title={decision === "authorized" ? t("terminal.approvedTitle") : t("terminal.deniedTitle")}
        subtitle={decision === "authorized" ? t("terminal.approvedBody") : t("terminal.deniedBody")}
      />
    );
  }

  // Approval step: we have the client + scopes, ask the user to approve or deny.
  if (ctx) {
    const scopes = ctx.scopes ?? [];
    return (
      <AuthCard
        className="max-w-md"
        title={t("authorize.title")}
        subtitle={
          <>
            <span className="text-foreground font-medium">
              {ctx.client_name || t("common:fallbacks.application")}
            </span>{" "}
            {t("authorize.wantsPermission")}
          </>
        }
      >
        <ScopeList scopes={scopes} />

        <FormAlert>{error}</FormAlert>

        <div className="flex gap-3">
          <Button
            variant="outline"
            size="lg"
            className="flex-1"
            disabled={loading}
            onClick={() => decide(false)}
          >
            {t("authorize.deny")}
          </Button>
          <Button size="lg" className="flex-1" disabled={loading} onClick={() => decide(true)}>
            {loading ? (
              <>
                <Spinner size="sm" className="mr-2" /> {t("authorize.approving")}
              </>
            ) : (
              t("authorize.approve")
            )}
          </Button>
        </div>
      </AuthCard>
    );
  }

  // Entry step: enter or confirm the user code from the device.
  return (
    <AuthCard className="max-w-md" title={t("entry.title")} subtitle={t("entry.description")}>
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
            className="text-center font-mono text-lg tracking-[0.3em]"
          />
        </div>

        <FormAlert>{error}</FormAlert>

        <Button type="submit" size="lg" className="w-full" disabled={loading}>
          {loading ? (
            <>
              <Spinner size="sm" className="mr-2" /> {t("entry.submitting")}
            </>
          ) : (
            t("entry.submit")
          )}
        </Button>
      </form>
    </AuthCard>
  );
}
