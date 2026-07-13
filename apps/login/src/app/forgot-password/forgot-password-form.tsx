"use client";

import { Button, Input, Spinner } from "@qeetrix/ui";
import { type FormEvent, useState } from "react";
import { useTranslation } from "react-i18next";

import { AuthCard } from "@/components/auth-card";
import { FormAlert } from "@/components/form-alert";
import { ApiError, apiPost } from "@/lib/api";
import type { Branding } from "@/lib/branding";

type ForgotPasswordFormProps = {
  returnTo: string;
  tenantId: string;
  branding?: Branding;
};

export function ForgotPasswordForm({ returnTo, tenantId, branding }: ForgotPasswordFormProps) {
  const { t } = useTranslation("recovery");
  const [email, setEmail] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [sent, setSent] = useState(false);

  const loginHref = `/login${returnTo ? `?return_to=${encodeURIComponent(returnTo)}` : ""}`;

  async function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      // Omit tenant_id when unknown: the backend expects a UUID, so an empty
      // string would 400. The response is enumeration-safe either way.
      const body: Record<string, string> = { email };
      if (tenantId) body.tenant_id = tenantId;
      await apiPost("/v1/auth/forgot-password", body);
      setSent(true);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t("common:errors.generic"));
    } finally {
      setLoading(false);
    }
  }

  return (
    <AuthCard branding={branding} title={t("forgot.title")} subtitle={t("forgot.subtitle")}>
      {sent ? (
        <p role="status" className="text-muted-foreground text-center text-sm">
          {t("forgot.sent")}
        </p>
      ) : (
        <form onSubmit={onSubmit} className="space-y-4">
          <div className="space-y-1.5">
            <label htmlFor="email" className="text-sm font-medium">
              {t("forgot.label")}
            </label>
            <Input
              id="email"
              type="email"
              autoComplete="email"
              autoFocus
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="you@example.com"
            />
          </div>

          <FormAlert>{error}</FormAlert>

          <Button type="submit" size="lg" className="w-full" disabled={loading}>
            {loading ? (
              <>
                <Spinner size="sm" className="mr-2" /> {t("forgot.submit.busy")}
              </>
            ) : (
              t("forgot.submit.idle")
            )}
          </Button>
        </form>
      )}

      <div className="text-center">
        <a
          href={loginHref}
          className="text-muted-foreground hover:text-foreground text-sm underline-offset-2 hover:underline"
        >
          {t("forgot.backToLogin")}
        </a>
      </div>
    </AuthCard>
  );
}
