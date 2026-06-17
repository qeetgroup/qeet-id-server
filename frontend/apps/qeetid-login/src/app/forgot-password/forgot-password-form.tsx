"use client";

import { Button, Card, CardContent, Input } from "@qeetrix/ui";
import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";

import { ApiError, apiPost } from "@/lib/api";

type ForgotPasswordFormProps = {
  returnTo: string;
  tenantId: string;
};

export function ForgotPasswordForm({ returnTo, tenantId }: ForgotPasswordFormProps) {
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
    <Card className="w-full max-w-sm">
      <CardContent className="space-y-6 pt-6">
        <div className="space-y-1 text-center">
          <h1 className="text-xl font-semibold tracking-tight">{t("forgot.title")}</h1>
          <p className="text-muted-foreground text-sm">{t("forgot.subtitle")}</p>
        </div>

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

            {error && (
              <p role="alert" className="text-destructive text-sm">
                {error}
              </p>
            )}

            <Button type="submit" className="w-full" disabled={loading}>
              {loading ? t("forgot.submit.busy") : t("forgot.submit.idle")}
            </Button>
          </form>
        )}

        <div className="text-center">
          <a
            href={loginHref}
            className="text-muted-foreground hover:text-foreground text-sm underline"
          >
            {t("forgot.backToLogin")}
          </a>
        </div>
      </CardContent>
    </Card>
  );
}
