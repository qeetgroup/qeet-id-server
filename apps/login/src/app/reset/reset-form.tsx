"use client";

import { Button, Card, CardContent, Input } from "@qeetrix/ui";
import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";

import { ApiError, apiPost } from "@/lib/api";

export function ResetForm({ token }: { token: string }) {
  const { t } = useTranslation("recovery");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [done, setDone] = useState(false);

  async function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    if (password !== confirm) {
      setError(t("reset.mismatch"));
      return;
    }
    setLoading(true);
    try {
      await apiPost("/v1/auth/reset-password", { token, new_password: password });
      setDone(true);
    } catch (err) {
      // The backend enforces length, weak-password and breach checks and returns
      // a clear message; surface it verbatim.
      setError(err instanceof ApiError ? err.message : t("common:errors.generic"));
    } finally {
      setLoading(false);
    }
  }

  return (
    <Card className="w-full max-w-sm">
      <CardContent className="space-y-6 pt-6">
        <div className="space-y-1 text-center">
          <h1 className="text-xl font-semibold tracking-tight">{t("reset.title")}</h1>
          <p className="text-muted-foreground text-sm">{t("reset.subtitle")}</p>
        </div>

        {done ? (
          <div className="space-y-4 text-center">
            <p role="status" className="text-muted-foreground text-sm">
              {t("reset.done")}
            </p>
            <Button render={<a href="/login" />} className="w-full">
              {t("reset.goToLogin")}
            </Button>
          </div>
        ) : !token ? (
          <p role="alert" className="text-destructive text-center text-sm">
            {t("reset.missingToken")}
          </p>
        ) : (
          <form onSubmit={onSubmit} className="space-y-4">
            <div className="space-y-1.5">
              <label htmlFor="password" className="text-sm font-medium">
                {t("reset.fields.password")}
              </label>
              <Input
                id="password"
                type="password"
                autoComplete="new-password"
                autoFocus
                required
                minLength={8}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
              <p className="text-muted-foreground text-xs">{t("reset.hint")}</p>
            </div>
            <div className="space-y-1.5">
              <label htmlFor="confirm" className="text-sm font-medium">
                {t("reset.fields.confirm")}
              </label>
              <Input
                id="confirm"
                type="password"
                autoComplete="new-password"
                required
                minLength={8}
                value={confirm}
                onChange={(e) => setConfirm(e.target.value)}
              />
            </div>

            {error && (
              <p role="alert" className="text-destructive text-sm">
                {error}
              </p>
            )}

            <Button type="submit" className="w-full" disabled={loading}>
              {loading ? t("reset.submit.busy") : t("reset.submit.idle")}
            </Button>
          </form>
        )}
      </CardContent>
    </Card>
  );
}
