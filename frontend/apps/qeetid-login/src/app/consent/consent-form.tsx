"use client";

import { Button, Card, CardContent } from "@qeetrix/ui";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { ApiError, apiPost } from "@/lib/api";

export type ConsentParams = {
  client_id: string;
  redirect_uri: string;
  scope: string;
  state: string;
  nonce: string;
  code_challenge: string;
  code_challenge_method: string;
};

export function ConsentForm({ params }: { params: ConsentParams }) {
  const { t } = useTranslation("consent");
  const scopes = params.scope.split(/\s+/).filter(Boolean);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function decide(approve: boolean) {
    setError(null);
    setLoading(true);
    try {
      const res = await apiPost<{ redirect: string }>("/v1/oauth/authorize/decision", {
        approve,
        ...params,
      });
      window.location.href = res.redirect;
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t("common:errors.generic"));
      setLoading(false);
    }
  }

  return (
    <Card className="w-full max-w-md">
      <CardContent className="space-y-5 pt-6">
        <div className="space-y-1">
          <h1 className="text-xl font-semibold tracking-tight">{t("title")}</h1>
          <p className="text-muted-foreground text-sm">
            <span className="text-foreground font-medium">
              {params.client_id || t("common:fallbacks.application")}
            </span>{" "}
            {t("wantsPermission")}
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
            {t("actions.deny")}
          </Button>
          <Button className="flex-1" disabled={loading} onClick={() => decide(true)}>
            {loading ? t("actions.allowing") : t("actions.allow")}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
