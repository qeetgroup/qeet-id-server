"use client";

import { Button, Spinner } from "@qeetrix/ui";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { AuthCard } from "@/components/auth-card";
import { FormAlert } from "@/components/form-alert";
import { ScopeList } from "@/components/scope-list";
import { ApiError, apiPost } from "@/lib/api";
import type { Branding } from "@/lib/branding";

export type ConsentParams = {
  client_id: string;
  redirect_uri: string;
  scope: string;
  state: string;
  nonce: string;
  code_challenge: string;
  code_challenge_method: string;
};

export function ConsentForm({
  params,
  clientName,
  branding,
}: {
  params: ConsentParams;
  clientName?: string;
  branding?: Branding;
}) {
  const { t } = useTranslation("consent");
  const scopes = params.scope.split(/\s+/).filter(Boolean);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const appName = clientName || params.client_id || t("common:fallbacks.application");

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
    <AuthCard
      branding={branding}
      className="max-w-md"
      title={t("title")}
      subtitle={
        <>
          <span className="text-foreground font-medium">{appName}</span> {t("wantsPermission")}
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
          {t("actions.deny")}
        </Button>
        <Button size="lg" className="flex-1" disabled={loading} onClick={() => decide(true)}>
          {loading ? (
            <>
              <Spinner size="sm" className="mr-2" /> {t("actions.allowing")}
            </>
          ) : (
            t("actions.allow")
          )}
        </Button>
      </div>
    </AuthCard>
  );
}
