import {
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  DataState,
  Field,
  FieldDescription,
  FieldLabel,
  Slider,
  Switch,
} from "@qeetrix/ui";
import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { PageHeader } from "@/components/page-header";
import { type AuthPolicy, useAuthPolicy, useUpdateAuthPolicy } from "@/lib/auth-policy";

export const Route = createFileRoute("/_app/auth/login-methods/password")({ component: PasswordPage });

function PasswordPage() {
  const { t } = useTranslation("auth");
  const policyQ = useAuthPolicy();
  return (
    <div className="flex min-w-0 flex-col gap-6">
      <PageHeader description={t("password.description")} />
      <DataState
        isLoading={policyQ.isLoading}
        isError={policyQ.isError}
        error={policyQ.error}
        isEmpty={false}
        skeletonRows={3}
      >
        {policyQ.data && <PasswordForm initial={policyQ.data} />}
      </DataState>
    </div>
  );
}

function PasswordForm({ initial }: { initial: AuthPolicy }) {
  const { t } = useTranslation("auth");
  const updateM = useUpdateAuthPolicy();
  const [draft, setDraft] = useState<AuthPolicy>(initial);
  const set = <K extends keyof AuthPolicy>(k: K, v: AuthPolicy[K]) => setDraft((d) => ({ ...d, [k]: v }));

  return (
    <>
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <div>
            <CardTitle>{t("password.authTitle")}</CardTitle>
            <CardDescription>{t("password.authDescription")}</CardDescription>
          </div>
          <Switch checked={draft.password_enabled} onCheckedChange={(v) => set("password_enabled", v)} />
        </CardHeader>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>{t("password.complexityTitle")}</CardTitle>
          <CardDescription>{t("password.complexityDescription")}</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-6 md:grid-cols-2">
          <Field>
            <FieldLabel>{t("password.minLength", { count: draft.password_min_length })}</FieldLabel>
            <Slider
              value={[draft.password_min_length]}
              onValueChange={(v) => set("password_min_length", Array.isArray(v) ? (v[0] ?? 8) : v)}
              min={8}
              max={64}
              step={1}
            />
            <FieldDescription>{t("password.minLengthHelp")}</FieldDescription>
          </Field>
          <div className="flex flex-col gap-4">
            <Field>
              <div className="flex items-center justify-between gap-4">
                <FieldLabel>{t("password.requireUppercase")}</FieldLabel>
                <Switch
                  checked={draft.password_require_uppercase}
                  onCheckedChange={(v) => set("password_require_uppercase", v)}
                />
              </div>
            </Field>
            <Field>
              <div className="flex items-center justify-between gap-4">
                <FieldLabel>{t("password.requireNumber")}</FieldLabel>
                <Switch
                  checked={draft.password_require_number}
                  onCheckedChange={(v) => set("password_require_number", v)}
                />
              </div>
            </Field>
            <Field>
              <div className="flex items-center justify-between gap-4">
                <FieldLabel>{t("password.requireSymbol")}</FieldLabel>
                <Switch
                  checked={draft.password_require_symbol}
                  onCheckedChange={(v) => set("password_require_symbol", v)}
                />
              </div>
            </Field>
          </div>
        </CardContent>
      </Card>

      <div className="flex justify-end gap-2">
        <Button variant="outline" onClick={() => setDraft(initial)} disabled={updateM.isPending}>
          {t("common:actions.reset")}
        </Button>
        <Button onClick={() => updateM.mutate(draft)} disabled={updateM.isPending}>
          {updateM.isPending ? t("common:actions.saving") : t("common:actions.saveChanges")}
        </Button>
      </div>
    </>
  );
}
