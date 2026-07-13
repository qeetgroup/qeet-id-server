import {
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  Field,
  FieldDescription,
  FieldError,
  FieldGroup,
  FieldLabel,
  Input,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Skeleton,
  Textarea,
} from "@qeetrix/ui";
import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckIcon, Loader2Icon } from "lucide-react";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { PageHeader } from "@/components/page-header";
import { ApiError, api } from "@/lib/api";
import { useTenantId } from "@/lib/auth";

export const Route = createFileRoute("/_app/access/policies")({ component: PoliciesPage });

type Policy = {
  tenant_id: string;
  ip_allowlist: string[] | null;
  ip_denylist: string[] | null;
  password_min_length: number;
  password_complexity: string;
  session_max_age: string;
  mfa_enforcement: string;
  settings?: Record<string, unknown> | null;
};

const empty: Policy = {
  tenant_id: "",
  ip_allowlist: [],
  ip_denylist: [],
  password_min_length: 8,
  password_complexity: "standard",
  session_max_age: "720h",
  mfa_enforcement: "optional",
};

function PoliciesPage() {
  const { t } = useTranslation("rbac");
  const tenantId = useTenantId();
  const qc = useQueryClient();
  const [draft, setDraft] = useState<Policy>(empty);
  const [savedAt, setSavedAt] = useState<Date | null>(null);

  const policyQ = useQuery({
    queryKey: ["policy", tenantId],
    queryFn: () => api<Policy>(`/v1/tenants/${tenantId}/policy`),
    enabled: !!tenantId,
  });

  useEffect(() => {
    if (policyQ.data) setDraft({ ...empty, ...policyQ.data });
  }, [policyQ.data]);

  const saveM = useMutation({
    mutationFn: (body: Policy) =>
      api<Policy>(`/v1/tenants/${tenantId}/policy`, { method: "PUT", body }),
    onSuccess: () => {
      setSavedAt(new Date());
      qc.invalidateQueries({ queryKey: ["policy", tenantId] });
    },
  });

  const set = <K extends keyof Policy>(k: K, v: Policy[K]) =>
    setDraft((d) => ({ ...d, [k]: v }));

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <PageHeader description={t("policies.description")} />

      {policyQ.isLoading ? (
        <Card>
          <CardContent className="space-y-3 p-6">
            {[...Array(5)].map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}
          </CardContent>
        </Card>
      ) : (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            saveM.mutate(draft);
          }}
          className="space-y-4"
        >
          <Card>
            <CardHeader>
              <CardTitle className="text-base">{t("policies.network.title")}</CardTitle>
              <CardDescription>{t("policies.network.description")}</CardDescription>
            </CardHeader>
            <CardContent>
              <FieldGroup>
                <Field>
                  <FieldLabel htmlFor="ip_allowlist">{t("policies.network.allowlistLabel")}</FieldLabel>
                  <Textarea
                    id="ip_allowlist"
                    rows={3}
                    value={(draft.ip_allowlist ?? []).join("\n")}
                    onChange={(e) =>
                      set(
                        "ip_allowlist",
                        e.target.value.split(/\n+/).map((s) => s.trim()).filter(Boolean)
                      )
                    }
                    placeholder="10.0.0.0/8&#10;203.0.113.0/24"
                  />
                  <FieldDescription>{t("policies.network.allowlistHelp")}</FieldDescription>
                </Field>
                <Field>
                  <FieldLabel htmlFor="ip_denylist">{t("policies.network.denylistLabel")}</FieldLabel>
                  <Textarea
                    id="ip_denylist"
                    rows={3}
                    value={(draft.ip_denylist ?? []).join("\n")}
                    onChange={(e) =>
                      set(
                        "ip_denylist",
                        e.target.value.split(/\n+/).map((s) => s.trim()).filter(Boolean)
                      )
                    }
                  />
                </Field>
              </FieldGroup>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-base">{t("policies.password.title")}</CardTitle>
              <CardDescription>{t("policies.password.description")}</CardDescription>
            </CardHeader>
            <CardContent>
              <FieldGroup>
                <Field className="grid grid-cols-2 gap-4">
                  <Field>
                    <FieldLabel htmlFor="password_min_length">{t("policies.password.minLengthLabel")}</FieldLabel>
                    <Input
                      id="password_min_length"
                      type="number"
                      min={8}
                      max={128}
                      value={draft.password_min_length}
                      onChange={(e) => set("password_min_length", parseInt(e.target.value || "8", 10))}
                    />
                  </Field>
                  <Field>
                    <FieldLabel>{t("policies.password.complexityLabel")}</FieldLabel>
                    <Select
                      value={draft.password_complexity}
                      onValueChange={(v) => set("password_complexity", v ?? "")}
                    >
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="basic">{t("policies.password.complexityBasic")}</SelectItem>
                        <SelectItem value="standard">{t("policies.password.complexityStandard")}</SelectItem>
                        <SelectItem value="strict">{t("policies.password.complexityStrict")}</SelectItem>
                      </SelectContent>
                    </Select>
                  </Field>
                </Field>
              </FieldGroup>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-base">{t("policies.session.title")}</CardTitle>
              <CardDescription>{t("policies.session.description")}</CardDescription>
            </CardHeader>
            <CardContent>
              <FieldGroup>
                <Field>
                  <FieldLabel htmlFor="session_max_age">{t("policies.session.maxAgeLabel")}</FieldLabel>
                  <Input
                    id="session_max_age"
                    value={draft.session_max_age}
                    onChange={(e) => set("session_max_age", e.target.value)}
                    placeholder="720h"
                  />
                  <FieldDescription>Go duration string. Examples: <code>24h</code>, <code>720h</code> (30 days), <code>2160h</code> (90 days).</FieldDescription>
                </Field>
              </FieldGroup>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-base">{t("policies.mfa.title")}</CardTitle>
              <CardDescription>{t("policies.mfa.description")}</CardDescription>
            </CardHeader>
            <CardContent>
              <FieldGroup>
                <Field>
                  <FieldLabel>{t("policies.mfa.modeLabel")}</FieldLabel>
                  <Select
                    value={draft.mfa_enforcement}
                    onValueChange={(v) => set("mfa_enforcement", v ?? "")}
                  >
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="disabled">{t("policies.mfa.disabled")}</SelectItem>
                      <SelectItem value="optional">{t("policies.mfa.optional")}</SelectItem>
                      <SelectItem value="required">{t("policies.mfa.required")}</SelectItem>
                      <SelectItem value="admin_only">{t("policies.mfa.adminOnly")}</SelectItem>
                    </SelectContent>
                  </Select>
                  <FieldDescription>{t("policies.mfa.noteHelp")}</FieldDescription>
                </Field>
              </FieldGroup>
            </CardContent>
          </Card>

          {saveM.error && (
            <Card className="border-destructive">
              <CardContent className="p-4">
                <FieldError>{(saveM.error as ApiError).message}</FieldError>
              </CardContent>
            </Card>
          )}

          <div className="flex items-center justify-between">
            <p className="text-xs text-muted-foreground">
              {savedAt ? t("policies.savedAt", { time: savedAt.toLocaleTimeString() }) : t("policies.unsaved")}
            </p>
            <div className="flex gap-2">
              <Button
                type="button"
                variant="outline"
                onClick={() => policyQ.data && setDraft({ ...empty, ...policyQ.data })}
                disabled={saveM.isPending}
              >
                {t("policies.resetBtn")}
              </Button>
              <Button type="submit" disabled={saveM.isPending}>
                {saveM.isPending && <Loader2Icon className="animate-spin" />}
                {saveM.isSuccess && !saveM.isPending && <CheckIcon />}
                {saveM.isPending ? t("policies.savingBtn") : t("policies.saveBtn")}
              </Button>
            </div>
          </div>
        </form>
      )}
    </div>
  );
}
