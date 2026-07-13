import {
  Badge,
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
  Skeleton,
} from "@qeetrix/ui";
import { createFileRoute, Link } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckIcon, ConstructionIcon, GlobeIcon, Loader2Icon } from "lucide-react";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { PageHeader } from "@/components/page-header";
import { ApiError, api } from "@/lib/api";
import { useTenantId } from "@/lib/auth";

export const Route = createFileRoute("/_app/settings/workspace/domains")({ component: DomainsPage });

type Branding = {
  tenant_id: string;
  custom_domain?: string | null;
  logo_url?: string | null;
  primary_color?: string | null;
  secondary_color?: string | null;
  email_from_name?: string | null;
  email_from_address?: string | null;
  settings?: Record<string, unknown> | null;
};

function DomainsPage() {
  const { t } = useTranslation("settings");
  const tenantId = useTenantId();
  const qc = useQueryClient();
  const [domain, setDomain] = useState("");
  const [savedAt, setSavedAt] = useState<Date | null>(null);

  const brandQ = useQuery({
    queryKey: ["branding", tenantId],
    queryFn: () => api<Branding>(`/v1/tenants/${tenantId}/branding`),
    enabled: !!tenantId,
  });

  useEffect(() => {
    if (brandQ.data) setDomain(brandQ.data.custom_domain ?? "");
  }, [brandQ.data]);

  const saveM = useMutation({
    mutationFn: () =>
      api<Branding>(`/v1/tenants/${tenantId}/branding`, {
        method: "PUT",
        body: { ...(brandQ.data ?? {}), custom_domain: domain || null },
      }),
    onSuccess: () => {
      setSavedAt(new Date());
      qc.invalidateQueries({ queryKey: ["branding", tenantId] });
    },
  });

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <PageHeader description={t("workspace.domains.description")} />

      <Card className="border-amber-500/40 bg-amber-50/30 dark:bg-amber-950/20">
        <CardContent className="flex items-start gap-3 p-4">
          <ConstructionIcon className="size-5 text-amber-700 dark:text-amber-500" />
          <div className="text-sm">
            <p className="font-medium">{t("workspace.domains.pendingBanner.title")}</p>
            <p className="text-muted-foreground">{t("workspace.domains.pendingBanner.description")}</p>
          </div>
        </CardContent>
      </Card>

      {brandQ.isLoading ? (
        <Card><CardContent className="p-6"><Skeleton className="h-10 w-full" /></CardContent></Card>
      ) : (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            saveM.mutate();
          }}
        >
          <Card>
            <CardHeader>
              <CardTitle className="text-base">{t("workspace.domains.custom.title")}</CardTitle>
              <CardDescription>{t("workspace.domains.custom.description")}</CardDescription>
            </CardHeader>
            <CardContent>
              <FieldGroup>
                <Field>
                  <FieldLabel htmlFor="custom_domain">{t("workspace.domains.custom.label")}</FieldLabel>
                  <Input
                    id="custom_domain"
                    value={domain}
                    onChange={(e) => setDomain(e.target.value)}
                    placeholder="auth.acme.com"
                  />
                  <FieldDescription>
                    Status: {brandQ.data?.custom_domain ? (
                      <Badge variant="warning" className="ml-1">{t("workspace.domains.custom.statusConfigured")}</Badge>
                    ) : (
                      <Badge variant="muted" className="ml-1">{t("workspace.domains.custom.statusNone")}</Badge>
                    )}
                  </FieldDescription>
                </Field>
                <Field>
                  <FieldLabel>{t("workspace.domains.custom.dnsRecords")}</FieldLabel>
                  <div className="rounded-md border bg-muted/50 p-3 text-xs font-mono space-y-1">
                    <div>CNAME @ → {tenantId ? `${tenantId.slice(0, 8)}.tenants.id.qeet.in` : "<tenant>.tenants.id.qeet.in"}</div>
                    <div>TXT _qeetid-verify → {tenantId ? `qeetid-verify=${tenantId.slice(0, 16)}` : "qeetid-verify=<token>"}</div>
                  </div>
                  <FieldDescription>{t("workspace.domains.custom.dnsHelp")}</FieldDescription>
                </Field>
                {saveM.error && <Field><FieldError>{(saveM.error as ApiError).message}</FieldError></Field>}
              </FieldGroup>
            </CardContent>
          </Card>

          <div className="mt-4 flex items-center justify-between">
            <p className="text-xs text-muted-foreground">
              {savedAt
                ? t("workspace.domains.footer.savedAt", { time: savedAt.toLocaleTimeString() })
                : t("workspace.domains.footer.unsaved")}{" "}
              · {t("workspace.domains.footer.brandingLink")}{" "}
              <Link to="/settings/branding" className="underline">Branding</Link>.
            </p>
            <div className="flex items-center gap-2">
              <GlobeIcon className="size-4 text-muted-foreground" />
              <Button type="submit" disabled={saveM.isPending}>
                {saveM.isPending && <Loader2Icon className="animate-spin" />}
                {saveM.isSuccess && !saveM.isPending && <CheckIcon />}
                {saveM.isPending ? t("workspace.domains.footer.saving") : t("workspace.domains.footer.save")}
              </Button>
            </div>
          </div>
        </form>
      )}
    </div>
  );
}
