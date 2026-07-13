import {
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  Field,
  FieldDescription,
  FieldLabel,
  Input,
} from "@qeetrix/ui";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";
import { GaugeIcon, Loader2Icon, RotateCcwIcon } from "lucide-react";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { useConfirmDialog } from "@/components/confirm-dialog";
import { PageHeader } from "@/components/page-header";
import { api } from "@/lib/api";
import { useTenantId } from "@/lib/auth";

export const Route = createFileRoute("/_app/security/threats/rate-limits")({
  component: RateLimitsPage,
});

interface LimitConfig {
  rate: number;
  capacity: number;
}

interface TenantLimits {
  tenant: LimitConfig;
  user: LimitConfig;
  api_key: LimitConfig;
}

function useRateLimits() {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: ["rate-limits", tenantId],
    queryFn: () => api<TenantLimits>(`/v1/tenants/${tenantId}/rate-limits`),
    enabled: !!tenantId,
  });
}

function useUpdateRateLimits() {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: TenantLimits) =>
      api<TenantLimits>(`/v1/tenants/${tenantId}/rate-limits`, {
        method: "PUT",
        body,
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["rate-limits", tenantId] }),
  });
}

function useResetRateLimits() {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => api<void>(`/v1/tenants/${tenantId}/rate-limits`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["rate-limits", tenantId] }),
  });
}

type LimitRowProps = {
  label: string;
  description: string;
  rate: number;
  capacity: number;
  onRate: (v: number) => void;
  onCapacity: (v: number) => void;
  rateLabel: string;
  burstLabel: string;
};

function LimitRow({
  label,
  description,
  rate,
  capacity,
  onRate,
  onCapacity,
  rateLabel,
  burstLabel,
}: LimitRowProps) {
  return (
    <div className="grid gap-3 sm:grid-cols-[1fr_120px_120px] sm:items-end border-b pb-4 last:border-0 last:pb-0">
      <Field>
        <FieldLabel>{label}</FieldLabel>
        <FieldDescription>{description}</FieldDescription>
      </Field>
      <Field>
        <FieldLabel htmlFor={`${label}-rate`}>{rateLabel}</FieldLabel>
        <Input
          id={`${label}-rate`}
          type="number"
          min={1}
          step={1}
          value={rate}
          onChange={(e) => onRate(Number(e.target.value) || 1)}
        />
      </Field>
      <Field>
        <FieldLabel htmlFor={`${label}-burst`}>{burstLabel}</FieldLabel>
        <Input
          id={`${label}-burst`}
          type="number"
          min={1}
          step={1}
          value={capacity}
          onChange={(e) => onCapacity(Number(e.target.value) || 1)}
        />
      </Field>
    </div>
  );
}

function RateLimitsPage() {
  const { t } = useTranslation("security");
  const [confirmDialog, openConfirm] = useConfirmDialog();
  const limitsQ = useRateLimits();
  const update = useUpdateRateLimits();
  const reset = useResetRateLimits();

  const [tenantRate, setTenantRate] = useState(100);
  const [tenantCap, setTenantCap] = useState(500);
  const [userRate, setUserRate] = useState(30);
  const [userCap, setUserCap] = useState(100);
  const [apiKeyRate, setApiKeyRate] = useState(50);
  const [apiKeyCap, setApiKeyCap] = useState(200);

  useEffect(() => {
    if (limitsQ.data) {
      setTenantRate(limitsQ.data.tenant.rate);
      setTenantCap(limitsQ.data.tenant.capacity);
      setUserRate(limitsQ.data.user.rate);
      setUserCap(limitsQ.data.user.capacity);
      setApiKeyRate(limitsQ.data.api_key.rate);
      setApiKeyCap(limitsQ.data.api_key.capacity);
    }
  }, [limitsQ.data]);

  const dirty =
    limitsQ.data &&
    (tenantRate !== limitsQ.data.tenant.rate ||
      tenantCap !== limitsQ.data.tenant.capacity ||
      userRate !== limitsQ.data.user.rate ||
      userCap !== limitsQ.data.user.capacity ||
      apiKeyRate !== limitsQ.data.api_key.rate ||
      apiKeyCap !== limitsQ.data.api_key.capacity);

  return (
    <div className="flex min-w-0 flex-col gap-4">
      {confirmDialog}
      <PageHeader description={t("threats.rateLimits.description")} />

      <Card>
        <CardHeader className="flex flex-row items-center justify-between gap-4">
          <div>
            <CardTitle className="flex items-center gap-2 text-base">
              <GaugeIcon className="size-4" />
              {t("threats.rateLimits.card.title")}
            </CardTitle>
            <CardDescription>{t("threats.rateLimits.card.description")}</CardDescription>
          </div>
          <Button
            variant="outline"
            size="sm"
            disabled={reset.isPending}
            onClick={() =>
              openConfirm({
                title: t("threats.rateLimits.card.resetConfirmTitle"),
                variant: "destructive",
                confirmLabel: t("threats.rateLimits.card.resetConfirmLabel"),
                onConfirm: () => reset.mutate(),
              })
            }
          >
            {reset.isPending ? <Loader2Icon className="animate-spin" /> : <RotateCcwIcon />}
            {t("threats.rateLimits.card.resetToDefaults")}
          </Button>
        </CardHeader>
        <CardContent>
          {limitsQ.isLoading ? (
            <p className="text-sm text-muted-foreground">{t("threats.rateLimits.card.loading")}</p>
          ) : (
            <form
              className="flex flex-col gap-5"
              onSubmit={(e) => {
                e.preventDefault();
                update.mutate({
                  tenant: { rate: tenantRate, capacity: tenantCap },
                  user: { rate: userRate, capacity: userCap },
                  api_key: { rate: apiKeyRate, capacity: apiKeyCap },
                });
              }}
            >
              <LimitRow
                label={t("threats.rateLimits.rows.tenant.label")}
                description={t("threats.rateLimits.rows.tenant.description")}
                rate={tenantRate}
                capacity={tenantCap}
                onRate={setTenantRate}
                onCapacity={setTenantCap}
                rateLabel={t("threats.rateLimits.card.rateLabel")}
                burstLabel={t("threats.rateLimits.card.burstLabel")}
              />
              <LimitRow
                label={t("threats.rateLimits.rows.user.label")}
                description={t("threats.rateLimits.rows.user.description")}
                rate={userRate}
                capacity={userCap}
                onRate={setUserRate}
                onCapacity={setUserCap}
                rateLabel={t("threats.rateLimits.card.rateLabel")}
                burstLabel={t("threats.rateLimits.card.burstLabel")}
              />
              <LimitRow
                label={t("threats.rateLimits.rows.apiKey.label")}
                description={t("threats.rateLimits.rows.apiKey.description")}
                rate={apiKeyRate}
                capacity={apiKeyCap}
                onRate={setApiKeyRate}
                onCapacity={setApiKeyCap}
                rateLabel={t("threats.rateLimits.card.rateLabel")}
                burstLabel={t("threats.rateLimits.card.burstLabel")}
              />
              <div className="flex items-center gap-3 pt-2">
                <Button type="submit" disabled={!dirty || update.isPending}>
                  {update.isPending && <Loader2Icon className="animate-spin" />}
                  {t("threats.rateLimits.card.save")}
                </Button>
                {update.isSuccess && (
                  <span className="text-sm text-green-600">
                    {t("threats.rateLimits.card.saved")}
                  </span>
                )}
              </div>
            </form>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
