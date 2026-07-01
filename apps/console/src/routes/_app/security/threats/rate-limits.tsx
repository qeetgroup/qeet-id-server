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
import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { GaugeIcon, Loader2Icon, RotateCcwIcon } from "lucide-react";
import { useEffect, useState } from "react";

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
      api<TenantLimits>(`/v1/tenants/${tenantId}/rate-limits`, { method: "PUT", body }),
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

function LimitRow({
  label,
  description,
  rate,
  capacity,
  onRate,
  onCapacity,
}: {
  label: string;
  description: string;
  rate: number;
  capacity: number;
  onRate: (v: number) => void;
  onCapacity: (v: number) => void;
}) {
  return (
    <div className="grid gap-3 sm:grid-cols-[1fr_120px_120px] sm:items-end border-b pb-4 last:border-0 last:pb-0">
      <Field>
        <FieldLabel>{label}</FieldLabel>
        <FieldDescription>{description}</FieldDescription>
      </Field>
      <Field>
        <FieldLabel htmlFor={`${label}-rate`}>Rate (req/s)</FieldLabel>
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
        <FieldLabel htmlFor={`${label}-burst`}>Burst</FieldLabel>
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
      <PageHeader description="Configure per-tenant rate limits. Rate is tokens per second; burst is the maximum burst capacity. These override the platform defaults for this tenant." />

      <Card>
        <CardHeader className="flex flex-row items-center justify-between gap-4">
          <div>
            <CardTitle className="flex items-center gap-2 text-base">
              <GaugeIcon className="size-4" />
              Rate Limits
            </CardTitle>
            <CardDescription>
              Limits are enforced per bucket (tenant, user, API key). Burst allows short spikes above the sustained rate.
            </CardDescription>
          </div>
          <Button
            variant="outline"
            size="sm"
            disabled={reset.isPending}
            onClick={() => {
              if (confirm("Reset all rate limits to platform defaults?")) reset.mutate();
            }}
          >
            {reset.isPending ? <Loader2Icon className="animate-spin" /> : <RotateCcwIcon />}
            Reset to defaults
          </Button>
        </CardHeader>
        <CardContent>
          {limitsQ.isLoading ? (
            <p className="text-sm text-muted-foreground">Loading…</p>
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
                label="Per-tenant"
                description="Total requests per second across all users in this tenant."
                rate={tenantRate}
                capacity={tenantCap}
                onRate={setTenantRate}
                onCapacity={setTenantCap}
              />
              <LimitRow
                label="Per-user"
                description="Requests per second per individual user account."
                rate={userRate}
                capacity={userCap}
                onRate={setUserRate}
                onCapacity={setUserCap}
              />
              <LimitRow
                label="Per-API-key"
                description="Requests per second per API key credential."
                rate={apiKeyRate}
                capacity={apiKeyCap}
                onRate={setApiKeyRate}
                onCapacity={setApiKeyCap}
              />
              <div className="flex items-center gap-3 pt-2">
                <Button type="submit" disabled={!dirty || update.isPending}>
                  {update.isPending && <Loader2Icon className="animate-spin" />}
                  Save changes
                </Button>
                {update.isSuccess && <span className="text-sm text-green-600">Saved.</span>}
              </div>
            </form>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
