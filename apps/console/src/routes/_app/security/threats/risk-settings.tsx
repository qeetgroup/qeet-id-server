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
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@qeetrix/ui";
import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Loader2Icon, ShieldCheckIcon } from "lucide-react";
import { useEffect, useState } from "react";

import { PageHeader } from "@/components/page-header";
import { api } from "@/lib/api";
import { useTenantId } from "@/lib/auth";

export const Route = createFileRoute("/_app/security/threats/risk-settings")({
  component: RiskSettingsPage,
});

interface RiskSettings {
  medium_threshold: number;
  high_threshold: number;
  force_mfa_at_level: "medium" | "high";
}

function useRiskSettings() {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: ["risk-settings", tenantId],
    queryFn: () => api<RiskSettings>(`/v1/tenants/${tenantId}/security/risk-settings`),
    enabled: !!tenantId,
  });
}

function useUpdateRiskSettings() {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: RiskSettings) =>
      api<RiskSettings>(`/v1/tenants/${tenantId}/security/risk-settings`, {
        method: "PUT",
        body,
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["risk-settings", tenantId] }),
  });
}

function RiskSettingsPage() {
  const settingsQ = useRiskSettings();
  const update = useUpdateRiskSettings();

  const [medium, setMedium] = useState(0.5);
  const [high, setHigh] = useState(0.8);
  const [forceAt, setForceAt] = useState<"medium" | "high">("high");

  useEffect(() => {
    if (settingsQ.data) {
      setMedium(settingsQ.data.medium_threshold);
      setHigh(settingsQ.data.high_threshold);
      setForceAt(settingsQ.data.force_mfa_at_level);
    }
  }, [settingsQ.data]);

  const dirty =
    settingsQ.data &&
    (medium !== settingsQ.data.medium_threshold ||
      high !== settingsQ.data.high_threshold ||
      forceAt !== settingsQ.data.force_mfa_at_level);

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <PageHeader description="Configure adaptive MFA risk thresholds. When a login request's bot score exceeds your chosen threshold, MFA is required even on a remembered device." />

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <ShieldCheckIcon className="size-4" />
            Risk Thresholds
          </CardTitle>
          <CardDescription>
            Bot scores range from 0 (clearly human) to 1 (clearly automated). A score above the
            High threshold forces MFA even on a trusted device.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {settingsQ.isLoading ? (
            <p className="text-sm text-muted-foreground">Loading…</p>
          ) : (
            <form
              className="flex flex-col gap-5"
              onSubmit={(e) => {
                e.preventDefault();
                update.mutate({ medium_threshold: medium, high_threshold: high, force_mfa_at_level: forceAt });
              }}
            >
              <div className="grid gap-4 sm:grid-cols-2">
                <Field>
                  <FieldLabel htmlFor="medium">Medium threshold (0.1–1.0)</FieldLabel>
                  <Input
                    id="medium"
                    type="number"
                    step="0.05"
                    min={0.1}
                    max={1.0}
                    value={medium}
                    onChange={(e) => setMedium(Number(e.target.value))}
                  />
                  <FieldDescription>
                    Score at/above this triggers a step-up MFA challenge for unrecognised devices.
                  </FieldDescription>
                </Field>
                <Field>
                  <FieldLabel htmlFor="high">High threshold (0.1–1.0)</FieldLabel>
                  <Input
                    id="high"
                    type="number"
                    step="0.05"
                    min={0.1}
                    max={1.0}
                    value={high}
                    onChange={(e) => setHigh(Number(e.target.value))}
                  />
                  <FieldDescription>
                    Score at/above this forces MFA even on a trusted/remembered device.
                  </FieldDescription>
                </Field>
              </div>

              <Field className="max-w-xs">
                <FieldLabel htmlFor="force-at">Force MFA at level</FieldLabel>
                <Select value={forceAt} onValueChange={(v) => setForceAt(v as "medium" | "high")}>
                  <SelectTrigger id="force-at">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="medium">Medium — force on any suspicious request</SelectItem>
                    <SelectItem value="high">High — force only on clearly automated requests</SelectItem>
                  </SelectContent>
                </Select>
                <FieldDescription>
                  Which risk level overrides the trusted-device skip.
                </FieldDescription>
              </Field>

              <div className="flex items-center gap-3">
                <Button type="submit" disabled={!dirty || update.isPending}>
                  {update.isPending && <Loader2Icon className="animate-spin" />}
                  Save changes
                </Button>
                {update.isSuccess && (
                  <span className="text-sm text-green-600">Saved.</span>
                )}
              </div>
            </form>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
