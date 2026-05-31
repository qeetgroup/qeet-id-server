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
      <PageHeader description="Tenant-wide security policy. Applies to every login, every session, every API call against this tenant." />

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
              <CardTitle className="text-base">Network policy</CardTitle>
              <CardDescription>
                IP allowlist takes precedence: if non-empty, only matching CIDRs may sign in. Denylist always blocks.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <FieldGroup>
                <Field>
                  <FieldLabel htmlFor="ip_allowlist">IP allowlist (CIDR, one per line)</FieldLabel>
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
                  <FieldDescription>Empty = allow from anywhere (subject to denylist).</FieldDescription>
                </Field>
                <Field>
                  <FieldLabel htmlFor="ip_denylist">IP denylist (CIDR, one per line)</FieldLabel>
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
              <CardTitle className="text-base">Password policy</CardTitle>
              <CardDescription>Enforced at signup, password change, and password reset.</CardDescription>
            </CardHeader>
            <CardContent>
              <FieldGroup>
                <Field className="grid grid-cols-2 gap-4">
                  <Field>
                    <FieldLabel htmlFor="password_min_length">Minimum length</FieldLabel>
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
                    <FieldLabel>Complexity</FieldLabel>
                    <Select
                      value={draft.password_complexity}
                      onValueChange={(v) => set("password_complexity", v ?? "")}
                    >
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="basic">Basic — letters only</SelectItem>
                        <SelectItem value="standard">Standard — mixed case + numbers</SelectItem>
                        <SelectItem value="strict">Strict — also requires symbols</SelectItem>
                      </SelectContent>
                    </Select>
                  </Field>
                </Field>
              </FieldGroup>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-base">Session policy</CardTitle>
              <CardDescription>Affects new sessions only; existing sessions keep their original lifetime.</CardDescription>
            </CardHeader>
            <CardContent>
              <FieldGroup>
                <Field>
                  <FieldLabel htmlFor="session_max_age">Maximum session age</FieldLabel>
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
              <CardTitle className="text-base">MFA enforcement</CardTitle>
              <CardDescription>How aggressively users are pushed toward enrolling a second factor.</CardDescription>
            </CardHeader>
            <CardContent>
              <FieldGroup>
                <Field>
                  <FieldLabel>Mode</FieldLabel>
                  <Select
                    value={draft.mfa_enforcement}
                    onValueChange={(v) => set("mfa_enforcement", v ?? "")}
                  >
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="disabled">Disabled — users cannot enrol MFA</SelectItem>
                      <SelectItem value="optional">Optional — users may enrol but aren&apos;t required</SelectItem>
                      <SelectItem value="required">Required — block login until enrolled</SelectItem>
                      <SelectItem value="admin_only">Admins only — require MFA for owner/admin roles</SelectItem>
                    </SelectContent>
                  </Select>
                  <FieldDescription>Step-up enforcement on login lands in P1-7 (see GAP-ANALYSIS).</FieldDescription>
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
              {savedAt ? `Saved ${savedAt.toLocaleTimeString()}` : "Unsaved changes"}
            </p>
            <div className="flex gap-2">
              <Button
                type="button"
                variant="outline"
                onClick={() => policyQ.data && setDraft({ ...empty, ...policyQ.data })}
                disabled={saveM.isPending}
              >
                Reset
              </Button>
              <Button type="submit" disabled={saveM.isPending}>
                {saveM.isPending && <Loader2Icon className="animate-spin" />}
                {saveM.isSuccess && !saveM.isPending && <CheckIcon />}
                {saveM.isPending ? "Saving…" : "Save policy"}
              </Button>
            </div>
          </div>
        </form>
      )}
    </div>
  );
}
