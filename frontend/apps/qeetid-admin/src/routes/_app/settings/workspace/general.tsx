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
  TimeSince,
} from "@qeetid/ui";
import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckIcon, Loader2Icon } from "lucide-react";
import { useEffect, useState } from "react";

import { PageHeader } from "@/components/page-header";
import { ApiError, api } from "@/lib/api";
import { useTenantId } from "@/lib/auth";

export const Route = createFileRoute("/_app/settings/workspace/general")({ component: WorkspaceGeneralPage });

type Tenant = {
  id: string;
  slug: string;
  name: string;
  status: "active" | "suspended" | "deleted";
  plan: string;
  region: string;
  metadata: Record<string, unknown>;
  created_at: string;
};

function WorkspaceGeneralPage() {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  const [draft, setDraft] = useState<Partial<Tenant>>({});
  const [savedAt, setSavedAt] = useState<Date | null>(null);

  const tenantQ = useQuery({
    queryKey: ["tenant", tenantId],
    queryFn: () => api<Tenant>(`/v1/tenants/${tenantId}`),
    enabled: !!tenantId,
  });

  useEffect(() => {
    if (tenantQ.data) setDraft(tenantQ.data);
  }, [tenantQ.data]);

  const saveM = useMutation({
    mutationFn: (body: { name?: string; plan?: string; region?: string; status?: string }) =>
      api<Tenant>(`/v1/tenants/${tenantId}`, { method: "PATCH", body }),
    onSuccess: () => {
      setSavedAt(new Date());
      qc.invalidateQueries({ queryKey: ["tenant", tenantId] });
      qc.invalidateQueries({ queryKey: ["tenants"] });
    },
  });

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <PageHeader description="The display name, plan, and region for this workspace. The slug is immutable." />

      {tenantQ.isLoading ? (
        <Card><CardContent className="space-y-3 p-6">{[...Array(4)].map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}</CardContent></Card>
      ) : (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            saveM.mutate({
              name: draft.name,
              plan: draft.plan,
              region: draft.region,
              status: draft.status,
            });
          }}
        >
          <div className="grid gap-4 lg:grid-cols-3">
            <div className="space-y-4 lg:col-span-2">
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Profile</CardTitle>
                  <CardDescription>Visible to members of this tenant.</CardDescription>
                </CardHeader>
                <CardContent>
                  <FieldGroup>
                    <Field>
                      <FieldLabel htmlFor="slug">Slug</FieldLabel>
                      <Input id="slug" value={draft.slug ?? ""} disabled className="font-mono" />
                      <FieldDescription>Immutable. Used in tenant URLs and SCIM/SAML metadata.</FieldDescription>
                    </Field>
                    <Field>
                      <FieldLabel htmlFor="name">Name</FieldLabel>
                      <Input id="name" value={draft.name ?? ""} onChange={(e) => setDraft((d) => ({ ...d, name: e.target.value }))} required />
                    </Field>
                    <Field className="grid grid-cols-2 gap-4">
                      <Field>
                        <FieldLabel>Plan</FieldLabel>
                        <Select value={draft.plan ?? "free"} onValueChange={(v) => setDraft((d) => ({ ...d, plan: v }))}>
                          <SelectTrigger><SelectValue /></SelectTrigger>
                          <SelectContent>
                            <SelectItem value="free">Free</SelectItem>
                            <SelectItem value="pro">Pro</SelectItem>
                            <SelectItem value="enterprise">Enterprise</SelectItem>
                          </SelectContent>
                        </Select>
                      </Field>
                      <Field>
                        <FieldLabel htmlFor="region">Region</FieldLabel>
                        <Input
                          id="region"
                          value={draft.region ?? ""}
                          onChange={(e) => setDraft((d) => ({ ...d, region: e.target.value }))}
                        />
                      </Field>
                    </Field>
                    <Field>
                      <FieldLabel>Status</FieldLabel>
                      <Select value={draft.status ?? "active"} onValueChange={(v) => setDraft((d) => ({ ...d, status: v as Tenant["status"] }))}>
                        <SelectTrigger><SelectValue /></SelectTrigger>
                        <SelectContent>
                          <SelectItem value="active">Active</SelectItem>
                          <SelectItem value="suspended">Suspended</SelectItem>
                        </SelectContent>
                      </Select>
                      <FieldDescription>Suspending blocks new logins for everyone in this tenant.</FieldDescription>
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
                  <Button type="button" variant="outline" onClick={() => tenantQ.data && setDraft(tenantQ.data)} disabled={saveM.isPending}>
                    Reset
                  </Button>
                  <Button type="submit" disabled={saveM.isPending}>
                    {saveM.isPending && <Loader2Icon className="animate-spin" />}
                    {saveM.isSuccess && !saveM.isPending && <CheckIcon />}
                    {saveM.isPending ? "Saving…" : "Save changes"}
                  </Button>
                </div>
              </div>
            </div>

            <div>
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Tenant ID</CardTitle>
                  <CardDescription>Reference value used by SCIM, SAML and API calls.</CardDescription>
                </CardHeader>
                <CardContent>
                  <code className="block break-all rounded-md border bg-muted px-3 py-2 text-xs">{draft.id ?? "—"}</code>
                  <p className="mt-4 text-xs text-muted-foreground">
                    Created{" "}
                    {draft.created_at ? <TimeSince value={draft.created_at} className="text-xs" /> : "—"}
                  </p>
                </CardContent>
              </Card>
            </div>
          </div>
        </form>
      )}
    </div>
  );
}
