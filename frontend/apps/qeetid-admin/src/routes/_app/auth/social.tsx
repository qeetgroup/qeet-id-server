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
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Sheet,
  SheetClose,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
  Skeleton,
} from "@qeetrix/ui";
import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Loader2Icon, NetworkIcon, PlusIcon, RefreshCwIcon } from "lucide-react";
import { useState } from "react";

import { PageHeader } from "@/components/page-header";
import { ApiError, api } from "@/lib/api";
import { useTenantId } from "@/lib/auth";

export const Route = createFileRoute("/_app/auth/social")({ component: SocialPage });

type Provider = {
  tenant_id: string;
  provider: string;
  client_id: string;
  discovery_url: string;
  enabled: boolean;
  updated_at: string;
};

const KNOWN_PROVIDERS = [
  { id: "google", label: "Google", discovery: "https://accounts.google.com/.well-known/openid-configuration" },
  { id: "github", label: "GitHub", discovery: "" },
  { id: "microsoft", label: "Microsoft", discovery: "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration" },
  { id: "apple", label: "Apple", discovery: "https://appleid.apple.com/.well-known/openid-configuration" },
];

function SocialPage() {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  const [editingProvider, setEditingProvider] = useState<string | null>(null);

  const listQ = useQuery({
    queryKey: ["social-providers", tenantId],
    queryFn: () => api<{ items: Provider[] }>(`/v1/tenants/${tenantId}/social/providers`),
    enabled: !!tenantId,
  });

  const configured = new Map((listQ.data?.items ?? []).map((p) => [p.provider, p]));

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <PageHeader
        description="Configure OAuth client credentials for social IdPs. The exchange flow (start / callback) returns 501 today — see GAP-ANALYSIS P1-1."
        actions={
          <Button variant="outline" size="sm" onClick={() => listQ.refetch()} disabled={listQ.isFetching}>
            <RefreshCwIcon className={listQ.isFetching ? "animate-spin" : ""} />
            Refresh
          </Button>
        }
      />

      <div className="grid gap-4 md:grid-cols-2">
        {KNOWN_PROVIDERS.map((p) => {
          const cfg = configured.get(p.id);
          return (
            <Card key={p.id}>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle className="text-base">{p.label}</CardTitle>
                    <CardDescription>{cfg ? "Configured" : "Not configured"}</CardDescription>
                  </div>
                  {cfg ? (
                    cfg.enabled ? <Badge variant="success">Enabled</Badge> : <Badge variant="muted">Disabled</Badge>
                  ) : (
                    <Badge variant="outline">Off</Badge>
                  )}
                </div>
              </CardHeader>
              <CardContent className="space-y-2">
                {listQ.isLoading ? (
                  <Skeleton className="h-12 w-full" />
                ) : cfg ? (
                  <code className="block break-all text-xs text-muted-foreground">
                    client_id={cfg.client_id.slice(0, 20)}…
                  </code>
                ) : (
                  <p className="text-xs text-muted-foreground">No credentials saved.</p>
                )}
                <Button variant="outline" size="sm" className="w-full" onClick={() => setEditingProvider(p.id)}>
                  <PlusIcon /> {cfg ? "Update" : "Configure"}
                </Button>
              </CardContent>
            </Card>
          );
        })}
      </div>

      {!listQ.isLoading && !configured.size && (
        <Card>
          <CardContent className="flex flex-col items-center gap-2 p-10 text-center">
            <NetworkIcon className="size-8 text-muted-foreground" />
            <p className="text-sm text-muted-foreground">
              No providers configured yet. Pick a provider above to enable social sign-in.
            </p>
          </CardContent>
        </Card>
      )}

      {editingProvider && (
        <ConfigureProviderSheet
          provider={editingProvider}
          tenantId={tenantId}
          existing={configured.get(editingProvider)}
          onClose={() => setEditingProvider(null)}
          onSaved={() => qc.invalidateQueries({ queryKey: ["social-providers"] })}
        />
      )}
    </div>
  );
}

type ConfigureSheetProps = {
  provider: string;
  tenantId: string | null;
  existing?: Provider;
  onClose: () => void;
  onSaved: () => void;
};

function ConfigureProviderSheet({ provider, tenantId, existing, onClose, onSaved }: ConfigureSheetProps) {
  const meta = KNOWN_PROVIDERS.find((p) => p.id === provider);
  const upsertM = useMutation({
    mutationFn: (body: {
      tenant_id: string;
      provider: string;
      client_id: string;
      client_secret: string;
      discovery_url: string;
    }) => api<Provider>("/v1/social/providers", { method: "POST", body }),
    onSuccess: () => {
      onSaved();
      onClose();
    },
  });

  return (
    <Sheet open onOpenChange={(o) => !o && onClose()}>
      <SheetContent side="right" className="w-full sm:max-w-md">
        <form
          className="flex h-full flex-col"
          onSubmit={(e) => {
            e.preventDefault();
            if (!tenantId) return;
            const data = new FormData(e.currentTarget);
            upsertM.mutate({
              tenant_id: tenantId,
              provider,
              client_id: String(data.get("client_id") ?? "").trim(),
              client_secret: String(data.get("client_secret") ?? "").trim(),
              discovery_url: String(data.get("discovery_url") ?? "").trim(),
            });
          }}
        >
          <SheetHeader>
            <SheetTitle>Configure {meta?.label ?? provider}</SheetTitle>
            <SheetDescription>
              Paste the OAuth client credentials from your IdP&apos;s developer console.
            </SheetDescription>
          </SheetHeader>
          <div className="flex-1 overflow-y-auto p-4">
            <FieldGroup>
              <Field>
                <FieldLabel>Provider</FieldLabel>
                <Select value={provider} disabled>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {KNOWN_PROVIDERS.map((p) => <SelectItem key={p.id} value={p.id}>{p.label}</SelectItem>)}
                  </SelectContent>
                </Select>
              </Field>
              <Field>
                <FieldLabel htmlFor="client_id">Client ID</FieldLabel>
                <Input id="client_id" name="client_id" defaultValue={existing?.client_id} required />
              </Field>
              <Field>
                <FieldLabel htmlFor="client_secret">Client secret</FieldLabel>
                <Input id="client_secret" name="client_secret" type="password" required placeholder={existing ? "Leave blank to keep existing" : ""} />
                <FieldDescription>Stored server-side as plaintext today — rotation is your responsibility.</FieldDescription>
              </Field>
              <Field>
                <FieldLabel htmlFor="discovery_url">Discovery URL</FieldLabel>
                <Input
                  id="discovery_url"
                  name="discovery_url"
                  type="url"
                  defaultValue={existing?.discovery_url ?? meta?.discovery}
                  placeholder="https://provider.example/.well-known/openid-configuration"
                />
                <FieldDescription>Optional. Used for OIDC providers; leave blank for plain OAuth 2.0.</FieldDescription>
              </Field>
              {upsertM.error && <Field><FieldError>{(upsertM.error as ApiError).message}</FieldError></Field>}
            </FieldGroup>
          </div>
          <SheetFooter className="flex-row justify-end gap-2 border-t">
            <SheetClose render={<Button type="button" variant="outline" />}>Cancel</SheetClose>
            <Button type="submit" disabled={upsertM.isPending}>
              {upsertM.isPending && <Loader2Icon className="animate-spin" />}
              {upsertM.isPending ? "Saving…" : "Save"}
            </Button>
          </SheetFooter>
        </form>
      </SheetContent>
    </Sheet>
  );
}
