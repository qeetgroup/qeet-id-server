import {
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  Field,
  FieldError,
  FieldGroup,
  FieldLabel,
  Input,
  Sheet,
  SheetClose,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
  Skeleton,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  Textarea,
} from "@qeetrix/ui";
import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { BotIcon, CopyIcon, Loader2Icon, PlusIcon, RefreshCwIcon, Trash2Icon } from "lucide-react";
import { useState } from "react";

import { PageHeader } from "@/components/page-header";
import { ApiError, api } from "@/lib/api";
import { useTenantId } from "@/lib/auth";

export const Route = createFileRoute("/_app/auth/api/machine-identities")({
  component: MachineIdentitiesPage,
});

type Principal = {
  id: string;
  tenant_id: string;
  name: string;
  description?: string | null;
  scopes: string[] | null;
  disabled_at?: string | null;
  created_at: string;
};

function MachineIdentitiesPage() {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  const [creating, setCreating] = useState(false);
  const [revealed, setRevealed] = useState<{ principal: Principal; secret: string } | null>(null);

  const listQ = useQuery({
    queryKey: ["principals", tenantId],
    queryFn: () => api<{ items: Principal[] }>(`/v1/tenants/${tenantId}/service-principals`),
    enabled: !!tenantId,
  });

  const disableM = useMutation({
    mutationFn: (id: string) => api<void>(`/v1/service-principals/${id}`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["principals"] }),
  });

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <PageHeader
        description="Service accounts for server-to-server calls. Authenticate via POST /v1/oauth/token with grant_type=client_credentials."
        actions={
          <>
            <Button variant="outline" size="sm" onClick={() => listQ.refetch()} disabled={listQ.isFetching}>
              <RefreshCwIcon className={listQ.isFetching ? "animate-spin" : ""} />
              Refresh
            </Button>
            <Button size="sm" onClick={() => setCreating(true)}>
              <PlusIcon /> New identity
            </Button>
          </>
        }
      />

      {revealed && (
        <Card className="border-emerald-500/40 bg-emerald-50/50 dark:bg-emerald-950/20">
          <CardHeader>
            <CardTitle className="text-base">Client credentials for {revealed.principal.name}</CardTitle>
            <CardDescription>
              We&apos;ll never show this secret again. Use it as <code>client_id</code> +{" "}
              <code>client_secret</code> on the token endpoint.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-2">
            <div className="flex items-center gap-2">
              <code className="flex-1 break-all rounded-md border bg-background px-3 py-2 text-xs">
                client_id={revealed.principal.id}
              </code>
              <Button variant="outline" size="sm" onClick={() => navigator.clipboard.writeText(revealed.principal.id)}>
                <CopyIcon />
              </Button>
            </div>
            <div className="flex items-center gap-2">
              <code className="flex-1 break-all rounded-md border bg-background px-3 py-2 text-xs">
                client_secret={revealed.secret}
              </code>
              <Button variant="outline" size="sm" onClick={() => navigator.clipboard.writeText(revealed.secret)}>
                <CopyIcon />
              </Button>
            </div>
            <Button variant="ghost" size="sm" onClick={() => setRevealed(null)}>
              Dismiss
            </Button>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Service principals</CardTitle>
          <CardDescription>{listQ.data?.items?.length ?? 0} identit{listQ.data?.items?.length === 1 ? "y" : "ies"}</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {listQ.isLoading ? (
            <div className="space-y-3 p-4">
              {[...Array(3)].map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}
            </div>
          ) : listQ.isError ? (
            <div className="p-6 text-sm text-destructive">{(listQ.error as Error).message}</div>
          ) : !listQ.data?.items?.length ? (
            <div className="flex flex-col items-center gap-2 p-10 text-center">
              <BotIcon className="size-8 text-muted-foreground" />
              <p className="text-sm text-muted-foreground">No service principals yet.</p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Client ID</TableHead>
                  <TableHead>Scopes</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {listQ.data.items.map((p) => (
                  <TableRow key={p.id}>
                    <TableCell className="font-medium">{p.name}</TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">{p.id.slice(0, 16)}…</TableCell>
                    <TableCell>
                      {p.scopes?.length ? (
                        <div className="flex flex-wrap gap-1">
                          {p.scopes.map((s) => <Badge key={s} variant="muted">{s}</Badge>)}
                        </div>
                      ) : <span className="text-muted-foreground">—</span>}
                    </TableCell>
                    <TableCell>
                      {p.disabled_at ? <Badge variant="destructive">Disabled</Badge> : <Badge variant="success">Active</Badge>}
                    </TableCell>
                    <TableCell className="text-muted-foreground">{new Date(p.created_at).toLocaleDateString()}</TableCell>
                    <TableCell className="text-right">
                      <Button
                        variant="ghost"
                        size="sm"
                        disabled={!!p.disabled_at || disableM.isPending}
                        onClick={() => {
                          if (confirm(`Disable "${p.name}"? Token issuance will be blocked immediately.`)) {
                            disableM.mutate(p.id);
                          }
                        }}
                      >
                        <Trash2Icon /> Disable
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <CreatePrincipalSheet
        open={creating}
        onOpenChange={setCreating}
        tenantId={tenantId}
        onCreated={(p, secret) => {
          qc.invalidateQueries({ queryKey: ["principals"] });
          setRevealed({ principal: p, secret });
        }}
      />
    </div>
  );
}

type CreatePrincipalSheetProps = {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  tenantId: string | null;
  onCreated: (p: Principal, secret: string) => void;
};

function CreatePrincipalSheet({ open, onOpenChange, tenantId, onCreated }: CreatePrincipalSheetProps) {
  const createM = useMutation({
    mutationFn: (body: {
      tenant_id: string;
      name: string;
      description?: string;
      scopes?: string[];
    }) =>
      api<Principal & { client_secret?: string; secret?: string }>("/v1/service-principals", {
        method: "POST",
        body,
      }),
    onSuccess: (res) => {
      const secret = (res as Principal & { client_secret?: string; secret?: string }).client_secret
        ?? (res as Principal & { client_secret?: string; secret?: string }).secret
        ?? "";
      onCreated(res as Principal, secret);
      onOpenChange(false);
    },
  });

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="w-full sm:max-w-md">
        <form
          className="flex h-full flex-col"
          onSubmit={(e) => {
            e.preventDefault();
            if (!tenantId) return;
            const data = new FormData(e.currentTarget);
            const scopesRaw = String(data.get("scopes") ?? "").trim();
            createM.mutate({
              tenant_id: tenantId,
              name: String(data.get("name") ?? "").trim(),
              description: String(data.get("description") ?? "").trim() || undefined,
              scopes: scopesRaw ? scopesRaw.split(/\s+/) : undefined,
            });
          }}
        >
          <SheetHeader>
            <SheetTitle>New machine identity</SheetTitle>
            <SheetDescription>
              Creates a service principal usable via OAuth 2.0 client_credentials.
            </SheetDescription>
          </SheetHeader>
          <div className="flex-1 overflow-y-auto p-4">
            <FieldGroup>
              <Field>
                <FieldLabel htmlFor="name">Name</FieldLabel>
                <Input id="name" name="name" placeholder="build-bot" required />
              </Field>
              <Field>
                <FieldLabel htmlFor="description">Description</FieldLabel>
                <Textarea id="description" name="description" rows={3} placeholder="What this identity is used for" />
              </Field>
              <Field>
                <FieldLabel htmlFor="scopes">Scopes (space-separated)</FieldLabel>
                <Input id="scopes" name="scopes" placeholder="user.read tenant.read" />
              </Field>
              {createM.error && (
                <Field>
                  <FieldError>{(createM.error as ApiError).message}</FieldError>
                </Field>
              )}
            </FieldGroup>
          </div>
          <SheetFooter className="flex-row justify-end gap-2 border-t">
            <SheetClose render={<Button type="button" variant="outline" />}>Cancel</SheetClose>
            <Button type="submit" disabled={createM.isPending}>
              {createM.isPending && <Loader2Icon className="animate-spin" />}
              {createM.isPending ? "Creating…" : "Create"}
            </Button>
          </SheetFooter>
        </form>
      </SheetContent>
    </Sheet>
  );
}
