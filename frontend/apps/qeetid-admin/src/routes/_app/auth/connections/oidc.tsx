import {
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  CopyableSecret,
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
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  Textarea,
} from "@qeetid/ui";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";
import {
  Loader2Icon,
  PlusIcon,
  RefreshCwIcon,
  Trash2Icon,
  WorkflowIcon,
} from "lucide-react";
import { useState } from "react";

import { PageHeader } from "@/components/page-header";
import { ApiError, api } from "@/lib/api";
import { useTenantId } from "@/lib/auth";

export const Route = createFileRoute("/_app/auth/connections/oidc")({ component: OidcPage });

type OidcClient = {
  id: string;
  tenant_id: string;
  client_id: string;
  name: string;
  type: "public" | "confidential";
  redirect_uris: string[];
  post_logout_uris?: string[] | null;
  grant_types: string[];
  scopes: string[];
  created_at: string;
};

function OidcPage() {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  const [creating, setCreating] = useState(false);
  const [revealed, setRevealed] = useState<{ client: OidcClient; secret: string } | null>(null);

  const listQ = useQuery({
    queryKey: ["oidc-clients", tenantId],
    queryFn: () => api<{ items: OidcClient[] }>(`/v1/tenants/${tenantId}/oidc/clients`),
    enabled: !!tenantId,
  });

  const deleteM = useMutation({
    mutationFn: (id: string) => api<void>(`/v1/oidc/clients/${id}`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["oidc-clients"] }),
  });

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <PageHeader
        description="OAuth 2.0 / OIDC applications that delegate authentication to Qeet ID. The /authorize and ID-token code flow is in progress — see GAP-ANALYSIS P0-4."
        actions={
          <>
            <Button
              variant="outline"
              size="sm"
              onClick={() => listQ.refetch()}
              disabled={listQ.isFetching}
            >
              <RefreshCwIcon className={listQ.isFetching ? "animate-spin" : ""} />
              Refresh
            </Button>
            <Button size="sm" onClick={() => setCreating(true)}>
              <PlusIcon /> Register application
            </Button>
          </>
        }
      />

      {revealed && (
        <Card className="border-emerald-500/40 bg-emerald-50/50 dark:bg-emerald-950/20">
          <CardHeader>
            <CardTitle className="text-base">
              Client credentials for {revealed.client.name}
            </CardTitle>
            <CardDescription>
              Confidential clients only. The secret is bcrypt-hashed server-side after this.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-2">
            <CopyableSecret value={revealed.client.client_id} label="client_id=" size="sm" />
            <CopyableSecret value={revealed.secret} label="client_secret=" size="sm" />
            <Button variant="ghost" size="sm" onClick={() => setRevealed(null)}>
              Dismiss
            </Button>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Registered applications</CardTitle>
          <CardDescription>
            {listQ.data?.items?.length ?? 0} app{listQ.data?.items?.length === 1 ? "" : "s"}
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {listQ.isLoading ? (
            <div className="space-y-3 p-4">
              {[...Array(3)].map((_, i) => (
                <Skeleton key={i} className="h-10 w-full" />
              ))}
            </div>
          ) : listQ.isError ? (
            <div className="p-6 text-sm text-destructive">{(listQ.error as Error).message}</div>
          ) : !listQ.data?.items?.length ? (
            <div className="flex flex-col items-center gap-2 p-10 text-center">
              <WorkflowIcon className="size-8 text-muted-foreground" />
              <p className="text-sm text-muted-foreground">No applications registered.</p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Client ID</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Redirect URIs</TableHead>
                  <TableHead>Scopes</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {listQ.data.items.map((c) => (
                  <TableRow key={c.id}>
                    <TableCell className="font-medium">{c.name}</TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">
                      {c.client_id.slice(0, 16)}…
                    </TableCell>
                    <TableCell>
                      <Badge variant={c.type === "confidential" ? "default" : "muted"}>
                        {c.type}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-muted-foreground text-xs">
                      {c.redirect_uris.slice(0, 2).join(", ")}
                      {c.redirect_uris.length > 2 && ` +${c.redirect_uris.length - 2}`}
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        {c.scopes.slice(0, 3).map((s) => (
                          <Badge key={s} variant="muted">
                            {s}
                          </Badge>
                        ))}
                        {c.scopes.length > 3 && (
                          <Badge variant="muted">+{c.scopes.length - 3}</Badge>
                        )}
                      </div>
                    </TableCell>
                    <TableCell className="text-right">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => {
                          if (
                            confirm(
                              `Delete "${c.name}"? Apps using this client_id will stop working.`,
                            )
                          ) {
                            deleteM.mutate(c.id);
                          }
                        }}
                        disabled={deleteM.isPending}
                      >
                        <Trash2Icon /> Delete
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <CreateOidcSheet
        open={creating}
        onOpenChange={setCreating}
        tenantId={tenantId}
        onCreated={(client, secret) => {
          qc.invalidateQueries({ queryKey: ["oidc-clients"] });
          if (secret) setRevealed({ client, secret });
        }}
      />
    </div>
  );
}

type CreateOidcSheetProps = {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  tenantId: string | null;
  onCreated: (c: OidcClient, secret: string) => void;
};

function CreateOidcSheet({ open, onOpenChange, tenantId, onCreated }: CreateOidcSheetProps) {
  const [type, setType] = useState<"public" | "confidential">("public");
  const createM = useMutation({
    mutationFn: (body: {
      tenant_id: string;
      name: string;
      type: string;
      redirect_uris: string[];
      post_logout_uris: string[];
      grant_types: string[];
      scopes: string[];
    }) =>
      api<OidcClient & { client_secret?: string }>("/v1/oidc/clients", { method: "POST", body }),
    onSuccess: (res) => {
      onCreated(res, res.client_secret ?? "");
      onOpenChange(false);
    },
  });

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="w-full sm:max-w-lg">
        <form
          className="flex h-full flex-col"
          onSubmit={(e) => {
            e.preventDefault();
            if (!tenantId) return;
            const data = new FormData(e.currentTarget);
            const lines = (k: string) =>
              String(data.get(k) ?? "")
                .split(/\n+/)
                .map((s) => s.trim())
                .filter(Boolean);
            const scopesRaw = String(data.get("scopes") ?? "openid profile email").trim();
            createM.mutate({
              tenant_id: tenantId,
              name: String(data.get("name") ?? "").trim(),
              type,
              redirect_uris: lines("redirect_uris"),
              post_logout_uris: lines("post_logout_uris"),
              grant_types: ["authorization_code", "refresh_token"],
              scopes: scopesRaw.split(/\s+/),
            });
          }}
        >
          <SheetHeader>
            <SheetTitle>Register OAuth / OIDC application</SheetTitle>
            <SheetDescription>
              Creates an OIDC client (RFC 7591 dynamic registration).
            </SheetDescription>
          </SheetHeader>
          <div className="flex-1 overflow-y-auto p-4">
            <FieldGroup>
              <Field>
                <FieldLabel htmlFor="name">Name</FieldLabel>
                <Input id="name" name="name" placeholder="My SPA" required />
              </Field>
              <Field>
                <FieldLabel>Type</FieldLabel>
                <Select value={type} onValueChange={(v) => setType(v as "public" | "confidential")}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="public">Public — SPA, mobile (PKCE)</SelectItem>
                    <SelectItem value="confidential">
                      Confidential — server-side app (client secret)
                    </SelectItem>
                  </SelectContent>
                </Select>
              </Field>
              <Field>
                <FieldLabel htmlFor="redirect_uris">Redirect URIs</FieldLabel>
                <Textarea
                  id="redirect_uris"
                  name="redirect_uris"
                  rows={3}
                  placeholder={"http://localhost:3000/callback\nhttps://app.acme.com/callback"}
                  required
                />
                <FieldDescription>
                  One URL per line. Must be HTTPS in production; localhost is allowed for dev.
                </FieldDescription>
              </Field>
              <Field>
                <FieldLabel htmlFor="post_logout_uris">Post-logout redirect URIs</FieldLabel>
                <Textarea
                  id="post_logout_uris"
                  name="post_logout_uris"
                  rows={2}
                  placeholder="https://app.acme.com/"
                />
              </Field>
              <Field>
                <FieldLabel htmlFor="scopes">Scopes</FieldLabel>
                <Input id="scopes" name="scopes" defaultValue="openid profile email" />
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
              {createM.isPending ? "Registering…" : "Register"}
            </Button>
          </SheetFooter>
        </form>
      </SheetContent>
    </Sheet>
  );
}
