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
  Sheet,
  SheetClose,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
  Skeleton,
  StatusPill,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@qeetid/ui";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";
import { KeyRoundIcon, Loader2Icon, PlusIcon, RefreshCwIcon, Trash2Icon } from "lucide-react";
import { useState } from "react";

import { PageHeader } from "@/components/page-header";
import { ApiError, api } from "@/lib/api";
import { useTenantId } from "@/lib/auth";

export const Route = createFileRoute("/_app/auth/api/keys")({ component: ApiKeysPage });

type ApiKey = {
  id: string;
  tenant_id: string;
  user_id?: string | null;
  name: string;
  prefix: string;
  scopes: string[] | null;
  expires_at?: string | null;
  last_used_at?: string | null;
  revoked_at?: string | null;
  created_at: string;
};

type ApiKeysResponse = { items: ApiKey[] };

function ApiKeysPage() {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  const [creating, setCreating] = useState(false);
  const [revealed, setRevealed] = useState<{ name: string; raw: string } | null>(null);

  const keysQ = useQuery({
    queryKey: ["api-keys", tenantId],
    queryFn: () => api<ApiKeysResponse>(`/v1/tenants/${tenantId}/api-keys`),
    enabled: !!tenantId,
  });

  const revokeM = useMutation({
    mutationFn: (id: string) => api<void>(`/v1/api-keys/${id}`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["api-keys"] }),
  });

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <PageHeader
        description="Long-lived secrets your apps and scripts use to call the Qeetid API. Send as Authorization: ApiKey <raw>."
        actions={
          <>
            <Button
              variant="outline"
              size="sm"
              onClick={() => keysQ.refetch()}
              disabled={keysQ.isFetching}
            >
              <RefreshCwIcon className={keysQ.isFetching ? "animate-spin" : ""} />
              Refresh
            </Button>
            <Button size="sm" onClick={() => setCreating(true)}>
              <PlusIcon /> New API key
            </Button>
          </>
        }
      />

      {revealed && (
        <Card className="border-emerald-500/40 bg-emerald-50/50 dark:bg-emerald-950/20">
          <CardHeader>
            <CardTitle className="text-base">Your new key — copy it now</CardTitle>
            <CardDescription>
              This is the only time we&apos;ll show <strong>{revealed.name}</strong>. Store it in
              your secret manager.
            </CardDescription>
          </CardHeader>
          <CardContent className="flex items-center gap-2">
            <CopyableSecret value={revealed.raw} className="flex-1" />
            <Button variant="ghost" size="sm" onClick={() => setRevealed(null)}>
              Dismiss
            </Button>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Active keys</CardTitle>
          <CardDescription>
            {keysQ.data?.items?.length ?? 0} key{keysQ.data?.items?.length === 1 ? "" : "s"}
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {keysQ.isLoading ? (
            <div className="space-y-3 p-4">
              {[...Array(3)].map((_, i) => (
                <Skeleton key={i} className="h-10 w-full" />
              ))}
            </div>
          ) : keysQ.isError ? (
            <div className="p-6 text-sm text-destructive">{(keysQ.error as Error).message}</div>
          ) : !keysQ.data?.items?.length ? (
            <div className="flex flex-col items-center gap-2 p-10 text-center">
              <KeyRoundIcon className="size-8 text-muted-foreground" />
              <p className="text-sm text-muted-foreground">No API keys yet.</p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Prefix</TableHead>
                  <TableHead>Scopes</TableHead>
                  <TableHead>Last used</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {keysQ.data.items.map((k) => (
                  <TableRow key={k.id}>
                    <TableCell className="font-medium">{k.name}</TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">
                      {k.prefix}…
                    </TableCell>
                    <TableCell>
                      {k.scopes?.length ? (
                        <div className="flex flex-wrap gap-1">
                          {k.scopes.map((s) => (
                            <Badge key={s} variant="muted">
                              {s}
                            </Badge>
                          ))}
                        </div>
                      ) : (
                        <span className="text-muted-foreground">—</span>
                      )}
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      {k.last_used_at ? new Date(k.last_used_at).toLocaleString() : "Never"}
                    </TableCell>
                    <TableCell>
                      <StatusPill
                        status={
                          k.revoked_at
                            ? "revoked"
                            : k.expires_at && new Date(k.expires_at) < new Date()
                              ? "expired"
                              : "active"
                        }
                      />
                    </TableCell>
                    <TableCell className="text-right">
                      <Button
                        variant="ghost"
                        size="sm"
                        disabled={!!k.revoked_at || revokeM.isPending}
                        onClick={() => {
                          if (
                            confirm(
                              `Revoke "${k.name}"? Any service using it will lose access immediately.`,
                            )
                          ) {
                            revokeM.mutate(k.id);
                          }
                        }}
                      >
                        <Trash2Icon /> Revoke
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <CreateApiKeySheet
        open={creating}
        onOpenChange={setCreating}
        tenantId={tenantId}
        onCreated={(k) => {
          qc.invalidateQueries({ queryKey: ["api-keys"] });
          setRevealed({ name: k.name, raw: k.raw });
        }}
      />
    </div>
  );
}

type CreateApiKeySheetProps = {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  tenantId: string | null;
  onCreated: (k: { name: string; raw: string }) => void;
};

type CreateApiKeyResponse = ApiKey & { raw: string };

function CreateApiKeySheet({ open, onOpenChange, tenantId, onCreated }: CreateApiKeySheetProps) {
  const createM = useMutation({
    mutationFn: (body: {
      tenant_id: string;
      name: string;
      scopes?: string[];
      expires_at?: string;
    }) => api<CreateApiKeyResponse>("/v1/api-keys", { method: "POST", body }),
    onSuccess: (res) => {
      onCreated({ name: res.name, raw: res.raw });
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
              scopes: scopesRaw ? scopesRaw.split(/\s+/) : undefined,
              expires_at: String(data.get("expires_at") ?? "") || undefined,
            });
          }}
        >
          <SheetHeader>
            <SheetTitle>New API key</SheetTitle>
            <SheetDescription>
              The full key is shown once after creation — we only store a bcrypt hash.
            </SheetDescription>
          </SheetHeader>
          <div className="flex-1 overflow-y-auto p-4">
            <FieldGroup>
              <Field>
                <FieldLabel htmlFor="name">Name</FieldLabel>
                <Input id="name" name="name" placeholder="CI deploy key" required maxLength={200} />
              </Field>
              <Field>
                <FieldLabel htmlFor="scopes">Scopes (space-separated)</FieldLabel>
                <Input id="scopes" name="scopes" placeholder="user.read tenant.read" />
                <FieldDescription>
                  Leave empty for full access (least-privilege scoping recommended).
                </FieldDescription>
              </Field>
              <Field>
                <FieldLabel htmlFor="expires_at">Expires at</FieldLabel>
                <Input id="expires_at" name="expires_at" type="datetime-local" />
                <FieldDescription>Optional. Empty = never expires.</FieldDescription>
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
              {createM.isPending ? "Creating…" : "Create key"}
            </Button>
          </SheetFooter>
        </form>
      </SheetContent>
    </Sheet>
  );
}
