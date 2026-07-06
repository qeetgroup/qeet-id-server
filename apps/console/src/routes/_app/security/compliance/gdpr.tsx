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
import { Loader2Icon, PlusIcon, RefreshCwIcon, ScrollTextIcon, ShieldCheckIcon } from "lucide-react";
import { useState } from "react";

import { PageHeader } from "@/components/page-header";
import { ApiError, api } from "@/lib/api";
import { useTenantId } from "@/lib/auth";

export const Route = createFileRoute("/_app/security/compliance/gdpr")({ component: GdprPage });

type PurgeRequest = {
  id: string;
  tenant_id: string;
  user_id: string;
  requested_by?: string | null;
  reason?: string | null;
  status: "pending" | "completed" | "cancelled";
  grace_until: string;
  completed_at?: string | null;
  created_at: string;
};

function GdprPage() {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  const [creating, setCreating] = useState(false);

  const listQ = useQuery({
    queryKey: ["gdpr-purges", tenantId],
    queryFn: () => api<{ items: PurgeRequest[] }>(`/v1/tenants/${tenantId}/gdpr/purge`),
    enabled: !!tenantId,
  });

  const cancelM = useMutation({
    mutationFn: (id: string) => api<void>(`/v1/gdpr/purge/${id}`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["gdpr-purges"] }),
  });

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <PageHeader
        description="GDPR Article 17 (right-to-erasure) requests. Each request enters a 30-day grace window before the background purge job redacts PII while preserving audit references."
        actions={
          <>
            <Button variant="outline" size="sm" onClick={() => listQ.refetch()} disabled={listQ.isFetching}>
              <RefreshCwIcon className={listQ.isFetching ? "animate-spin" : ""} />
              Refresh
            </Button>
            <Button size="sm" onClick={() => setCreating(true)}>
              <PlusIcon /> File erasure request
            </Button>
          </>
        }
      />

      <Card className="border-amber-500/40 bg-amber-50/30 dark:bg-amber-950/20">
        <CardContent className="flex items-start gap-3 p-4">
          <ShieldCheckIcon className="size-5 text-emerald-700 dark:text-emerald-500" />
          <div className="text-sm">
            <p className="font-medium">Right-to-erasure runs an async background purge.</p>
            <p className="text-muted-foreground">
              Requests are recorded with a 30-day grace window; the purge job then redacts PII while
              preserving the tamper-evident audit trail.
            </p>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Erasure requests</CardTitle>
          <CardDescription>{listQ.data?.items?.length ?? 0} request{listQ.data?.items?.length === 1 ? "" : "s"}</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {listQ.isLoading ? (
            <div className="space-y-3 p-4">{[...Array(3)].map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}</div>
          ) : listQ.isError ? (
            <div className="p-6 text-sm text-destructive">{(listQ.error as Error).message}</div>
          ) : !listQ.data?.items?.length ? (
            <div className="flex flex-col items-center gap-2 p-10 text-center">
              <ScrollTextIcon className="size-8 text-muted-foreground" />
              <p className="text-sm text-muted-foreground">No GDPR erasure requests on file.</p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>User</TableHead>
                  <TableHead>Reason</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Grace until</TableHead>
                  <TableHead>Filed</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {listQ.data.items.map((r) => {
                  const variant =
                    r.status === "completed" ? "destructive" :
                    r.status === "cancelled" ? "muted" :
                    "warning";
                  return (
                    <TableRow key={r.id}>
                      <TableCell className="font-mono text-xs text-muted-foreground">{r.user_id.slice(0, 16)}…</TableCell>
                      <TableCell className="max-w-md truncate text-muted-foreground" title={r.reason ?? ""}>
                        {r.reason ?? "—"}
                      </TableCell>
                      <TableCell><Badge variant={variant}>{r.status}</Badge></TableCell>
                      <TableCell className="text-muted-foreground">{new Date(r.grace_until).toLocaleDateString()}</TableCell>
                      <TableCell className="text-muted-foreground">{new Date(r.created_at).toLocaleDateString()}</TableCell>
                      <TableCell className="text-right">
                        <Button
                          variant="ghost"
                          size="sm"
                          disabled={r.status !== "pending" || cancelM.isPending}
                          onClick={() => {
                            if (confirm("Cancel this erasure request?")) cancelM.mutate(r.id);
                          }}
                        >
                          Cancel
                        </Button>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <CreatePurgeSheet
        open={creating}
        onOpenChange={setCreating}
        tenantId={tenantId}
        onCreated={() => qc.invalidateQueries({ queryKey: ["gdpr-purges"] })}
      />
    </div>
  );
}

type CreatePurgeSheetProps = {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  tenantId: string | null;
  onCreated: () => void;
};

function CreatePurgeSheet({ open, onOpenChange, tenantId, onCreated }: CreatePurgeSheetProps) {
  const createM = useMutation({
    mutationFn: (body: { tenant_id: string; user_id: string; reason: string }) =>
      api<PurgeRequest>("/v1/gdpr/purge", { method: "POST", body }),
    onSuccess: () => {
      onCreated();
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
            createM.mutate({
              tenant_id: tenantId,
              user_id: String(data.get("user_id") ?? "").trim(),
              reason: String(data.get("reason") ?? "").trim(),
            });
          }}
        >
          <SheetHeader>
            <SheetTitle>File erasure request</SheetTitle>
            <SheetDescription>
              Starts the 30-day grace window. The user is not deleted yet — cancel before grace expires to abort.
            </SheetDescription>
          </SheetHeader>
          <div className="flex-1 overflow-y-auto p-4">
            <FieldGroup>
              <Field>
                <FieldLabel htmlFor="user_id">User ID</FieldLabel>
                <Input
                  id="user_id"
                  name="user_id"
                  pattern="[0-9a-fA-F-]{36}"
                  placeholder="00000000-0000-0000-0000-000000000000"
                  required
                />
                <FieldDescription>UUID of the user to erase. Copy from the Users page.</FieldDescription>
              </Field>
              <Field>
                <FieldLabel htmlFor="reason">Reason</FieldLabel>
                <Textarea id="reason" name="reason" rows={4} placeholder="User requested account deletion via support ticket #1234" />
                <FieldDescription>Optional but strongly recommended for audit-trail purposes.</FieldDescription>
              </Field>
              {createM.error && <Field><FieldError>{(createM.error as ApiError).message}</FieldError></Field>}
            </FieldGroup>
          </div>
          <SheetFooter className="flex-row justify-end gap-2 border-t">
            <SheetClose render={<Button type="button" variant="outline" />}>Cancel</SheetClose>
            <Button type="submit" disabled={createM.isPending}>
              {createM.isPending && <Loader2Icon className="animate-spin" />}
              {createM.isPending ? "Filing…" : "File request"}
            </Button>
          </SheetFooter>
        </form>
      </SheetContent>
    </Sheet>
  );
}
