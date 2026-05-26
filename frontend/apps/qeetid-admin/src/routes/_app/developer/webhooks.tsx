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
  DataState,
  StatusPill,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  TimeSince,
} from "@qeetid/ui";
import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Loader2Icon, PlayIcon, PlusIcon, RefreshCwIcon, Trash2Icon, WebhookIcon } from "lucide-react";
import { useState } from "react";

import { PageHeader } from "@/components/page-header";
import { ApiError, api } from "@/lib/api";
import { useTenantId } from "@/lib/auth";

export const Route = createFileRoute("/_app/developer/webhooks")({ component: WebhooksPage });

type Webhook = {
  id: string;
  tenant_id: string;
  url: string;
  secret: string;
  events: string[];
  disabled_at?: string | null;
  created_at: string;
};

const KNOWN_EVENTS = [
  "user.created",
  "user.updated",
  "user.deleted",
  "tenant.created",
  "tenant.updated",
  "session.created",
  "session.revoked",
  "mfa.enrolled",
  "auth.failed",
];

function WebhooksPage() {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  const [creating, setCreating] = useState(false);

  const listQ = useQuery({
    queryKey: ["webhooks", tenantId],
    queryFn: () => api<{ items: Webhook[] }>(`/v1/tenants/${tenantId}/webhooks`),
    enabled: !!tenantId,
  });

  const disableM = useMutation({
    mutationFn: (id: string) => api<void>(`/v1/webhooks/${id}`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["webhooks"] }),
    meta: { successMessage: "Webhook disabled" },
  });

  const testM = useMutation({
    mutationFn: (id: string) => api<void>(`/v1/webhooks/${id}/test`, { method: "POST" }),
    meta: { successMessage: "Test event queued" },
  });

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <PageHeader
        description="HTTP endpoints we POST events to. Every delivery is HMAC-SHA256 signed via the X-Signature header and retried with exponential backoff."
        actions={
          <>
            <Button variant="outline" size="sm" onClick={() => listQ.refetch()} disabled={listQ.isFetching}>
              <RefreshCwIcon className={listQ.isFetching ? "animate-spin" : ""} />
              Refresh
            </Button>
            <Button size="sm" onClick={() => setCreating(true)}>
              <PlusIcon /> New webhook
            </Button>
          </>
        }
      />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Subscriptions</CardTitle>
          <CardDescription>
            {listQ.data?.items?.length ?? 0} subscription{listQ.data?.items?.length === 1 ? "" : "s"}
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <DataState
            isLoading={listQ.isLoading}
            isError={listQ.isError}
            error={listQ.error}
            isEmpty={!listQ.data?.items?.length}
            emptyIcon={WebhookIcon}
            emptyTitle="No webhooks yet."
            skeletonRows={3}
          >
            {listQ.data && (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>URL</TableHead>
                  <TableHead>Events</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {listQ.data.items.map((w) => (
                  <TableRow key={w.id}>
                    <TableCell className="font-mono text-xs">{w.url}</TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        {w.events.slice(0, 3).map((e) => <Badge key={e} variant="muted">{e}</Badge>)}
                        {w.events.length > 3 && <Badge variant="muted">+{w.events.length - 3}</Badge>}
                      </div>
                    </TableCell>
                    <TableCell>
                      <StatusPill status={w.disabled_at ? "disabled" : "active"} />
                    </TableCell>
                    <TableCell><TimeSince value={w.created_at} /></TableCell>
                    <TableCell className="text-right">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => testM.mutate(w.id)}
                        disabled={!!w.disabled_at || testM.isPending}
                      >
                        <PlayIcon /> Test
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => {
                          if (confirm(`Disable webhook ${w.url}?`)) disableM.mutate(w.id);
                        }}
                        disabled={!!w.disabled_at || disableM.isPending}
                      >
                        <Trash2Icon /> Disable
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            )}
          </DataState>
        </CardContent>
      </Card>

      <CreateWebhookSheet
        open={creating}
        onOpenChange={setCreating}
        tenantId={tenantId}
        onCreated={() => qc.invalidateQueries({ queryKey: ["webhooks"] })}
      />
    </div>
  );
}

type CreateWebhookSheetProps = {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  tenantId: string | null;
  onCreated: () => void;
};

function CreateWebhookSheet({ open, onOpenChange, tenantId, onCreated }: CreateWebhookSheetProps) {
  const [selectedEvents, setSelectedEvents] = useState<string[]>(KNOWN_EVENTS.slice(0, 3));
  const createM = useMutation({
    mutationFn: (body: { tenant_id: string; url: string; events: string[] }) =>
      api<Webhook>("/v1/webhooks", { method: "POST", body }),
    onSuccess: () => {
      onCreated();
      onOpenChange(false);
    },
  });

  const toggle = (ev: string) =>
    setSelectedEvents((s) => (s.includes(ev) ? s.filter((e) => e !== ev) : [...s, ev]));

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
              url: String(data.get("url") ?? "").trim(),
              events: selectedEvents,
            });
          }}
        >
          <SheetHeader>
            <SheetTitle>New webhook subscription</SheetTitle>
            <SheetDescription>We&apos;ll POST signed JSON to your URL for each selected event.</SheetDescription>
          </SheetHeader>
          <div className="flex-1 overflow-y-auto p-4">
            <FieldGroup>
              <Field>
                <FieldLabel htmlFor="url">URL</FieldLabel>
                <Input id="url" name="url" type="url" placeholder="https://example.com/webhook" required />
                <FieldDescription>Must respond 2xx within 10 seconds; we retry up to 10 times with exponential backoff.</FieldDescription>
              </Field>
              <Field>
                <FieldLabel>Events</FieldLabel>
                <div className="grid grid-cols-1 gap-2 rounded-md border p-3">
                  {KNOWN_EVENTS.map((ev) => (
                    <label key={ev} className="flex items-center gap-2 text-sm">
                      <input
                        type="checkbox"
                        checked={selectedEvents.includes(ev)}
                        onChange={() => toggle(ev)}
                      />
                      <code className="text-xs">{ev}</code>
                    </label>
                  ))}
                </div>
                <FieldDescription>Selected {selectedEvents.length} event{selectedEvents.length === 1 ? "" : "s"}.</FieldDescription>
              </Field>
              {createM.error && (
                <Field><FieldError>{(createM.error as ApiError).message}</FieldError></Field>
              )}
            </FieldGroup>
          </div>
          <SheetFooter className="flex-row justify-end gap-2 border-t">
            <SheetClose render={<Button type="button" variant="outline" />}>Cancel</SheetClose>
            <Button type="submit" disabled={createM.isPending || selectedEvents.length === 0}>
              {createM.isPending && <Loader2Icon className="animate-spin" />}
              {createM.isPending ? "Creating…" : "Create"}
            </Button>
          </SheetFooter>
        </form>
      </SheetContent>
    </Sheet>
  );
}
