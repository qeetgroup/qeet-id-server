import {
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  DataState,
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
  StatusPill,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  TimeSince,
} from "@qeetrix/ui";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute, Link } from "@tanstack/react-router";
import {
  Loader2Icon,
  PlayIcon,
  PlusIcon,
  RefreshCwIcon,
  Trash2Icon,
  WebhookIcon,
} from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { useConfirmDialog } from "@/components/confirm-dialog";
import { ListToolbar, SortHeader } from "@/components/data-table";
import { PageHeader } from "@/components/page-header";
import { type ApiError, api } from "@/lib/api";
import { useTenantId } from "@/lib/auth";
import { type CsvColumn, exportToCsv, exportToJson } from "@/lib/export";
import { useListView } from "@/lib/list-view";

export const Route = createFileRoute("/_app/developer/webhooks/")({
  component: WebhooksPage,
});

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

const webhookCsvColumns: CsvColumn<Webhook>[] = [
  { header: "id", value: (w) => w.id },
  { header: "url", value: (w) => w.url },
  { header: "events", value: (w) => w.events.join("; ") },
  { header: "status", value: (w) => (w.disabled_at ? "disabled" : "active") },
  { header: "created_at", value: (w) => w.created_at },
];

function WebhooksPage() {
  const { t } = useTranslation("developer");
  const [confirmDialog, openConfirm] = useConfirmDialog();
  const tenantId = useTenantId();
  const qc = useQueryClient();
  const [creating, setCreating] = useState(false);

  const listQ = useQuery({
    queryKey: ["webhooks", tenantId],
    queryFn: () => api<{ items: Webhook[] }>(`/v1/tenants/${tenantId}/webhooks`),
    enabled: !!tenantId,
  });

  const items = listQ.data?.items ?? [];
  const lv = useListView(items, {
    searchFields: (w) => [w.url, ...w.events],
    filterFields: { status: (w) => (w.disabled_at ? "disabled" : "active") },
    sortFields: { url: (w) => w.url, created: (w) => w.created_at },
  });
  const rows = lv.view;
  const denseCls = lv.density === "compact" ? "[&_td]:py-1.5 [&_th]:py-2" : undefined;

  const disableM = useMutation({
    mutationFn: (id: string) => api<void>(`/v1/webhooks/${id}`, { method: "DELETE" }),
    // Optimistic remove: drop from every active webhooks-query cache,
    // snapshot for rollback. Same pattern as users.tsx.
    onMutate: async (id) => {
      await qc.cancelQueries({ queryKey: ["webhooks"] });
      const snapshots = qc.getQueriesData<{ items: Webhook[] }>({
        queryKey: ["webhooks"],
      });
      qc.setQueriesData<{ items: Webhook[] }>({ queryKey: ["webhooks"] }, (prev) =>
        prev ? { ...prev, items: prev.items.filter((w) => w.id !== id) } : prev,
      );
      return { snapshots };
    },
    onError: (_err, _id, ctx) => {
      ctx?.snapshots.forEach(([key, snap]) => qc.setQueryData(key, snap));
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ["webhooks"] }),
    meta: { successMessage: t("webhooks.toast.disabled") },
  });

  const testM = useMutation({
    mutationFn: (id: string) => api<void>(`/v1/webhooks/${id}/test`, { method: "POST" }),
    meta: { successMessage: t("webhooks.toast.testQueued") },
  });

  return (
    <div className="flex min-w-0 flex-col gap-4">
      {confirmDialog}
      <PageHeader
        description={t("webhooks.description")}
        actions={
          <>
            <Button
              variant="outline"
              size="sm"
              onClick={() => listQ.refetch()}
              disabled={listQ.isFetching}
            >
              <RefreshCwIcon className={listQ.isFetching ? "animate-spin" : ""} />
              {t("webhooks.refresh")}
            </Button>
            <Button size="sm" onClick={() => setCreating(true)}>
              <PlusIcon /> {t("webhooks.new")}
            </Button>
          </>
        }
      />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">{t("webhooks.list.title")}</CardTitle>
          <CardDescription>
            {t("webhooks.list.count", {
              shown: rows.length,
              total: items.length,
            })}
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <ListToolbar
            search={lv.search}
            onSearchChange={lv.setSearch}
            searchPlaceholder={t("webhooks.list.searchPlaceholder")}
            filters={[
              {
                id: "status",
                label: t("webhooks.list.filters.status.label"),
                value: lv.filters.status ?? "",
                options: [
                  {
                    label: t("webhooks.list.filters.status.active"),
                    value: "active",
                  },
                  {
                    label: t("webhooks.list.filters.status.disabled"),
                    value: "disabled",
                  },
                ],
                onChange: (v) => lv.setFilter("status", v),
              },
            ]}
            columns={[
              { id: "events", label: t("webhooks.list.columns.events") },
              { id: "created", label: t("webhooks.list.columns.created") },
            ]}
            isColumnVisible={lv.isVisible}
            onToggleColumn={lv.toggleColumn}
            density={lv.density}
            onDensityChange={lv.setDensity}
            onExport={(fmt) =>
              fmt === "csv"
                ? exportToCsv("webhooks", rows, webhookCsvColumns)
                : exportToJson("webhooks", rows)
            }
            exportDisabled={rows.length === 0}
            hasActiveFilters={lv.hasActiveFilters}
            onClear={lv.clear}
          />
          <DataState
            isLoading={listQ.isLoading}
            isError={listQ.isError}
            error={listQ.error}
            isEmpty={rows.length === 0}
            emptyIcon={WebhookIcon}
            emptyTitle={
              lv.hasActiveFilters ? t("webhooks.list.emptyFiltered") : t("webhooks.list.empty")
            }
            skeletonRows={3}
          >
            {listQ.data && (
              <Table className={denseCls}>
                <TableHeader>
                  <TableRow>
                    <SortHeader columnKey="url" sort={lv.sort} onToggle={lv.toggleSort}>
                      {t("webhooks.list.columns.url")}
                    </SortHeader>
                    {lv.isVisible("events") && (
                      <TableHead>{t("webhooks.list.columns.events")}</TableHead>
                    )}
                    <TableHead>{t("webhooks.list.columns.status")}</TableHead>
                    {lv.isVisible("created") && (
                      <SortHeader columnKey="created" sort={lv.sort} onToggle={lv.toggleSort}>
                        {t("webhooks.list.columns.created")}
                      </SortHeader>
                    )}
                    <TableHead className="text-right">
                      {t("webhooks.list.columns.actions")}
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {rows.map((w) => (
                    <TableRow key={w.id}>
                      <TableCell className="font-mono text-xs">
                        <Link
                          to="/developer/webhooks/$id"
                          params={{ id: w.id }}
                          className="hover:underline"
                        >
                          {w.url}
                        </Link>
                      </TableCell>
                      {lv.isVisible("events") && (
                        <TableCell>
                          <div className="flex flex-wrap gap-1">
                            {w.events.slice(0, 3).map((e) => (
                              <Badge key={e} variant="muted">
                                {e}
                              </Badge>
                            ))}
                            {w.events.length > 3 && (
                              <Badge variant="muted">+{w.events.length - 3}</Badge>
                            )}
                          </div>
                        </TableCell>
                      )}
                      <TableCell>
                        <StatusPill status={w.disabled_at ? "disabled" : "active"} />
                      </TableCell>
                      {lv.isVisible("created") && (
                        <TableCell>
                          <TimeSince value={w.created_at} />
                        </TableCell>
                      )}
                      <TableCell className="text-right">
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => testM.mutate(w.id)}
                          disabled={!!w.disabled_at || testM.isPending}
                        >
                          <PlayIcon /> {t("webhooks.table.test")}
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() =>
                            openConfirm({
                              title: t("webhooks.confirm.disableTitle"),
                              description: t("webhooks.confirm.disableDescription", { url: w.url }),
                              variant: "destructive",
                              confirmLabel: t("webhooks.confirm.disableLabel"),
                              onConfirm: () => disableM.mutate(w.id),
                            })
                          }
                          disabled={!!w.disabled_at || disableM.isPending}
                        >
                          <Trash2Icon /> {t("webhooks.table.disable")}
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
  const { t } = useTranslation("developer");
  const [selectedEvents, setSelectedEvents] = useState<string[]>(KNOWN_EVENTS.slice(0, 3));
  const createM = useMutation({
    mutationFn: (body: { tenant_id: string; url: string; events: string[] }) =>
      api<Webhook>("/v1/webhooks", { method: "POST", body }),
    onSuccess: () => {
      onCreated();
      onOpenChange(false);
    },
    meta: { successMessage: t("webhooks.toast.created") },
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
            <SheetTitle>{t("webhooks.create.title")}</SheetTitle>
            <SheetDescription>{t("webhooks.create.description")}</SheetDescription>
          </SheetHeader>
          <div className="flex-1 overflow-y-auto p-4">
            <FieldGroup>
              <Field>
                <FieldLabel htmlFor="webhook-url">{t("webhooks.create.url")}</FieldLabel>
                <Input
                  id="webhook-url"
                  name="url"
                  type="url"
                  placeholder={t("webhooks.create.urlPlaceholder")}
                  required
                />
                <FieldDescription>{t("webhooks.create.urlHelp")}</FieldDescription>
              </Field>
              <Field>
                <FieldLabel>{t("webhooks.create.events")}</FieldLabel>
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
                <FieldDescription>
                  {t("webhooks.create.eventsCount", {
                    count: selectedEvents.length,
                  })}
                </FieldDescription>
              </Field>
              {createM.error && (
                <Field>
                  <FieldError>{(createM.error as ApiError).message}</FieldError>
                </Field>
              )}
            </FieldGroup>
          </div>
          <SheetFooter className="flex-row justify-end gap-2 border-t">
            <SheetClose render={<Button type="button" variant="outline" />}>
              {t("webhooks.create.cancel")}
            </SheetClose>
            <Button type="submit" disabled={createM.isPending || selectedEvents.length === 0}>
              {createM.isPending && <Loader2Icon className="animate-spin" />}
              {createM.isPending ? t("webhooks.create.submitting") : t("webhooks.create.submit")}
            </Button>
          </SheetFooter>
        </form>
      </SheetContent>
    </Sheet>
  );
}
