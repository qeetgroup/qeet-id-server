import {
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  DataState,
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
  Input,
  PaginationBar,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  TimeSince,
} from "@qeetrix/ui";
import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { DownloadIcon, FileSearchIcon, Loader2Icon, RefreshCwIcon, XIcon } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";

import { PageHeader } from "@/components/page-header";
import { api } from "@/lib/api";
import { useTenantId } from "@/lib/auth";

// URL-driven filter state — the audit-logs view bookmarks any filter
// combination as `/_app/security/audit-logs?action=user.create` so
// engineers can paste-share a triage view in Slack. `validateSearch`
// keeps every field optional + string so a malformed URL never crashes
// the route.
type AuditSearch = {
  q?: string;
  action?: string;
  resource_type?: string;
  actor_user_id?: string;
};

function validateAuditSearch(raw: Record<string, unknown>): AuditSearch {
  const pick = (k: string): string | undefined => {
    const v = raw[k];
    return typeof v === "string" && v.trim() !== "" ? v : undefined;
  };
  return {
    q: pick("q"),
    action: pick("action"),
    resource_type: pick("resource_type"),
    actor_user_id: pick("actor_user_id"),
  };
}

export const Route = createFileRoute("/_app/security/audit-logs")({
  component: AuditLogsPage,
  validateSearch: validateAuditSearch,
});

type AuditEvent = {
  id: string;
  tenant_id: string;
  actor_user_id?: string | null;
  actor_type: string;
  action: string;
  resource_type: string;
  resource_id?: string | null;
  ip?: string | null;
  request_id?: string | null;
  metadata?: Record<string, unknown>;
  created_at: string;
};

type AuditResponse = { items: AuditEvent[]; next_cursor?: string };

// Cap exports so an open-ended fetch loop can't run forever on enormous
// tenants. Users hitting the cap get a warning toast; for larger exports
// they should narrow the filter range or use a future server-side
// streaming endpoint.
const EXPORT_ROW_CAP = 10_000;

type ExportFormat = "csv" | "json";

const CSV_HEADERS = [
  "id",
  "created_at",
  "actor_type",
  "actor_user_id",
  "action",
  "resource_type",
  "resource_id",
  "ip",
  "request_id",
  "metadata",
] as const;

function csvCell(v: unknown): string {
  if (v == null) return "";
  const s = typeof v === "string" ? v : JSON.stringify(v);
  if (s.includes(",") || s.includes('"') || s.includes("\n") || s.includes("\r")) {
    return `"${s.replace(/"/g, '""')}"`;
  }
  return s;
}

function rowsToCSV(items: AuditEvent[]): string {
  const lines = [CSV_HEADERS.join(",")];
  for (const ev of items) {
    lines.push(
      CSV_HEADERS.map((h) => csvCell((ev as Record<string, unknown>)[h])).join(","),
    );
  }
  return lines.join("\n");
}

function downloadBlob(content: string, mime: string, filename: string) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function AuditLogsPage() {
  const { t } = useTranslation("security");
  const tenantId = useTenantId();
  const search = Route.useSearch();
  const navigate = Route.useNavigate();
  // Mirror URL → form state. Empty strings (vs undefined) are how the
  // <Input> tracks "unfiltered" — the validateSearch normalises both
  // directions so the URL doesn't accumulate trailing `?action=`.
  const filters = {
    q: search.q ?? "",
    action: search.action ?? "",
    resource_type: search.resource_type ?? "",
    actor_user_id: search.actor_user_id ?? "",
  };
  function setFilters(updater: (prev: typeof filters) => typeof filters) {
    const next = updater(filters);
    navigate({
      search: () => ({
        q: next.q || undefined,
        action: next.action || undefined,
        resource_type: next.resource_type || undefined,
        actor_user_id: next.actor_user_id || undefined,
      }),
      replace: true, // typing in a filter shouldn't pile up history entries
    });
  }
  const [cursor, setCursor] = useState<string | undefined>(undefined);
  const [exporting, setExporting] = useState<ExportFormat | null>(null);

  async function exportAll(format: ExportFormat) {
    if (!tenantId || exporting) return;
    setExporting(format);
    try {
      const all: AuditEvent[] = [];
      let next: string | undefined = undefined;
      let truncated = false;
      // Walk the cursor pages with the current filter set. The first call
      // intentionally skips the cursor so we always start from the newest
      // matching event rather than wherever the UI currently sits.
      do {
        const page: AuditResponse = await api<AuditResponse>(
          `/v1/tenants/${tenantId}/audit`,
          {
            query: {
              limit: 200,
              cursor: next,
              q: filters.q || undefined,
              action: filters.action || undefined,
              resource_type: filters.resource_type || undefined,
              actor_user_id: filters.actor_user_id || undefined,
            },
          },
        );
        all.push(...page.items);
        next = page.next_cursor;
        if (all.length >= EXPORT_ROW_CAP) {
          truncated = true;
          break;
        }
      } while (next);

      const stamp = new Date().toISOString().replace(/[:.]/g, "-");
      if (format === "csv") {
        downloadBlob(rowsToCSV(all), "text/csv;charset=utf-8", `audit-${stamp}.csv`);
      } else {
        downloadBlob(JSON.stringify(all, null, 2), "application/json", `audit-${stamp}.json`);
      }
      const noun = all.length === 1 ? "event" : "events";
      toast.success(`Exported ${all.length.toLocaleString()} ${noun}`, {
        description: truncated
          ? `Capped at ${EXPORT_ROW_CAP.toLocaleString()} rows. Narrow your filter to capture older history.`
          : undefined,
      });
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Export failed");
    } finally {
      setExporting(null);
    }
  }

  const auditQ = useQuery({
    queryKey: ["audit", tenantId, filters, cursor],
    queryFn: () =>
      api<AuditResponse>(`/v1/tenants/${tenantId}/audit`, {
        query: {
          limit: 50,
          cursor,
          q: filters.q || undefined,
          action: filters.action || undefined,
          resource_type: filters.resource_type || undefined,
          actor_user_id: filters.actor_user_id || undefined,
        },
      }),
    enabled: !!tenantId,
  });

  const hasFilters = Object.values(filters).some(Boolean);
  const [searchDraft, setSearchDraft] = useState(filters.q);
  const itemCount = auditQ.data?.items?.length ?? 0;

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <PageHeader
        description={t("auditLogs.description")}
        actions={
          <>
            <DropdownMenu>
              <DropdownMenuTrigger
                render={
                  <Button variant="outline" size="sm" disabled={!!exporting}>
                    {exporting ? (
                      <Loader2Icon className="animate-spin" />
                    ) : (
                      <DownloadIcon />
                    )}
                    {exporting
                      ? t("auditLogs.exporting", { format: exporting.toUpperCase() })
                      : t("auditLogs.export")}
                  </Button>
                }
              />
              <DropdownMenuContent align="end" sideOffset={4} className="min-w-36">
                <DropdownMenuItem onClick={() => exportAll("csv")}>
                  {t("auditLogs.exportCsv")}
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => exportAll("json")}>
                  {t("auditLogs.exportJson")}
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
            <Button
              variant="outline"
              size="sm"
              onClick={() => auditQ.refetch()}
              disabled={auditQ.isFetching}
            >
              <RefreshCwIcon className={auditQ.isFetching ? "animate-spin" : ""} />
              {t("auditLogs.refresh")}
            </Button>
          </>
        }
      />

      {/* Filter bar */}
      <Card>
        <CardContent className="flex flex-col gap-3 p-4">
          {/* Free-text search — committed on Enter; supports quoted phrases, -exclusions, OR */}
          <form
            onSubmit={(e) => {
              e.preventDefault();
              setFilters((f) => ({ ...f, q: searchDraft }));
              setCursor(undefined);
            }}
            className="flex gap-2"
          >
            <Input
              className="flex-1"
              placeholder={t("auditLogs.filter.searchPlaceholder")}
              value={searchDraft}
              onChange={(e) => setSearchDraft(e.target.value)}
              aria-label={t("auditLogs.filter.searchLabel")}
            />
            <Button type="submit" variant="outline" size="sm">
              {t("auditLogs.filter.search")}
            </Button>
          </form>
          {/* Exact-match filters + clear */}
          <div className="grid gap-3 md:grid-cols-4">
            <Input
              placeholder={t("auditLogs.filter.actionPlaceholder")}
              value={filters.action}
              onChange={(e) => {
                setFilters((f) => ({ ...f, action: e.target.value }));
                setCursor(undefined);
              }}
            />
            <Input
              placeholder={t("auditLogs.filter.resourceTypePlaceholder")}
              value={filters.resource_type}
              onChange={(e) => {
                setFilters((f) => ({ ...f, resource_type: e.target.value }));
                setCursor(undefined);
              }}
            />
            <Input
              placeholder={t("auditLogs.filter.actorPlaceholder")}
              value={filters.actor_user_id}
              onChange={(e) => {
                setFilters((f) => ({ ...f, actor_user_id: e.target.value }));
                setCursor(undefined);
              }}
            />
            <Button
              variant="outline"
              disabled={!hasFilters}
              onClick={() => {
                setFilters(() => ({ q: "", action: "", resource_type: "", actor_user_id: "" }));
                setSearchDraft("");
                setCursor(undefined);
              }}
            >
              <XIcon /> {t("auditLogs.filter.clear")}
            </Button>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">{t("auditLogs.list.title")}</CardTitle>
          <CardDescription>
            {t("auditLogs.list.count", { count: itemCount })}
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <DataState
            isLoading={auditQ.isLoading}
            isError={auditQ.isError}
            error={auditQ.error}
            isEmpty={!auditQ.data?.items?.length}
            emptyIcon={FileSearchIcon}
            emptyTitle={t("auditLogs.list.empty")}
          >
            {auditQ.data && (
              <>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>{t("auditLogs.list.columns.time")}</TableHead>
                    <TableHead>{t("auditLogs.list.columns.actor")}</TableHead>
                    <TableHead>{t("auditLogs.list.columns.action")}</TableHead>
                    <TableHead>{t("auditLogs.list.columns.resource")}</TableHead>
                    <TableHead>{t("auditLogs.list.columns.ip")}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {auditQ.data.items.map((ev) => (
                    <TableRow key={ev.id}>
                      <TableCell>
                        <TimeSince value={ev.created_at} className="font-mono text-xs" />
                      </TableCell>
                      <TableCell>
                        <Badge variant="muted">{ev.actor_type}</Badge>
                        {ev.actor_user_id && (
                          <span className="ml-2 font-mono text-xs text-muted-foreground">
                            {ev.actor_user_id.slice(0, 8)}…
                          </span>
                        )}
                      </TableCell>
                      <TableCell className="font-medium">{ev.action}</TableCell>
                      <TableCell className="text-muted-foreground">
                        {ev.resource_type}
                        {ev.resource_id && (
                          <span className="ml-1 font-mono text-xs">
                            ({ev.resource_id.slice(0, 8)}…)
                          </span>
                        )}
                      </TableCell>
                      <TableCell className="font-mono text-xs text-muted-foreground">
                        {ev.ip ?? "—"}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
              {(cursor || auditQ.data.next_cursor) && (
                <PaginationBar
                  hasPrev={!!cursor}
                  hasNext={!!auditQ.data.next_cursor}
                  onFirst={() => setCursor(undefined)}
                  onNext={() => setCursor(auditQ.data?.next_cursor)}
                  itemsOnPage={auditQ.data.items.length}
                  pageSize={50}
                  loading={auditQ.isFetching}
                />
              )}
              </>
            )}
          </DataState>
        </CardContent>
      </Card>
    </div>
  );
}
