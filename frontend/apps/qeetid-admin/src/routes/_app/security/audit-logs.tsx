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
} from "@qeetid/ui";
import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { DownloadIcon, FileSearchIcon, Loader2Icon, RefreshCwIcon, XIcon } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

import { PageHeader } from "@/components/page-header";
import { api } from "@/lib/api";
import { useTenantId } from "@/lib/auth";

export const Route = createFileRoute("/_app/security/audit-logs")({ component: AuditLogsPage });

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
  const tenantId = useTenantId();
  const [filters, setFilters] = useState({ action: "", resource_type: "", actor_user_id: "" });
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
          action: filters.action || undefined,
          resource_type: filters.resource_type || undefined,
          actor_user_id: filters.actor_user_id || undefined,
        },
      }),
    enabled: !!tenantId,
  });

  const hasFilters = Object.values(filters).some(Boolean);

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <PageHeader
        description="Every state-changing event in this tenant, written atomically with the underlying business row."
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
                    {exporting ? `Exporting ${exporting.toUpperCase()}…` : "Export"}
                  </Button>
                }
              />
              <DropdownMenuContent align="end" sideOffset={4} className="min-w-36">
                <DropdownMenuItem onClick={() => exportAll("csv")}>
                  Download as CSV
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => exportAll("json")}>
                  Download as JSON
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
              Refresh
            </Button>
          </>
        }
      />

      {/* Filter bar */}
      <Card>
        <CardContent className="grid gap-3 p-4 md:grid-cols-4">
          <Input
            placeholder="Filter by action (e.g. user.create)"
            value={filters.action}
            onChange={(e) => {
              setFilters((f) => ({ ...f, action: e.target.value }));
              setCursor(undefined);
            }}
          />
          <Input
            placeholder="Filter by resource type"
            value={filters.resource_type}
            onChange={(e) => {
              setFilters((f) => ({ ...f, resource_type: e.target.value }));
              setCursor(undefined);
            }}
          />
          <Input
            placeholder="Filter by actor user_id"
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
              setFilters({ action: "", resource_type: "", actor_user_id: "" });
              setCursor(undefined);
            }}
          >
            <XIcon /> Clear
          </Button>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Events</CardTitle>
          <CardDescription>
            {auditQ.data?.items?.length ?? 0} event{auditQ.data?.items?.length === 1 ? "" : "s"} on
            this page
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <DataState
            isLoading={auditQ.isLoading}
            isError={auditQ.isError}
            error={auditQ.error}
            isEmpty={!auditQ.data?.items?.length}
            emptyIcon={FileSearchIcon}
            emptyTitle="No events match your filters yet."
          >
            {auditQ.data && (
              <>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Time</TableHead>
                    <TableHead>Actor</TableHead>
                    <TableHead>Action</TableHead>
                    <TableHead>Resource</TableHead>
                    <TableHead>IP</TableHead>
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
