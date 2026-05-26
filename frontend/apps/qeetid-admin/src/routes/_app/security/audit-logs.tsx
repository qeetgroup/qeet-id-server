import {
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  Input,
  Skeleton,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@qeetid/ui";
import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { FileSearchIcon, RefreshCwIcon, XIcon } from "lucide-react";
import { useState } from "react";

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

function AuditLogsPage() {
  const tenantId = useTenantId();
  const [filters, setFilters] = useState({ action: "", resource_type: "", actor_user_id: "" });
  const [cursor, setCursor] = useState<string | undefined>(undefined);

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
          <Button
            variant="outline"
            size="sm"
            onClick={() => auditQ.refetch()}
            disabled={auditQ.isFetching}
          >
            <RefreshCwIcon className={auditQ.isFetching ? "animate-spin" : ""} />
            Refresh
          </Button>
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
          {auditQ.isLoading ? (
            <div className="space-y-3 p-4">
              {[...Array(6)].map((_, i) => (
                <Skeleton key={i} className="h-10 w-full" />
              ))}
            </div>
          ) : auditQ.isError ? (
            <div className="p-6 text-sm text-destructive">
              {(auditQ.error as Error).message ?? "Failed to load audit events"}
            </div>
          ) : !auditQ.data?.items?.length ? (
            <div className="flex flex-col items-center gap-2 p-10 text-center">
              <FileSearchIcon className="size-8 text-muted-foreground" />
              <p className="text-sm text-muted-foreground">
                No events match your filters yet.
              </p>
            </div>
          ) : (
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
                      <TableCell className="font-mono text-xs text-muted-foreground">
                        {new Date(ev.created_at).toLocaleString()}
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
                <div className="flex items-center justify-between border-t p-3 text-sm">
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={!cursor}
                    onClick={() => setCursor(undefined)}
                  >
                    First page
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={!auditQ.data.next_cursor}
                    onClick={() => setCursor(auditQ.data?.next_cursor)}
                  >
                    Next page
                  </Button>
                </div>
              )}
            </>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
