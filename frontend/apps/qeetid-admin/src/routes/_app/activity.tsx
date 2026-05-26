import {
  Badge,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  Skeleton,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  TimeSince,
} from "@qeetid/ui";
import { createFileRoute, Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { ActivityIcon } from "lucide-react";

import { PageHeader } from "@/components/page-header";
import { api } from "@/lib/api";
import { useTenantId } from "@/lib/auth";

export const Route = createFileRoute("/_app/activity")({ component: ActivityPage });

type AuditEvent = {
  id: string;
  actor_user_id?: string | null;
  actor_type: string;
  action: string;
  resource_type: string;
  resource_id?: string | null;
  ip?: string | null;
  created_at: string;
};

function ActivityPage() {
  const tenantId = useTenantId();
  const eventsQ = useQuery({
    queryKey: ["activity-recent", tenantId],
    queryFn: () =>
      api<{ items: AuditEvent[] }>(`/v1/tenants/${tenantId}/audit`, { query: { limit: 20 } }),
    enabled: !!tenantId,
    refetchInterval: 30_000,
  });

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <PageHeader description="The 20 most recent events across this tenant. Auto-refreshes every 30 seconds. For full filtering and search, head to Audit Logs." />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Recent activity</CardTitle>
          <CardDescription>
            For deep search and export, see{" "}
            <Link to="/security/audit-logs" className="underline">Audit Logs</Link>.
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {eventsQ.isLoading ? (
            <div className="space-y-3 p-4">{[...Array(5)].map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}</div>
          ) : eventsQ.isError ? (
            <div className="p-6 text-sm text-destructive">{(eventsQ.error as Error).message}</div>
          ) : !eventsQ.data?.items?.length ? (
            <div className="flex flex-col items-center gap-2 p-10 text-center">
              <ActivityIcon className="size-8 text-muted-foreground" />
              <p className="text-sm text-muted-foreground">No recent activity in this tenant yet.</p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>When</TableHead>
                  <TableHead>Actor</TableHead>
                  <TableHead>Action</TableHead>
                  <TableHead>Resource</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {eventsQ.data.items.map((e) => (
                  <TableRow key={e.id}>
                    <TableCell>
                      <TimeSince value={e.created_at} className="font-mono text-xs" />
                    </TableCell>
                    <TableCell>
                      <Badge variant="muted">{e.actor_type}</Badge>
                    </TableCell>
                    <TableCell className="font-medium">{e.action}</TableCell>
                    <TableCell className="text-muted-foreground">
                      {e.resource_type}
                      {e.resource_id && (
                        <span className="ml-1 font-mono text-xs">({e.resource_id.slice(0, 8)}…)</span>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
