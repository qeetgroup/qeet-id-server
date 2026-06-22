import {
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  DataState,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  TimeSince,
} from "@qeetrix/ui";
import { createFileRoute } from "@tanstack/react-router";
import {
  AlertTriangleIcon,
  MapPinIcon,
  RefreshCwIcon,
  ShieldAlertIcon,
  UserXIcon,
} from "lucide-react";

import { PageHeader } from "@/components/page-header";
import { useAnomalies, useAnomalySummary, useResolveAnomaly } from "@/lib/anomalies";

export const Route = createFileRoute("/_app/security/threats/anomalies")({
  component: AnomaliesPage,
});

function severityBadge(s: string) {
  if (s === "high") return <Badge variant="destructive">{s}</Badge>;
  if (s === "medium") return <Badge variant="secondary">{s}</Badge>;
  return <Badge variant="outline">{s}</Badge>;
}

function AnomaliesPage() {
  const anomaliesQ = useAnomalies();
  const summaryQ = useAnomalySummary();
  const resolve = useResolveAnomaly();
  const items = anomaliesQ.data?.items ?? [];
  const sm = summaryQ.data;

  const summary = [
    {
      label: "Open incidents",
      value: sm?.open ?? 0,
      icon: <AlertTriangleIcon className="size-4" />,
    },
    {
      label: "Resolved (24h)",
      value: sm?.resolved_24h ?? 0,
      icon: <ShieldAlertIcon className="size-4" />,
    },
    {
      label: "Affected accounts",
      value: sm?.affected_accounts ?? 0,
      icon: <UserXIcon className="size-4" />,
    },
    {
      label: "High severity (24h)",
      value: sm?.high_severity_24h ?? 0,
      icon: <MapPinIcon className="size-4" />,
    },
  ];

  return (
    <div className="flex min-w-0 flex-col gap-6">
      <PageHeader
        description="Behavioral anomalies detected across logins, sessions, and API access."
        actions={
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              anomaliesQ.refetch();
              summaryQ.refetch();
            }}
            disabled={anomaliesQ.isFetching}
          >
            <RefreshCwIcon className={anomaliesQ.isFetching ? "animate-spin" : ""} />
            Refresh
          </Button>
        }
      />

      <div className="grid grid-cols-1 gap-4 md:grid-cols-4">
        {summary.map((s) => (
          <Card key={s.label}>
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardDescription>{s.label}</CardDescription>
              <span className="text-muted-foreground">{s.icon}</span>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-semibold tracking-tight">{s.value}</div>
            </CardContent>
          </Card>
        ))}
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Recent anomalies</CardTitle>
          <CardDescription>Most recent detections, newest first</CardDescription>
        </CardHeader>
        <CardContent className="overflow-x-auto p-0">
          <DataState
            isLoading={anomaliesQ.isLoading}
            isError={anomaliesQ.isError}
            error={anomaliesQ.error}
            isEmpty={items.length === 0}
            emptyIcon={AlertTriangleIcon}
            emptyTitle="No anomalies detected."
            skeletonRows={3}
          >
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Type</TableHead>
                  <TableHead>User</TableHead>
                  <TableHead>Detail</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>When</TableHead>
                  <TableHead className="text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((i) => (
                  <TableRow key={i.id}>
                    <TableCell className="font-mono text-xs">{i.type}</TableCell>
                    <TableCell>{i.user_email ?? "—"}</TableCell>
                    <TableCell className="max-w-[320px] truncate text-sm text-muted-foreground">
                      {i.detail}
                    </TableCell>
                    <TableCell>{severityBadge(i.severity)}</TableCell>
                    <TableCell>
                      <Badge variant="outline">{i.status}</Badge>
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      <TimeSince value={i.created_at} />
                    </TableCell>
                    <TableCell className="text-right">
                      {i.status === "resolved" ? (
                        <span className="text-xs text-muted-foreground">Resolved</span>
                      ) : (
                        <Button
                          variant="ghost"
                          size="sm"
                          disabled={resolve.isPending}
                          onClick={() => resolve.mutate(i.id)}
                        >
                          Resolve
                        </Button>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </DataState>
        </CardContent>
      </Card>
    </div>
  );
}
