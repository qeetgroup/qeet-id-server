import {
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@qeetrix/ui";
import { createFileRoute } from "@tanstack/react-router";
import { AlertTriangleIcon, MapPinIcon, ShieldAlertIcon, UserXIcon } from "lucide-react";

import { PageHeader } from "@/components/page-header";

export const Route = createFileRoute("/_app/security/threats/anomalies")({ component: AnomaliesPage });

const incidents = [
  {
    id: "1",
    type: "impossible_travel",
    user: "alice@acme.com",
    detail: "London → São Paulo in 9 minutes",
    severity: "high",
    when: "4m ago",
    status: "blocked",
  },
  {
    id: "2",
    type: "credential_stuffing",
    user: "—",
    detail: "1,402 logins from /24 range in 2 minutes",
    severity: "high",
    when: "12m ago",
    status: "rate-limited",
  },
  {
    id: "3",
    type: "new_device",
    user: "bob@acme.com",
    detail: "First login from macOS 15.4 / Safari",
    severity: "low",
    when: "31m ago",
    status: "challenged",
  },
  {
    id: "4",
    type: "tor_exit_node",
    user: "carol@acme.com",
    detail: "Tor exit node 185.220.101.x",
    severity: "medium",
    when: "1h ago",
    status: "challenged",
  },
  {
    id: "5",
    type: "session_hijack_suspect",
    user: "dave@acme.com",
    detail: "IP change mid-session, new country",
    severity: "high",
    when: "2h ago",
    status: "session-revoked",
  },
];

const summary = [
  { label: "Open incidents", value: "3", icon: <AlertTriangleIcon className="size-4" /> },
  { label: "Resolved (24h)", value: "12", icon: <ShieldAlertIcon className="size-4" /> },
  { label: "Compromised accounts", value: "0", icon: <UserXIcon className="size-4" /> },
  { label: "Geo anomalies", value: "5", icon: <MapPinIcon className="size-4" /> },
];

function severityBadge(s: string) {
  if (s === "high") return <Badge variant="destructive">high</Badge>;
  if (s === "medium") return <Badge variant="secondary">medium</Badge>;
  return <Badge variant="outline">low</Badge>;
}

function AnomaliesPage() {
  return (
    <div className="flex min-w-0 flex-col gap-6">
      <PageHeader
        description="Behavioral anomalies detected across logins, sessions, and API access."
        actions={
          <>
            <Button variant="outline">Replay rules</Button>
            <Button>Configure detection</Button>
          </>
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
          <CardDescription>Last 24 hours, newest first</CardDescription>
        </CardHeader>
        <CardContent className="overflow-x-auto p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Type</TableHead>
                <TableHead>User</TableHead>
                <TableHead>Detail</TableHead>
                <TableHead>Severity</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>When</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {incidents.map((i) => (
                <TableRow key={i.id}>
                  <TableCell className="font-mono text-xs">{i.type}</TableCell>
                  <TableCell>{i.user}</TableCell>
                  <TableCell className="max-w-[320px] truncate text-sm text-muted-foreground">
                    {i.detail}
                  </TableCell>
                  <TableCell>{severityBadge(i.severity)}</TableCell>
                  <TableCell>
                    <Badge variant="outline">{i.status}</Badge>
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">{i.when}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
