import {
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  Input,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@qeetrix/ui";
import { createFileRoute } from "@tanstack/react-router";
import { GaugeIcon, PlusIcon } from "lucide-react";

import { PageHeader } from "@/components/page-header";

export const Route = createFileRoute("/_app/security/threats/rate-limits")({ component: ThreatRateLimitsPage });

const rules = [
  { id: "1", endpoint: "/v1/auth/login", scope: "per-ip", limit: 10, window: "1m", action: "throttle", hits24: 412 },
  { id: "2", endpoint: "/v1/auth/login", scope: "per-account", limit: 5, window: "5m", action: "block", hits24: 67 },
  { id: "3", endpoint: "/v1/auth/refresh", scope: "per-ip", limit: 30, window: "1m", action: "throttle", hits24: 89 },
  { id: "4", endpoint: "/v1/users", scope: "per-tenant", limit: 1000, window: "1m", action: "throttle", hits24: 4 },
  { id: "5", endpoint: "/v1/oauth/token", scope: "per-client", limit: 50, window: "1m", action: "throttle", hits24: 18 },
  { id: "6", endpoint: "/v1/oauth/authorize", scope: "per-ip", limit: 20, window: "1m", action: "captcha", hits24: 142 },
];

function actionBadge(a: string) {
  if (a === "block") return <Badge variant="destructive">block</Badge>;
  if (a === "captcha") return <Badge variant="secondary">captcha</Badge>;
  return <Badge variant="outline">throttle</Badge>;
}

function ThreatRateLimitsPage() {
  return (
    <div className="flex min-w-0 flex-col gap-6">
      <PageHeader
        description="Per-endpoint rate-limit rules. Buckets are enforced at the edge before any database read."
        actions={
          <Button>
            <PlusIcon className="mr-2 size-4" />
            New rule
          </Button>
        }
      />

      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardDescription>Active rules</CardDescription>
            <GaugeIcon className="size-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold tracking-tight">{rules.length}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardDescription>Hits triggered (24h)</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold tracking-tight">
              {rules.reduce((s, r) => s + r.hits24, 0).toLocaleString()}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardDescription>Strictest rule</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="text-sm font-medium">/v1/auth/login</div>
            <div className="text-xs text-muted-foreground">5 / 5m per account</div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <CardTitle>Rules</CardTitle>
            <CardDescription>Evaluated in order, first match wins.</CardDescription>
          </div>
          <div className="flex gap-2">
            <Input placeholder="Filter endpoint…" className="w-[220px]" />
            <Select defaultValue="all">
              <SelectTrigger className="w-[140px]">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All scopes</SelectItem>
                <SelectItem value="per-ip">per-ip</SelectItem>
                <SelectItem value="per-account">per-account</SelectItem>
                <SelectItem value="per-tenant">per-tenant</SelectItem>
                <SelectItem value="per-client">per-client</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardHeader>
        <CardContent className="overflow-x-auto p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Endpoint</TableHead>
                <TableHead>Scope</TableHead>
                <TableHead>Limit</TableHead>
                <TableHead>Window</TableHead>
                <TableHead>Action</TableHead>
                <TableHead>Hits (24h)</TableHead>
                <TableHead className="w-[1%]" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {rules.map((r) => (
                <TableRow key={r.id}>
                  <TableCell className="font-mono text-xs">{r.endpoint}</TableCell>
                  <TableCell>
                    <Badge variant="outline">{r.scope}</Badge>
                  </TableCell>
                  <TableCell className="text-sm">{r.limit}</TableCell>
                  <TableCell className="text-sm">{r.window}</TableCell>
                  <TableCell>{actionBadge(r.action)}</TableCell>
                  <TableCell className="text-sm">{r.hits24.toLocaleString()}</TableCell>
                  <TableCell>
                    <Button variant="ghost" size="sm">
                      Edit
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
