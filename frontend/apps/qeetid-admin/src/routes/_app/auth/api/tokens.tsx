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
import { ClockIcon, KeyRoundIcon, RefreshCwIcon, RotateCcwIcon } from "lucide-react";

import { PageHeader } from "@/components/page-header";

export const Route = createFileRoute("/_app/auth/api/tokens")({ component: AccessTokensPage });

const tokens = [
  {
    id: "t_4f1a",
    type: "access",
    user: "alice@acme.com",
    client: "Acme Web",
    scopes: ["openid", "profile", "email"],
    issued: "2m ago",
    expires: "13m",
  },
  {
    id: "t_92cb",
    type: "refresh",
    user: "alice@acme.com",
    client: "Acme Web",
    scopes: ["offline_access"],
    issued: "12m ago",
    expires: "29d 23h",
  },
  {
    id: "t_8d12",
    type: "access",
    user: "bob@acme.com",
    client: "Acme iOS",
    scopes: ["openid", "profile", "email", "offline_access"],
    issued: "9m ago",
    expires: "6m",
  },
  {
    id: "t_1e7f",
    type: "access",
    user: "—",
    client: "build-bot (service)",
    scopes: ["user.read", "tenant.read"],
    issued: "44s ago",
    expires: "59m",
  },
  {
    id: "t_b21c",
    type: "refresh",
    user: "carol@acme.com",
    client: "Internal Admin",
    scopes: ["offline_access"],
    issued: "2h ago",
    expires: "29d 21h",
  },
];

const stats = [
  { label: "Active access tokens", value: "18,402", icon: <KeyRoundIcon className="size-4" /> },
  { label: "Active refresh tokens", value: "21,108", icon: <RotateCcwIcon className="size-4" /> },
  { label: "Avg. access TTL", value: "15m", icon: <ClockIcon className="size-4" /> },
];

function AccessTokensPage() {
  return (
    <div className="flex min-w-0 flex-col gap-6">
      <PageHeader
        description="Inspect or revoke OAuth access and refresh tokens currently outstanding."
        actions={
          <>
            <Button variant="outline">
              <RefreshCwIcon className="mr-2 size-4" />
              Refresh
            </Button>
            <Button variant="destructive">Revoke all (this tenant)</Button>
          </>
        }
      />

      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        {stats.map((s) => (
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
        <CardHeader className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <CardTitle>Outstanding tokens</CardTitle>
            <CardDescription>Last 100 issued; use search to find a specific principal.</CardDescription>
          </div>
          <div className="flex gap-2">
            <Input placeholder="email, client, or token id…" className="w-[260px]" />
            <Select defaultValue="all">
              <SelectTrigger className="w-[140px]">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All types</SelectItem>
                <SelectItem value="access">Access</SelectItem>
                <SelectItem value="refresh">Refresh</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardHeader>
        <CardContent className="overflow-x-auto p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Token ID</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>User / Service</TableHead>
                <TableHead>Client</TableHead>
                <TableHead>Scopes</TableHead>
                <TableHead>Issued</TableHead>
                <TableHead>Expires in</TableHead>
                <TableHead className="w-[1%]" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {tokens.map((t) => (
                <TableRow key={t.id}>
                  <TableCell className="font-mono text-xs">{t.id}</TableCell>
                  <TableCell>
                    <Badge variant={t.type === "refresh" ? "secondary" : "default"}>{t.type}</Badge>
                  </TableCell>
                  <TableCell className="text-sm">{t.user}</TableCell>
                  <TableCell className="text-sm">{t.client}</TableCell>
                  <TableCell className="max-w-[260px]">
                    <div className="flex flex-wrap gap-1">
                      {t.scopes.map((s) => (
                        <Badge key={s} variant="outline" className="font-mono text-[10px]">
                          {s}
                        </Badge>
                      ))}
                    </div>
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">{t.issued}</TableCell>
                  <TableCell className="text-xs text-muted-foreground">{t.expires}</TableCell>
                  <TableCell>
                    <Button size="sm" variant="ghost">
                      Revoke
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
