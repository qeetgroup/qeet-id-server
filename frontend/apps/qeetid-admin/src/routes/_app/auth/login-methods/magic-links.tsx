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
  FieldLabel,
  Input,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Switch,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  Textarea,
} from "@qeetrix/ui";
import { createFileRoute } from "@tanstack/react-router";
import { SparklesIcon } from "lucide-react";
import { useState } from "react";

import { PageHeader } from "@/components/page-header";

export const Route = createFileRoute("/_app/auth/login-methods/magic-links")({
  component: MagicLinksPage,
});

const sample = [
  { id: "1", email: "alice@acme.com", sent: "2m ago", consumed: "1m 47s ago", status: "consumed" },
  { id: "2", email: "bob@acme.com", sent: "5m ago", consumed: "—", status: "pending" },
  { id: "3", email: "carol@acme.com", sent: "12m ago", consumed: "—", status: "expired" },
  { id: "4", email: "dave@acme.com", sent: "20m ago", consumed: "19m 50s ago", status: "consumed" },
  { id: "5", email: "eve@acme.com", sent: "1h ago", consumed: "—", status: "expired" },
];

function statusBadge(s: string) {
  if (s === "consumed") return <Badge variant="default">consumed</Badge>;
  if (s === "pending") return <Badge variant="secondary">pending</Badge>;
  return <Badge variant="outline">expired</Badge>;
}

function MagicLinksPage() {
  const [ttl, setTtl] = useState("15m");
  const [singleUse, setSingleUse] = useState(true);
  const [redirect, setRedirect] = useState("https://app.acme.com/login/callback");

  return (
    <div className="flex min-w-0 flex-col gap-6">
      <PageHeader description="Email-delivered single-use URLs that complete a login without a password." />

      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardDescription>Sent (24h)</CardDescription>
            <SparklesIcon className="size-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold tracking-tight">1,283</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardDescription>Consumed</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold tracking-tight">1,041</div>
            <p className="text-xs text-muted-foreground">81% consumption rate</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardDescription>Avg. time-to-click</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold tracking-tight">42s</div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Settings</CardTitle>
          <CardDescription>Lifetime, redirect, and template.</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-6 md:grid-cols-2">
          <Field>
            <FieldLabel>Token TTL</FieldLabel>
            <Select value={ttl} onValueChange={(v) => v && setTtl(v)}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="5m">5 minutes</SelectItem>
                <SelectItem value="15m">15 minutes</SelectItem>
                <SelectItem value="30m">30 minutes</SelectItem>
                <SelectItem value="1h">1 hour</SelectItem>
              </SelectContent>
            </Select>
            <FieldDescription>Links older than this 410-Gone.</FieldDescription>
          </Field>
          <Field>
            <FieldLabel>Default redirect URI</FieldLabel>
            <Input value={redirect} onChange={(e) => setRedirect(e.target.value)} />
            <FieldDescription>Where users land after a successful magic-link login.</FieldDescription>
          </Field>
          <Field>
            <div className="flex items-center justify-between gap-4">
              <div>
                <FieldLabel>Single-use</FieldLabel>
                <FieldDescription>Re-clicking a consumed link returns 410.</FieldDescription>
              </div>
              <Switch checked={singleUse} onCheckedChange={setSingleUse} />
            </div>
          </Field>
          <Field>
            <div className="flex items-center justify-between gap-4">
              <div>
                <FieldLabel>Auto-create user</FieldLabel>
                <FieldDescription>
                  If a magic link is sent to an unknown email, create the account on consume.
                </FieldDescription>
              </div>
              <Switch defaultChecked />
            </div>
          </Field>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Email template</CardTitle>
          <CardDescription>Variables: <code>{"{{user.email}}"}</code>, <code>{"{{link}}"}</code>, <code>{"{{tenant.name}}"}</code></CardDescription>
        </CardHeader>
        <CardContent>
          <Textarea
            className="min-h-[160px] font-mono text-xs"
            defaultValue={`Subject: Sign in to {{tenant.name}}\n\nHi,\n\nClick this link to sign in. It expires in 15 minutes and can only be used once.\n\n{{link}}\n\nIf you didn't request this, you can ignore the email.`}
          />
          <div className="mt-3 flex justify-end gap-2">
            <Button variant="outline">Send test</Button>
            <Button>Save template</Button>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Recent links</CardTitle>
          <CardDescription>Last hour</CardDescription>
        </CardHeader>
        <CardContent className="overflow-x-auto p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Email</TableHead>
                <TableHead>Sent</TableHead>
                <TableHead>Consumed</TableHead>
                <TableHead>Status</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {sample.map((row) => (
                <TableRow key={row.id}>
                  <TableCell className="text-sm">{row.email}</TableCell>
                  <TableCell className="text-xs text-muted-foreground">{row.sent}</TableCell>
                  <TableCell className="text-xs text-muted-foreground">{row.consumed}</TableCell>
                  <TableCell>{statusBadge(row.status)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
