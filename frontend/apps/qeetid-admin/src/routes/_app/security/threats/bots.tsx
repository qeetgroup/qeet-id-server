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
  Switch,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@qeetrix/ui";
import { createFileRoute } from "@tanstack/react-router";
import { BotIcon, ShieldOffIcon, ZapIcon } from "lucide-react";
import { useState } from "react";

import { PageHeader } from "@/components/page-header";

export const Route = createFileRoute("/_app/security/threats/bots")({ component: BotsPage });

const recent = [
  { id: "1", ip: "203.0.113.42", ua: "python-requests/2.31.0", verdict: "blocked", score: 0.94, time: "12s ago" },
  { id: "2", ip: "198.51.100.7", ua: "curl/8.4.0", verdict: "challenged", score: 0.62, time: "1m ago" },
  { id: "3", ip: "192.0.2.119", ua: "HeadlessChrome/124.0", verdict: "blocked", score: 0.88, time: "3m ago" },
  { id: "4", ip: "203.0.113.91", ua: "Mozilla/5.0 (compatible; bot)", verdict: "allowed", score: 0.31, time: "7m ago" },
  { id: "5", ip: "198.51.100.55", ua: "PostmanRuntime/7.32", verdict: "challenged", score: 0.71, time: "11m ago" },
];

const stats = [
  { label: "Blocked (24h)", value: "12,481", icon: <ShieldOffIcon className="size-4" /> },
  { label: "Challenged (24h)", value: "3,209", icon: <ZapIcon className="size-4" /> },
  { label: "Bot score threshold", value: "0.70", icon: <BotIcon className="size-4" /> },
];

function verdictBadge(v: string) {
  switch (v) {
    case "blocked":
      return <Badge variant="destructive">blocked</Badge>;
    case "challenged":
      return <Badge variant="secondary">challenged</Badge>;
    default:
      return <Badge variant="outline">allowed</Badge>;
  }
}

function BotsPage() {
  const [uaCheck, setUaCheck] = useState(true);
  const [honeypot, setHoneypot] = useState(true);
  const [captcha, setCaptcha] = useState(true);
  const [signature, setSignature] = useState(false);

  return (
    <div className="flex min-w-0 flex-col gap-6">
      <PageHeader
        description="Detection rules and recent challenges against suspected automated traffic."
        actions={<Button variant="outline">Export decisions</Button>}
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
        <CardHeader>
          <CardTitle>Detection rules</CardTitle>
          <CardDescription>Heuristics evaluated before each authentication attempt.</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-4 md:grid-cols-2">
          <Field>
            <div className="flex items-center justify-between gap-4">
              <div>
                <FieldLabel>User-Agent fingerprinting</FieldLabel>
                <FieldDescription>Block known bot UA strings and headless browsers.</FieldDescription>
              </div>
              <Switch checked={uaCheck} onCheckedChange={setUaCheck} />
            </div>
          </Field>
          <Field>
            <div className="flex items-center justify-between gap-4">
              <div>
                <FieldLabel>Honeypot fields</FieldLabel>
                <FieldDescription>Hidden form inputs that bots will fill.</FieldDescription>
              </div>
              <Switch checked={honeypot} onCheckedChange={setHoneypot} />
            </div>
          </Field>
          <Field>
            <div className="flex items-center justify-between gap-4">
              <div>
                <FieldLabel>CAPTCHA challenge</FieldLabel>
                <FieldDescription>hCaptcha shown for score &gt; threshold.</FieldDescription>
              </div>
              <Switch checked={captcha} onCheckedChange={setCaptcha} />
            </div>
          </Field>
          <Field>
            <div className="flex items-center justify-between gap-4">
              <div>
                <FieldLabel>Request-signature analysis</FieldLabel>
                <FieldDescription>TLS JA3 + header-order fingerprinting (beta).</FieldDescription>
              </div>
              <Switch checked={signature} onCheckedChange={setSignature} />
            </div>
          </Field>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Recent decisions</CardTitle>
          <CardDescription>Last 15 minutes</CardDescription>
        </CardHeader>
        <CardContent className="overflow-x-auto p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>IP</TableHead>
                <TableHead>User-Agent</TableHead>
                <TableHead>Verdict</TableHead>
                <TableHead>Score</TableHead>
                <TableHead>When</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {recent.map((r) => (
                <TableRow key={r.id}>
                  <TableCell className="font-mono text-xs">{r.ip}</TableCell>
                  <TableCell className="max-w-[280px] truncate text-xs">{r.ua}</TableCell>
                  <TableCell>{verdictBadge(r.verdict)}</TableCell>
                  <TableCell className="font-mono text-xs">{r.score.toFixed(2)}</TableCell>
                  <TableCell className="text-xs text-muted-foreground">{r.time}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
