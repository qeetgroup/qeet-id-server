import {
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  DataState,
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
  TimeSince,
} from "@qeetrix/ui";
import { createFileRoute } from "@tanstack/react-router";
import { BotIcon, RefreshCwIcon, ShieldOffIcon, ZapIcon } from "lucide-react";

import { PageHeader } from "@/components/page-header";
import { useBotOverview, useBotSettings, useUpdateBotSettings, type BotSettings } from "@/lib/bots";

export const Route = createFileRoute("/_app/security/threats/bots")({ component: BotsPage });

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
  const overviewQ = useBotOverview();
  const settingsQ = useBotSettings();
  const update = useUpdateBotSettings();

  const recent = overviewQ.data?.recent ?? [];
  const s = overviewQ.data?.stats;
  const settings = settingsQ.data;

  const stats = [
    {
      label: "Blocked (24h)",
      value: s?.blocked_24h ?? 0,
      icon: <ShieldOffIcon className="size-4" />,
    },
    {
      label: "Challenged (24h)",
      value: s?.challenged_24h ?? 0,
      icon: <ZapIcon className="size-4" />,
    },
    {
      label: "Bot score threshold",
      value: (s?.threshold ?? 0.7).toFixed(2),
      icon: <BotIcon className="size-4" />,
    },
  ];

  // Toggling a switch persists the full settings object (the scorer only
  // enforces ua_check today; the others are stored for future enforcement).
  function set(patch: Partial<BotSettings>) {
    if (!settings) return;
    update.mutate({ ...settings, ...patch });
  }

  return (
    <div className="flex min-w-0 flex-col gap-6">
      <PageHeader
        description="Detection rules and recent challenges against suspected automated traffic."
        actions={
          <Button
            variant="outline"
            size="sm"
            onClick={() => overviewQ.refetch()}
            disabled={overviewQ.isFetching}
          >
            <RefreshCwIcon className={overviewQ.isFetching ? "animate-spin" : ""} />
            Refresh
          </Button>
        }
      />

      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        {stats.map((st) => (
          <Card key={st.label}>
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardDescription>{st.label}</CardDescription>
              <span className="text-muted-foreground">{st.icon}</span>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-semibold tracking-tight">{st.value}</div>
            </CardContent>
          </Card>
        ))}
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Detection rules</CardTitle>
          <CardDescription>
            Heuristics evaluated on each authentication attempt. User-Agent fingerprinting is
            enforced today; the others are stored for upcoming enforcement.
          </CardDescription>
        </CardHeader>
        <CardContent className="grid gap-4 md:grid-cols-2">
          <Field>
            <div className="flex items-center justify-between gap-4">
              <div>
                <FieldLabel>User-Agent fingerprinting</FieldLabel>
                <FieldDescription>
                  Score known bot UA strings and headless browsers.
                </FieldDescription>
              </div>
              <Switch
                checked={settings?.ua_check ?? false}
                disabled={!settings || update.isPending}
                onCheckedChange={(v) => set({ ua_check: v })}
              />
            </div>
          </Field>
          <Field>
            <div className="flex items-center justify-between gap-4">
              <div>
                <FieldLabel>Honeypot fields</FieldLabel>
                <FieldDescription>Hidden form inputs that bots will fill.</FieldDescription>
              </div>
              <Switch
                checked={settings?.honeypot ?? false}
                disabled={!settings || update.isPending}
                onCheckedChange={(v) => set({ honeypot: v })}
              />
            </div>
          </Field>
          <Field>
            <div className="flex items-center justify-between gap-4">
              <div>
                <FieldLabel>CAPTCHA challenge</FieldLabel>
                <FieldDescription>hCaptcha shown for score &gt; threshold.</FieldDescription>
              </div>
              <Switch
                checked={settings?.captcha ?? false}
                disabled={!settings || update.isPending}
                onCheckedChange={(v) => set({ captcha: v })}
              />
            </div>
          </Field>
          <Field>
            <div className="flex items-center justify-between gap-4">
              <div>
                <FieldLabel>Request-signature analysis</FieldLabel>
                <FieldDescription>TLS JA3 + header-order fingerprinting (beta).</FieldDescription>
              </div>
              <Switch
                checked={settings?.signature ?? false}
                disabled={!settings || update.isPending}
                onCheckedChange={(v) => set({ signature: v })}
              />
            </div>
          </Field>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Recent decisions</CardTitle>
          <CardDescription>Suspicious authentication attempts, newest first</CardDescription>
        </CardHeader>
        <CardContent className="overflow-x-auto p-0">
          <DataState
            isLoading={overviewQ.isLoading}
            isError={overviewQ.isError}
            error={overviewQ.error}
            isEmpty={recent.length === 0}
            emptyIcon={BotIcon}
            emptyTitle="No bot activity detected."
            skeletonRows={3}
          >
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
                    <TableCell className="font-mono text-xs">{r.ip ?? "—"}</TableCell>
                    <TableCell className="max-w-[280px] truncate text-xs">{r.user_agent}</TableCell>
                    <TableCell>{verdictBadge(r.verdict)}</TableCell>
                    <TableCell className="font-mono text-xs">{r.score.toFixed(2)}</TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      <TimeSince value={r.created_at} />
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
