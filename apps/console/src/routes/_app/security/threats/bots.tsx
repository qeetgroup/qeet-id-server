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
import { useTranslation } from "react-i18next";

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
  const { t } = useTranslation("security");
  const overviewQ = useBotOverview();
  const settingsQ = useBotSettings();
  const update = useUpdateBotSettings();

  const recent = overviewQ.data?.recent ?? [];
  const s = overviewQ.data?.stats;
  const settings = settingsQ.data;

  const stats = [
    { key: "blocked", value: s?.blocked_24h ?? 0, icon: <ShieldOffIcon className="size-4" /> },
    { key: "challenged", value: s?.challenged_24h ?? 0, icon: <ZapIcon className="size-4" /> },
    { key: "threshold", value: (s?.threshold ?? 0.7).toFixed(2), icon: <BotIcon className="size-4" /> },
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
        description={t("bots.description")}
        actions={
          <Button
            variant="outline"
            size="sm"
            onClick={() => overviewQ.refetch()}
            disabled={overviewQ.isFetching}
          >
            <RefreshCwIcon className={overviewQ.isFetching ? "animate-spin" : ""} />
            {t("bots.refresh")}
          </Button>
        }
      />

      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        {stats.map((st) => (
          <Card key={st.key}>
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardDescription>{t(`bots.stats.${st.key}`)}</CardDescription>
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
          <CardTitle>{t("bots.rules.title")}</CardTitle>
          <CardDescription>{t("bots.rules.description")}</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-4 md:grid-cols-2">
          <Field>
            <div className="flex items-center justify-between gap-4">
              <div>
                <FieldLabel>{t("bots.rules.uaCheck")}</FieldLabel>
                <FieldDescription>{t("bots.rules.uaCheckHelp")}</FieldDescription>
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
                <FieldLabel>{t("bots.rules.honeypot")}</FieldLabel>
                <FieldDescription>{t("bots.rules.honeypotHelp")}</FieldDescription>
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
                <FieldLabel>{t("bots.rules.captcha")}</FieldLabel>
                <FieldDescription>{t("bots.rules.captchaHelp")}</FieldDescription>
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
                <FieldLabel>{t("bots.rules.signature")}</FieldLabel>
                <FieldDescription>{t("bots.rules.signatureHelp")}</FieldDescription>
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
          <CardTitle>{t("bots.recent.title")}</CardTitle>
          <CardDescription>{t("bots.recent.description")}</CardDescription>
        </CardHeader>
        <CardContent className="overflow-x-auto p-0">
          <DataState
            isLoading={overviewQ.isLoading}
            isError={overviewQ.isError}
            error={overviewQ.error}
            isEmpty={recent.length === 0}
            emptyIcon={BotIcon}
            emptyTitle={t("bots.recent.empty")}
            skeletonRows={3}
          >
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t("bots.recent.columns.ip")}</TableHead>
                  <TableHead>{t("bots.recent.columns.userAgent")}</TableHead>
                  <TableHead>{t("bots.recent.columns.verdict")}</TableHead>
                  <TableHead>{t("bots.recent.columns.score")}</TableHead>
                  <TableHead>{t("bots.recent.columns.when")}</TableHead>
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
