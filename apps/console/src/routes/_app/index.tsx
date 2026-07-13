import {
  Button,
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  type ChartConfig,
  ChartContainer,
  ChartLegend,
  ChartLegendContent,
  ChartTooltip,
  ChartTooltipContent,
  EmptyState,
  PresenceIndicator,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Sparkline,
  statDeltaVariants,
  TimeSince,
} from "@qeetrix/ui";
import { useQuery } from "@tanstack/react-query";
import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import {
  ActivityIcon,
  ArrowDownRightIcon,
  ArrowUpRightIcon,
  Building2Icon,
  ChevronRightIcon,
  FileTextIcon,
  GaugeIcon,
  KeyRoundIcon,
  LogInIcon,
  PlusIcon,
  RepeatIcon,
  ShieldAlertIcon,
  ShieldIcon,
  UserCheckIcon,
  UserIcon,
  UserPlusIcon,
  UsersIcon,
} from "lucide-react";
import type * as React from "react";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Label,
  Line,
  LineChart,
  Pie,
  PieChart,
  ReferenceLine,
  XAxis,
  YAxis,
} from "recharts";
import { OnboardingChecklist } from "@/features/dashboard/components/onboarding-checklist";
import { PasskeyPromptCard } from "@/features/dashboard/components/passkey-prompt-card";
import { formatShortDate, useAnalyticsOverview } from "@/lib/analytics";
import { api } from "@/lib/api";
import { useTenantId } from "@/lib/auth";

export const Route = createFileRoute("/_app/")({
  component: DashboardPage,
});

// ---- Chart configs ----

const activityConfig = {
  password: { label: "Password", color: "var(--chart-1)" },
  passkey: { label: "Passkey", color: "var(--chart-2)" },
  social: { label: "Social", color: "var(--chart-3)" },
  saml: { label: "SAML", color: "var(--chart-4)" },
  oidc: { label: "OIDC", color: "var(--chart-5)" },
} satisfies ChartConfig;

const mixConfig = {
  value: { label: "Sign-ins" },
  password: { label: "Password", color: "var(--chart-1)" },
  passkey: { label: "Passkey", color: "var(--chart-2)" },
  social: { label: "Social", color: "var(--chart-3)" },
  saml: { label: "SAML", color: "var(--chart-4)" },
  oidc: { label: "OIDC", color: "var(--chart-5)" },
} satisfies ChartConfig;

const mfaConfig = {
  users: { label: "Users" },
  totp: { label: "TOTP", color: "var(--chart-1)" },
  passkey: { label: "Passkey", color: "var(--chart-2)" },
  sms: { label: "SMS", color: "var(--chart-3)" },
  email: { label: "Email OTP", color: "var(--chart-4)" },
  recovery: { label: "Recovery Codes", color: "var(--chart-5)" },
} satisfies ChartConfig;

const failedConfig = {
  attempts: { label: "Failed attempts", color: "var(--chart-1)" },
} satisfies ChartConfig;

const METHOD_KEYS = ["password", "passkey", "social", "saml", "oidc"] as const;

function methodFill(method: string): string {
  const key = method.toLowerCase().replace(/[^a-z]/g, "");
  if ((METHOD_KEYS as readonly string[]).includes(key)) return `var(--color-${key})`;
  return "var(--chart-1)";
}

function mfaFill(method: string): string {
  const key = method.toLowerCase();
  if (key.startsWith("totp")) return "var(--color-totp)";
  if (key.startsWith("passkey")) return "var(--color-passkey)";
  if (key.startsWith("sms")) return "var(--color-sms)";
  if (key.startsWith("email")) return "var(--color-email)";
  if (key.startsWith("recovery")) return "var(--color-recovery)";
  return "var(--chart-1)";
}

function formatDelta(pct: number, unit: "%" | "pp" = "%"): string {
  const sign = pct >= 0 ? "+" : "";
  return `${sign}${pct.toFixed(1)}${unit}`;
}

// Subtle lift on hover, suppressed for reduced-motion users.
const cardLift =
  "motion-safe:transition-transform motion-safe:duration-200 motion-safe:hover:-translate-y-0.5";

function getQuickActions(t: (k: string) => string) {
  return [
    {
      icon: UserPlusIcon,
      label: t("quickActions.inviteLabel"),
      description: t("quickActions.inviteDesc"),
      href: "/invitations",
      iconClass: "bg-primary/10 text-primary",
    },
    {
      icon: KeyRoundIcon,
      label: t("quickActions.apiKeyLabel"),
      description: t("quickActions.apiKeyDesc"),
      href: "/developer/api-keys",
      iconClass: "bg-info/10 text-info",
    },
    {
      icon: ShieldIcon,
      label: t("quickActions.threatsLabel"),
      description: t("quickActions.threatsDesc"),
      href: "/security/threats",
      iconClass: "bg-destructive/10 text-destructive",
    },
    {
      icon: FileTextIcon,
      label: t("quickActions.auditLabel"),
      description: t("quickActions.auditDesc"),
      href: "/security/audit-logs",
      iconClass: "bg-success/10 text-success",
    },
  ] as const;
}

type AuditEvent = {
  id: string;
  actor_type: string;
  action: string;
  resource_type: string;
  created_at: string;
};

function useRecentActivity(tenantId: string | undefined) {
  return useQuery({
    queryKey: ["activity-recent-dashboard", tenantId],
    queryFn: () => api<{ items: AuditEvent[] }>(`/v1/tenants/${tenantId}/audit?limit=5`),
    staleTime: 60_000,
    refetchInterval: 15_000,
    refetchIntervalInBackground: false,
    enabled: !!tenantId,
  });
}

function activityIcon(action: string): React.ReactNode {
  if (action.startsWith("user.login") || action.startsWith("session.")) return <LogInIcon />;
  if (action.startsWith("user.")) return <UserIcon />;
  if (action.startsWith("mfa.") || action.startsWith("api_key.")) return <KeyRoundIcon />;
  return <ActivityIcon />;
}

function formatAction(action: string): string {
  return action.replace(/[._]/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

type RangeKey = "7d" | "14d";

// ---- Components ----

type StatCardProps = {
  icon: React.ReactNode;
  title: string;
  value: string;
  delta: string;
  positive?: boolean;
  data: { d: number; v: number }[];
  variant?: "area" | "line";
  iconClass?: string;
};

function StatCard({
  icon,
  title,
  value,
  delta,
  positive,
  data,
  variant = "area",
  iconClass = "bg-primary/10 text-primary",
}: StatCardProps) {
  const { t } = useTranslation("dashboard");
  const trend = positive ? ("up" as const) : ("down" as const);
  const textClass = iconClass.split(" ").find((c) => c.startsWith("text-")) ?? "text-primary";
  return (
    <Card className={`overflow-hidden ${cardLift}`}>
      <CardHeader className="flex flex-row items-center justify-between gap-2 pb-2">
        <CardTitle className="text-sm font-medium text-muted-foreground">{title}</CardTitle>
        <div
          className={`grid size-9 shrink-0 place-items-center rounded-lg [&_svg]:size-4 ${iconClass}`}
        >
          {icon}
        </div>
      </CardHeader>
      <CardContent className="pb-2">
        <div className="text-2xl font-semibold tabular-nums">{value}</div>
        <div className="mt-0.5 flex items-center gap-2">
          <span className={statDeltaVariants({ trend })}>
            {positive ? (
              <ArrowUpRightIcon className="size-3.5" />
            ) : (
              <ArrowDownRightIcon className="size-3.5" />
            )}
            {delta}
          </span>
          <span className="text-xs text-muted-foreground">{t("vsLastWeek")}</span>
        </div>
      </CardContent>
      <div className={`border-t border-border/40 ${textClass}`}>
        <Sparkline data={data.map((p) => p.v)} type={variant} height={56} className="w-full" />
      </div>
    </Card>
  );
}

type MiniStatProps = {
  icon: React.ReactNode;
  label: string;
  value: string;
  sub?: string;
};

function MiniStat({ icon, label, value, sub }: MiniStatProps) {
  return (
    <Card className={cardLift}>
      <CardContent className="flex items-center gap-3 py-4">
        <div className="grid size-9 shrink-0 place-items-center rounded-lg bg-primary/10 text-primary [&_svg]:size-4">
          {icon}
        </div>
        <div className="min-w-0">
          <div className="text-lg font-semibold tabular-nums leading-tight">{value}</div>
          <div className="truncate text-xs text-muted-foreground">
            {label}
            {sub ? ` · ${sub}` : ""}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function StatSkeleton() {
  return (
    <Card className="overflow-hidden">
      <CardHeader className="flex flex-row items-center justify-between gap-2 pb-2">
        <div className="h-3 w-24 rounded bg-muted" />
        <div className="size-4 rounded bg-muted" />
      </CardHeader>
      <CardContent className="pb-2">
        <div className="h-6 w-20 animate-pulse rounded bg-muted" />
        <div className="mt-2 h-3 w-32 animate-pulse rounded bg-muted" />
      </CardContent>
      <div className="h-14 w-full animate-pulse bg-muted/40" />
    </Card>
  );
}

function ChartSkeleton({ heightClass = "h-72" }: { heightClass?: string }) {
  return <div className={`w-full animate-pulse rounded bg-muted/40 ${heightClass}`} />;
}

// Tenant-less users (fresh signup) get the create-workspace prompt instead of the tenant-scoped dashboard.
function DashboardPage() {
  const tenantId = useTenantId();
  if (!tenantId) return <NoWorkspaceOnboarding />;
  return <DashboardContent />;
}

function NoWorkspaceOnboarding() {
  const navigate = useNavigate();
  const { t } = useTranslation("dashboard");
  return (
    <div className="flex min-w-0 flex-1 items-center justify-center py-16">
      <Card className="w-full max-w-md text-center">
        <CardHeader>
          <div className="mx-auto flex size-12 items-center justify-center rounded-xl bg-muted">
            <Building2Icon className="size-6 text-muted-foreground" />
          </div>
          <CardTitle className="mt-2">{t("noWorkspace.title")}</CardTitle>
          <CardDescription>{t("noWorkspace.description")}</CardDescription>
        </CardHeader>
        <CardContent className="flex justify-center">
          <Button onClick={() => navigate({ to: "/organizations/tenants" })}>
            <PlusIcon /> {t("noWorkspace.cta")}
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}

function DashboardContent() {
  const tenantId = useTenantId();
  const navigate = useNavigate();
  const { t } = useTranslation("dashboard");
  const { data, isLoading, isError, error } = useAnalyticsOverview();
  const { data: activityData, isLoading: activityLoading } = useRecentActivity(
    tenantId ?? undefined,
  );
  const [range, setRange] = useState<RangeKey>("14d");
  const take = range === "7d" ? 7 : 14;
  const quickActions = getQuickActions(t);

  if (isError) {
    return (
      <div className="flex min-w-0 flex-col gap-4">
        <Card>
          <CardContent className="py-12 text-center text-sm text-muted-foreground">
            {t("error")}
            {error instanceof Error ? `: ${error.message}` : ""}.
          </CardContent>
        </Card>
      </div>
    );
  }

  const overview = data;
  const tail = <T,>(arr: T[]): T[] => (arr.length > take ? arr.slice(-take) : arr);

  const sparkUsers = tail(overview?.user_trend_14d ?? []).map((p, i) => ({
    d: i,
    v: p.value,
  }));
  const sparkLogins = tail(overview?.login_trend_14d ?? []).map((p, i) => ({
    d: i,
    v: p.value,
  }));
  const sparkMFA = tail(overview?.mfa_trend_14d ?? []).map((p, i) => ({
    d: i,
    v: p.value,
  }));
  const sparkFailed = tail(overview?.failed_trend_14d ?? []).map((p, i) => ({
    d: i,
    v: p.value,
  }));

  const activityRows = tail(overview?.login_activity_14d ?? []).map((p) => ({
    day: formatShortDate(p.date),
    password: p.password,
    passkey: p.passkey,
    social: p.social,
    saml: p.saml,
    oidc: p.oidc,
  }));

  const mixRows = (overview?.login_methods_mix ?? []).map((m) => ({
    method: m.method,
    value: m.value,
    fill: methodFill(m.method),
  }));

  const mfaRows = (overview?.mfa_methods_adoption ?? []).map((m) => ({
    method: m.method,
    users: m.users,
    fill: mfaFill(m.method),
  }));

  const failedRows = overview?.failed_logins_hourly_24h ?? [];

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <OnboardingChecklist />
      <PasskeyPromptCard />

      {/* Title row + trend-window control */}
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="font-heading text-2xl font-semibold tracking-tight">{t("title")}</h1>
          <p className="text-sm text-muted-foreground">{t("subtitle")}</p>
        </div>
        <div className="flex items-center gap-3">
          <span className="hidden items-center gap-1.5 text-xs text-success sm:flex">
            <PresenceIndicator status="online" size="sm" pulse />
            {t("systemsOk")}
          </span>
          <Select value={range} onValueChange={(v) => v && setRange(v as RangeKey)}>
            <SelectTrigger size="sm" className="w-auto min-w-36">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="7d">{t("range7d")}</SelectItem>
              <SelectItem value="14d">{t("range14d")}</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>

      {/* KPI cards */}
      <div className="grid auto-rows-min gap-4 md:grid-cols-2 lg:grid-cols-4">
        {isLoading || !overview ? (
          <>
            <StatSkeleton />
            <StatSkeleton />
            <StatSkeleton />
            <StatSkeleton />
          </>
        ) : (
          <>
            <StatCard
              icon={<UsersIcon />}
              title={t("kpi.mau")}
              value={overview.kpis.mau.value.toLocaleString("en-US")}
              delta={formatDelta(overview.kpis.mau.delta_pct)}
              positive={overview.kpis.mau.delta_pct >= 0}
              data={sparkUsers}
              iconClass="bg-info/10 text-info"
            />
            <StatCard
              icon={<ActivityIcon />}
              title={t("kpi.loginsToday")}
              value={overview.kpis.logins_today.value.toLocaleString("en-US")}
              delta={formatDelta(overview.kpis.logins_today.delta_pct)}
              positive={overview.kpis.logins_today.delta_pct >= 0}
              data={sparkLogins}
              iconClass="bg-primary/10 text-primary"
            />
            <StatCard
              icon={<KeyRoundIcon />}
              title={t("kpi.mfaAdoption")}
              value={`${overview.kpis.mfa_adoption_pct.value.toFixed(1)}%`}
              delta={formatDelta(overview.kpis.mfa_adoption_pct.delta_pct, "pp")}
              positive={overview.kpis.mfa_adoption_pct.delta_pct >= 0}
              data={sparkMFA}
              variant="line"
              iconClass="bg-success/10 text-success"
            />
            <StatCard
              icon={<ShieldAlertIcon />}
              title={t("kpi.failedLogins24h")}
              value={overview.kpis.failed_logins_24h.value.toLocaleString("en-US")}
              delta={formatDelta(overview.kpis.failed_logins_24h.delta_pct)}
              positive={overview.kpis.failed_logins_24h.delta_pct <= 0}
              data={sparkFailed}
              variant="line"
              iconClass="bg-destructive/10 text-destructive"
            />
          </>
        )}
      </div>

      {/* Secondary glance stats */}
      {overview && !isLoading && (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <MiniStat
            icon={<UsersIcon />}
            label={t("stats.totalUsers")}
            value={overview.kpis.total_users.value.toLocaleString("en-US")}
          />
          <MiniStat
            icon={<UserCheckIcon />}
            label={t("stats.dailyActive")}
            value={overview.kpis.dau.value.toLocaleString("en-US")}
            sub={formatDelta(overview.kpis.dau.delta_pct)}
          />
          <MiniStat
            icon={<GaugeIcon />}
            label={t("stats.stickiness")}
            value={`${overview.kpis.stickiness_pct.value.toFixed(0)}%`}
          />
          <MiniStat
            icon={<RepeatIcon />}
            label={t("stats.avgSessions")}
            value={overview.kpis.avg_sessions_per_user.value.toFixed(1)}
          />
        </div>
      )}

      {/* Quick Actions */}
      <div className="flex flex-col gap-2">
        <h2 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
          {t("quickActions.heading")}
        </h2>
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {quickActions.map(({ icon: Icon, label, description, href, iconClass }) => (
            <Link key={href} to={href as never} className="block">
              <Card
                className={`flex cursor-pointer items-center gap-3 p-4 transition-colors hover:bg-muted/40 ${cardLift}`}
              >
                <div
                  className={`grid size-9 shrink-0 place-items-center rounded-lg [&_svg]:size-4 ${iconClass}`}
                >
                  <Icon />
                </div>
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-medium leading-none">{label}</p>
                  <p className="mt-1 truncate text-xs text-muted-foreground">{description}</p>
                </div>
                <ChevronRightIcon className="ml-auto size-4 shrink-0 text-muted-foreground/40" />
              </Card>
            </Link>
          ))}
        </div>
      </div>

      {/* Bento: activity (wide) + method mix */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-6">
        <Card className={`lg:col-span-4 ${cardLift}`}>
          <CardHeader>
            <CardTitle>{t("charts.authActivity.title")}</CardTitle>
            <CardDescription>{t("charts.authActivity.description", { take })}</CardDescription>
            <CardAction>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => navigate({ to: "/analytics" as never })}
              >
                {t("charts.viewAnalytics")}
              </Button>
            </CardAction>
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <ChartSkeleton heightClass="h-72" />
            ) : activityRows.length === 0 ? (
              <EmptyState
                icon={ActivityIcon}
                title={t("charts.authActivity.emptyTitle")}
                description={t("charts.authActivity.emptyDescription")}
              />
            ) : (
              <ChartContainer config={activityConfig} className="aspect-auto h-72 w-full">
                <AreaChart data={activityRows}>
                  <defs>
                    {METHOD_KEYS.map((k) => (
                      <linearGradient key={k} id={`fill-${k}`} x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor={`var(--color-${k})`} stopOpacity={0.55} />
                        <stop offset="100%" stopColor={`var(--color-${k})`} stopOpacity={0.05} />
                      </linearGradient>
                    ))}
                  </defs>
                  <CartesianGrid vertical={false} stroke="var(--border)" strokeDasharray="3 3" />
                  <XAxis dataKey="day" tickLine={false} axisLine={false} tickMargin={8} />
                  <YAxis tickLine={false} axisLine={false} tickMargin={8} width={40} />
                  <ChartTooltip content={<ChartTooltipContent indicator="dot" />} />
                  <ChartLegend content={<ChartLegendContent />} />
                  {(["oidc", "saml", "social", "passkey", "password"] as const).map((k) => (
                    <Area
                      key={k}
                      type="monotone"
                      dataKey={k}
                      stackId="1"
                      stroke={`var(--color-${k})`}
                      fill={`url(#fill-${k})`}
                      strokeWidth={1.5}
                    />
                  ))}
                </AreaChart>
              </ChartContainer>
            )}
          </CardContent>
        </Card>

        <Card className={`lg:col-span-2 ${cardLift}`}>
          <CardHeader>
            <CardTitle>{t("charts.loginMix.title")}</CardTitle>
            <CardDescription>{t("charts.loginMix.description")}</CardDescription>
          </CardHeader>
          <CardContent className="flex justify-center">
            {isLoading ? (
              <ChartSkeleton heightClass="h-72 aspect-square" />
            ) : mixRows.length === 0 ? (
              <EmptyState
                icon={ActivityIcon}
                title={t("charts.loginMix.emptyTitle")}
                description={t("charts.loginMix.emptyDescription")}
              />
            ) : (
              <ChartContainer config={mixConfig} className="aspect-square h-72">
                <PieChart>
                  <ChartTooltip content={<ChartTooltipContent nameKey="method" hideLabel />} />
                  <Pie
                    data={mixRows}
                    dataKey="value"
                    nameKey="method"
                    innerRadius={60}
                    outerRadius={100}
                    strokeWidth={2}
                  >
                    <Label
                      content={({ viewBox }: { viewBox?: { cx?: number; cy?: number } }) => {
                        if (!viewBox || !("cx" in viewBox) || !("cy" in viewBox)) return null;
                        return (
                          <text
                            x={viewBox.cx}
                            y={viewBox.cy}
                            textAnchor="middle"
                            dominantBaseline="middle"
                          >
                            <tspan
                              x={viewBox.cx}
                              y={viewBox.cy}
                              className="fill-foreground text-2xl font-bold"
                            >
                              100%
                            </tspan>
                            <tspan
                              x={viewBox.cx}
                              y={(viewBox.cy ?? 0) + 22}
                              className="fill-muted-foreground text-xs"
                            >
                              {t("charts.loginMix.methodCount", {
                                count: mixRows.length,
                              })}
                            </tspan>
                          </text>
                        );
                      }}
                    />
                  </Pie>
                  <ChartLegend content={<ChartLegendContent nameKey="method" />} />
                </PieChart>
              </ChartContainer>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Bento: MFA adoption + failed logins */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-6">
        <Card className={`lg:col-span-3 ${cardLift}`}>
          <CardHeader>
            <CardTitle>{t("charts.mfa.title")}</CardTitle>
            <CardDescription>{t("charts.mfa.description")}</CardDescription>
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <ChartSkeleton heightClass="h-64" />
            ) : mfaRows.length === 0 ? (
              <EmptyState
                icon={KeyRoundIcon}
                title={t("charts.mfa.emptyTitle")}
                description={t("charts.mfa.emptyDescription")}
              />
            ) : (
              <ChartContainer config={mfaConfig} className="aspect-auto h-64 w-full">
                <BarChart data={mfaRows} layout="vertical" margin={{ left: 12, right: 24 }}>
                  <CartesianGrid horizontal={false} stroke="var(--border)" strokeDasharray="3 3" />
                  <XAxis type="number" tickLine={false} axisLine={false} />
                  <YAxis
                    type="category"
                    dataKey="method"
                    tickLine={false}
                    axisLine={false}
                    width={110}
                  />
                  <ChartTooltip cursor={false} content={<ChartTooltipContent hideLabel />} />
                  <Bar dataKey="users" radius={[0, 6, 6, 0]}>
                    {mfaRows.map((row) => (
                      <Cell key={row.method} fill={row.fill} />
                    ))}
                  </Bar>
                </BarChart>
              </ChartContainer>
            )}
          </CardContent>
        </Card>

        <Card className={`lg:col-span-3 ${cardLift}`}>
          <CardHeader>
            <CardTitle>{t("charts.failedLogins.title")}</CardTitle>
            <CardDescription>{t("charts.failedLogins.description")}</CardDescription>
            <CardAction>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => navigate({ to: "/security/audit-logs" as never })}
              >
                {t("charts.viewLogs")}
              </Button>
            </CardAction>
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <ChartSkeleton heightClass="h-64" />
            ) : failedRows.length === 0 ? (
              <EmptyState
                icon={ShieldAlertIcon}
                title={t("charts.failedLogins.emptyTitle")}
                description={t("charts.failedLogins.emptyDescription")}
              />
            ) : (
              <ChartContainer config={failedConfig} className="aspect-auto h-64 w-full">
                <LineChart data={failedRows} margin={{ left: 0, right: 16 }}>
                  <CartesianGrid vertical={false} stroke="var(--border)" strokeDasharray="3 3" />
                  <XAxis dataKey="hour" tickLine={false} axisLine={false} tickMargin={8} />
                  <YAxis tickLine={false} axisLine={false} tickMargin={8} width={40} />
                  <ChartTooltip content={<ChartTooltipContent indicator="line" />} />
                  <ReferenceLine
                    y={250}
                    stroke="var(--chart-5)"
                    strokeDasharray="4 4"
                    label={{
                      value: t("charts.failedLogins.threshold"),
                      position: "insideTopRight",
                      fontSize: 11,
                      fill: "var(--muted-foreground)",
                    }}
                  />
                  <Line
                    type="monotone"
                    dataKey="attempts"
                    stroke="var(--color-attempts)"
                    strokeWidth={2}
                    dot={{ r: 3 }}
                    activeDot={{ r: 5 }}
                  />
                </LineChart>
              </ChartContainer>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Recent Activity */}
      <Card>
        <CardHeader>
          <CardTitle>{t("activity.title")}</CardTitle>
          <CardDescription>{t("activity.description")}</CardDescription>
          <CardAction>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => navigate({ to: "/security/audit-logs" as never })}
            >
              {t("activity.viewAll")}
            </Button>
          </CardAction>
        </CardHeader>
        <CardContent className="p-0">
          {activityLoading ? (
            <ul className="divide-y divide-border/60">
              {Array.from({ length: 5 }).map((_, i) => (
                <li key={i} className="flex items-center gap-3 px-6 py-3">
                  <div className="size-8 animate-pulse rounded-lg bg-muted" />
                  <div className="flex-1 space-y-1.5">
                    <div className="h-3 w-40 animate-pulse rounded bg-muted" />
                    <div className="h-2.5 w-24 animate-pulse rounded bg-muted" />
                  </div>
                  <div className="h-2.5 w-14 animate-pulse rounded bg-muted" />
                </li>
              ))}
            </ul>
          ) : !activityData?.items?.length ? (
            <div className="px-6 py-8">
              <EmptyState
                icon={ActivityIcon}
                title={t("activity.emptyTitle")}
                description={t("activity.emptyDescription")}
              />
            </div>
          ) : (
            <ul className="divide-y divide-border/60">
              {activityData.items.map((event) => (
                <li key={event.id} className="flex items-center gap-3 px-6 py-3">
                  <div className="grid size-8 shrink-0 place-items-center rounded-lg bg-muted text-muted-foreground [&_svg]:size-3.5">
                    {activityIcon(event.action)}
                  </div>
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-sm font-medium">{formatAction(event.action)}</p>
                    <p className="text-xs text-muted-foreground">{event.resource_type}</p>
                  </div>
                  <TimeSince
                    value={event.created_at}
                    className="shrink-0 text-xs text-muted-foreground"
                  />
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
