import {
  Card,
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
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@qeetrix/ui";
import { createFileRoute } from "@tanstack/react-router";
import {
  ActivityIcon,
  GaugeIcon,
  KeyRoundIcon,
  RepeatIcon,
  ShieldAlertIcon,
  UserCheckIcon,
  UsersIcon,
} from "lucide-react";
import { useState } from "react";

import { useAnalyticsOverview, formatShortDate } from "@/lib/analytics";
import { OnboardingChecklist } from "@/features/dashboard/components/onboarding-checklist";
import { PasskeyPromptCard } from "@/features/dashboard/components/passkey-prompt-card";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Label,
  Line,
  LineChart,
  Pie,
  PieChart,
  ReferenceLine,
  XAxis,
  YAxis,
} from "recharts";

export const Route = createFileRoute("/_app/dashboard")({
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

const sparkConfig = {
  v: { label: "Value", color: "var(--chart-1)" },
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
const cardLift = "motion-safe:transition-transform motion-safe:duration-200 motion-safe:hover:-translate-y-0.5";

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
};

function StatCard({ icon, title, value, delta, positive, data, variant = "area" }: StatCardProps) {
  return (
    <Card className={`overflow-hidden ${cardLift}`}>
      <CardHeader className="flex flex-row items-center justify-between gap-2 pb-2">
        <CardTitle className="text-sm font-medium text-muted-foreground">{title}</CardTitle>
        <div className="text-muted-foreground [&_svg]:size-4">{icon}</div>
      </CardHeader>
      <CardContent className="pb-2">
        <div className="text-2xl font-bold tabular-nums">{value}</div>
        <p
          className={`text-xs ${positive ? "text-emerald-600 dark:text-emerald-400" : "text-rose-600 dark:text-rose-400"}`}
        >
          {delta} <span className="text-muted-foreground">vs last week</span>
        </p>
      </CardContent>
      <ChartContainer config={sparkConfig} className="aspect-auto h-16 w-full">
        {variant === "area" ? (
          <AreaChart data={data} margin={{ left: 0, right: 0, top: 0, bottom: 0 }}>
            <defs>
              <linearGradient id="spark-fill" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="var(--color-v)" stopOpacity={0.35} />
                <stop offset="100%" stopColor="var(--color-v)" stopOpacity={0} />
              </linearGradient>
            </defs>
            <Area
              type="monotone"
              dataKey="v"
              stroke="var(--color-v)"
              strokeWidth={2}
              fill="url(#spark-fill)"
            />
          </AreaChart>
        ) : (
          <LineChart data={data} margin={{ left: 0, right: 0, top: 0, bottom: 0 }}>
            <Line type="monotone" dataKey="v" stroke="var(--color-v)" strokeWidth={2} dot={false} />
          </LineChart>
        )}
      </ChartContainer>
    </Card>
  );
}

type MiniStatProps = { icon: React.ReactNode; label: string; value: string; sub?: string };

function MiniStat({ icon, label, value, sub }: MiniStatProps) {
  return (
    <Card className={cardLift}>
      <CardContent className="flex items-center gap-3 py-4">
        <div className="grid size-9 shrink-0 place-items-center rounded-lg bg-muted text-muted-foreground [&_svg]:size-4">
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
      <div className="h-16 w-full animate-pulse bg-muted/40" />
    </Card>
  );
}

function ChartSkeleton({ heightClass = "h-72" }: { heightClass?: string }) {
  return <div className={`w-full animate-pulse rounded bg-muted/40 ${heightClass}`} />;
}

function EmptyState({ message }: { message: string }) {
  return (
    <div className="flex h-full min-h-32 items-center justify-center text-center text-sm text-muted-foreground">
      {message}
    </div>
  );
}

function DashboardPage() {
  const { data, isLoading, isError, error } = useAnalyticsOverview();
  const [range, setRange] = useState<RangeKey>("14d");
  const take = range === "7d" ? 7 : 14;

  if (isError) {
    return (
      <div className="flex min-w-0 flex-col gap-4">
        <Card>
          <CardContent className="py-12 text-center text-sm text-muted-foreground">
            Couldn&apos;t load dashboard analytics
            {error instanceof Error ? `: ${error.message}` : ""}.
          </CardContent>
        </Card>
      </div>
    );
  }

  const overview = data;
  const tail = <T,>(arr: T[]): T[] => (arr.length > take ? arr.slice(-take) : arr);

  const sparkUsers = tail(overview?.user_trend_14d ?? []).map((p, i) => ({ d: i, v: p.value }));
  const sparkLogins = tail(overview?.login_trend_14d ?? []).map((p, i) => ({ d: i, v: p.value }));
  const sparkMFA = tail(overview?.mfa_trend_14d ?? []).map((p, i) => ({ d: i, v: p.value }));
  const sparkFailed = tail(overview?.failed_trend_14d ?? []).map((p, i) => ({ d: i, v: p.value }));

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
          <h1 className="text-2xl font-semibold tracking-tight">Overview</h1>
          <p className="text-sm text-muted-foreground">
            Identity health for this workspace at a glance.
          </p>
        </div>
        <Select value={range} onValueChange={(v) => v && setRange(v as RangeKey)}>
          <SelectTrigger size="sm" className="w-auto min-w-36">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="7d">Last 7 days</SelectItem>
            <SelectItem value="14d">Last 14 days</SelectItem>
          </SelectContent>
        </Select>
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
              title="Active Users (MAU)"
              value={overview.kpis.mau.value.toLocaleString("en-US")}
              delta={formatDelta(overview.kpis.mau.delta_pct)}
              positive={overview.kpis.mau.delta_pct >= 0}
              data={sparkUsers}
            />
            <StatCard
              icon={<ActivityIcon />}
              title="Logins Today"
              value={overview.kpis.logins_today.value.toLocaleString("en-US")}
              delta={formatDelta(overview.kpis.logins_today.delta_pct)}
              positive={overview.kpis.logins_today.delta_pct >= 0}
              data={sparkLogins}
            />
            <StatCard
              icon={<KeyRoundIcon />}
              title="MFA Adoption"
              value={`${overview.kpis.mfa_adoption_pct.value.toFixed(1)}%`}
              delta={formatDelta(overview.kpis.mfa_adoption_pct.delta_pct, "pp")}
              positive={overview.kpis.mfa_adoption_pct.delta_pct >= 0}
              data={sparkMFA}
              variant="line"
            />
            <StatCard
              icon={<ShieldAlertIcon />}
              title="Failed Logins (24h)"
              value={overview.kpis.failed_logins_24h.value.toLocaleString("en-US")}
              delta={formatDelta(overview.kpis.failed_logins_24h.delta_pct)}
              positive={overview.kpis.failed_logins_24h.delta_pct <= 0}
              data={sparkFailed}
              variant="line"
            />
          </>
        )}
      </div>

      {/* Secondary glance stats */}
      {overview && !isLoading && (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <MiniStat
            icon={<UsersIcon />}
            label="Total users"
            value={overview.kpis.total_users.value.toLocaleString("en-US")}
          />
          <MiniStat
            icon={<UserCheckIcon />}
            label="Daily active"
            value={overview.kpis.dau.value.toLocaleString("en-US")}
            sub={formatDelta(overview.kpis.dau.delta_pct)}
          />
          <MiniStat
            icon={<GaugeIcon />}
            label="Stickiness (DAU/MAU)"
            value={`${overview.kpis.stickiness_pct.value.toFixed(0)}%`}
          />
          <MiniStat
            icon={<RepeatIcon />}
            label="Avg sessions / user"
            value={overview.kpis.avg_sessions_per_user.value.toFixed(1)}
          />
        </div>
      )}

      {/* Bento: activity (wide) + method mix */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-6">
        <Card className={`lg:col-span-4 ${cardLift}`}>
          <CardHeader>
            <CardTitle>Authentication Activity</CardTitle>
            <CardDescription>Daily logins by method · last {take} days</CardDescription>
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <ChartSkeleton heightClass="h-72" />
            ) : activityRows.length === 0 ? (
              <EmptyState message="No logins recorded in this window." />
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
                  <CartesianGrid vertical={false} />
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
            <CardTitle>Login Methods Mix</CardTitle>
            <CardDescription>Last 30 days</CardDescription>
          </CardHeader>
          <CardContent className="flex justify-center">
            {isLoading ? (
              <ChartSkeleton heightClass="h-72 aspect-square" />
            ) : mixRows.length === 0 ? (
              <EmptyState message="No sign-ins recorded yet." />
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
                      content={({ viewBox }) => {
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
                              {mixRows.length} method{mixRows.length === 1 ? "" : "s"}
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
            <CardTitle>MFA Methods Adoption</CardTitle>
            <CardDescription>Users by second factor</CardDescription>
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <ChartSkeleton heightClass="h-64" />
            ) : mfaRows.length === 0 ? (
              <EmptyState message="No users have enrolled in MFA yet." />
            ) : (
              <ChartContainer config={mfaConfig} className="aspect-auto h-64 w-full">
                <BarChart data={mfaRows} layout="vertical" margin={{ left: 12, right: 24 }}>
                  <CartesianGrid horizontal={false} />
                  <XAxis type="number" tickLine={false} axisLine={false} />
                  <YAxis
                    type="category"
                    dataKey="method"
                    tickLine={false}
                    axisLine={false}
                    width={110}
                  />
                  <ChartTooltip cursor={false} content={<ChartTooltipContent hideLabel />} />
                  <Bar dataKey="users" radius={[0, 6, 6, 0]} />
                </BarChart>
              </ChartContainer>
            )}
          </CardContent>
        </Card>

        <Card className={`lg:col-span-3 ${cardLift}`}>
          <CardHeader>
            <CardTitle>Failed Login Attempts</CardTitle>
            <CardDescription>Hourly · last 24h (threshold 250)</CardDescription>
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <ChartSkeleton heightClass="h-64" />
            ) : failedRows.length === 0 ? (
              <EmptyState message="No failed-login telemetry yet." />
            ) : (
              <ChartContainer config={failedConfig} className="aspect-auto h-64 w-full">
                <LineChart data={failedRows} margin={{ left: 0, right: 16 }}>
                  <CartesianGrid vertical={false} />
                  <XAxis dataKey="hour" tickLine={false} axisLine={false} tickMargin={8} />
                  <YAxis tickLine={false} axisLine={false} tickMargin={8} width={40} />
                  <ChartTooltip content={<ChartTooltipContent indicator="line" />} />
                  <ReferenceLine
                    y={250}
                    stroke="var(--chart-5)"
                    strokeDasharray="4 4"
                    label={{
                      value: "Threshold",
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
    </div>
  );
}
