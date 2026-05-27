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
} from "@qeetid/ui";
import { createFileRoute } from "@tanstack/react-router";
import {
  ArrowDownRightIcon,
  ArrowUpRightIcon,
  GlobeIcon,
  TrendingUpIcon,
  UsersIcon,
  ZapIcon,
} from "lucide-react";
import { useState } from "react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  XAxis,
  YAxis,
} from "recharts";

import { PageHeader } from "@/components/page-header";
import { useAnalyticsOverview } from "@/lib/analytics";

export const Route = createFileRoute("/_app/analytics")({ component: AnalyticsPage });

const mauConfig: ChartConfig = {
  wau: { label: "WAU", color: "var(--chart-1)" },
  dau: { label: "DAU (avg)", color: "var(--chart-2)" },
};

function formatDelta(pct: number, suffix = "%"): string {
  const sign = pct >= 0 ? "+" : "";
  return `${sign}${pct.toFixed(1)}${suffix}`;
}

function fmtInt(n: number): string {
  return Math.round(n).toLocaleString("en-US");
}

function KpiCard({
  label,
  value,
  delta,
  hint,
  icon,
  positiveIsGood = true,
}: {
  label: string;
  value: string;
  delta: number;
  hint: string;
  icon: React.ReactNode;
  positiveIsGood?: boolean;
}) {
  const isPositive = delta >= 0;
  const isGood = positiveIsGood ? isPositive : !isPositive;
  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardDescription>{label}</CardDescription>
        <span className="text-muted-foreground">{icon}</span>
      </CardHeader>
      <CardContent>
        <div className="text-2xl font-semibold tracking-tight">{value}</div>
        <p className="mt-1 flex items-center gap-1 text-xs text-muted-foreground">
          {isPositive ? (
            <ArrowUpRightIcon className={`size-3 ${isGood ? "text-emerald-500" : "text-rose-500"}`} />
          ) : (
            <ArrowDownRightIcon className={`size-3 ${isGood ? "text-emerald-500" : "text-rose-500"}`} />
          )}
          <span className={isGood ? "text-emerald-500" : "text-rose-500"}>{formatDelta(delta)}</span>
          <span>{hint}</span>
        </p>
      </CardContent>
    </Card>
  );
}

function KpiSkeleton() {
  return (
    <Card>
      <CardHeader className="pb-2">
        <div className="h-3 w-20 animate-pulse rounded bg-muted" />
      </CardHeader>
      <CardContent>
        <div className="h-7 w-24 animate-pulse rounded bg-muted" />
        <div className="mt-2 h-3 w-32 animate-pulse rounded bg-muted" />
      </CardContent>
    </Card>
  );
}

function EmptyChart({ message, height = "h-[280px]" }: { message: string; height?: string }) {
  return (
    <div
      className={`flex w-full items-center justify-center rounded-md border border-dashed text-center text-sm text-muted-foreground ${height}`}
    >
      {message}
    </div>
  );
}

function AnalyticsPage() {
  // Range selector is kept for visual parity with the future API.
  // Today the backend overview is fixed-window (24h / 7d / 14d / 30d
  // depending on the metric); the selector is a no-op until §4.8 is
  // extended with a range parameter.
  const [range, setRange] = useState("30d");

  const { data, isLoading, isError, error } = useAnalyticsOverview();

  if (isError) {
    return (
      <div className="flex min-w-0 flex-col gap-6">
        <PageHeader description="Product analytics across tenants, applications, and authentication methods." />
        <Card>
          <CardContent className="py-12 text-center text-sm text-muted-foreground">
            Couldn&apos;t load analytics{error instanceof Error ? `: ${error.message}` : ""}.
          </CardContent>
        </Card>
      </div>
    );
  }

  // Coalesce every KPI individually so an older backend (one that
  // hasn't been redeployed with the §4.8 extra fields) renders zeros
  // and skeleton-deltas instead of crashing the whole page.
  const ZERO = { value: 0, delta_pct: 0 };
  const k = data?.kpis;
  const kpis = data
    ? {
        mau: k?.mau ?? ZERO,
        logins_today: k?.logins_today ?? ZERO,
        mfa_adoption_pct: k?.mfa_adoption_pct ?? ZERO,
        failed_logins_24h: k?.failed_logins_24h ?? ZERO,
        dau: k?.dau ?? ZERO,
        total_users: k?.total_users ?? ZERO,
        avg_sessions_per_user: k?.avg_sessions_per_user ?? ZERO,
        stickiness_pct: k?.stickiness_pct ?? ZERO,
      }
    : null;
  const weekly = data?.weekly_activity_8w ?? [];

  return (
    <div className="flex min-w-0 flex-col gap-6">
      <PageHeader
        description="Product analytics across tenants, applications, and authentication methods."
        actions={
          <Select value={range} onValueChange={(v) => v && setRange(v)}>
            <SelectTrigger className="w-[180px]">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="24h">Last 24 hours</SelectItem>
              <SelectItem value="7d">Last 7 days</SelectItem>
              <SelectItem value="30d">Last 30 days</SelectItem>
              <SelectItem value="90d">Last 90 days</SelectItem>
            </SelectContent>
          </Select>
        }
      />

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {isLoading || !kpis ? (
          <>
            <KpiSkeleton />
            <KpiSkeleton />
            <KpiSkeleton />
            <KpiSkeleton />
          </>
        ) : (
          <>
            <KpiCard
              label="MAU"
              value={fmtInt(kpis.mau.value)}
              delta={kpis.mau.delta_pct}
              hint="vs last 30 days"
              icon={<UsersIcon className="size-4" />}
            />
            <KpiCard
              label="DAU / MAU"
              value={`${kpis.stickiness_pct.value.toFixed(1)}%`}
              delta={kpis.stickiness_pct.delta_pct}
              hint="stickiness"
              icon={<ZapIcon className="size-4" />}
            />
            <KpiCard
              label="Avg sessions / user"
              value={kpis.avg_sessions_per_user.value.toFixed(1)}
              delta={kpis.avg_sessions_per_user.delta_pct}
              hint="last 30 days"
              icon={<TrendingUpIcon className="size-4" />}
            />
            <KpiCard
              label="Total users"
              value={fmtInt(kpis.total_users.value)}
              delta={kpis.total_users.delta_pct}
              hint="vs 30 days ago"
              icon={<GlobeIcon className="size-4" />}
            />
          </>
        )}
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Active users</CardTitle>
            <CardDescription>Weekly WAU and average DAU · last 8 weeks</CardDescription>
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <div className="h-[280px] w-full animate-pulse rounded bg-muted/40" />
            ) : weekly.length === 0 || weekly.every((w) => w.wau === 0 && w.dau === 0) ? (
              <EmptyChart message="No session activity recorded in the last 8 weeks." />
            ) : (
              <ChartContainer config={mauConfig} className="h-[280px] w-full">
                <AreaChart data={weekly}>
                  <CartesianGrid vertical={false} />
                  <XAxis dataKey="week" tickLine={false} axisLine={false} />
                  <YAxis tickLine={false} axisLine={false} />
                  <ChartTooltip content={<ChartTooltipContent indicator="dot" />} />
                  <ChartLegend content={<ChartLegendContent />} />
                  <Area
                    type="monotone"
                    dataKey="wau"
                    stroke="var(--color-wau)"
                    fill="var(--color-wau)"
                    fillOpacity={0.2}
                  />
                  <Area
                    type="monotone"
                    dataKey="dau"
                    stroke="var(--color-dau)"
                    fill="var(--color-dau)"
                    fillOpacity={0.2}
                  />
                </AreaChart>
              </ChartContainer>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Geography</CardTitle>
            <CardDescription>Users by region</CardDescription>
          </CardHeader>
          <CardContent>
            <EmptyChart message="Requires GeoIP enrichment (roadmap §4.6)." />
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-1">
          <CardHeader>
            <CardTitle>API volume</CardTitle>
            <CardDescription>Requests per day</CardDescription>
          </CardHeader>
          <CardContent>
            <EmptyChart message="Requires request-volume instrumentation." height="h-[220px]" />
          </CardContent>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Top applications</CardTitle>
            <CardDescription>Ranked by logins in the selected period</CardDescription>
          </CardHeader>
          <CardContent>
            <EmptyChart
              message="Requires per-application login tagging on auth events."
              height="h-[220px]"
            />
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
