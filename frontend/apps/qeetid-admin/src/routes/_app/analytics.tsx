import {
  Badge,
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
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Line,
  LineChart,
  Pie,
  PieChart,
  XAxis,
  YAxis,
} from "recharts";

import { PageHeader } from "@/components/page-header";

export const Route = createFileRoute("/_app/analytics")({ component: AnalyticsPage });

// ── Mock data ──────────────────────────────────────────────────────────────
const mauTrend = [
  { week: "W18", mau: 18200, dau: 4100 },
  { week: "W19", mau: 19400, dau: 4380 },
  { week: "W20", mau: 21100, dau: 4720 },
  { week: "W21", mau: 22800, dau: 5050 },
  { week: "W22", mau: 24600, dau: 5410 },
  { week: "W23", mau: 26900, dau: 5870 },
  { week: "W24", mau: 29200, dau: 6310 },
  { week: "W25", mau: 31700, dau: 6720 },
];

const geo = [
  { region: "North America", users: 14820, fill: "var(--chart-1)" },
  { region: "Europe", users: 9430, fill: "var(--chart-2)" },
  { region: "Asia-Pacific", users: 5210, fill: "var(--chart-3)" },
  { region: "LATAM", users: 1640, fill: "var(--chart-4)" },
  { region: "MEA", users: 600, fill: "var(--chart-5)" },
];

const apiVolume = [
  { day: "Mon", reqs: 1.2 },
  { day: "Tue", reqs: 1.4 },
  { day: "Wed", reqs: 1.35 },
  { day: "Thu", reqs: 1.55 },
  { day: "Fri", reqs: 1.7 },
  { day: "Sat", reqs: 0.9 },
  { day: "Sun", reqs: 0.7 },
];

const topApps = [
  { name: "Acme Web", logins: 18420, dau: 4310, change: 12.4 },
  { name: "Acme iOS", logins: 9120, dau: 2480, change: 8.1 },
  { name: "Internal Admin", logins: 410, dau: 92, change: -3.2 },
  { name: "Acme Android", logins: 7820, dau: 2210, change: 5.6 },
  { name: "Partner API", logins: 2480, dau: 1140, change: 22.7 },
];

const kpis = [
  { label: "MAU", value: "31,720", delta: 8.2, hint: "vs last month", icon: <UsersIcon className="size-4" /> },
  { label: "DAU / MAU", value: "21.2%", delta: 1.4, hint: "stickiness", icon: <ZapIcon className="size-4" /> },
  { label: "Avg sessions / user", value: "4.7", delta: 0.3, hint: "per week", icon: <TrendingUpIcon className="size-4" /> },
  { label: "Tenants", value: "248", delta: 12, hint: "active orgs", icon: <GlobeIcon className="size-4" /> },
];

const mauConfig: ChartConfig = {
  mau: { label: "MAU", color: "var(--chart-1)" },
  dau: { label: "DAU", color: "var(--chart-2)" },
};
const apiConfig: ChartConfig = {
  reqs: { label: "Requests (M)", color: "var(--chart-3)" },
};
const geoConfig: ChartConfig = {
  users: { label: "Users" },
  "North America": { label: "North America", color: "var(--chart-1)" },
  Europe: { label: "Europe", color: "var(--chart-2)" },
  "Asia-Pacific": { label: "Asia-Pacific", color: "var(--chart-3)" },
  LATAM: { label: "LATAM", color: "var(--chart-4)" },
  MEA: { label: "MEA", color: "var(--chart-5)" },
};

function AnalyticsPage() {
  const [range, setRange] = useState("30d");

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
        {kpis.map((k) => (
          <Card key={k.label}>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardDescription>{k.label}</CardDescription>
              <span className="text-muted-foreground">{k.icon}</span>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-semibold tracking-tight">{k.value}</div>
              <p className="mt-1 flex items-center gap-1 text-xs text-muted-foreground">
                {k.delta >= 0 ? (
                  <ArrowUpRightIcon className="size-3 text-emerald-500" />
                ) : (
                  <ArrowDownRightIcon className="size-3 text-rose-500" />
                )}
                <span className={k.delta >= 0 ? "text-emerald-500" : "text-rose-500"}>
                  {k.delta >= 0 ? "+" : ""}
                  {k.delta}%
                </span>
                <span>{k.hint}</span>
              </p>
            </CardContent>
          </Card>
        ))}
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Active users</CardTitle>
            <CardDescription>Weekly MAU and DAU</CardDescription>
          </CardHeader>
          <CardContent>
            <ChartContainer config={mauConfig} className="h-[280px] w-full">
              <AreaChart data={mauTrend}>
                <CartesianGrid vertical={false} />
                <XAxis dataKey="week" tickLine={false} axisLine={false} />
                <YAxis tickLine={false} axisLine={false} />
                <ChartTooltip content={<ChartTooltipContent indicator="dot" />} />
                <ChartLegend content={<ChartLegendContent />} />
                <Area
                  type="monotone"
                  dataKey="mau"
                  stroke="var(--color-mau)"
                  fill="var(--color-mau)"
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
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Geography</CardTitle>
            <CardDescription>Users by region</CardDescription>
          </CardHeader>
          <CardContent>
            <ChartContainer config={geoConfig} className="mx-auto h-[280px] w-full">
              <PieChart>
                <ChartTooltip content={<ChartTooltipContent />} />
                <Pie data={geo} dataKey="users" nameKey="region" innerRadius={55} strokeWidth={2}>
                  {geo.map((d) => (
                    <Cell key={d.region} fill={d.fill} />
                  ))}
                </Pie>
                <ChartLegend content={<ChartLegendContent nameKey="region" />} />
              </PieChart>
            </ChartContainer>
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-1">
          <CardHeader>
            <CardTitle>API volume</CardTitle>
            <CardDescription>Requests per day (millions)</CardDescription>
          </CardHeader>
          <CardContent>
            <ChartContainer config={apiConfig} className="h-[220px] w-full">
              <LineChart data={apiVolume}>
                <CartesianGrid vertical={false} />
                <XAxis dataKey="day" tickLine={false} axisLine={false} />
                <YAxis tickLine={false} axisLine={false} />
                <ChartTooltip content={<ChartTooltipContent />} />
                <Line type="monotone" dataKey="reqs" stroke="var(--color-reqs)" strokeWidth={2} dot={false} />
              </LineChart>
            </ChartContainer>
          </CardContent>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Top applications</CardTitle>
            <CardDescription>Ranked by logins in the selected period</CardDescription>
          </CardHeader>
          <CardContent>
            <ChartContainer config={{ logins: { label: "Logins", color: "var(--chart-1)" } }} className="h-[220px] w-full">
              <BarChart data={topApps} layout="vertical">
                <CartesianGrid horizontal={false} />
                <XAxis type="number" tickLine={false} axisLine={false} />
                <YAxis dataKey="name" type="category" tickLine={false} axisLine={false} width={120} />
                <ChartTooltip content={<ChartTooltipContent />} />
                <Bar dataKey="logins" fill="var(--color-logins)" radius={4} />
              </BarChart>
            </ChartContainer>
            <div className="mt-3 grid grid-cols-1 gap-2 text-xs sm:grid-cols-2">
              {topApps.map((a) => (
                <div key={a.name} className="flex items-center justify-between rounded-md border px-3 py-2">
                  <span className="font-medium">{a.name}</span>
                  <Badge variant={a.change >= 0 ? "default" : "secondary"} className="gap-1">
                    {a.change >= 0 ? (
                      <ArrowUpRightIcon className="size-3" />
                    ) : (
                      <ArrowDownRightIcon className="size-3" />
                    )}
                    {a.change >= 0 ? "+" : ""}
                    {a.change}%
                  </Badge>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
