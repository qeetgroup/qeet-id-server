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
} from "@qeetid/ui";
import { createFileRoute } from "@tanstack/react-router";
import { ActivityIcon, KeyRoundIcon, ShieldAlertIcon, UsersIcon } from "lucide-react";

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

// ---- Mock data ----

const loginActivity = [
  { day: "May 1", password: 4200, passkey: 980, social: 1450, saml: 620, oidc: 310 },
  { day: "May 2", password: 4100, passkey: 1040, social: 1380, saml: 680, oidc: 290 },
  { day: "May 3", password: 3900, passkey: 1180, social: 1520, saml: 710, oidc: 320 },
  { day: "May 4", password: 3700, passkey: 1320, social: 1610, saml: 750, oidc: 340 },
  { day: "May 5", password: 3550, passkey: 1480, social: 1680, saml: 790, oidc: 360 },
  { day: "May 6", password: 3300, passkey: 1650, social: 1740, saml: 820, oidc: 380 },
  { day: "May 7", password: 3150, passkey: 1820, social: 1810, saml: 850, oidc: 410 },
  { day: "May 8", password: 3050, passkey: 2010, social: 1880, saml: 880, oidc: 430 },
  { day: "May 9", password: 2950, passkey: 2210, social: 1940, saml: 910, oidc: 450 },
  { day: "May 10", password: 2860, passkey: 2380, social: 2010, saml: 940, oidc: 470 },
  { day: "May 11", password: 2780, passkey: 2540, social: 2080, saml: 970, oidc: 490 },
  { day: "May 12", password: 2700, passkey: 2690, social: 2150, saml: 1000, oidc: 510 },
  { day: "May 13", password: 2620, passkey: 2840, social: 2210, saml: 1030, oidc: 530 },
  { day: "May 14", password: 2540, passkey: 2980, social: 2280, saml: 1060, oidc: 550 },
];

const loginMethodsMix = [
  { method: "password", value: 38, fill: "var(--color-password)" },
  { method: "passkey", value: 27, fill: "var(--color-passkey)" },
  { method: "social", value: 21, fill: "var(--color-social)" },
  { method: "saml", value: 9, fill: "var(--color-saml)" },
  { method: "oidc", value: 5, fill: "var(--color-oidc)" },
];

const mfaAdoption = [
  { method: "TOTP", users: 14200, fill: "var(--color-totp)" },
  { method: "Passkey", users: 9800, fill: "var(--color-passkeyMfa)" },
  { method: "SMS", users: 6300, fill: "var(--color-sms)" },
  { method: "Email OTP", users: 4100, fill: "var(--color-email)" },
  { method: "Recovery Codes", users: 2700, fill: "var(--color-recovery)" },
];

const failedLogins = [
  { hour: "00:00", attempts: 42 },
  { hour: "02:00", attempts: 38 },
  { hour: "04:00", attempts: 51 },
  { hour: "06:00", attempts: 67 },
  { hour: "08:00", attempts: 124 },
  { hour: "10:00", attempts: 145 },
  { hour: "12:00", attempts: 168 },
  { hour: "14:00", attempts: 195 },
  { hour: "16:00", attempts: 247 },
  { hour: "18:00", attempts: 312 },
  { hour: "20:00", attempts: 188 },
  { hour: "22:00", attempts: 96 },
];

const userTrend = [
  { d: 1, v: 38400 },
  { d: 2, v: 38620 },
  { d: 3, v: 38900 },
  { d: 4, v: 39120 },
  { d: 5, v: 39350 },
  { d: 6, v: 39580 },
  { d: 7, v: 39820 },
  { d: 8, v: 40080 },
  { d: 9, v: 40340 },
  { d: 10, v: 40620 },
  { d: 11, v: 40890 },
  { d: 12, v: 41200 },
  { d: 13, v: 41530 },
  { d: 14, v: 41890 },
];

const loginTrend = userTrend.map((p) => ({ d: p.d, v: 8200 + p.d * 140 + (p.d % 3) * 80 }));
const mfaTrend = userTrend.map((p) => ({ d: p.d, v: 62 + p.d * 0.4 }));
const failedTrend = userTrend.map((p) => ({ d: p.d, v: 1100 + (p.d % 4) * 200 + p.d * 30 }));

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
  passkeyMfa: { label: "Passkey", color: "var(--chart-2)" },
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
    <Card className="overflow-hidden">
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

function DashboardPage() {
  return (
    <div className="flex min-w-0 flex-col gap-4">
      <OnboardingChecklist />
      <PasskeyPromptCard />
      {/* KPI cards */}
      <div className="grid auto-rows-min gap-4 md:grid-cols-2 lg:grid-cols-4">
        <StatCard
          icon={<UsersIcon />}
          title="Active Users (MAU)"
          value="41,892"
          delta="+3.4%"
          positive
          data={userTrend}
        />
        <StatCard
          icon={<ActivityIcon />}
          title="Logins Today"
          value="10,184"
          delta="+8.2%"
          positive
          data={loginTrend}
        />
        <StatCard
          icon={<KeyRoundIcon />}
          title="MFA Adoption"
          value="67.6%"
          delta="+2.1pp"
          positive
          data={mfaTrend}
          variant="line"
        />
        <StatCard
          icon={<ShieldAlertIcon />}
          title="Failed Logins (24h)"
          value="1,873"
          delta="+12.5%"
          positive={false}
          data={failedTrend}
          variant="line"
        />
      </div>

      {/* Authentication Activity + Login Methods Mix */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Authentication Activity</CardTitle>
            <CardDescription>Daily logins by method · last 14 days</CardDescription>
          </CardHeader>
          <CardContent>
            <ChartContainer config={activityConfig} className="aspect-auto h-72 w-full">
              <AreaChart data={loginActivity}>
                <defs>
                  {(["password", "passkey", "social", "saml", "oidc"] as const).map((k) => (
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
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Login Methods Mix</CardTitle>
            <CardDescription>Current distribution</CardDescription>
          </CardHeader>
          <CardContent className="flex justify-center">
            <ChartContainer config={mixConfig} className="aspect-square h-72">
              <PieChart>
                <ChartTooltip content={<ChartTooltipContent nameKey="method" hideLabel />} />
                <Pie
                  data={loginMethodsMix}
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
                            5 methods
                          </tspan>
                        </text>
                      );
                    }}
                  />
                </Pie>
                <ChartLegend content={<ChartLegendContent nameKey="method" />} />
              </PieChart>
            </ChartContainer>
          </CardContent>
        </Card>
      </div>

      {/* MFA Adoption + Failed Logins */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>MFA Methods Adoption</CardTitle>
            <CardDescription>Users by second factor</CardDescription>
          </CardHeader>
          <CardContent>
            <ChartContainer config={mfaConfig} className="aspect-auto h-64 w-full">
              <BarChart data={mfaAdoption} layout="vertical" margin={{ left: 12, right: 24 }}>
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
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Failed Login Attempts</CardTitle>
            <CardDescription>Hourly · last 24h (threshold 250)</CardDescription>
          </CardHeader>
          <CardContent>
            <ChartContainer config={failedConfig} className="aspect-auto h-64 w-full">
              <LineChart data={failedLogins} margin={{ left: 0, right: 16 }}>
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
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
