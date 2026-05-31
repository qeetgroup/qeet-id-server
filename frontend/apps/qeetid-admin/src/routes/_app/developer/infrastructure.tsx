import {
  Badge,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  type ChartConfig,
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@qeetrix/ui";
import { createFileRoute } from "@tanstack/react-router";
import {
  ActivityIcon,
  CheckCircle2Icon,
  CloudIcon,
  CpuIcon,
  DatabaseIcon,
  RadioIcon,
} from "lucide-react";
import { CartesianGrid, Line, LineChart, XAxis, YAxis } from "recharts";

import { PageHeader } from "@/components/page-header";

export const Route = createFileRoute("/_app/developer/infrastructure")({ component: InfrastructurePage });

const latency = [
  { t: "00:00", p50: 18, p95: 84, p99: 142 },
  { t: "02:00", p50: 17, p95: 78, p99: 138 },
  { t: "04:00", p50: 19, p95: 91, p99: 152 },
  { t: "06:00", p50: 23, p95: 108, p99: 170 },
  { t: "08:00", p50: 32, p95: 142, p99: 220 },
  { t: "10:00", p50: 38, p95: 168, p99: 246 },
  { t: "12:00", p50: 41, p95: 182, p99: 260 },
  { t: "14:00", p50: 45, p95: 205, p99: 284 },
  { t: "16:00", p50: 39, p95: 170, p99: 248 },
  { t: "18:00", p50: 30, p95: 124, p99: 198 },
  { t: "20:00", p50: 26, p95: 102, p99: 170 },
  { t: "22:00", p50: 22, p95: 92, p99: 158 },
];

const services = [
  { name: "API gateway",  status: "healthy", region: "us-east-1", pods: 24, cpu: "38%", mem: "61%" },
  { name: "Auth service", status: "healthy", region: "us-east-1", pods: 12, cpu: "42%", mem: "57%" },
  { name: "Token signer", status: "healthy", region: "us-east-1", pods: 6,  cpu: "21%", mem: "44%" },
  { name: "Webhook dispatcher", status: "degraded", region: "us-east-1", pods: 4, cpu: "78%", mem: "82%" },
  { name: "SCIM endpoint", status: "healthy", region: "us-east-1", pods: 4, cpu: "12%", mem: "38%" },
  { name: "Audit ingest", status: "healthy", region: "us-east-1", pods: 6, cpu: "35%", mem: "51%" },
];

const datastores = [
  { name: "PostgreSQL (Aurora)", role: "primary",  replicas: 2, lagMs: 12,  conns: 142 },
  { name: "Redis Cluster",       role: "primary",  replicas: 3, lagMs: 1,   conns: 480 },
  { name: "Kafka (MSK)",         role: "—",        replicas: 6, lagMs: 24,  conns: 38 },
  { name: "S3 (audit cold)",     role: "—",        replicas: 0, lagMs: 0,   conns: 0 },
];

function statusBadge(s: string) {
  if (s === "healthy") return <Badge className="gap-1"><CheckCircle2Icon className="size-3" />healthy</Badge>;
  if (s === "degraded") return <Badge variant="secondary">degraded</Badge>;
  return <Badge variant="destructive">down</Badge>;
}

const latencyConfig: ChartConfig = {
  p50: { label: "p50", color: "var(--chart-1)" },
  p95: { label: "p95", color: "var(--chart-2)" },
  p99: { label: "p99", color: "var(--chart-3)" },
};

function InfrastructurePage() {
  return (
    <div className="flex min-w-0 flex-col gap-6">
      <PageHeader description="Real-time platform health across services, regions, and datastores." />

      <div className="grid grid-cols-1 gap-4 md:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardDescription>Region</CardDescription>
            <CloudIcon className="size-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-base font-medium">us-east-1</div>
            <p className="text-xs text-muted-foreground">Multi-AZ · 3 zones</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardDescription>Active pods</CardDescription>
            <CpuIcon className="size-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold tracking-tight">
              {services.reduce((s, x) => s + x.pods, 0)}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardDescription>Requests / sec</CardDescription>
            <ActivityIcon className="size-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold tracking-tight">4,180</div>
            <p className="text-xs text-muted-foreground">5-min avg</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardDescription>SLO compliance</CardDescription>
            <RadioIcon className="size-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold tracking-tight">99.97%</div>
            <p className="text-xs text-muted-foreground">30-day rolling</p>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Request latency</CardTitle>
          <CardDescription>p50 / p95 / p99 in milliseconds, last 24 hours</CardDescription>
        </CardHeader>
        <CardContent>
          <ChartContainer config={latencyConfig} className="h-[280px] w-full">
            <LineChart data={latency}>
              <CartesianGrid vertical={false} />
              <XAxis dataKey="t" tickLine={false} axisLine={false} />
              <YAxis tickLine={false} axisLine={false} />
              <ChartTooltip content={<ChartTooltipContent />} />
              <Line type="monotone" dataKey="p50" stroke="var(--color-p50)" dot={false} strokeWidth={2} />
              <Line type="monotone" dataKey="p95" stroke="var(--color-p95)" dot={false} strokeWidth={2} />
              <Line type="monotone" dataKey="p99" stroke="var(--color-p99)" dot={false} strokeWidth={2} />
            </LineChart>
          </ChartContainer>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Services</CardTitle>
          <CardDescription>Per-deployment health and resource utilisation.</CardDescription>
        </CardHeader>
        <CardContent className="overflow-x-auto p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Service</TableHead>
                <TableHead>Region</TableHead>
                <TableHead>Pods</TableHead>
                <TableHead>CPU</TableHead>
                <TableHead>Memory</TableHead>
                <TableHead>Status</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {services.map((s) => (
                <TableRow key={s.name}>
                  <TableCell className="font-medium">{s.name}</TableCell>
                  <TableCell className="text-sm">{s.region}</TableCell>
                  <TableCell className="text-sm">{s.pods}</TableCell>
                  <TableCell className="text-sm">{s.cpu}</TableCell>
                  <TableCell className="text-sm">{s.mem}</TableCell>
                  <TableCell>{statusBadge(s.status)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Datastores</CardTitle>
          <CardDescription>Persistence tier — replication lag and connection counts.</CardDescription>
        </CardHeader>
        <CardContent className="overflow-x-auto p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Store</TableHead>
                <TableHead>Role</TableHead>
                <TableHead>Replicas</TableHead>
                <TableHead>Lag (ms)</TableHead>
                <TableHead>Connections</TableHead>
                <TableHead className="w-[1%]" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {datastores.map((d) => (
                <TableRow key={d.name}>
                  <TableCell className="flex items-center gap-2 font-medium">
                    <DatabaseIcon className="size-4 text-muted-foreground" />
                    {d.name}
                  </TableCell>
                  <TableCell className="text-sm">{d.role}</TableCell>
                  <TableCell className="text-sm">{d.replicas}</TableCell>
                  <TableCell className="text-sm">{d.lagMs}</TableCell>
                  <TableCell className="text-sm">{d.conns}</TableCell>
                  <TableCell />
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
