import {
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@qeetrix/ui";
import { createFileRoute } from "@tanstack/react-router";
import { CheckCircle2Icon, CircleDashedIcon, DownloadIcon, RocketIcon } from "lucide-react";

import { PageHeader } from "@/components/page-header";

export const Route = createFileRoute("/_app/security/compliance/iso27001")({ component: Iso27001Page });

const annexA = [
  { code: "A.5",  name: "Organizational controls", controls: 37, ready: 31 },
  { code: "A.6",  name: "People controls", controls: 8, ready: 6 },
  { code: "A.7",  name: "Physical controls", controls: 14, ready: 12 },
  { code: "A.8",  name: "Technological controls", controls: 34, ready: 26 },
];

const milestones = [
  { phase: "Gap analysis", state: "done", date: "Feb 2026" },
  { phase: "Statement of applicability (SoA)", state: "done", date: "Mar 2026" },
  { phase: "Risk assessment", state: "in-progress", date: "May 2026" },
  { phase: "Internal audit", state: "todo", date: "Jul 2026" },
  { phase: "Stage 1 audit", state: "todo", date: "Sep 2026" },
  { phase: "Stage 2 audit", state: "todo", date: "Nov 2026" },
];

function stateIcon(s: string) {
  if (s === "done") return <CheckCircle2Icon className="size-4 text-emerald-500" />;
  if (s === "in-progress") return <CircleDashedIcon className="size-4 text-amber-500" />;
  return <CircleDashedIcon className="size-4 text-muted-foreground" />;
}

function Iso27001Page() {
  const totalControls = annexA.reduce((s, c) => s + c.controls, 0);
  const totalReady = annexA.reduce((s, c) => s + c.ready, 0);
  return (
    <div className="flex min-w-0 flex-col gap-6">
      <PageHeader
        description="ISO/IEC 27001:2022 readiness. Annex A controls are evidenced in the management system."
        actions={
          <Button variant="outline">
            <DownloadIcon className="mr-2 size-4" />
            Statement of Applicability
          </Button>
        }
      />

      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Target certification</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="text-base font-medium">Nov 2026</div>
            <p className="text-xs text-muted-foreground">Stage 2 audit window</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Controls ready</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold tracking-tight">
              {totalReady}/{totalControls}
            </div>
            <p className="text-xs text-muted-foreground">{Math.round((totalReady / totalControls) * 100)}% coverage</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Assessor</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="text-base font-medium">Prescient CPAs</div>
            <p className="text-xs text-muted-foreground">Same as SOC 2 — joint engagement</p>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Roadmap</CardTitle>
          <CardDescription>Sequential phases — each gate signs off before the next begins.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {milestones.map((m) => (
            <div key={m.phase} className="flex items-center justify-between rounded-md border px-3 py-2">
              <div className="flex items-center gap-3">
                {stateIcon(m.state)}
                <span className="text-sm font-medium">{m.phase}</span>
              </div>
              <div className="flex items-center gap-3">
                <Badge variant={m.state === "done" ? "default" : m.state === "in-progress" ? "secondary" : "outline"}>
                  {m.state}
                </Badge>
                <span className="text-xs text-muted-foreground">{m.date}</span>
              </div>
            </div>
          ))}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Annex A coverage</CardTitle>
          <CardDescription>Counts reflect the 2022 revision of the standard.</CardDescription>
        </CardHeader>
        <CardContent className="overflow-x-auto p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Code</TableHead>
                <TableHead>Category</TableHead>
                <TableHead>Controls</TableHead>
                <TableHead>Ready</TableHead>
                <TableHead>Progress</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {annexA.map((c) => {
                const pct = Math.round((c.ready / c.controls) * 100);
                return (
                  <TableRow key={c.code}>
                    <TableCell className="font-mono text-xs">{c.code}</TableCell>
                    <TableCell>{c.name}</TableCell>
                    <TableCell className="text-sm">{c.controls}</TableCell>
                    <TableCell className="text-sm">{c.ready}</TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <div className="h-2 w-32 overflow-hidden rounded-full bg-muted">
                          <div className="h-full bg-primary" style={{ width: `${pct}%` }} />
                        </div>
                        <span className="text-xs text-muted-foreground">{pct}%</span>
                      </div>
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Card className="border-dashed">
        <CardContent className="flex flex-col items-center gap-3 py-6 text-center">
          <RocketIcon className="size-6 text-muted-foreground" />
          <div>
            <p className="text-sm font-medium">ISMS portal opens once Stage 1 is scheduled</p>
            <p className="text-xs text-muted-foreground">
              Risks, treatments, and SoA changes will live here.
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
