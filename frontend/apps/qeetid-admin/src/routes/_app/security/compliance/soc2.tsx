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
import {
  CheckCircle2Icon,
  CircleAlertIcon,
  CircleDashedIcon,
  DownloadIcon,
  FileTextIcon,
} from "lucide-react";

import { PageHeader } from "@/components/page-header";

export const Route = createFileRoute("/_app/security/compliance/soc2")({ component: Soc2Page });

const tsc = [
  { code: "CC1", name: "Control Environment", status: "passing", controls: 12, evidence: 41 },
  { code: "CC2", name: "Communication & Information", status: "passing", controls: 9, evidence: 28 },
  { code: "CC3", name: "Risk Assessment", status: "in-progress", controls: 8, evidence: 22 },
  { code: "CC4", name: "Monitoring", status: "passing", controls: 7, evidence: 31 },
  { code: "CC5", name: "Control Activities", status: "passing", controls: 11, evidence: 36 },
  { code: "CC6", name: "Logical & Physical Access", status: "passing", controls: 18, evidence: 64 },
  { code: "CC7", name: "System Operations", status: "passing", controls: 14, evidence: 47 },
  { code: "CC8", name: "Change Management", status: "passing", controls: 6, evidence: 19 },
  { code: "CC9", name: "Risk Mitigation", status: "in-progress", controls: 5, evidence: 11 },
  { code: "A1",  name: "Availability", status: "passing", controls: 4, evidence: 18 },
  { code: "C1",  name: "Confidentiality", status: "passing", controls: 6, evidence: 22 },
  { code: "P1",  name: "Privacy", status: "outstanding", controls: 9, evidence: 4 },
];

const docs = [
  { name: "SOC 2 Type I report (2026)", kind: "PDF", size: "1.2 MB", updated: "12 Mar 2026" },
  { name: "Information security policy", kind: "PDF", size: "412 KB", updated: "3 Feb 2026" },
  { name: "Incident response runbook", kind: "PDF", size: "287 KB", updated: "18 Jan 2026" },
  { name: "Vendor management policy", kind: "PDF", size: "198 KB", updated: "5 Nov 2025" },
  { name: "Sub-processor list", kind: "PDF", size: "84 KB", updated: "1 Apr 2026" },
];

function statusBadge(s: string) {
  if (s === "passing") return <Badge className="gap-1"><CheckCircle2Icon className="size-3" />passing</Badge>;
  if (s === "in-progress") return <Badge variant="secondary" className="gap-1"><CircleDashedIcon className="size-3" />in-progress</Badge>;
  return <Badge variant="destructive" className="gap-1"><CircleAlertIcon className="size-3" />outstanding</Badge>;
}

function Soc2Page() {
  const passing = tsc.filter((t) => t.status === "passing").length;
  const total = tsc.length;
  const evidence = tsc.reduce((s, t) => s + t.evidence, 0);
  return (
    <div className="flex min-w-0 flex-col gap-6">
      <PageHeader
        description="SOC 2 readiness for AICPA Trust Service Criteria. Type I report attests this control set at a point in time."
        actions={
          <>
            <Button variant="outline">Open evidence vault</Button>
            <Button>
              <DownloadIcon className="mr-2 size-4" />
              Download report
            </Button>
          </>
        }
      />

      <div className="grid grid-cols-1 gap-4 md:grid-cols-4">
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Audit firm</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="text-base font-medium">Prescient CPAs</div>
            <p className="text-xs text-muted-foreground">Type I issued 12 Mar 2026</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Categories passing</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold tracking-tight">{passing}/{total}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Evidence artifacts</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold tracking-tight">{evidence}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Type II window</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="text-base font-medium">12 Mar – 12 Sep 2026</div>
            <p className="text-xs text-muted-foreground">6 months of operational effectiveness</p>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Trust Service Criteria</CardTitle>
          <CardDescription>Common Criteria + Availability, Confidentiality, Privacy.</CardDescription>
        </CardHeader>
        <CardContent className="overflow-x-auto p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Code</TableHead>
                <TableHead>Category</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Controls</TableHead>
                <TableHead>Evidence</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {tsc.map((t) => (
                <TableRow key={t.code}>
                  <TableCell className="font-mono text-xs">{t.code}</TableCell>
                  <TableCell>{t.name}</TableCell>
                  <TableCell>{statusBadge(t.status)}</TableCell>
                  <TableCell className="text-sm">{t.controls}</TableCell>
                  <TableCell className="text-sm">{t.evidence}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Reports &amp; policies</CardTitle>
          <CardDescription>Shared under NDA — request access for the unredacted versions.</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-2">
          {docs.map((d) => (
            <div key={d.name} className="flex items-center justify-between rounded-md border px-3 py-2">
              <div className="flex items-center gap-3">
                <FileTextIcon className="size-4 text-muted-foreground" />
                <div>
                  <div className="text-sm font-medium">{d.name}</div>
                  <div className="text-xs text-muted-foreground">
                    {d.kind} · {d.size} · updated {d.updated}
                  </div>
                </div>
              </div>
              <Button size="sm" variant="ghost">
                Download
              </Button>
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  );
}
