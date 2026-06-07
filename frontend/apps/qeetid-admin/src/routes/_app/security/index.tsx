import {
  Card,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@qeetrix/ui";
import { Link, createFileRoute } from "@tanstack/react-router";
import {
  ChevronRightIcon,
  GaugeIcon,
  LockKeyholeIcon,
  MonitorSmartphoneIcon,
  ScrollTextIcon,
  ShieldAlertIcon,
  ShieldIcon,
  type LucideIcon,
} from "lucide-react";

import { PageHeader } from "@/components/page-header";

export const Route = createFileRoute("/_app/security/")({ component: SecurityOverviewPage });

// Each card deep-links into a real sub-page (the bare parent paths like
// /security/threats are themselves placeholders, so we jump to a built child).
const SECTIONS: { title: string; description: string; to: string; icon: LucideIcon }[] = [
  {
    title: "Threat Protection",
    description: "Bot detection, anomalies, rate limits and IP allowlists.",
    to: "/security/threats/bots",
    icon: ShieldAlertIcon,
  },
  {
    title: "Sessions",
    description: "Active sessions across the workspace — revoke any you don't recognise.",
    to: "/security/sessions",
    icon: ShieldIcon,
  },
  {
    title: "Device Authorizations",
    description: "Devices that completed the device-authorization flow.",
    to: "/security/device-authorizations",
    icon: MonitorSmartphoneIcon,
  },
  {
    title: "Rate Limits",
    description: "Per-endpoint gateway limits and tenant network policy.",
    to: "/security/rate-limits",
    icon: GaugeIcon,
  },
  {
    title: "Audit Logs",
    description: "Hash-chained, append-only record of every security event.",
    to: "/security/audit-logs",
    icon: ScrollTextIcon,
  },
  {
    title: "Compliance",
    description: "SOC 2, GDPR, ISO 27001 and data-retention controls.",
    to: "/security/compliance/soc2",
    icon: LockKeyholeIcon,
  },
];

function SecurityOverviewPage() {
  return (
    <div className="flex min-w-0 flex-col gap-4">
      <PageHeader description="Your workspace's security posture at a glance. Jump into any area below." />

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {SECTIONS.map((s) => {
          const Icon = s.icon;
          return (
            <Link key={s.to} to={s.to} className="group rounded-xl focus:outline-none">
              <Card className="h-full transition-colors hover:border-primary/50 hover:bg-muted/40 group-focus-visible:ring-2 group-focus-visible:ring-ring">
                <CardHeader>
                  <div className="flex items-center justify-between gap-2">
                    <span className="flex size-9 items-center justify-center rounded-lg border bg-background text-muted-foreground transition-colors group-hover:text-foreground">
                      <Icon className="size-4" />
                    </span>
                    <ChevronRightIcon className="size-4 text-muted-foreground transition-transform group-hover:translate-x-0.5" />
                  </div>
                  <CardTitle className="mt-2 text-base">{s.title}</CardTitle>
                  <CardDescription>{s.description}</CardDescription>
                </CardHeader>
              </Card>
            </Link>
          );
        })}
      </div>
    </div>
  );
}
