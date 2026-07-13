import { Card, CardDescription, CardHeader, CardTitle } from "@qeetrix/ui";
import { createFileRoute, Link } from "@tanstack/react-router";
import {
  ChevronRightIcon,
  GaugeIcon,
  LockKeyholeIcon,
  type LucideIcon,
  MonitorSmartphoneIcon,
  ScrollTextIcon,
  ShieldAlertIcon,
  ShieldIcon,
} from "lucide-react";
import { useTranslation } from "react-i18next";

import { PageHeader } from "@/components/page-header";

export const Route = createFileRoute("/_app/security/")({
  component: SecurityOverviewPage,
});

// Each card deep-links into a real sub-page (the bare parent paths like
// /security/threats are themselves placeholders, so we jump to a built child).
const SECTIONS: { key: string; to: string; icon: LucideIcon }[] = [
  {
    key: "threatProtection",
    to: "/security/threats/bots",
    icon: ShieldAlertIcon,
  },
  { key: "sessions", to: "/security/sessions", icon: ShieldIcon },
  {
    key: "deviceAuthorizations",
    to: "/security/device-authorizations",
    icon: MonitorSmartphoneIcon,
  },
  { key: "rateLimits", to: "/security/rate-limits", icon: GaugeIcon },
  { key: "auditLogs", to: "/security/audit-logs", icon: ScrollTextIcon },
  { key: "compliance", to: "/security/compliance/soc2", icon: LockKeyholeIcon },
];

function SecurityOverviewPage() {
  const { t } = useTranslation("security");

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <PageHeader description={t("overview.description")} />

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
                  <CardTitle className="mt-2 text-base">
                    {t(`overview.sections.${s.key}.title`)}
                  </CardTitle>
                  <CardDescription>{t(`overview.sections.${s.key}.description`)}</CardDescription>
                </CardHeader>
              </Card>
            </Link>
          );
        })}
      </div>
    </div>
  );
}
