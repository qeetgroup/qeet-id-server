import { Badge, buttonVariants } from "@qeetrix/ui";
import { PageState } from "@qeetrix/ui/blocks";
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
import type { Capability } from "@/features/access-control/capability-model";
import { useCapabilities } from "@/features/access-control/capability-provider";

export const Route = createFileRoute("/_app/security/")({
  component: SecurityOverviewPage,
});

// Each card deep-links into a real sub-page (the bare parent paths like
// /security/threats are themselves placeholders, so we jump to a built child).
const SECTIONS: { key: string; to: string; icon: LucideIcon; requiredPermission: Capability }[] = [
  {
    key: "threatProtection",
    to: "/security/threats/bots",
    icon: ShieldAlertIcon,
    requiredPermission: "policy.read",
  },
  {
    key: "sessions",
    to: "/security/sessions",
    icon: ShieldIcon,
    requiredPermission: "user.read",
  },
  {
    key: "deviceAuthorizations",
    to: "/security/device-authorizations",
    icon: MonitorSmartphoneIcon,
    requiredPermission: "connection.read",
  },
  {
    key: "rateLimits",
    to: "/security/rate-limits",
    icon: GaugeIcon,
    requiredPermission: "policy.read",
  },
  {
    key: "auditLogs",
    to: "/security/audit-logs",
    icon: ScrollTextIcon,
    requiredPermission: "audit.read",
  },
  {
    key: "compliance",
    to: "/security/compliance/soc2",
    icon: LockKeyholeIcon,
    requiredPermission: "audit.read",
  },
];

function SecurityOverviewPage() {
  const { t } = useTranslation("security");
  const access = useCapabilities();
  const sections = SECTIONS.filter((section) => access.can(section.requiredPermission));

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <PageHeader description={t("overview.description")} />

      {sections.length === 0 ? (
        <section className="enterprise-panel">
          <PageState
            icon={ShieldIcon}
            title="No security areas are available"
            description="Your workspace role does not include security or audit visibility. Ask a workspace administrator if you need access."
            actions={
              <Link to="/" className={buttonVariants()}>
                Go to overview
              </Link>
            }
          />
        </section>
      ) : (
        <section className="enterprise-panel" aria-labelledby="security-sections-title">
          <header className="enterprise-panel-header items-center">
            <div>
              <h2 id="security-sections-title" className="font-heading text-base font-semibold">
                Security operations
              </h2>
              <p className="mt-1 text-sm text-muted-foreground">
                Investigate identity risk, enforce policy, and verify control evidence.
              </p>
            </div>
            <Badge variant="muted" className="shrink-0 tabular-nums">
              {sections.length} available
            </Badge>
          </header>
          <nav aria-label="Available security areas" className="grid md:grid-cols-2">
            {sections.map((section) => {
              const Icon = section.icon;
              return (
                <Link
                  key={section.to}
                  to={section.to}
                  className="group flex min-h-28 items-start gap-4 border-t border-border/70 p-5 outline-none transition-colors duration-150 hover:bg-muted/35 focus-visible:bg-muted/45 focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring md:odd:border-e"
                >
                  <span className="grid size-10 shrink-0 place-items-center rounded-lg bg-muted text-muted-foreground ring-1 ring-foreground/6 transition-colors group-hover:text-foreground">
                    <Icon className="size-4" aria-hidden="true" />
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className="block font-heading text-sm font-semibold">
                      {t(`overview.sections.${section.key}.title`)}
                    </span>
                    <span className="mt-1 block text-xs leading-5 text-muted-foreground">
                      {t(`overview.sections.${section.key}.description`)}
                    </span>
                  </span>
                  <ChevronRightIcon className="mt-1 size-4 shrink-0 text-muted-foreground transition-transform duration-150 group-hover:translate-x-0.5" />
                </Link>
              );
            })}
          </nav>
        </section>
      )}
    </div>
  );
}
