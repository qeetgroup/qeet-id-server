import { Badge, buttonVariants, cn, Skeleton, TimeSince } from "@qeetrix/ui";
import { Link } from "@tanstack/react-router";
import {
  ActivityIcon,
  ArrowUpRightIcon,
  FileTextIcon,
  FlaskConicalIcon,
  KeyRoundIcon,
  LogInIcon,
  ShieldAlertIcon,
  UserIcon,
  UserPlusIcon,
} from "lucide-react";
import type * as React from "react";
import { useTranslation } from "react-i18next";

import type { Capability } from "@/features/access-control/capability-model";
import { useCapabilities } from "@/features/access-control/capability-provider";
import { formatAuditAction } from "../dashboard-model";
import type { DashboardAuditEvent } from "../use-dashboard-activity";
import { DashboardPanel } from "./dashboard-panel";

const ACTIVITY_SKELETON_IDS = ["one", "two", "three", "four", "five"] as const;

function getOperatorActions(t: (key: string) => string) {
  return [
    {
      icon: UserPlusIcon,
      label: t("quickActions.inviteLabel"),
      description: t("quickActions.inviteDesc"),
      href: "/invitations",
      tone: "brand" as const,
      requiredPermissions: ["user.read", "user.write", "role.read"] satisfies Capability[],
    },
    {
      icon: KeyRoundIcon,
      label: t("quickActions.apiKeyLabel"),
      description: t("quickActions.apiKeyDesc"),
      href: "/auth/api/keys",
      tone: "info" as const,
      requiredPermissions: ["apikey.read", "apikey.write"] satisfies Capability[],
    },
    {
      icon: ShieldAlertIcon,
      label: t("quickActions.threatsLabel"),
      description: t("quickActions.threatsDesc"),
      href: "/security/threats/anomalies",
      tone: "danger" as const,
      requiredPermissions: ["audit.read"] satisfies Capability[],
    },
    {
      icon: FlaskConicalIcon,
      label: "Test an access decision",
      description: "Evaluate a policy before it reaches production",
      href: "/authorization/simulator",
      tone: "warning" as const,
      requiredPermissions: ["role.read"] satisfies Capability[],
    },
    {
      icon: FileTextIcon,
      label: t("quickActions.auditLabel"),
      description: t("quickActions.auditDesc"),
      href: "/security/audit-logs",
      tone: "success" as const,
      requiredPermissions: ["audit.read"] satisfies Capability[],
    },
  ];
}

function eventIcon(action: string): React.ReactNode {
  if (action.startsWith("user.login") || action.startsWith("session.")) return <LogInIcon />;
  if (action.startsWith("user.")) return <UserIcon />;
  if (action.startsWith("mfa.") || action.startsWith("api_key.")) return <KeyRoundIcon />;
  return <ActivityIcon />;
}

export function RecentActivityPanel({
  events,
  loading,
  className,
}: {
  events: DashboardAuditEvent[];
  loading: boolean;
  className?: string;
}) {
  const { t } = useTranslation("dashboard");

  return (
    <DashboardPanel
      className={className}
      title={t("activity.title")}
      description={t("activity.description")}
      contentClassName="p-0 sm:p-0"
      action={
        <Link
          to="/security/audit-logs"
          className={buttonVariants({ variant: "ghost", size: "sm" })}
        >
          {t("activity.viewAll")}
        </Link>
      }
    >
      {loading ? (
        <ul className="divide-y divide-border/60" aria-label="Loading recent activity">
          {ACTIVITY_SKELETON_IDS.map((id) => (
            <li key={id} className="flex items-center gap-3 px-4 py-3.5 sm:px-4.5">
              <Skeleton className="size-9 shrink-0 rounded-lg" />
              <div className="min-w-0 flex-1 space-y-2">
                <Skeleton className="h-3 w-44 max-w-full" />
                <Skeleton className="h-2.5 w-28 max-w-full" />
              </div>
              <Skeleton className="h-3 w-14" />
            </li>
          ))}
        </ul>
      ) : events.length === 0 ? (
        <div className="flex min-h-64 flex-col items-center justify-center px-6 py-10 text-center">
          <span className="grid size-11 place-items-center rounded-xl bg-muted text-muted-foreground">
            <ActivityIcon className="size-5" />
          </span>
          <p className="mt-3 text-sm font-semibold">{t("activity.emptyTitle")}</p>
          <p className="mt-1 max-w-sm text-xs leading-5 text-muted-foreground">
            {t("activity.emptyDescription")}
          </p>
        </div>
      ) : (
        <ol className="divide-y divide-border/60">
          {events.map((event) => (
            <li
              key={event.id}
              className="group flex min-w-0 items-center gap-3 px-4 py-3 transition-colors duration-150 hover:bg-muted/35 sm:px-4.5"
            >
              <span className="grid size-9 shrink-0 place-items-center rounded-lg bg-muted text-muted-foreground ring-1 ring-foreground/6 [&_svg]:size-3.5">
                {eventIcon(event.action)}
              </span>
              <div className="min-w-0 flex-1">
                <p className="truncate text-sm font-medium">{formatAuditAction(event.action)}</p>
                <div className="mt-1 flex min-w-0 items-center gap-2">
                  <Badge variant="muted" className="max-w-32 truncate text-[10px]">
                    {event.actor_type}
                  </Badge>
                  <span className="truncate text-[11px] text-muted-foreground">
                    {event.resource_type}
                  </span>
                </div>
              </div>
              <TimeSince
                value={event.created_at}
                className="shrink-0 text-[11px] text-muted-foreground tabular-nums"
              />
            </li>
          ))}
        </ol>
      )}
    </DashboardPanel>
  );
}

const actionTone = {
  brand: "bg-primary/10 text-primary",
  info: "bg-info/10 text-info",
  danger: "bg-destructive/10 text-destructive",
  warning: "bg-warning/10 text-warning",
  success: "bg-success/10 text-success",
} as const;

export function OperatorActionsPanel({ className }: { className?: string }) {
  const { t } = useTranslation("dashboard");
  const access = useCapabilities();
  const actions = getOperatorActions(t).filter((action) =>
    access.canAll(action.requiredPermissions),
  );

  if (actions.length === 0) return null;

  return (
    <DashboardPanel
      className={className}
      title={t("quickActions.heading")}
      description="Frequent operator workflows"
      contentClassName="p-2 sm:p-2"
    >
      <nav aria-label={t("quickActions.heading")} className="space-y-1">
        {actions.map(({ icon: Icon, label, description, href, tone }) => (
          <Link
            key={href}
            to={href as never}
            className="group flex min-h-14 items-center gap-3 rounded-lg px-2.5 py-2 outline-none transition-colors duration-150 hover:bg-muted/55 focus-visible:ring-2 focus-visible:ring-ring"
          >
            <span
              className={cn(
                "grid size-9 shrink-0 place-items-center rounded-lg ring-1 ring-current/10",
                actionTone[tone],
              )}
            >
              <Icon className="size-4" aria-hidden="true" />
            </span>
            <span className="min-w-0 flex-1">
              <span className="block truncate text-xs font-semibold">{label}</span>
              <span className="mt-0.5 block truncate text-[11px] text-muted-foreground">
                {description}
              </span>
            </span>
            <ArrowUpRightIcon className="size-3.5 shrink-0 text-muted-foreground transition-transform duration-150 group-hover:-translate-y-0.5 group-hover:translate-x-0.5" />
          </Link>
        ))}
      </nav>
    </DashboardPanel>
  );
}
