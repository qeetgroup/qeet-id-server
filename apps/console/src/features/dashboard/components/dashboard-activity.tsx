import { Badge, buttonVariants, cn, EmptyState, Skeleton, TimeSince } from "@qeetrix/ui";
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
import { LiveIndicator } from "@/features/activity/components/live-indicator";
import type { ActivityEvent } from "@/features/activity/types";
import { useDashboardActivity } from "../use-dashboard-activity";
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

function eventIcon(event: ActivityEvent): React.ReactNode {
  const cat = event.category.toLowerCase();
  if (cat === "authentication" || event.type.startsWith("session.")) return <LogInIcon />;
  if (cat === "user" || event.type.startsWith("user.")) return <UserIcon />;
  if (cat === "mfa" || cat === "apikey") return <KeyRoundIcon />;
  return <ActivityIcon />;
}

// ---------------------------------------------------------------------------
// RecentActivityPanel — now self-contained, reads from the shared activity store
// ---------------------------------------------------------------------------

/**
 * Dashboard widget showing the latest ~10 live activity events.
 * Acquires the shared SSE subscription so events arrive in real-time.
 * When the stream is connecting, shows loading skeletons.
 * Links to the full Live Activity Center at /activity.
 */
export function RecentActivityPanel({ className }: { className?: string }) {
  const { t } = useTranslation("dashboard");
  const { events, status, connecting } = useDashboardActivity(undefined, true);

  const hasCritical = events.some((e) => e.severity === "critical" || e.severity === "error");

  return (
    <DashboardPanel
      className={className}
      title={
        <span className="flex items-center gap-2">
          {t("activity.title")}
          <LiveIndicator status={status} />
        </span>
      }
      description={t("activity.description")}
      contentClassName="p-0 sm:p-0"
      action={
        <Link
          to="/activity"
          className={buttonVariants({ variant: "ghost", size: "sm" })}
          aria-label="Open full activity center"
        >
          {t("activity.viewAll")}
        </Link>
      }
    >
      {/* Disconnected / reconnecting with no events yet → show skeletons */}
      {connecting ? (
        <ul
          className="divide-y divide-border/60"
          aria-label="Loading recent activity"
          aria-busy="true"
        >
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
        <div className="flex min-h-64 items-center justify-center px-6 py-10">
          <EmptyState
            icon={ActivityIcon}
            title={t("activity.emptyTitle")}
            description={t("activity.emptyDescription")}
            action={<LiveIndicator status={status} />}
          />
        </div>
      ) : (
        <ol
          className="divide-y divide-border/60"
          aria-label="Recent activity events"
          aria-live="polite"
        >
          {events.map((event) => {
            const isCritical = event.severity === "critical" || event.severity === "error";
            return (
              <li
                key={event.id}
                className={cn(
                  "group flex min-w-0 items-center gap-3 px-4 py-3 transition-colors duration-150 hover:bg-muted/35 sm:px-4.5",
                  isCritical && "bg-destructive/5 hover:bg-destructive/10",
                )}
              >
                <span
                  className={cn(
                    "grid size-9 shrink-0 place-items-center rounded-lg bg-muted text-muted-foreground ring-1 ring-foreground/6 [&_svg]:size-3.5",
                    isCritical && "bg-destructive/10 text-destructive ring-destructive/15",
                  )}
                  aria-hidden="true"
                >
                  {eventIcon(event)}
                </span>
                <div className="min-w-0 flex-1">
                  <p className="truncate text-sm font-medium">{event.title}</p>
                  <div className="mt-1 flex min-w-0 items-center gap-2">
                    {event.actor?.type && (
                      <Badge variant="muted" className="max-w-32 truncate text-[10px]">
                        {event.actor.type}
                      </Badge>
                    )}
                    <span className="truncate text-[11px] text-muted-foreground">
                      {event.category}
                    </span>
                    {isCritical && (
                      <Badge variant="destructive" className="ml-auto text-[10px]">
                        {event.severity}
                      </Badge>
                    )}
                  </div>
                </div>
                <TimeSince
                  value={event.at}
                  className="shrink-0 text-[11px] text-muted-foreground tabular-nums"
                />
              </li>
            );
          })}
        </ol>
      )}

      {/* Unread / critical alert for screen readers */}
      {hasCritical && (
        <div role="alert" className="sr-only">
          Critical security events detected in the activity feed
        </div>
      )}
    </DashboardPanel>
  );
}

// ---------------------------------------------------------------------------
// OperatorActionsPanel — unchanged from original
// ---------------------------------------------------------------------------

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
