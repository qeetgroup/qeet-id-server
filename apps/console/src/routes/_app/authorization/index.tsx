import {
  Badge,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  Stat,
  Timeline,
  TimelineContent,
  TimelineDescription,
  TimelineIndicator,
  TimelineItem,
  TimelineTime,
  TimelineTitle,
} from "@qeetrix/ui";
import { createFileRoute, Link } from "@tanstack/react-router";
import {
  AlertTriangleIcon,
  BlocksIcon,
  KeyRoundIcon,
  ScrollTextIcon,
  ShieldCheckIcon,
  SlidersHorizontalIcon,
  TrendingUpIcon,
} from "lucide-react";
import { useMemo } from "react";

import { PageHeader } from "@/components/page-header";
import { ComingSoon } from "@/features/authorization/components/shared/coming-soon";
import { useAbacPolicies } from "@/lib/authz-abac";
import { isAuthzEvent, useAuditEvents } from "@/lib/authz-audit";
import { usePermissions, useRoles, wildcardPermissions } from "@/lib/authz-rbac";

export const Route = createFileRoute("/_app/authorization/")({
  component: DashboardPage,
});

function DashboardPage() {
  const rolesQ = useRoles();
  const permsQ = usePermissions();
  const policiesQ = useAbacPolicies();
  const auditQ = useAuditEvents({ limit: 50 });

  const roles = rolesQ.data?.items ?? [];
  const perms = permsQ.data?.items ?? [];
  const policies = policiesQ.data?.items ?? [];

  const insights = useMemo(() => {
    const wildcards = wildcardPermissions(perms);
    const disabled = policies.filter((p) => !p.enabled);
    const denies = policies.filter((p) => p.effect === "deny");
    const unconditional = policies.filter(
      (p) => p.enabled && p.effect === "allow" && p.condition == null,
    );
    return [
      {
        id: "wildcard",
        severity: wildcards.length > 0 ? "warning" : "ok",
        title: "Wildcard permissions",
        count: wildcards.length,
        detail: "Permissions containing * grant broad access.",
      },
      {
        id: "unconditional",
        severity: unconditional.length > 0 ? "warning" : "ok",
        title: "Unconditional allow policies",
        count: unconditional.length,
        detail: "Enabled allow policies with no condition match everything.",
      },
      {
        id: "disabled",
        severity: disabled.length > 0 ? "info" : "ok",
        title: "Disabled policies",
        count: disabled.length,
        detail: "Policies that exist but are not enforced.",
      },
      {
        id: "deny",
        severity: "info",
        title: "Explicit deny policies",
        count: denies.length,
        detail: "Deny-effect policies (deny wins over allow).",
      },
    ] as const;
  }, [perms, policies]);

  const changes = (auditQ.data?.items ?? []).filter(isAuthzEvent).slice(0, 8);

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <PageHeader description="A single view of your authorization posture: what's configured, what's risky, and what changed." />

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <Stat
          label="Roles"
          value={roles.length}
          icon={ShieldCheckIcon}
          hint={`${roles.filter((r) => r.is_system).length} system`}
        />
        <Stat label="Permissions" value={perms.length} icon={KeyRoundIcon} />
        <Stat
          label="ABAC policies"
          value={policies.length}
          icon={SlidersHorizontalIcon}
          hint={`${policies.filter((p) => p.enabled).length} enabled`}
        />
        <Stat
          label="Deny policies"
          value={policies.filter((p) => p.effect === "deny").length}
          icon={AlertTriangleIcon}
        />
      </div>

      <div className="grid gap-4 lg:grid-cols-[1fr_1fr]">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Security insights</CardTitle>
            <CardDescription>Computed from your live configuration.</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-2">
            {insights.map((i) => (
              <div
                key={i.id}
                className="flex items-center justify-between gap-3 rounded-md border p-3"
              >
                <div>
                  <p className="text-sm font-medium">{i.title}</p>
                  <p className="text-xs text-muted-foreground">{i.detail}</p>
                </div>
                <Badge
                  variant={
                    i.severity === "warning"
                      ? "warning"
                      : i.severity === "info"
                        ? "secondary"
                        : "success"
                  }
                >
                  {i.count}
                </Badge>
              </div>
            ))}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex-row items-center justify-between gap-2 space-y-0">
            <div>
              <CardTitle className="text-base">Recent policy changes</CardTitle>
              <CardDescription>From the audit log</CardDescription>
            </div>
            <Link to="/authorization/audit" className="text-xs text-primary hover:underline">
              View all
            </Link>
          </CardHeader>
          <CardContent>
            {changes.length === 0 ? (
              <p className="flex items-center gap-2 py-6 text-sm text-muted-foreground">
                <ScrollTextIcon className="size-4" aria-hidden /> No recent authorization changes.
              </p>
            ) : (
              <Timeline>
                {changes.map((e) => (
                  <TimelineItem key={e.id}>
                    <TimelineIndicator>
                      <span className="size-2 rounded-full bg-primary" />
                    </TimelineIndicator>
                    <TimelineContent>
                      <TimelineTitle className="font-mono text-xs">{e.action}</TimelineTitle>
                      <TimelineDescription>
                        {e.resource_type}
                        {e.actor_user_id ? ` · by ${e.actor_user_id.slice(0, 8)}` : ""}
                      </TimelineDescription>
                      <TimelineTime>{new Date(e.created_at).toLocaleString()}</TimelineTime>
                    </TimelineContent>
                  </TimelineItem>
                ))}
              </Timeline>
            )}
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="lg:col-span-2">
          <ComingSoon
            icon={TrendingUpIcon}
            title="Evaluation analytics"
            description="Allow-vs-deny trends, authorization latency, top resources and most-active roles will appear here once the authorization engine emits decision metrics."
            note="no authz metrics endpoint yet — real counts shown above"
          />
        </div>
        <Card className="flex flex-col justify-center">
          <CardContent className="flex flex-col items-center gap-3 py-8 text-center">
            <BlocksIcon className="size-6 text-muted-foreground" aria-hidden />
            <p className="text-sm font-medium">Start building</p>
            <Link to="/authorization/builder" className="text-sm text-primary hover:underline">
              Open the Policy Builder →
            </Link>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
