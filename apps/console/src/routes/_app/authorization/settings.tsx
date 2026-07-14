import { Badge, Card, CardContent, CardDescription, CardHeader, CardTitle } from "@qeetrix/ui";
import { createFileRoute, Link } from "@tanstack/react-router";
import { GaugeIcon, LayersIcon, ShieldIcon } from "lucide-react";

import { PageHeader } from "@/components/page-header";

export const Route = createFileRoute("/_app/authorization/settings")({
  component: SettingsPage,
});

function SettingsPage() {
  return (
    <div className="flex min-w-0 flex-col gap-4">
      <PageHeader description="How the authorization engine evaluates decisions, and where to configure related controls." />

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <LayersIcon className="size-4" aria-hidden /> Evaluation model
          </CardTitle>
          <CardDescription>The order and semantics used to reach a decision.</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-3 sm:grid-cols-2">
          <Fact
            title="Deny wins"
            detail="An explicit deny from any matching policy overrides every allow."
          />
          <Fact
            title="Priority ordering"
            detail="ABAC policies evaluate in descending priority; default is deny."
          />
          <Fact
            title="Composed engines"
            detail="The unified PDP resolves RBAC (permissions) and ReBAC (relationships) together."
          />
          <Fact
            title="Explainability"
            detail="Every engine returns a grant-path / trace when explain is requested."
          />
        </CardContent>
      </Card>

      <div className="grid gap-4 sm:grid-cols-2">
        <LinkCard
          icon={ShieldIcon}
          title="Security policy"
          detail="IP allow/deny lists, session limits, and MFA enforcement."
          to="/settings/workspace/security-policy"
          badge="tenant policy"
        />
        <LinkCard
          icon={GaugeIcon}
          title="Access Tester"
          detail="Run an ad-hoc RBAC check with the full grant path."
          to="/authorization/access-tester"
          badge="diagnostics"
        />
      </div>
    </div>
  );
}

function Fact({ title, detail }: { title: string; detail: string }) {
  return (
    <div className="rounded-md border p-3">
      <p className="text-sm font-medium">{title}</p>
      <p className="text-xs text-muted-foreground">{detail}</p>
    </div>
  );
}

function LinkCard({
  icon: Icon,
  title,
  detail,
  to,
  badge,
}: {
  icon: typeof ShieldIcon;
  title: string;
  detail: string;
  to: string;
  badge: string;
}) {
  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="flex items-center gap-2 text-base">
            <Icon className="size-4" aria-hidden /> {title}
          </CardTitle>
          <Badge variant="muted">{badge}</Badge>
        </div>
        <CardDescription>{detail}</CardDescription>
      </CardHeader>
      <CardContent>
        <Link to={to} className="text-sm text-primary hover:underline">
          Open →
        </Link>
      </CardContent>
    </Card>
  );
}
