import {
  Badge,
  Button,
  buttonVariants,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Skeleton,
  TimeSince,
} from "@qeetrix/ui";
import { QeetLogoMark } from "@qeetrix/ui/brand";
import { Link } from "@tanstack/react-router";
import {
  ActivityIcon,
  AlertTriangleIcon,
  ArrowRightIcon,
  Building2Icon,
  GaugeIcon,
  KeyRoundIcon,
  PlusIcon,
  RefreshCwIcon,
  RepeatIcon,
  ScrollTextIcon,
  ShieldCheckIcon,
  UserCheckIcon,
  UserPlusIcon,
  UsersIcon,
} from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { useCapabilities } from "@/features/access-control/capability-provider";
import { formatShortDate, useAnalyticsOverview } from "@/lib/analytics";
import { useTenantId } from "@/lib/auth";
import {
  authMethodColor,
  type DashboardRange,
  formatDelta,
  mfaMethodColor,
  takeLatest,
} from "../dashboard-model";
import { useDashboardActivity } from "../use-dashboard-activity";
import { OperatorActionsPanel, RecentActivityPanel } from "./dashboard-activity";
import {
  AuthenticationActivityPanel,
  FailedLoginsPanel,
  LoginMethodMixPanel,
  MfaAdoptionPanel,
} from "./dashboard-charts";
import {
  type DashboardMetric,
  DashboardMetricRail,
  DashboardSecondaryRail,
} from "./dashboard-metrics";
import { OnboardingChecklist } from "./onboarding-checklist";
import { PasskeyPromptCard } from "./passkey-prompt-card";

function hasLiveTelemetry(generatedAt: string | undefined): generatedAt is string {
  if (!generatedAt) return false;
  const timestamp = new Date(generatedAt).getTime();
  return Number.isFinite(timestamp) && timestamp > 0;
}

function DashboardHeading({
  range,
  onRangeChange,
  generatedAt,
  loading,
  telemetryAvailable,
  canInvite,
}: {
  range: DashboardRange;
  onRangeChange: (range: DashboardRange) => void;
  generatedAt?: string;
  loading: boolean;
  telemetryAvailable: boolean;
  canInvite: boolean;
}) {
  const { t } = useTranslation("dashboard");
  const live = hasLiveTelemetry(generatedAt);

  return (
    <header className="flex flex-col gap-5 border-b border-border/70 pb-5 lg:flex-row lg:items-end lg:justify-between">
      <div className="min-w-0">
        <div className="mb-2 flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">
          <span className="h-px w-5 bg-primary" aria-hidden="true" />
          Identity operations
        </div>
        <h1 className="text-balance font-heading text-3xl font-semibold tracking-[-0.04em] sm:text-[2.25rem]">
          {t("title")}
        </h1>
        <p className="mt-2 max-w-2xl text-pretty text-sm leading-6 text-muted-foreground">
          {t("subtitle")}
        </p>
      </div>

      <div className="flex flex-wrap items-center gap-2 lg:justify-end">
        {telemetryAvailable ? (
          <>
            <div className="me-1 flex min-h-8 items-center gap-2 rounded-lg border border-border/75 bg-card/70 px-2.5 text-[11px] text-muted-foreground">
              {loading ? (
                <Skeleton className="h-3 w-28" />
              ) : (
                <>
                  <span
                    className={`size-1.5 rounded-full ${live ? "bg-success shadow-[0_0_0_3px_color-mix(in_oklab,var(--success)_16%,transparent)]" : "bg-warning"}`}
                    aria-hidden="true"
                  />
                  {live ? (
                    <span>
                      Telemetry updated <TimeSince value={generatedAt} className="font-medium" />
                    </span>
                  ) : (
                    <span>Awaiting workspace telemetry</span>
                  )}
                </>
              )}
            </div>
            <Select
              value={range}
              onValueChange={(value) => value && onRangeChange(value as DashboardRange)}
            >
              <SelectTrigger size="sm" className="min-w-36 bg-card">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="7d">{t("range7d")}</SelectItem>
                <SelectItem value="14d">{t("range14d")}</SelectItem>
              </SelectContent>
            </Select>
          </>
        ) : null}
        {canInvite ? (
          <Link to="/invitations" className={buttonVariants({ size: "sm" })}>
            <UserPlusIcon /> {t("quickActions.inviteLabel")}
          </Link>
        ) : null}
      </div>
    </header>
  );
}

export function DashboardOverview() {
  const tenantId = useTenantId();
  const { t } = useTranslation("dashboard");
  const access = useCapabilities();
  const canViewAnalytics = access.can("analytics.read");
  const canViewAudit = access.can("audit.read");
  const canInvite = access.canAll(["user.read", "user.write", "role.read"]);
  const analytics = useAnalyticsOverview(canViewAnalytics);
  const activity = useDashboardActivity(tenantId ?? undefined, canViewAudit);
  const [range, setRange] = useState<DashboardRange>("14d");
  const take = range === "7d" ? 7 : 14;

  if (canViewAnalytics && analytics.isError) {
    return (
      <div className="flex min-w-0 flex-col gap-6">
        <DashboardHeading
          range={range}
          onRangeChange={setRange}
          loading={false}
          telemetryAvailable
          canInvite={canInvite}
        />
        <section className="enterprise-panel grid min-h-80 place-items-center p-8 text-center">
          <div className="max-w-md">
            <span className="mx-auto grid size-12 place-items-center rounded-xl bg-destructive/10 text-destructive">
              <AlertTriangleIcon className="size-5" />
            </span>
            <h2 className="mt-4 font-heading text-lg font-semibold">{t("error")}</h2>
            <p className="mt-1 text-sm leading-6 text-muted-foreground">
              {analytics.error instanceof Error
                ? analytics.error.message
                : "The analytics service did not return a response."}
            </p>
            <Button className="mt-5" variant="outline" onClick={() => analytics.refetch()}>
              <RefreshCwIcon /> Retry
            </Button>
          </div>
        </section>
      </div>
    );
  }

  const overview = analytics.data;
  const metricData = {
    users: takeLatest(overview?.user_trend_14d ?? [], take).map((point) => point.value),
    logins: takeLatest(overview?.login_trend_14d ?? [], take).map((point) => point.value),
    mfa: takeLatest(overview?.mfa_trend_14d ?? [], take).map((point) => point.value),
    failed: takeLatest(overview?.failed_trend_14d ?? [], take).map((point) => point.value),
  };

  const metrics: DashboardMetric[] = overview
    ? [
        {
          id: "mau",
          icon: UsersIcon,
          label: t("kpi.mau"),
          value: overview.kpis.mau.value.toLocaleString("en-US"),
          delta: overview.kpis.mau.delta_pct,
          favorable: overview.kpis.mau.delta_pct >= 0,
          data: metricData.users,
          tone: "info",
        },
        {
          id: "logins",
          icon: ActivityIcon,
          label: t("kpi.loginsToday"),
          value: overview.kpis.logins_today.value.toLocaleString("en-US"),
          delta: overview.kpis.logins_today.delta_pct,
          favorable: overview.kpis.logins_today.delta_pct >= 0,
          data: metricData.logins,
          tone: "brand",
        },
        {
          id: "mfa",
          icon: KeyRoundIcon,
          label: t("kpi.mfaAdoption"),
          value: `${overview.kpis.mfa_adoption_pct.value.toFixed(1)}%`,
          delta: overview.kpis.mfa_adoption_pct.delta_pct,
          unit: "pp",
          favorable: overview.kpis.mfa_adoption_pct.delta_pct >= 0,
          data: metricData.mfa,
          variant: "line",
          tone: "success",
        },
        {
          id: "failed",
          icon: ShieldCheckIcon,
          label: t("kpi.failedLogins24h"),
          value: overview.kpis.failed_logins_24h.value.toLocaleString("en-US"),
          delta: overview.kpis.failed_logins_24h.delta_pct,
          favorable: overview.kpis.failed_logins_24h.delta_pct <= 0,
          data: metricData.failed,
          variant: "line",
          tone: "danger",
        },
      ]
    : [];

  const secondaryStats = overview
    ? [
        {
          id: "total",
          icon: <UsersIcon />,
          label: t("stats.totalUsers"),
          value: overview.kpis.total_users.value.toLocaleString("en-US"),
        },
        {
          id: "daily",
          icon: <UserCheckIcon />,
          label: t("stats.dailyActive"),
          value: overview.kpis.dau.value.toLocaleString("en-US"),
          detail: formatDelta(overview.kpis.dau.delta_pct),
        },
        {
          id: "stickiness",
          icon: <GaugeIcon />,
          label: t("stats.stickiness"),
          value: `${overview.kpis.stickiness_pct.value.toFixed(0)}%`,
        },
        {
          id: "sessions",
          icon: <RepeatIcon />,
          label: t("stats.avgSessions"),
          value: overview.kpis.avg_sessions_per_user.value.toFixed(1),
        },
      ]
    : [];

  const authenticationRows = takeLatest(overview?.login_activity_14d ?? [], take).map((point) => ({
    day: formatShortDate(point.date),
    password: point.password,
    passkey: point.passkey,
    social: point.social,
    saml: point.saml,
    oidc: point.oidc,
  }));
  const methodRows = (overview?.login_methods_mix ?? []).map((method) => ({
    method: method.method,
    value: method.value,
    fill: authMethodColor(method.method),
  }));
  const mfaRows = (overview?.mfa_methods_adoption ?? []).map((method) => ({
    method: method.method,
    users: method.users,
    fill: mfaMethodColor(method.method),
  }));

  return (
    <div className="flex min-w-0 flex-col gap-6">
      <DashboardHeading
        range={range}
        onRangeChange={setRange}
        generatedAt={overview?.generated_at}
        loading={analytics.isLoading}
        telemetryAvailable={canViewAnalytics}
        canInvite={canInvite}
      />

      {canViewAnalytics ? (
        <>
          <DashboardMetricRail metrics={metrics} loading={analytics.isLoading || !overview} />
          {overview ? <DashboardSecondaryRail items={secondaryStats} /> : null}
        </>
      ) : (
        <section className="enterprise-panel flex flex-col gap-4 p-5 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex min-w-0 items-start gap-3">
            <span className="grid size-10 shrink-0 place-items-center rounded-xl bg-muted text-muted-foreground">
              <ShieldCheckIcon className="size-4.5" aria-hidden="true" />
            </span>
            <div className="min-w-0">
              <h2 className="font-heading text-base font-semibold">Your operator view is scoped</h2>
              <p className="mt-1 max-w-2xl text-sm leading-6 text-muted-foreground">
                Workspace analytics are not part of your role. Available navigation and actions are
                tailored to your effective permissions.
              </p>
            </div>
          </div>
          <Badge variant="muted" className="w-fit shrink-0 capitalize">
            {access.mode.replace("-", " ")} access
          </Badge>
        </section>
      )}

      <div className="grid gap-3">
        <OnboardingChecklist />
        <PasskeyPromptCard />
      </div>

      <div className="grid min-w-0 grid-cols-1 gap-4 xl:grid-cols-12">
        {canViewAnalytics ? (
          <>
            <AuthenticationActivityPanel
              className="xl:col-span-8"
              rows={authenticationRows}
              loading={analytics.isLoading}
              take={take}
            />
            <LoginMethodMixPanel
              className="xl:col-span-4"
              rows={methodRows}
              loading={analytics.isLoading}
            />
            <MfaAdoptionPanel
              className="xl:col-span-6"
              rows={mfaRows}
              loading={analytics.isLoading}
            />
            <FailedLoginsPanel
              className="xl:col-span-6"
              rows={overview?.failed_logins_hourly_24h ?? []}
              loading={analytics.isLoading}
            />
          </>
        ) : null}
        {canViewAudit ? (
          <RecentActivityPanel
            className="xl:col-span-8"
            events={activity.data?.items ?? []}
            loading={activity.isLoading}
          />
        ) : null}
        <OperatorActionsPanel className="xl:col-span-4" />
      </div>
    </div>
  );
}

const workspaceFoundations = [
  {
    icon: ShieldCheckIcon,
    title: "Tenant boundary",
    description: "Isolate identities, policies, and administrators from every other workspace.",
  },
  {
    icon: KeyRoundIcon,
    title: "Authentication policy",
    description: "Configure passkeys, federation, MFA, and application credentials in one plane.",
  },
  {
    icon: ScrollTextIcon,
    title: "Verifiable audit trail",
    description: "Record operator and identity events from the first configuration change.",
  },
] as const;

export function NoWorkspaceOnboarding() {
  const { t } = useTranslation("dashboard");

  return (
    <section className="enterprise-panel grid min-h-136 lg:grid-cols-[minmax(0,1.2fr)_minmax(22rem,0.8fr)]">
      <div className="flex flex-col justify-center p-7 sm:p-10 lg:p-14">
        <span className="grid size-12 place-items-center rounded-xl bg-primary/10 ring-1 ring-primary/15">
          <QeetLogoMark size={28} title="Qeet" />
        </span>
        <p className="mt-8 text-[11px] font-semibold uppercase tracking-[0.14em] text-primary">
          Workspace initialization
        </p>
        <h1 className="mt-2 max-w-xl text-balance font-heading text-3xl font-semibold tracking-[-0.04em] sm:text-4xl">
          {t("noWorkspace.title")}
        </h1>
        <p className="mt-4 max-w-xl text-pretty text-sm leading-6 text-muted-foreground sm:text-base sm:leading-7">
          {t("noWorkspace.description")}
        </p>
        <div className="mt-7 flex flex-wrap items-center gap-3">
          <Link to="/organizations/tenants" className={buttonVariants({ size: "lg" })}>
            <PlusIcon /> {t("noWorkspace.cta")}
          </Link>
          <Link to="/account/security" className={buttonVariants({ variant: "ghost", size: "lg" })}>
            Review account security <ArrowRightIcon />
          </Link>
        </div>
      </div>

      <aside className="relative m-3 overflow-hidden rounded-xl bg-sidebar p-6 text-sidebar-foreground ring-1 ring-white/10 sm:m-4 sm:p-8 lg:m-5 lg:p-9">
        <div
          className="absolute -inset-e-20 -top-20 size-60 rounded-full bg-sidebar-primary/10 blur-3xl"
          aria-hidden="true"
        />
        <div className="relative">
          <div className="flex items-center gap-2 text-xs font-semibold text-sidebar-foreground/80">
            <Building2Icon className="size-4 text-sidebar-primary" />
            What a workspace establishes
          </div>
          <ol className="mt-8 space-y-7">
            {workspaceFoundations.map(({ icon: Icon, title, description }, index) => (
              <li key={title} className="grid grid-cols-[2rem_minmax(0,1fr)] gap-x-3">
                <span className="grid size-8 place-items-center rounded-lg bg-white/6 text-sidebar-primary ring-1 ring-white/10">
                  <Icon className="size-4" />
                </span>
                <div>
                  <div className="flex items-baseline gap-2">
                    <span className="font-mono text-[10px] text-sidebar-foreground/35">
                      0{index + 1}
                    </span>
                    <h2 className="text-sm font-semibold">{title}</h2>
                  </div>
                  <p className="mt-1.5 text-xs leading-5 text-sidebar-foreground/58">
                    {description}
                  </p>
                </div>
              </li>
            ))}
          </ol>
          <div className="mt-9 flex items-center gap-2 border-t border-white/10 pt-5 text-[11px] text-sidebar-foreground/45">
            <ShieldCheckIcon className="size-3.5" />
            Built for least privilege from the first operator session
          </div>
        </div>
      </aside>
    </section>
  );
}
