import { Skeleton, Sparkline } from "@qeetrix/ui";
import { ArrowDownRightIcon, ArrowUpRightIcon, type LucideIcon, MinusIcon } from "lucide-react";
import type * as React from "react";

import { formatDelta } from "../dashboard-model";

export type DashboardMetric = {
  id: string;
  icon: LucideIcon;
  label: string;
  value: string;
  delta: number;
  favorable: boolean;
  data: number[];
  variant?: "area" | "line";
  tone: "brand" | "info" | "success" | "danger";
  unit?: "%" | "pp";
};

const toneClass: Record<DashboardMetric["tone"], string> = {
  brand: "bg-primary/10 text-primary",
  info: "bg-info/10 text-info",
  success: "bg-success/10 text-success",
  danger: "bg-destructive/10 text-destructive",
};

const toneColor: Record<DashboardMetric["tone"], string> = {
  brand: "var(--primary)",
  info: "var(--info)",
  success: "var(--success)",
  danger: "var(--destructive)",
};

const METRIC_SKELETON_IDS = ["users", "logins", "mfa", "failed"] as const;

function MetricSkeleton() {
  return (
    <div className="dashboard-metric min-h-44" aria-hidden="true">
      <div className="flex items-center justify-between gap-3">
        <Skeleton className="h-3 w-28" />
        <Skeleton className="size-8 rounded-lg" />
      </div>
      <Skeleton className="mt-5 h-8 w-24" />
      <Skeleton className="mt-2 h-3 w-32" />
      <Skeleton className="mt-5 h-10 w-full rounded-none" />
    </div>
  );
}

function Metric({ metric }: { metric: DashboardMetric }) {
  const Icon = metric.icon;
  const isNeutral = metric.delta === 0;
  const DirectionIcon = isNeutral
    ? MinusIcon
    : metric.delta > 0
      ? ArrowUpRightIcon
      : ArrowDownRightIcon;

  return (
    <article
      className="dashboard-metric group"
      aria-label={`${metric.label}: ${metric.value}, ${formatDelta(metric.delta, metric.unit)}`}
    >
      <div className="flex items-center justify-between gap-3">
        <h2 className="truncate text-xs font-semibold text-muted-foreground">{metric.label}</h2>
        <span
          className={`grid size-8 shrink-0 place-items-center rounded-lg ring-1 ring-current/10 ${toneClass[metric.tone]}`}
        >
          <Icon className="size-3.5" aria-hidden="true" />
        </span>
      </div>
      <div className="mt-4 flex items-end justify-between gap-3">
        <p className="font-heading text-[1.75rem] font-semibold leading-none tracking-[-0.035em] tabular-nums sm:text-[2rem]">
          {metric.value}
        </p>
        <span
          className={`inline-flex items-center gap-0.5 rounded-md px-1.5 py-0.5 text-[11px] font-semibold tabular-nums ${
            isNeutral
              ? "bg-muted text-muted-foreground"
              : metric.favorable
                ? "bg-success/10 text-success"
                : "bg-destructive/10 text-destructive"
          }`}
        >
          <DirectionIcon className="size-3" aria-hidden="true" />
          {formatDelta(metric.delta, metric.unit)}
        </span>
      </div>
      <p className="mt-1.5 text-[11px] text-muted-foreground">Compared with the prior period</p>
      <div className="mx-[-1.15rem] mt-3 h-12">
        <Sparkline
          data={metric.data}
          type={metric.variant ?? "area"}
          color={toneColor[metric.tone]}
          height={48}
          className="size-full opacity-80 transition-opacity duration-200 group-hover:opacity-100"
        />
      </div>
    </article>
  );
}

export function DashboardMetricRail({
  metrics,
  loading,
}: {
  metrics: DashboardMetric[];
  loading: boolean;
}) {
  return (
    <section className="dashboard-metric-rail" aria-label="Workspace performance indicators">
      {loading
        ? METRIC_SKELETON_IDS.map((id) => <MetricSkeleton key={id} />)
        : metrics.map((metric) => <Metric key={metric.id} metric={metric} />)}
    </section>
  );
}

export type DashboardSecondaryStat = {
  id: string;
  icon: React.ReactNode;
  label: string;
  value: string;
  detail?: string;
};

export function DashboardSecondaryRail({ items }: { items: DashboardSecondaryStat[] }) {
  return (
    <dl className="dashboard-secondary-rail" aria-label="Directory health indicators">
      {items.map((item) => (
        <div key={item.id} className="dashboard-secondary-stat">
          <span className="row-span-2 mt-0.5 grid size-8 place-items-center rounded-lg bg-muted text-muted-foreground [&_svg]:size-3.5">
            {item.icon}
          </span>
          <dt className="truncate text-[11px] font-medium text-muted-foreground">{item.label}</dt>
          <dd className="mt-0.5 flex min-w-0 items-baseline gap-2">
            <span className="font-heading text-lg font-semibold tabular-nums">{item.value}</span>
            {item.detail ? (
              <span className="truncate text-[11px] text-muted-foreground">{item.detail}</span>
            ) : null}
          </dd>
        </div>
      ))}
    </dl>
  );
}
