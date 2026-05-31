import { StatusPill, cn } from "@qeetrix/ui";
import { CheckCircle2Icon } from "lucide-react";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "System status",
  description: "Real-time operational status and 90-day uptime history for Qeet ID services.",
};

type ComponentStatus = "operational" | "degraded";

const components: { name: string; status: ComponentStatus; uptime: string }[] = [
  { name: "Authentication API", status: "operational", uptime: "99.99%" },
  { name: "Sign-in & SSO", status: "operational", uptime: "99.99%" },
  { name: "RBAC permission checks", status: "operational", uptime: "100.00%" },
  { name: "Dashboard", status: "operational", uptime: "99.98%" },
  { name: "Webhooks & events", status: "operational", uptime: "99.97%" },
  { name: "Audit log export", status: "operational", uptime: "99.99%" },
];

// Deterministic 90-day history; a single illustrative degraded day.
const DEGRADED_DAY = 61;
const history = Array.from({ length: 90 }, (_, i) => (i === DEGRADED_DAY ? "degraded" : "up"));

export default function StatusPage() {
  return (
    <>
      <section className="border-b border-border/60">
        <div className="mx-auto max-w-4xl px-4 py-20 sm:px-6 lg:px-8 lg:py-24">
          <p className="text-sm font-medium uppercase tracking-widest text-primary">Status</p>
          <h1 className="mt-2 font-display text-4xl font-semibold tracking-tight text-balance sm:text-5xl">
            System status
          </h1>

          <div className="mt-8 flex items-center gap-3 rounded-2xl border border-emerald-500/30 bg-emerald-500/10 p-5">
            <span className="grid size-10 place-items-center rounded-full bg-emerald-500/20 text-emerald-600 dark:text-emerald-400">
              <CheckCircle2Icon className="size-5" />
            </span>
            <div className="flex flex-col">
              <span className="font-display text-lg font-semibold tracking-tight">
                All systems operational
              </span>
              <span className="text-sm text-muted-foreground">
                Updated continuously · 99.99% uptime over the last 90 days
              </span>
            </div>
          </div>
        </div>
      </section>

      <section className="border-b border-border/60 bg-muted/30">
        <div className="mx-auto max-w-4xl px-4 py-16 sm:px-6 lg:px-8">
          <h2 className="font-display text-2xl font-semibold tracking-tight">Components</h2>
          <ul className="mt-6 flex flex-col divide-y divide-border/60 overflow-hidden rounded-2xl border border-border/60 bg-background">
            {components.map((c) => (
              <li key={c.name} className="flex items-center justify-between gap-4 px-5 py-4">
                <span className="font-medium">{c.name}</span>
                <div className="flex items-center gap-3">
                  <span className="hidden text-xs text-muted-foreground sm:inline">
                    {c.uptime} · 90d
                  </span>
                  <StatusPill
                    kind={c.status === "operational" ? "success" : "warning"}
                  >
                    {c.status === "operational" ? "Operational" : "Degraded"}
                  </StatusPill>
                </div>
              </li>
            ))}
          </ul>
        </div>
      </section>

      <section className="border-b border-border/60">
        <div className="mx-auto max-w-4xl px-4 py-16 sm:px-6 lg:px-8">
          <h2 className="font-display text-2xl font-semibold tracking-tight">90-day uptime</h2>
          <p className="mt-2 text-sm text-muted-foreground">
            Each bar is one day. Hover legend below for the key.
          </p>
          <div className="mt-6 flex gap-[3px]" aria-label="90 day uptime history">
            {history.map((day, i) => (
              <span
                key={i}
                title={day === "up" ? "Operational" : "Degraded"}
                className={cn(
                  "h-9 flex-1 rounded-[2px]",
                  day === "up" ? "bg-emerald-500/70" : "bg-amber-500/70",
                )}
              />
            ))}
          </div>
          <div className="mt-3 flex items-center justify-between text-xs text-muted-foreground">
            <span>90 days ago</span>
            <span className="flex items-center gap-4">
              <span className="flex items-center gap-1.5">
                <span className="size-2.5 rounded-[2px] bg-emerald-500/70" /> Operational
              </span>
              <span className="flex items-center gap-1.5">
                <span className="size-2.5 rounded-[2px] bg-amber-500/70" /> Degraded
              </span>
            </span>
            <span>Today</span>
          </div>
        </div>
      </section>
    </>
  );
}
