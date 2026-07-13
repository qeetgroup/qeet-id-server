import { cn, StatusPill } from "@qeetrix/ui";
import { CheckCircle2Icon, InfoIcon } from "lucide-react";
import type { Metadata } from "next";

import { Reveal, Stagger, StaggerItem } from "@/components/marketing/motion";

export const metadata: Metadata = {
  title: "System status",
  description:
    "Illustrative operational status and 90-day uptime view for Qeet ID services — API, sign-in & SSO, RBAC, dashboard, webhooks, and audit export.",
};

type ComponentStatus = "operational" | "degraded";

const components: {
  name: string;
  description: string;
  status: ComponentStatus;
  uptime: string;
}[] = [
  {
    name: "Authentication API",
    description: "Token issuance, introspection, and the JWKS endpoint.",
    status: "operational",
    uptime: "99.99%",
  },
  {
    name: "Sign-in & SSO",
    description: "Hosted login, passkeys, SAML, and OIDC federation.",
    status: "operational",
    uptime: "99.99%",
  },
  {
    name: "RBAC permission checks",
    description: "The /check hot-path and effective-permissions queries.",
    status: "operational",
    uptime: "100.00%",
  },
  {
    name: "Dashboard",
    description: "The admin console and tenant management UI.",
    status: "operational",
    uptime: "99.98%",
  },
  {
    name: "Webhooks & events",
    description: "Signed event delivery, the outbox, and retries.",
    status: "operational",
    uptime: "99.97%",
  },
  {
    name: "Docs & audit export",
    description: "Documentation site and streaming audit-log export.",
    status: "operational",
    uptime: "99.99%",
  },
];

// Deterministic 90-day history; a single illustrative degraded day so the
// legend reads as real rather than a flat green wall.
const DEGRADED_DAY = 61;
const history = Array.from({ length: 90 }, (_, i) => (i === DEGRADED_DAY ? "degraded" : "up"));

export default function StatusPage() {
  return (
    <>
      {/* Header + overall banner */}
      <section className="relative overflow-hidden border-b border-border/60">
        <div className="relative mx-auto max-w-4xl px-4 py-16 sm:px-6 lg:px-8 lg:py-20">
          <Reveal>
            <p className="text-sm font-medium uppercase tracking-widest text-brand-text">Status</p>
            <h1 className="mt-2 font-display text-4xl font-semibold tracking-tight text-balance sm:text-5xl">
              System status
            </h1>
          </Reveal>

          <Reveal delay={0.08}>
            <div className="mt-8 flex items-center gap-4 rounded-2xl border border-emerald-500/30 bg-emerald-500/10 p-5">
              <span className="grid size-10 shrink-0 place-items-center rounded-full bg-emerald-500/20 text-emerald-600 dark:text-emerald-400">
                <CheckCircle2Icon className="size-5" aria-hidden />
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
          </Reveal>
        </div>
      </section>

      {/* Components */}
      <section className="border-b border-border/60 bg-muted/30">
        <div className="mx-auto max-w-4xl px-4 py-14 sm:px-6 lg:px-8">
          <Reveal>
            <h2 className="font-display text-2xl font-semibold tracking-tight">Components</h2>
          </Reveal>
          <Stagger
            staggerDelay={0.05}
            className="mt-6 flex flex-col divide-y divide-border/60 overflow-hidden rounded-2xl border border-border/60 bg-background"
          >
            {components.map((c) => (
              <StaggerItem key={c.name}>
                <div className="flex items-center justify-between gap-4 px-5 py-4">
                  <div className="flex flex-col gap-0.5">
                    <span className="font-medium">{c.name}</span>
                    <span className="text-xs text-muted-foreground">{c.description}</span>
                  </div>
                  <div className="flex shrink-0 items-center gap-3">
                    <span className="hidden text-xs text-muted-foreground sm:inline">
                      {c.uptime} · 90d
                    </span>
                    <StatusPill kind={c.status === "operational" ? "success" : "warning"}>
                      {c.status === "operational" ? "Operational" : "Degraded"}
                    </StatusPill>
                  </div>
                </div>
              </StaggerItem>
            ))}
          </Stagger>
        </div>
      </section>

      {/* 90-day uptime */}
      <section className="border-b border-border/60">
        <div className="mx-auto max-w-4xl px-4 py-14 sm:px-6 lg:px-8">
          <Reveal>
            <h2 className="font-display text-2xl font-semibold tracking-tight">90-day uptime</h2>
            <p className="mt-2 text-sm text-muted-foreground">
              Each bar is one day across all components. Hover a bar for that day&apos;s state.
            </p>
          </Reveal>

          <Reveal delay={0.05}>
            <div
              className="mt-6 flex gap-[3px]"
              role="img"
              aria-label="90 day uptime history, all operational except one degraded day"
            >
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
                  <span aria-hidden className="size-2.5 rounded-[2px] bg-emerald-500/70" />{" "}
                  Operational
                </span>
                <span className="flex items-center gap-1.5">
                  <span aria-hidden className="size-2.5 rounded-[2px] bg-amber-500/70" /> Degraded
                </span>
              </span>
              <span>Today</span>
            </div>
          </Reveal>
        </div>
      </section>

      {/* Illustrative-view disclosure */}
      <section className="border-b border-border/60 bg-muted/30">
        <div className="mx-auto max-w-4xl px-4 py-12 sm:px-6 lg:px-8">
          <Reveal>
            <div className="flex items-start gap-3 rounded-2xl border border-border/60 bg-background p-5 text-sm text-muted-foreground">
              <InfoIcon className="mt-0.5 size-4 shrink-0 text-brand" aria-hidden />
              <p>
                This is an illustrative, static status view — not a live feed. Before GA it will be
                wired to real uptime monitoring with incident history and subscribe-to-updates. For
                anything urgent today, reach{" "}
                <a
                  href="mailto:support@qeet.in"
                  className="font-medium text-brand-text underline focus-ring-brand"
                >
                  support@qeet.in
                </a>
                .
              </p>
            </div>
          </Reveal>
        </div>
      </section>
    </>
  );
}
