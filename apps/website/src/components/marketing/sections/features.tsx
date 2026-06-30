import {
  IconApiKey,
  IconAuditLog,
  IconCrossDevice,
  IconMfaShield,
  IconPasskey,
  IconSamlConnector,
  IconScimSync,
  IconTenant,
  type QeetIconProps,
} from "@qeetrix/ui/brand";
import { cn } from "@qeetrix/ui";
import type { ComponentType } from "react";

import { Reveal, Stagger, StaggerItem, Tilt, WordReveal } from "@/components/marketing/motion";

type Accent = "brand" | "violet" | "cyan" | "emerald" | "amber" | "rose" | "indigo" | "teal";

type FeatureCard = {
  icon: ComponentType<QeetIconProps>;
  title: string;
  body: string;
  accent: Accent;
  /** Bento span: wide cells take two columns on large screens. */
  span?: "wide";
};

const cards: FeatureCard[] = [
  {
    icon: IconSamlConnector,
    title: "Single sign-on",
    body: "SAML 2.0, OIDC, Google, Microsoft, Apple, GitHub, and 40+ more — one config away. Toggle providers from the dashboard, no deploys.",
    accent: "brand",
    span: "wide",
  },
  {
    icon: IconPasskey,
    title: "Passkeys & MFA",
    body: "WebAuthn passkeys, TOTP, SMS, and email OTP — phishing-resistant by default.",
    accent: "violet",
  },
  {
    icon: IconMfaShield,
    title: "RBAC & ABAC",
    body: "Hot-path permission checks in under 30 ms, cached at the edge globally.",
    accent: "cyan",
  },
  {
    icon: IconCrossDevice,
    title: "Stateful sessions",
    body: "Cluster-wide revocation. One click signs a user out across every device.",
    accent: "emerald",
  },
  {
    icon: IconTenant,
    title: "Multi-tenant",
    body: "Hard isolation per organization. Per-tenant branding, domains, and residency.",
    accent: "rose",
  },
  {
    icon: IconAuditLog,
    title: "Audit & compliance",
    body: "Immutable logs to your SIEM. SOC 2, ISO 27001, GDPR, HIPAA — all ready.",
    accent: "amber",
  },
  {
    icon: IconScimSync,
    title: "Runs at the edge",
    body: "30+ regions worldwide. Sub-50 ms p99 sign-in latency for every user.",
    accent: "indigo",
  },
  {
    icon: IconApiKey,
    title: "Drop-in SDKs",
    body: "TypeScript, Go, Python, Rust — first-class. React, Next.js, mobile included.",
    accent: "teal",
    span: "wide",
  },
];

const accent: Record<Accent, { icon: string; glow: string; ring: string }> = {
  brand: { icon: "text-brand", glow: "from-brand/45", ring: "group-hover:ring-brand/40" },
  violet: { icon: "text-violet-500", glow: "from-violet-500/40", ring: "group-hover:ring-violet-500/40" },
  cyan: { icon: "text-cyan-500", glow: "from-cyan-500/40", ring: "group-hover:ring-cyan-500/40" },
  emerald: { icon: "text-emerald-500", glow: "from-emerald-500/40", ring: "group-hover:ring-emerald-500/40" },
  amber: { icon: "text-amber-500", glow: "from-amber-500/40", ring: "group-hover:ring-amber-500/40" },
  rose: { icon: "text-rose-500", glow: "from-rose-500/40", ring: "group-hover:ring-rose-500/40" },
  indigo: { icon: "text-indigo-500", glow: "from-indigo-500/40", ring: "group-hover:ring-indigo-500/40" },
  teal: { icon: "text-teal-500", glow: "from-teal-500/40", ring: "group-hover:ring-teal-500/40" },
};

// Small live visual for the SSO hero cell: a stack of provider chips.
function SsoVisual() {
  const providers = ["SAML 2.0", "OIDC", "Google", "Okta", "Azure AD", "GitHub"];
  return (
    <div aria-hidden className="mt-auto flex flex-wrap gap-2 pt-2">
      {providers.map((p) => (
        <span
          key={p}
          className="rounded-md border border-border/60 bg-background/60 px-2.5 py-1 font-mono text-[11px] text-muted-foreground backdrop-blur transition-colors group-hover:border-brand/30"
        >
          {p}
        </span>
      ))}
    </div>
  );
}

// Small live visual for the SDK hero cell: an install command line.
function SdkVisual() {
  return (
    <div
      aria-hidden
      className="mt-auto rounded-lg border border-border/60 bg-background/60 px-3 py-2 font-mono text-[11px] backdrop-blur transition-colors group-hover:border-brand/30"
    >
      <span className="text-emerald-500">$</span>{" "}
      <span className="text-muted-foreground">pnpm add</span>{" "}
      <span className="text-foreground">@qeetid/react</span>
    </div>
  );
}

function FeatureCardItem({ icon: Icon, title, body, accent: key, span }: FeatureCard) {
  const wide = span === "wide";
  return (
    <Tilt max={4} perspective={1200} className="h-full">
      <article
        className={cn(
          "group relative flex h-full flex-col gap-3 overflow-hidden rounded-2xl border border-border/60 p-6 ring-1 ring-transparent transition-[transform,border-color,box-shadow] duration-300 hover:-translate-y-1 hover:border-foreground/20 hover:shadow-xl hover:shadow-black/5",
          accent[key].ring,
          wide ? "bg-card/60 backdrop-blur lg:p-8" : "bg-background",
        )}
      >
        <span
          aria-hidden
          className={cn(
            "pointer-events-none absolute -right-12 -top-12 size-40 rounded-full bg-linear-to-br to-transparent opacity-30 blur-3xl transition-opacity duration-500 group-hover:opacity-90",
            accent[key].glow,
          )}
        />
        <span
          className={cn(
            "relative grid size-11 place-items-center rounded-xl bg-muted/60 ring-1 ring-border/50 transition-transform duration-300 group-hover:scale-105",
            accent[key].icon,
          )}
        >
          <Icon size={22} />
        </span>
        <h3 className="relative font-display text-lg font-semibold tracking-tight">{title}</h3>
        <p className={cn("relative text-sm text-muted-foreground", wide && "max-w-md")}>{body}</p>
        {wide && title === "Single sign-on" && <SsoVisual />}
        {wide && title === "Drop-in SDKs" && <SdkVisual />}
      </article>
    </Tilt>
  );
}

export function Features() {
  return (
    <section className="border-b border-border/60">
      <div className="mx-auto max-w-7xl px-4 py-20 sm:px-6 lg:px-8 lg:py-28">
        <Reveal className="mx-auto max-w-2xl text-center">
          <p className="text-sm font-medium uppercase tracking-widest text-brand-text">Platform</p>
          <h2 className="mt-2 font-display text-3xl font-semibold tracking-tight text-balance sm:text-5xl">
            <WordReveal text="Everything you need." className="block" />
            <WordReveal
              text="Nothing you don’t."
              className="block text-muted-foreground"
              initialDelay={0.28}
            />
          </h2>
        </Reveal>

        <Stagger
          staggerDelay={0.07}
          className="mt-14 grid auto-rows-fr grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4"
        >
          {cards.map((card) => (
            <StaggerItem
              key={card.title}
              className={cn("h-full", card.span === "wide" && "lg:col-span-2")}
            >
              <FeatureCardItem {...card} />
            </StaggerItem>
          ))}
        </Stagger>
      </div>
    </section>
  );
}
