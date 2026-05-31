import { cn } from "@qeetrix/ui";
import {
  Building2Icon,
  FingerprintIcon,
  GlobeIcon,
  KeyRoundIcon,
  ScrollTextIcon,
  ShieldCheckIcon,
  UsersIcon,
  ZapIcon,
  type LucideIcon,
} from "lucide-react";

type Accent = "primary" | "violet" | "cyan" | "emerald" | "amber" | "rose" | "indigo" | "teal";

type FeatureCard = {
  icon: LucideIcon;
  title: string;
  body: string;
  accent: Accent;
  /** Bento span: wide cells take two columns on large screens. */
  span?: "wide";
};

const cards: FeatureCard[] = [
  {
    icon: KeyRoundIcon,
    title: "Single sign-on",
    body: "SAML 2.0, OIDC, Google, Microsoft, Apple, GitHub, and 40+ more — one config away. Toggle providers from the dashboard, no deploys.",
    accent: "primary",
    span: "wide",
  },
  {
    icon: FingerprintIcon,
    title: "Passkeys & MFA",
    body: "WebAuthn passkeys, TOTP, SMS, and email OTP — phishing-resistant by default.",
    accent: "violet",
  },
  {
    icon: UsersIcon,
    title: "RBAC & ABAC",
    body: "Hot-path permission checks in under 30 ms, cached at the edge globally.",
    accent: "cyan",
  },
  {
    icon: ShieldCheckIcon,
    title: "Stateful sessions",
    body: "Cluster-wide revocation. One click signs a user out across every device.",
    accent: "emerald",
  },
  {
    icon: Building2Icon,
    title: "Multi-tenant",
    body: "Hard isolation per organization. Per-tenant branding, domains, and residency.",
    accent: "rose",
  },
  {
    icon: ScrollTextIcon,
    title: "Audit & compliance",
    body: "Immutable logs to your SIEM. SOC 2, ISO 27001, GDPR, HIPAA — all ready.",
    accent: "amber",
  },
  {
    icon: GlobeIcon,
    title: "Runs at the edge",
    body: "30+ regions worldwide. Sub-50 ms p99 sign-in latency for every user.",
    accent: "indigo",
  },
  {
    icon: ZapIcon,
    title: "Drop-in SDKs",
    body: "TypeScript, Go, Python, Rust — first-class. React, Next.js, mobile included.",
    accent: "teal",
    span: "wide",
  },
];

const accent: Record<Accent, { icon: string; glow: string }> = {
  primary: { icon: "text-primary", glow: "from-primary/40" },
  violet: { icon: "text-violet-500", glow: "from-violet-500/40" },
  cyan: { icon: "text-cyan-500", glow: "from-cyan-500/40" },
  emerald: { icon: "text-emerald-500", glow: "from-emerald-500/40" },
  amber: { icon: "text-amber-500", glow: "from-amber-500/40" },
  rose: { icon: "text-rose-500", glow: "from-rose-500/40" },
  indigo: { icon: "text-indigo-500", glow: "from-indigo-500/40" },
  teal: { icon: "text-teal-500", glow: "from-teal-500/40" },
};

// Small live visual for the SSO hero cell: a stack of provider chips.
function SsoVisual() {
  const providers = ["SAML 2.0", "OIDC", "Google", "Okta", "Azure AD", "GitHub"];
  return (
    <div aria-hidden className="mt-auto flex flex-wrap gap-2 pt-2">
      {providers.map((p) => (
        <span
          key={p}
          className="rounded-md border border-border/60 bg-background/60 px-2.5 py-1 font-mono text-[11px] text-muted-foreground backdrop-blur"
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
      className="mt-auto rounded-lg border border-border/60 bg-background/60 px-3 py-2 font-mono text-[11px] backdrop-blur"
    >
      <span className="text-emerald-500">$</span>{" "}
      <span className="text-muted-foreground">pnpm add</span>{" "}
      <span className="text-foreground">@qeetid/react</span>
    </div>
  );
}

export function Features() {
  return (
    <section className="border-b border-border/60">
      <div className="mx-auto max-w-7xl px-4 py-20 sm:px-6 lg:px-8 lg:py-28">
        <div className="mx-auto max-w-2xl text-center">
          <p className="text-sm font-medium uppercase tracking-widest text-primary">Platform</p>
          <h2 className="mt-2 font-display text-3xl font-semibold tracking-tight text-balance sm:text-5xl">
            Everything you need.
            <br />
            <span className="text-muted-foreground">Nothing you don&apos;t.</span>
          </h2>
        </div>

        <div className="mt-14 grid auto-rows-fr grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {cards.map(({ icon: Icon, title, body, accent: key, span }) => {
            const wide = span === "wide";
            return (
              <article
                key={title}
                className={cn(
                  "group relative flex h-full flex-col gap-3 overflow-hidden rounded-2xl border border-border/60 p-6 transition-colors hover:border-foreground/20",
                  wide
                    ? "bg-card/60 backdrop-blur lg:col-span-2 lg:p-8"
                    : "bg-background",
                )}
              >
                <span
                  aria-hidden
                  className={cn(
                    "pointer-events-none absolute -right-12 -top-12 size-40 rounded-full bg-gradient-to-br to-transparent opacity-30 blur-3xl transition-opacity duration-500 group-hover:opacity-90",
                    accent[key].glow,
                  )}
                />
                <span
                  className={cn(
                    "relative grid size-10 place-items-center rounded-lg bg-muted/60 ring-1 ring-border/50",
                    accent[key].icon,
                  )}
                >
                  <Icon className="size-5" />
                </span>
                <h3 className="relative font-display text-lg font-semibold tracking-tight">
                  {title}
                </h3>
                <p className={cn("relative text-sm text-muted-foreground", wide && "max-w-md")}>
                  {body}
                </p>
                {wide && title === "Single sign-on" && <SsoVisual />}
                {wide && title === "Drop-in SDKs" && <SdkVisual />}
              </article>
            );
          })}
        </div>
      </div>
    </section>
  );
}
