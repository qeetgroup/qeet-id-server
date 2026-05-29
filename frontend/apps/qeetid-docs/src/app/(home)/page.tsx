import { Go, Nodedotjs, Python, React as ReactLogo, Rust, Typescript } from "@thesvg/react";
import {
  ArrowRightIcon,
  BookOpenIcon,
  BuildingIcon,
  CommandIcon,
  FingerprintIcon,
  GlobeIcon,
  KeyRoundIcon,
  PackageIcon,
  PlugZapIcon,
  ScrollTextIcon,
  SearchIcon,
  ShieldCheckIcon,
  TerminalIcon,
  UsersIcon,
  ZapIcon,
} from "lucide-react";
import Link from "next/link";
import type { ComponentType, ReactNode, SVGProps } from "react";
import { useId } from "react";
import { BorderBeam } from "@/components/effects/border-beam";
import { CyclingText } from "@/components/effects/cycling-text";
import { Ripple } from "@/components/effects/ripple";
import { cn } from "@/lib/cn";

export default function HomePage() {
  return (
    <main className="relative isolate">
      <Hero />
      <QuickStart />
      <Topics />
      <Sdks />
      <Resources />
    </main>
  );
}

/* ===== Hero ===== */

const SEARCH_QUERIES = [
  "How do I add MFA?",
  "Configure SAML SSO",
  "WebAuthn passkeys",
  "Rate limit best practices",
  "Webhook signatures",
  "Migrate from Auth0",
];

const QUICK_TILES = [
  {
    href: "/docs/quickstart",
    label: "Quickstart",
    sub: "Ship in 5 min",
    icon: ZapIcon,
  },
  {
    href: "/docs/api",
    label: "API reference",
    sub: "Every endpoint",
    icon: TerminalIcon,
  },
  {
    href: "/docs/sdks",
    label: "SDKs",
    sub: "8 languages",
    icon: PackageIcon,
  },
  {
    href: "/docs/concepts",
    label: "Concepts",
    sub: "Mental model",
    icon: BookOpenIcon,
  },
];

const POPULAR_LINKS = [
  { label: "sign-in", href: "/docs/authentication/sign-in" },
  { label: "SAML", href: "/docs/authentication/sso" },
  { label: "passkeys", href: "/docs/authentication/passkeys" },
  { label: "rate limits", href: "/docs/rate-limits" },
  { label: "webhooks", href: "/docs/webhooks" },
  { label: "RBAC", href: "/docs/rbac" },
];

const HERO_METRICS = [
  { label: "auth p99", value: "< 50 ms" },
  { label: "SDKs", value: "8 stacks" },
  { label: "regions", value: "32" },
];

const HERO_EVENTS = [
  { event: "session.created", count: "2.4k/min", tone: "bg-emerald-500" },
  { event: "policy.evaluated", count: "9.8k/min", tone: "bg-cyan-500" },
  { event: "tenant.resolved", count: "1.1k/min", tone: "bg-violet-500" },
];

function Hero() {
  return (
    <section className="relative isolate grid min-h-[calc(100svh-3.5rem)] overflow-hidden border-fd-border border-b bg-fd-background">
      <HeroBackground />

      <div className="relative z-10 mx-auto grid w-full max-w-7xl items-center gap-12 px-6 py-16 sm:py-20 lg:grid-cols-[minmax(0,1fr)_minmax(360px,0.86fr)] lg:gap-14 lg:py-0">
        <div className="max-w-3xl animate-fade-up">
          <Link
            href="/docs/changelog"
            className="group inline-flex max-w-full items-center gap-2 rounded-full border border-fd-border bg-fd-background/80 py-1 pr-3 pl-1 font-medium text-fd-muted-foreground text-xs shadow-sm backdrop-blur transition-colors hover:border-fd-foreground/25 hover:text-fd-foreground"
          >
            <span className="inline-flex items-center gap-1 rounded-full bg-fd-foreground px-2 py-0.5 font-semibold text-[10px] text-fd-background uppercase">
              v1.4
            </span>
            <span className="truncate">Passkey-first auth docs are live</span>
            <ArrowRightIcon className="size-3 text-fd-muted-foreground transition-transform group-hover:translate-x-0.5" />
          </Link>

          <h1 className="mt-7 max-w-4xl text-balance font-semibold text-5xl leading-[0.96] tracking-normal sm:text-6xl lg:text-7xl">
            Identity docs that feel as fast as the product.
          </h1>

          <p className="mt-6 max-w-2xl text-balance text-base text-fd-muted-foreground leading-8 sm:text-lg">
            Guides, API reference, SDKs, and operational playbooks for building sign-in, sessions,
            passkeys, SSO, RBAC, and audit trails on Qeet ID.
          </p>

          <div className="mt-9 grid gap-3 sm:grid-cols-[minmax(0,1fr)_auto]">
            <Link
              href="/docs"
              className="group relative flex min-h-14 items-center gap-3 overflow-hidden rounded-lg border border-fd-border bg-fd-card/95 px-4 text-left backdrop-blur-xl transition-all hover:-translate-y-0.5 hover:border-fd-foreground/25"
            >
              <SearchIcon className="size-5 shrink-0 text-fd-muted-foreground transition-colors group-hover:text-fd-foreground" />
              <span className="flex min-w-0 flex-1 items-baseline gap-2">
                <span className="text-fd-muted-foreground text-sm">Search</span>
                <span className="truncate font-medium text-fd-foreground text-sm sm:text-base">
                  <CyclingText items={SEARCH_QUERIES} />
                </span>
              </span>
              <kbd className="inline-flex shrink-0 items-center gap-1 rounded-md border border-fd-border bg-fd-muted px-2 py-1 font-medium font-mono text-[11px] text-fd-muted-foreground">
                <CommandIcon className="size-3" /> K
              </kbd>
            </Link>

            <Link
              href="/docs/quickstart"
              className="inline-flex min-h-14 items-center justify-center gap-2 rounded-lg bg-fd-foreground px-5 font-medium text-fd-background text-sm shadow-black/10 shadow-lg transition-all hover:-translate-y-0.5 hover:opacity-90"
            >
              Start building <ArrowRightIcon className="size-4" />
            </Link>
          </div>

          <div className="mt-5 flex flex-wrap items-center gap-2">
            <span className="font-medium text-[10px] text-fd-muted-foreground uppercase">
              Popular
            </span>
            {POPULAR_LINKS.map((c) => (
              <Link
                key={c.href}
                href={c.href}
                className="rounded-md border border-fd-border/70 bg-fd-background/70 px-2.5 py-1 font-medium font-mono text-[11px] text-fd-foreground/80 backdrop-blur transition-colors hover:border-fd-foreground/25 hover:bg-fd-card hover:text-fd-foreground"
              >
                {c.label}
              </Link>
            ))}
          </div>

          <div className="mt-8 grid max-w-2xl grid-cols-1 gap-2 sm:grid-cols-3">
            {HERO_METRICS.map((metric) => (
              <div
                key={metric.label}
                className="rounded-lg border border-fd-border bg-fd-background/65 px-4 py-3 backdrop-blur"
              >
                <p className="font-mono text-[11px] text-fd-muted-foreground">{metric.label}</p>
                <p className="mt-1 font-semibold text-fd-foreground text-lg">{metric.value}</p>
              </div>
            ))}
          </div>
        </div>

        <div className="relative mx-auto w-full max-w-[540px] animate-fade-in lg:mx-0 lg:justify-self-end">
          <HeroConsole />
        </div>
      </div>
    </section>
  );
}

function HeroBackground() {
  return (
    <div aria-hidden className="pointer-events-none absolute inset-0 z-0 overflow-hidden">
      <div className="absolute inset-0 bg-[linear-gradient(180deg,var(--color-fd-background)_0%,color-mix(in_oklab,var(--color-fd-muted)_60%,transparent)_52%,var(--color-fd-background)_100%)]" />
      <div className="absolute inset-0 animate-hero-grid opacity-30 [background-image:linear-gradient(to_right,color-mix(in_oklab,var(--color-fd-border)_70%,transparent)_1px,transparent_1px),linear-gradient(to_bottom,color-mix(in_oklab,var(--color-fd-border)_70%,transparent)_1px,transparent_1px)] [background-size:56px_56px] [mask-image:linear-gradient(to_bottom,black_0%,black_66%,transparent_96%)]" />
      <Ripple
        className="opacity-90 [mask-image:radial-gradient(ellipse_at_center,black_28%,transparent_76%)]"
        mainCircleOpacity={0.32}
        mainCircleSize={300}
        numCircles={9}
      />
      <div className="absolute inset-x-0 top-0 h-full animate-hero-scan bg-[linear-gradient(110deg,transparent_0%,transparent_38%,color-mix(in_oklab,var(--color-fd-foreground)_7%,transparent)_50%,transparent_62%,transparent_100%)] opacity-35" />
      <div className="absolute top-24 left-[6%] h-px w-80 animate-signal-flow bg-gradient-to-r from-transparent via-fd-foreground/20 to-transparent" />
      <div className="absolute top-40 right-[8%] h-px w-64 animate-signal-flow bg-gradient-to-r from-transparent via-fd-primary/25 to-transparent [animation-delay:-4s]" />
      <div className="absolute inset-x-0 bottom-0 h-32 bg-gradient-to-t from-fd-background to-transparent" />
    </div>
  );
}

function CodeLine({ n, children }: { n: string; children?: ReactNode }) {
  return (
    <span className="grid grid-cols-[2ch_minmax(0,1fr)] gap-4">
      <span className="select-none text-right text-[#46536f]">{n}</span>
      <span className="min-w-0 overflow-hidden whitespace-pre text-[#cfdaee]">{children}</span>
    </span>
  );
}

function HeroConsole() {
  return (
    <div className="relative animate-float-soft">
      <div
        aria-hidden
        className="absolute -inset-px rounded-lg bg-[linear-gradient(135deg,color-mix(in_oklab,var(--color-fd-foreground)_18%,transparent),transparent_35%,color-mix(in_oklab,var(--color-fd-primary)_22%,transparent))]"
      />
      <div className="relative overflow-hidden rounded-lg border border-fd-border bg-fd-card/90 shadow-2xl shadow-black/[0.08] backdrop-blur-xl">
        <BorderBeam className="z-20" size={230} duration={10} />
        <div className="relative z-10 flex items-center justify-between border-fd-border border-b bg-fd-muted/35 px-4 py-3">
          <div className="flex items-center gap-2">
            <span className="grid size-7 place-items-center rounded-md bg-fd-foreground text-fd-background">
              <ShieldCheckIcon className="size-4" />
            </span>
            <div className="leading-tight">
              <p className="font-semibold text-sm">qeetid.auth</p>
              <p className="font-mono text-[11px] text-fd-muted-foreground">production tenant</p>
            </div>
          </div>
          <span className="inline-flex items-center gap-1.5 rounded-md border border-emerald-500/20 bg-emerald-500/10 px-2 py-1 font-medium font-mono text-[11px] text-emerald-600 dark:text-emerald-400">
            <span className="relative flex size-1.5">
              <span className="absolute inset-0 animate-ping rounded-full bg-emerald-500 opacity-60" />
              <span className="relative size-1.5 rounded-full bg-emerald-500" />
            </span>
            live
          </span>
        </div>

        <div className="relative z-10 grid gap-0">
          <div className="relative overflow-hidden border-fd-border border-b bg-[#070a12]">
            <div
              aria-hidden
              className="absolute inset-0 bg-[radial-gradient(circle_at_18%_0%,rgba(56,189,248,0.16),transparent_34%),radial-gradient(circle_at_82%_18%,rgba(167,139,250,0.15),transparent_36%),linear-gradient(180deg,rgba(255,255,255,0.045),transparent_36%)]"
            />
            <div
              aria-hidden
              className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-sky-300/60 to-transparent"
            />
            <div className="relative flex items-center justify-between border-white/10 border-b bg-white/[0.035] px-4 py-2.5 font-mono text-[11px]">
              <span className="inline-flex items-center gap-2 text-slate-300">
                <span className="rounded bg-sky-400/15 px-1.5 py-0.5 font-semibold text-[10px] text-sky-200">
                  TS
                </span>
                auth.config.ts
              </span>
              <span className="text-emerald-300/80">typed</span>
            </div>
            <pre className="relative overflow-hidden p-4 font-mono text-[11px] text-slate-200 leading-6 sm:p-5 sm:text-[12px]">
              <code className="grid gap-0">
                <CodeLine n="1">
                  <span className="text-[#84d8ff]">import</span>{" "}
                  <span className="text-[#d9e6ff]">{"{ qeetid }"}</span>{" "}
                  <span className="text-[#84d8ff]">from</span>{" "}
                  <span className="text-[#9ff5c8]">{"'@qeetid/sdk'"}</span>
                </CodeLine>
                <CodeLine n="2" />
                <CodeLine n="3">
                  <span className="text-[#84d8ff]">const</span>{" "}
                  <span className="text-[#ffd58a]">auth</span>{" "}
                  <span className="text-[#d9e6ff]">=</span>{" "}
                  <span className="text-[#d6b4ff]">qeetid</span>
                  <span className="text-[#d9e6ff]">{"({"}</span>
                </CodeLine>
                <CodeLine n="4">
                  {"  "}tenant: <span className="text-[#9ff5c8]">&apos;acme&apos;</span>,
                </CodeLine>
                <CodeLine n="5">
                  {"  "}passkeys: <span className="text-[#ff9fb7]">true</span>,
                </CodeLine>
                <CodeLine n="6">
                  {"  "}session: <span className="text-[#d9e6ff]">{"{"}</span> mode:{" "}
                  <span className="text-[#9ff5c8]">&apos;stateful&apos;</span>{" "}
                  <span className="text-[#d9e6ff]">{"}"}</span>,
                </CodeLine>
                <CodeLine n="7">
                  {"  "}policy: <span className="text-[#d9e6ff]">[</span>
                  <span className="text-[#9ff5c8]">&apos;rbac&apos;</span>,{" "}
                  <span className="text-[#9ff5c8]">&apos;audit&apos;</span>
                  <span className="text-[#d9e6ff]">]</span>,
                </CodeLine>
                <CodeLine n="8">
                  <span className="text-[#d9e6ff]">{"});"}</span>
                </CodeLine>
                <CodeLine n="9" />
                <CodeLine n="10">
                  <span className="text-[#6f7d9c]">{"// hot-path authorization"}</span>
                </CodeLine>
                <CodeLine n="11">
                  <span className="text-[#84d8ff]">await</span> auth.
                  <span className="text-[#d6b4ff]">can</span>
                  <span className="text-[#d9e6ff]">(</span>
                  <span className="text-[#9ff5c8]">{"'invoice:read'"}</span>
                  <span className="text-[#d9e6ff]">);</span>
                </CodeLine>
              </code>
            </pre>
          </div>

          <div className="flex flex-col justify-between gap-5 p-5">
            <div>
              <p className="font-mono text-[11px] text-fd-muted-foreground">Live event stream</p>
              <div className="mt-3 divide-y divide-fd-border rounded-lg border border-fd-border bg-fd-background/70">
                {HERO_EVENTS.map((item) => (
                  <div
                    key={item.event}
                    className="flex items-center justify-between gap-3 px-3 py-3"
                  >
                    <span className="flex min-w-0 items-center gap-2">
                      <span className={cn("size-1.5 rounded-full", item.tone)} />
                      <span className="truncate font-mono text-[11px] text-fd-foreground">
                        {item.event}
                      </span>
                    </span>
                    <span className="font-mono text-[11px] text-fd-muted-foreground">
                      {item.count}
                    </span>
                  </div>
                ))}
              </div>
            </div>

            <div className="grid grid-cols-2 gap-2">
              {QUICK_TILES.map((tile) => (
                <Link
                  key={tile.href}
                  href={tile.href}
                  className="group rounded-lg border border-fd-border bg-fd-background/70 p-3 transition-colors hover:border-fd-foreground/25 hover:bg-fd-muted/40"
                >
                  <tile.icon className="size-4 text-fd-muted-foreground transition-colors group-hover:text-fd-foreground" />
                  <p className="mt-2 font-medium text-xs">{tile.label}</p>
                  <p className="mt-0.5 text-[11px] text-fd-muted-foreground">{tile.sub}</p>
                </Link>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

/* ===== Quick start path ===== */

const quickStart = [
  {
    n: "01",
    title: "Install the SDK",
    body: "One line in your app. Works with any framework or runtime.",
    href: "/docs/quickstart",
  },
  {
    n: "02",
    title: "Add a sign-in page",
    body: "Drop in <QeetidSignIn /> or build your own UI on top of our hooks.",
    href: "/docs/authentication/sign-in",
  },
  {
    n: "03",
    title: "Enable MFA",
    body: "TOTP, SMS, email OTP, and WebAuthn passkeys in one toggle.",
    href: "/docs/mfa",
  },
  {
    n: "04",
    title: "Authorize with RBAC",
    body: "Check permissions on the hot path. Cached at the edge in 28 ms p99.",
    href: "/docs/rbac",
  },
];

function QuickStart() {
  return (
    <section className="border-fd-border border-b">
      <div className="mx-auto max-w-7xl px-6 py-20 lg:py-24">
        <div className="flex flex-col items-start justify-between gap-6 sm:flex-row sm:items-end">
          <div>
            <p className="font-semibold text-fd-primary text-xs uppercase tracking-widest">
              Get started
            </p>
            <h2 className="mt-2 text-balance font-semibold text-3xl tracking-tight sm:text-4xl">
              From npm install to production in four steps
            </h2>
          </div>
          <Link
            href="/docs/quickstart"
            className="inline-flex items-center gap-1.5 font-medium text-fd-primary text-sm hover:underline"
          >
            View full quickstart <ArrowRightIcon className="size-4" />
          </Link>
        </div>

        <ol className="mt-12 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {quickStart.map((s) => (
            <li key={s.n}>
              <Link
                href={s.href}
                className="group relative flex h-full flex-col gap-3 overflow-hidden rounded-2xl border border-fd-border bg-fd-card p-6 transition-colors hover:border-fd-foreground/20"
              >
                <span
                  aria-hidden
                  className="pointer-events-none absolute -top-12 -right-12 size-40 rounded-full bg-gradient-to-br from-fd-primary/30 to-transparent opacity-40 blur-3xl transition-opacity duration-500 group-hover:opacity-90"
                />
                <span className="relative font-medium font-mono text-fd-primary text-xs">
                  {s.n}
                </span>
                <h3 className="relative font-semibold text-lg tracking-tight">{s.title}</h3>
                <p className="relative text-fd-muted-foreground text-sm">{s.body}</p>
                <span className="relative mt-auto inline-flex items-center gap-1 font-medium text-fd-foreground/80 text-xs transition-colors group-hover:text-fd-primary">
                  Open guide{" "}
                  <ArrowRightIcon className="size-3 transition-transform group-hover:translate-x-0.5" />
                </span>
              </Link>
            </li>
          ))}
        </ol>
      </div>
    </section>
  );
}

/* ===== Topic cards ===== */

const topics = [
  {
    href: "/docs/authentication",
    icon: KeyRoundIcon,
    title: "Authentication",
    body: "Sign-in, sign-up, magic links, social providers, and SAML/OIDC SSO.",
    accent: "primary",
    featured: true,
  },
  {
    href: "/docs/mfa",
    icon: FingerprintIcon,
    title: "MFA & Passkeys",
    body: "WebAuthn, TOTP, SMS, email OTP, recovery codes, and step-up flows.",
    accent: "violet",
  },
  {
    href: "/docs/rbac",
    icon: UsersIcon,
    title: "RBAC & ABAC",
    body: "Roles, permissions, group assignments, and hot-path policy checks.",
    accent: "cyan",
  },
  {
    href: "/docs/sessions",
    icon: ShieldCheckIcon,
    title: "Sessions",
    body: "Stateful sessions, cluster-wide revocation, JWT bridges, idle timeouts.",
    accent: "emerald",
  },
  {
    href: "/docs/multi-tenancy",
    icon: BuildingIcon,
    title: "Multi-tenancy",
    body: "Tenant isolation, per-org branding, domains, residency, and SCIM.",
    accent: "rose",
  },
  {
    href: "/docs/audit",
    icon: ScrollTextIcon,
    title: "Audit & compliance",
    body: "Immutable logs, SIEM export, SOC 2, ISO 27001, GDPR, HIPAA.",
    accent: "amber",
  },
  {
    href: "/docs/edge",
    icon: GlobeIcon,
    title: "Edge runtime",
    body: "30+ regions with sub-50 ms p99 sign-in worldwide.",
    accent: "indigo",
  },
  {
    href: "/docs/webhooks",
    icon: PlugZapIcon,
    title: "Webhooks & events",
    body: "React to identity events from Kafka or HTTP, with retries built in.",
    accent: "teal",
  },
];

const accentText: Record<string, string> = {
  primary: "text-fd-primary",
  violet: "text-violet-500",
  cyan: "text-cyan-500",
  emerald: "text-emerald-500",
  rose: "text-rose-500",
  amber: "text-amber-500",
  indigo: "text-indigo-500",
  teal: "text-teal-500",
};
const accentGlow: Record<string, string> = {
  primary: "from-fd-primary/40",
  violet: "from-violet-500/40",
  cyan: "from-cyan-500/40",
  emerald: "from-emerald-500/40",
  rose: "from-rose-500/40",
  amber: "from-amber-500/40",
  indigo: "from-indigo-500/40",
  teal: "from-teal-500/40",
};

function Topics() {
  return (
    <section className="border-fd-border border-b bg-fd-muted/30">
      <div className="mx-auto max-w-7xl px-6 py-20 lg:py-24">
        <div className="mx-auto max-w-2xl text-center">
          <p className="font-semibold text-fd-primary text-xs uppercase tracking-widest">Explore</p>
          <h2 className="mt-2 text-balance font-semibold text-3xl tracking-tight sm:text-4xl">
            Everything you need.
            <span className="text-fd-muted-foreground"> Nothing you don&apos;t.</span>
          </h2>
        </div>

        <div className="mt-14 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {topics.map((t) => (
            <Link
              key={t.href}
              href={t.href}
              className="group relative flex h-full flex-col gap-3 overflow-hidden rounded-2xl border border-fd-border bg-fd-card p-6 transition-colors hover:border-fd-foreground/20"
            >
              {t.featured && <BorderBeam size={200} duration={8} />}
              <span
                aria-hidden
                className={cn(
                  "pointer-events-none absolute -top-12 -right-12 size-40 rounded-full bg-gradient-to-br to-transparent opacity-30 blur-3xl transition-opacity duration-500 group-hover:opacity-90",
                  accentGlow[t.accent],
                )}
              />
              <span
                className={cn(
                  "relative grid size-10 place-items-center rounded-lg bg-fd-muted/60",
                  accentText[t.accent],
                )}
              >
                <t.icon className="size-5" />
              </span>
              <h3 className="relative font-semibold text-base tracking-tight">{t.title}</h3>
              <p className="relative text-fd-muted-foreground text-sm">{t.body}</p>
            </Link>
          ))}
        </div>
      </div>
    </section>
  );
}

/* ===== SDKs ===== */
type BrandIcon = ComponentType<SVGProps<SVGSVGElement>>;

/**
 * Official Next.js mark — black bowl + white gradient strokes.
 * Inlined because @thesvg/react@3.0.1's `nextdotjs` still ships a malformed
 * `dataCircle` (camelCase) prop on its internal <circle>, which React 19 rejects.
 * IDs are generated via useId() so multiple instances don't collide.
 * Pair with the `dark:invert` tint to flip colors automatically in dark mode.
 */
const NextLogo: BrandIcon = (props) => {
  const maskId = useId();
  const grad1Id = useId();
  const grad2Id = useId();
  return (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 180 180" aria-hidden {...props}>
      <title>Next.js</title>
      <mask
        height="180"
        id={maskId}
        maskUnits="userSpaceOnUse"
        width="180"
        x="0"
        y="0"
        style={{ maskType: "alpha" }}
      >
        <circle cx="90" cy="90" fill="black" r="90" />
      </mask>
      <g mask={`url(#${maskId})`}>
        <circle cx="90" cy="90" data-circle="true" fill="black" r="90" />
        <path
          d="M149.508 157.52L69.142 54H54V125.97H66.1136V69.3836L139.999 164.845C143.333 162.614 146.509 160.165 149.508 157.52Z"
          fill={`url(#${grad1Id})`}
        />
        <rect fill={`url(#${grad2Id})`} height="72" width="12" x="115" y="54" />
      </g>
      <defs>
        <linearGradient
          gradientUnits="userSpaceOnUse"
          id={grad1Id}
          x1="109"
          x2="144.5"
          y1="116.5"
          y2="160.5"
        >
          <stop stopColor="white" />
          <stop offset="1" stopColor="white" stopOpacity="0" />
        </linearGradient>
        <linearGradient
          gradientUnits="userSpaceOnUse"
          id={grad2Id}
          x1="121"
          x2="120.799"
          y1="54"
          y2="106.875"
        >
          <stop stopColor="white" />
          <stop offset="1" stopColor="white" stopOpacity="0" />
        </linearGradient>
      </defs>
    </svg>
  );
};

const sdks: { name: string; href: string; Icon: BrandIcon; tint: string }[] = [
  // Icons with baked-in brand colors — `tint` left empty (no styling needed).
  {
    name: "TypeScript",
    href: "/docs/sdks/typescript",
    Icon: Typescript,
    tint: "",
  },
  { name: "React", href: "/docs/sdks/react", Icon: ReactLogo, tint: "" },
  { name: "Python", href: "/docs/sdks/python", Icon: Python, tint: "" },
  { name: "Node.js", href: "/docs/sdks/node", Icon: Nodedotjs, tint: "" },
  {
    name: "React Native",
    href: "/docs/sdks/react-native",
    Icon: ReactLogo,
    tint: "",
  },
  // Icons hardcoded to white — invert to black in light mode, keep white in dark.
  { name: "Go", href: "/docs/sdks/go", Icon: Go, tint: "invert dark:invert-0" },
  {
    name: "Rust",
    href: "/docs/sdks/rust",
    Icon: Rust,
    tint: "invert dark:invert-0",
  },
  // Custom inline SVG using currentColor — flips in dark mode via invert.
  {
    name: "Next.js",
    href: "/docs/sdks/nextjs",
    Icon: NextLogo,
    tint: "dark:invert",
  },
];

function Sdks() {
  return (
    <section className="border-fd-border border-b">
      <div className="mx-auto max-w-7xl px-6 py-20 lg:py-24">
        <div className="flex flex-col items-start justify-between gap-6 sm:flex-row sm:items-end">
          <div>
            <p className="font-semibold text-fd-primary text-xs uppercase tracking-widest">SDKs</p>
            <h2 className="mt-2 text-balance font-semibold text-3xl tracking-tight sm:text-4xl">
              First-class libraries for every stack
            </h2>
            <p className="mt-3 max-w-xl text-fd-muted-foreground">
              Type-safe clients, server middleware, and UI components — generated from the same
              OpenAPI spec, shipped under the same versioning.
            </p>
          </div>
          <Link
            href="/docs/sdks"
            className="inline-flex items-center gap-1.5 font-medium text-fd-primary text-sm hover:underline"
          >
            All SDKs <ArrowRightIcon className="size-4" />
          </Link>
        </div>

        <div className="mt-12 grid grid-cols-2 gap-3 sm:grid-cols-4 lg:grid-cols-8">
          {sdks.map((s) => (
            <Link
              key={s.name}
              href={s.href}
              className="group flex flex-col items-center gap-3 rounded-xl border border-fd-border bg-fd-card p-4 text-center transition-colors hover:border-fd-foreground/20 hover:bg-fd-muted/40"
            >
              <span className="grid size-10 place-items-center rounded-lg bg-fd-muted/50 transition-colors group-hover:bg-fd-muted">
                <s.Icon className={cn("size-6", s.tint)} aria-hidden />
              </span>
              <span className="font-medium text-xs">{s.name}</span>
            </Link>
          ))}
        </div>
      </div>
    </section>
  );
}

/* ===== Resources ===== */

type ResourceCardProps = {
  icon: ReactNode;
  title: string;
  body: string;
  href: string;
  external?: boolean;
};

function ResourceCard({ icon, title, body, href, external }: ResourceCardProps) {
  return (
    <Link
      href={href}
      target={external ? "_blank" : undefined}
      rel={external ? "noreferrer" : undefined}
      className="group flex items-start gap-4 rounded-2xl border border-fd-border bg-fd-card p-5 transition-colors hover:border-fd-foreground/20"
    >
      <span className="grid size-10 shrink-0 place-items-center rounded-lg bg-fd-muted/60 text-fd-primary">
        {icon}
      </span>
      <div className="flex flex-col gap-1">
        <span className="flex items-center gap-1 font-medium text-sm">
          {title}
          <ArrowRightIcon className="size-3 text-fd-muted-foreground transition-transform group-hover:translate-x-0.5" />
        </span>
        <span className="text-fd-muted-foreground text-xs">{body}</span>
      </div>
    </Link>
  );
}

function Resources() {
  return (
    <section className="bg-fd-muted/30">
      <div className="mx-auto grid max-w-7xl gap-12 px-6 py-20 lg:grid-cols-[1fr_2fr] lg:py-24">
        <div className="flex flex-col gap-3">
          <p className="font-semibold text-fd-primary text-xs uppercase tracking-widest">
            Resources
          </p>
          <h2 className="font-semibold text-3xl tracking-tight">Need a hand?</h2>
          <p className="text-fd-muted-foreground">
            Talk to engineers, browse the source, or jump into the API explorer.
          </p>
        </div>
        <div className="grid gap-3 sm:grid-cols-2">
          <ResourceCard
            icon={<BookOpenIcon className="size-5" />}
            title="API reference"
            body="Every endpoint, with copy-paste examples in 5 languages."
            href="/docs/api"
          />
          <ResourceCard
            icon={<TerminalIcon className="size-5" />}
            title="CLI"
            body="Provision tenants, rotate keys, replay events from your terminal."
            href="/docs/cli"
          />
          <ResourceCard
            icon={<PackageIcon className="size-5" />}
            title="Changelog"
            body="What we shipped this week."
            href="/docs/changelog"
          />
          <ResourceCard
            icon={<ZapIcon className="size-5" />}
            title="Status"
            body="Live system health across regions."
            href="https://status.qeetid.com"
            external
          />
        </div>
      </div>
    </section>
  );
}
