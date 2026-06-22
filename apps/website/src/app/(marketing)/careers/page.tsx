import { Badge } from "@qeetrix/ui";
import {
  ArrowRightIcon,
  CompassIcon,
  GlobeIcon,
  HeartPulseIcon,
  LaptopIcon,
  LockKeyholeIcon,
  PlaneIcon,
  ShieldCheckIcon,
  SproutIcon,
  UsersIcon,
  WalletIcon,
} from "lucide-react";
import type { Metadata } from "next";

import { ButtonLink } from "@/components/marketing/button-link";
import { Reveal, Stagger, StaggerItem } from "@/components/marketing/motion";
import { PageHero } from "@/components/marketing/page-hero";
import { Section, SectionHeader } from "@/components/marketing/section";

export const metadata: Metadata = {
  title: "Careers",
  description:
    "Help us make secure identity the default for every product team. Remote-first, async, deeply technical, and security-obsessed.",
};

const values = [
  {
    icon: ShieldCheckIcon,
    title: "Security is the product",
    body: "We hold ourselves to the standard our customers trust us with. Secure-by-default isn't a slogan here — it's the review bar.",
  },
  {
    icon: LockKeyholeIcon,
    title: "Earn trust, then keep it",
    body: "We're honest about what's shipped versus planned, internally and on the marketing site. Credibility compounds.",
  },
  {
    icon: CompassIcon,
    title: "Default to ownership",
    body: "Small, senior team. You'll own problems end-to-end and ship the fix, not file it for someone else.",
  },
  {
    icon: UsersIcon,
    title: "Async, written, kind",
    body: "Decisions live in docs, not in heads. We write things down, disagree well, and keep meetings rare.",
  },
];

const perks = [
  {
    icon: GlobeIcon,
    title: "Remote-first",
    body: "Work from anywhere across many time zones. Async by default, with deliberate overlap.",
  },
  {
    icon: WalletIcon,
    title: "Top-of-market pay",
    body: "Competitive salary, meaningful equity, and transparent compensation bands.",
  },
  {
    icon: HeartPulseIcon,
    title: "Health & wellness",
    body: "Comprehensive medical, dental, vision, and a wellness stipend.",
  },
  {
    icon: PlaneIcon,
    title: "Real time off",
    body: "A minimum PTO we actually enforce, plus company-wide recharge weeks.",
  },
  {
    icon: LaptopIcon,
    title: "Home-office budget",
    body: "Pick your hardware — we cover the setup that makes you productive.",
  },
  {
    icon: SproutIcon,
    title: "Growth",
    body: "Learning budget, conference travel, and mentorship from day one.",
  },
];

const roles = [
  {
    title: "Senior Backend Engineer (Go)",
    team: "Platform",
    location: "Remote · Global",
    blurb: "Own core auth, OIDC, and RBAC paths in the Go modular monolith.",
  },
  {
    title: "Security Engineer",
    team: "Security",
    location: "Remote · Global",
    blurb: "Threat-model new surfaces, drive the SOC 2 / pen-test program, and harden defaults.",
  },
  {
    title: "Developer Advocate",
    team: "DevRel",
    location: "Remote · Americas",
    blurb: "Build SDK samples, write the docs people actually finish, and meet developers where they are.",
  },
  {
    title: "Product Designer",
    team: "Design",
    location: "Remote · EU / UK",
    blurb: "Design login, dashboard, and developer flows that feel effortless and trustworthy.",
  },
  {
    title: "Site Reliability Engineer",
    team: "Infrastructure",
    location: "Remote · Global",
    blurb: "Keep the identity layer fast and available — it's in everyone's critical path.",
  },
];

export default function CareersPage() {
  return (
    <>
      <PageHero
        eyebrow="Careers"
        title="Build the identity layer"
        titleAccent="the internet runs on"
        subtitle="We're a small, senior, remote-first team that cares deeply about security and craft. If you want your work in the critical path of thousands of products, you'll fit right in."
        cta={
          <ButtonLink href="#open-roles">
            See open roles <ArrowRightIcon className="size-4" aria-hidden />
          </ButtonLink>
        }
      />

      {/* Values */}
      <Section>
        <SectionHeader
          eyebrow="How we work"
          title="What we"
          titleAccent="value"
          subtitle="A short list we actually hold each other to — not a poster on the wall."
        />
        <Stagger staggerDelay={0.07} className="mt-12 grid gap-6 sm:grid-cols-2">
          {values.map(({ icon: Icon, title, body }) => (
            <StaggerItem key={title} className="h-full">
              <article className="flex h-full flex-col gap-3 rounded-2xl border border-border/60 bg-card p-6">
                <span className="grid size-10 place-items-center rounded-lg bg-brand/10 text-brand">
                  <Icon className="size-5" aria-hidden />
                </span>
                <h3 className="font-display text-lg font-semibold tracking-tight">{title}</h3>
                <p className="text-sm text-muted-foreground">{body}</p>
              </article>
            </StaggerItem>
          ))}
        </Stagger>
      </Section>

      {/* Benefits */}
      <Section muted>
        <SectionHeader
          eyebrow="Benefits"
          title="Why you'll like it"
          titleAccent="here"
        />
        <Stagger staggerDelay={0.06} className="mt-12 grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
          {perks.map(({ icon: Icon, title, body }) => (
            <StaggerItem key={title} className="h-full">
              <div className="flex h-full flex-col gap-3 rounded-2xl border border-border/60 bg-background p-6">
                <span className="grid size-10 place-items-center rounded-lg bg-brand/10 text-brand">
                  <Icon className="size-5" aria-hidden />
                </span>
                <h3 className="font-display text-lg font-semibold tracking-tight">{title}</h3>
                <p className="text-sm text-muted-foreground">{body}</p>
              </div>
            </StaggerItem>
          ))}
        </Stagger>
      </Section>

      {/* Open roles */}
      <Section id="open-roles" className="scroll-mt-20">
        <SectionHeader
          align="left"
          eyebrow="Open roles"
          title="Come build"
          titleAccent="with us"
          subtitle="Roles below are illustrative of the team we're growing. Apply by email and tell us what you'd own."
        />
        <Stagger staggerDelay={0.06} className="mt-10 flex flex-col gap-3">
          {roles.map((r) => (
            <StaggerItem key={r.title}>
              <a
                href={`mailto:careers@qeet.id?subject=${encodeURIComponent(`Application: ${r.title}`)}`}
                className="group flex flex-col gap-3 rounded-2xl border border-border/60 bg-card p-6 transition-colors hover:border-brand/50 focus-ring-brand sm:flex-row sm:items-center sm:justify-between"
              >
                <div className="flex flex-col gap-2">
                  <span className="font-display text-lg font-semibold tracking-tight">
                    {r.title}
                  </span>
                  <p className="text-sm text-muted-foreground">{r.blurb}</p>
                  <div className="mt-1 flex flex-wrap items-center gap-2 text-sm text-muted-foreground">
                    <Badge variant="secondary">{r.team}</Badge>
                    <span>{r.location}</span>
                  </div>
                </div>
                <span className="inline-flex shrink-0 items-center gap-1 text-sm font-medium text-brand-text">
                  Apply
                  <ArrowRightIcon
                    className="size-4 transition-transform group-hover:translate-x-0.5"
                    aria-hidden
                  />
                </span>
              </a>
            </StaggerItem>
          ))}
        </Stagger>

        <Reveal className="mt-12">
          <div className="flex flex-col items-start gap-4 rounded-2xl border border-border/60 bg-muted/30 p-8 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex flex-col gap-1">
              <h3 className="font-display text-lg font-semibold tracking-tight">
                Don&apos;t see your role?
              </h3>
              <p className="text-sm text-muted-foreground">
                We&apos;re always glad to meet exceptional people. Tell us what you&apos;d build.
              </p>
            </div>
            <ButtonLink variant="outline" href="mailto:careers@qeet.id">
              Get in touch
            </ButtonLink>
          </div>
        </Reveal>
      </Section>
    </>
  );
}
