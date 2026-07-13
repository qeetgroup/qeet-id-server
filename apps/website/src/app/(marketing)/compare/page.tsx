import { ArrowRightIcon, CheckIcon } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { Reveal, Stagger, StaggerItem } from "@/components/marketing/motion";
import { PageHero } from "@/components/marketing/page-hero";
import { Section, SectionHeader } from "@/components/marketing/section";

export const metadata: Metadata = {
  title: "Compare Qeet ID",
  description:
    "Honest, side-by-side comparisons of Qeet ID against Auth0, Clerk, WorkOS, and Stytch — feature parity, deployment model, and pricing, verified against what we ship.",
};

const competitors = [
  {
    slug: "auth0",
    name: "Auth0",
    category: "Enterprise CIAM",
    tagline:
      "The Okta-owned market leader for federation. Compare on self-hosting, transparent per-MAU pricing, and the no-SSO-tax model.",
  },
  {
    slug: "clerk",
    name: "Clerk",
    category: "Developer-first auth",
    tagline:
      "The polished React-first auth-as-a-service. Compare on self-hosting, multi-tenant B2B defaults, and owning your own database.",
  },
  {
    slug: "workos",
    name: "WorkOS",
    category: "Enterprise-readiness APIs",
    tagline:
      "SSO / SCIM / Audit APIs you bolt onto your own user store. Compare when you want the user store, MFA, and admin in one place.",
  },
  {
    slug: "stytch",
    name: "Stytch",
    category: "Passwordless + fraud",
    tagline:
      "A passwordless-first API with strong device intelligence. Compare on the built-in admin UI, B2B multi-tenancy, and self-hosting.",
  },
];

const edges = [
  "Open-source core, self-hostable down to air-gapped — you own your data and deployment.",
  "Both an OIDC and a SAML IdP, with SCIM Users + Groups, and no “SSO tax.”",
  "A tamper-evident, hash-chained audit log with a /verify endpoint most platforms don't ship.",
  "Refresh-token theft detection, per-account lockout, and a prod boot-gate — secure by default.",
  "Five first-party SDKs and a 100%-route-covered OpenAPI spec, guarded in CI.",
  "Linear per-MAU pricing with a real 5,000-MAU free tier — no tier-jump surprises.",
];

export default function ComparePage() {
  return (
    <>
      <PageHero
        eyebrow="Compare"
        title="Qeet ID vs."
        titleAccent="the field"
        subtitle="We've put together honest, side-by-side comparisons against the identity platforms you've probably already evaluated. Each one is verified against what Qeet ID actually ships today — gaps included — and against the competitor's public docs."
      />

      <Section innerClassName="mx-auto max-w-6xl px-4 py-20 sm:px-6 lg:px-8 lg:py-24">
        <Stagger staggerDelay={0.08} className="grid gap-4 sm:grid-cols-2">
          {competitors.map((c) => (
            <StaggerItem key={c.slug} className="h-full">
              <Link
                href={`/compare/${c.slug}`}
                className="group flex h-full flex-col gap-3 rounded-2xl border border-border/60 bg-card p-6 transition-colors hover:border-brand/50 focus-ring-brand"
              >
                <div className="flex items-center justify-between gap-3">
                  <span className="text-xs font-medium uppercase tracking-widest text-brand-text">
                    {c.category}
                  </span>
                  <ArrowRightIcon className="size-4 text-muted-foreground transition-transform group-hover:translate-x-1 group-hover:text-foreground" />
                </div>
                <h2 className="font-display text-xl font-semibold tracking-tight">
                  Qeet ID <span className="text-muted-foreground">vs.</span> {c.name}
                </h2>
                <p className="text-sm text-muted-foreground">{c.tagline}</p>
              </Link>
            </StaggerItem>
          ))}
        </Stagger>
      </Section>

      <Section muted innerClassName="mx-auto max-w-6xl px-4 py-20 sm:px-6 lg:px-8 lg:py-24">
        <div className="grid gap-12 lg:grid-cols-[1fr_1.3fr] lg:items-start">
          <SectionHeader
            align="left"
            eyebrow="Positioning"
            title="Where Qeet ID"
            titleAccent="wins"
            subtitle="The developer experience of Clerk, the enterprise model of WorkOS, and an audit log nobody else ships — open-source and without the SSO tax."
          />
          <Stagger staggerDelay={0.07} className="grid gap-3 sm:grid-cols-2">
            {edges.map((e) => (
              <StaggerItem key={e}>
                <div className="flex h-full items-start gap-2.5 rounded-xl border border-border/60 bg-background p-4 text-sm">
                  <span className="mt-0.5 inline-flex size-5 shrink-0 items-center justify-center rounded-full bg-brand/15 text-brand">
                    <CheckIcon className="size-3" aria-hidden />
                  </span>
                  <span>{e}</span>
                </div>
              </StaggerItem>
            ))}
          </Stagger>
        </div>
      </Section>

      <Section innerClassName="mx-auto max-w-3xl px-4 py-16 sm:px-6 lg:px-8">
        <Reveal className="text-center">
          <p className="text-sm text-muted-foreground text-balance">
            Comparisons reflect publicly-available product information at the time of writing, and
            Qeet ID&apos;s implemented status as of mid-2026. We try hard to be accurate — and to be
            candid about where we&apos;re still building. Spotted something inaccurate?{" "}
            <Link href="/contact" className="underline">
              Let us know
            </Link>
            .
          </p>
        </Reveal>
      </Section>
    </>
  );
}
