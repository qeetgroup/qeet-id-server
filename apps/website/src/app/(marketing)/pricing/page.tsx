import { ButtonLink } from "@/components/marketing/button-link";
import { BorderBeam } from "@/components/marketing/effects/border-beam";
import { FaqAccordion } from "@/components/marketing/faq-accordion";
import { Reveal, Stagger, StaggerItem } from "@/components/marketing/motion";
import { PricingCalculator } from "@/components/marketing/pricing-calculator";
import { Section, SectionHeader } from "@/components/marketing/section";
import { FaqJsonLd } from "@/components/marketing/structured-data";
import { cn } from "@qeetrix/ui";
import { CheckIcon } from "lucide-react";
import type { Metadata } from "next";

import { PageHero } from "@/components/marketing/page-hero";

export const metadata: Metadata = {
  title: "Pricing",
  description:
    "Free for developers. Per-MAU pricing for growing teams. Custom contracts for enterprise.",
};

const tiers = [
  {
    name: "Free",
    description: "For developers and side projects.",
    price: "$0",
    period: "forever",
    cta: { label: "Start free", href: "/sign-up" },
    features: [
      "Up to 5,000 monthly active users",
      "Unlimited social providers",
      "Passkeys + TOTP MFA",
      "RBAC with up to 5 roles",
      "Community support",
      "Hosted EU or US",
    ],
  },
  {
    name: "Pro",
    description: "For teams shipping to real customers.",
    price: "$99",
    period: "/ month + $0.02 / MAU",
    cta: { label: "Start 14-day trial", href: "/sign-up?plan=pro" },
    featured: true,
    features: [
      "Up to 50,000 MAU included",
      "All providers + magic link",
      "Unlimited RBAC + ABAC policies",
      "Audit log export (7-day retention)",
      "Email + chat support, 24h SLA",
      "99.95% uptime SLA",
    ],
  },
  {
    name: "Enterprise",
    description: "For regulated industries and scale.",
    price: "Custom",
    period: "annual contract",
    cta: { label: "Talk to sales", href: "/contact" },
    features: [
      "Unlimited MAU and tenants",
      "SAML, OIDC, SCIM, LDAP",
      "Dedicated single-tenant deploy option",
      "Audit log retention to your S3 / SIEM",
      "Named CSM + 24/7 phone support",
      "99.99% uptime SLA, custom DPAs",
      "SOC 2 Type II, ISO 27001, HIPAA BAA",
    ],
  },
];

const compare = [
  {
    feature: "Monthly active users",
    free: "5,000",
    pro: "50,000 included",
    enterprise: "Unlimited",
  },
  { feature: "Social providers", free: "All", pro: "All", enterprise: "All" },
  { feature: "Passkeys / WebAuthn", free: "✓", pro: "✓", enterprise: "✓" },
  { feature: "MFA (TOTP, SMS, Email OTP)", free: "TOTP only", pro: "All", enterprise: "All" },
  { feature: "Enterprise SSO (SAML/OIDC)", free: "—", pro: "Add-on", enterprise: "✓" },
  { feature: "SCIM / Directory sync", free: "—", pro: "—", enterprise: "✓" },
  { feature: "RBAC roles", free: "5", pro: "Unlimited", enterprise: "Unlimited + ABAC" },
  { feature: "Audit log retention", free: "7 days", pro: "30 days + export", enterprise: "Custom" },
  { feature: "Data residency", free: "US or EU", pro: "US, EU, APAC", enterprise: "Custom" },
  { feature: "Support", free: "Community", pro: "Email + chat, 24h", enterprise: "Phone, 24/7" },
  { feature: "Uptime SLA", free: "—", pro: "99.95%", enterprise: "99.99%" },
];

const faq = [
  {
    q: "What counts as a Monthly Active User?",
    a: "Any unique end-user who signs in or refreshes a session within a calendar month. Machine-to-machine tokens are not counted.",
  },
  {
    q: "Can I switch plans anytime?",
    a: "Yes. Upgrades take effect immediately; downgrades take effect at the next billing cycle.",
  },
  {
    q: "Do you offer non-profit or open-source discounts?",
    a: "We offer 50% off the Pro plan for registered non-profits and 100% off for verified open-source projects.",
  },
  {
    q: "Is there a self-hosted option?",
    a: "Yes, on Enterprise contracts. We ship a Kubernetes deploy with a Helm chart and a DR runbook, monitored by your team.",
  },
];

export default function PricingPage() {
  return (
    <>
      <PageHero
        eyebrow="Pricing"
        title="Simple pricing."
        titleAccent="Real free tier."
        subtitle="Free up to 5,000 MAU. No card required. Predictable per-MAU pricing as you grow — no tier-jump surprises."
      />

      <Section innerClassName="mx-auto max-w-7xl px-4 py-16 sm:px-6 lg:px-8 lg:py-20">
        <Stagger staggerDelay={0.1} className="grid gap-6 lg:grid-cols-3">
          {tiers.map((t) => (
            <StaggerItem key={t.name} className="h-full">
              <div
                className={cn(
                  "relative flex h-full flex-col gap-6 overflow-hidden rounded-2xl border bg-background p-6",
                  t.featured
                    ? "border-brand/40 shadow-xl shadow-brand/10"
                    : "border-border/60",
                )}
              >
                {t.featured && (
                  <>
                    <BorderBeam
                      size={280}
                      duration={9}
                      colorFrom="var(--brand-500)"
                      colorTo="var(--brand-300)"
                    />
                    <span
                      aria-hidden
                      className="pointer-events-none absolute inset-x-0 top-0 h-px bg-[image:var(--brand-gradient)]"
                    />
                  </>
                )}
                <div className="flex items-center justify-between">
                  <h3 className="font-display text-xl font-semibold tracking-tight">{t.name}</h3>
                  {t.featured && (
                    <span className="rounded-full bg-[image:var(--brand-gradient)] px-2 py-0.5 text-xs font-medium text-brand-foreground">
                      Most popular
                    </span>
                  )}
                </div>
                <p className="text-sm text-muted-foreground">{t.description}</p>
                <div className="flex items-baseline gap-2">
                  <span
                    className={cn(
                      "font-display text-4xl font-semibold tracking-tight",
                      t.featured && "text-gradient-brand",
                    )}
                  >
                    {t.price}
                  </span>
                  <span className="text-sm text-muted-foreground">{t.period}</span>
                </div>
                <ButtonLink
                  size="lg"
                  variant={t.featured ? "default" : "outline"}
                  className="w-full"
                  href={t.cta.href}
                >
                  {t.cta.label}
                </ButtonLink>
                <ul className="flex flex-col gap-2.5 border-t border-border/60 pt-6 text-sm">
                  {t.features.map((f) => (
                    <li key={f} className="flex gap-2">
                      <CheckIcon className="mt-0.5 size-4 shrink-0 text-brand" aria-hidden />
                      <span className="text-muted-foreground">{f}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </StaggerItem>
          ))}
        </Stagger>
      </Section>

      <PricingCalculator />

      <Section muted innerClassName="mx-auto max-w-7xl px-4 py-20 sm:px-6 lg:px-8 lg:py-28">
        <SectionHeader title="Compare" titleAccent="plans" />

        <Reveal className="mt-12 overflow-hidden rounded-2xl border border-border/60 bg-background">
          <table className="w-full text-left text-sm">
            <caption className="sr-only">Feature comparison across Free, Pro, and Enterprise plans</caption>
            <thead>
              <tr className="border-b border-border/60 bg-muted/40 text-xs uppercase tracking-widest text-muted-foreground">
                <th scope="col" className="px-4 py-3 font-medium">
                  Feature
                </th>
                <th scope="col" className="px-4 py-3 font-medium">
                  Free
                </th>
                <th scope="col" className="px-4 py-3 font-medium">
                  <span className="text-gradient-brand font-semibold">Pro</span>
                </th>
                <th scope="col" className="px-4 py-3 font-medium">
                  Enterprise
                </th>
              </tr>
            </thead>
            <tbody>
              {compare.map((row, i) => (
                <tr
                  key={row.feature}
                  className={cn(i !== compare.length - 1 && "border-b border-border/60")}
                >
                  <th scope="row" className="px-4 py-3 text-left font-medium">
                    {row.feature}
                  </th>
                  <td className="px-4 py-3 text-muted-foreground">{row.free}</td>
                  <td className="px-4 py-3 text-muted-foreground">{row.pro}</td>
                  <td className="px-4 py-3 text-muted-foreground">{row.enterprise}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Reveal>
      </Section>

      <Section innerClassName="mx-auto max-w-3xl px-4 py-20 sm:px-6 lg:px-8 lg:py-28">
        {/* FAQPage rich-result data — mirrors the visible accordion below. */}
        <FaqJsonLd items={faq} />
        <SectionHeader align="left" title="Pricing" titleAccent="FAQ" />
        <FaqAccordion items={faq} />
      </Section>
    </>
  );
}
