import { ButtonLink } from "@/components/marketing/button-link";
import { BorderBeam } from "@/components/marketing/effects/border-beam";
import { PricingCalculator } from "@/components/marketing/pricing-calculator";
import { cn } from "@qeetid/ui";
import { CheckIcon } from "lucide-react";
import type { Metadata } from "next";

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
    a: "Yes, on Enterprise contracts. We ship a Kubernetes deploy with Terraform modules, monitored by your team.",
  },
];

export default function PricingPage() {
  return (
    <>
      <section className="border-b border-border/60">
        <div className="mx-auto max-w-7xl px-4 py-20 sm:px-6 lg:px-8 lg:py-24">
          <div className="mx-auto max-w-2xl text-center">
            <p className="text-sm font-medium uppercase tracking-widest text-primary">Pricing</p>
            <h1 className="mt-2 font-display text-4xl font-semibold tracking-tight text-balance sm:text-5xl">
              Simple pricing. Real free tier.
            </h1>
            <p className="mt-5 text-muted-foreground text-balance sm:text-lg">
              Free up to 5,000 MAU. No card required. Predictable per-MAU pricing as you grow.
            </p>
          </div>

          <div className="mt-14 grid gap-6 lg:grid-cols-3">
            {tiers.map((t) => (
              <div
                key={t.name}
                className={cn(
                  "relative flex flex-col gap-6 overflow-hidden rounded-2xl border bg-background p-6",
                  t.featured ? "border-primary/40 shadow-xl shadow-primary/10" : "border-border/60",
                )}
              >
                {t.featured && <BorderBeam size={280} duration={9} />}
                <div className="flex items-center justify-between">
                  <h3 className="font-display text-xl font-semibold tracking-tight">{t.name}</h3>
                  {t.featured && (
                    <span className="rounded-full bg-primary px-2 py-0.5 text-xs font-medium text-primary-foreground">
                      Most popular
                    </span>
                  )}
                </div>
                <p className="text-sm text-muted-foreground">{t.description}</p>
                <div className="flex items-baseline gap-2">
                  <span className="font-display text-4xl font-semibold tracking-tight">
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
                      <CheckIcon className="mt-0.5 size-4 shrink-0 text-primary" />
                      <span className="text-muted-foreground">{f}</span>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </div>
      </section>

      <PricingCalculator />

      <section className="border-b border-border/60 bg-muted/30">
        <div className="mx-auto max-w-7xl px-4 py-20 sm:px-6 lg:px-8 lg:py-28">
          <div className="mx-auto max-w-2xl text-center">
            <h2 className="font-display text-3xl font-semibold tracking-tight text-balance sm:text-4xl">
              Compare plans
            </h2>
          </div>

          <div className="mt-12 overflow-hidden rounded-2xl border border-border/60 bg-background">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="border-b border-border/60 bg-muted/40 text-xs uppercase tracking-widest text-muted-foreground">
                  <th className="px-4 py-3 font-medium">Feature</th>
                  <th className="px-4 py-3 font-medium">Free</th>
                  <th className="px-4 py-3 font-medium">Pro</th>
                  <th className="px-4 py-3 font-medium">Enterprise</th>
                </tr>
              </thead>
              <tbody>
                {compare.map((row, i) => (
                  <tr
                    key={row.feature}
                    className={cn(i !== compare.length - 1 && "border-b border-border/60")}
                  >
                    <td className="px-4 py-3 font-medium">{row.feature}</td>
                    <td className="px-4 py-3 text-muted-foreground">{row.free}</td>
                    <td className="px-4 py-3 text-muted-foreground">{row.pro}</td>
                    <td className="px-4 py-3 text-muted-foreground">{row.enterprise}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      <section className="border-b border-border/60">
        <div className="mx-auto max-w-3xl px-4 py-20 sm:px-6 lg:px-8 lg:py-28">
          <h2 className="font-display text-3xl font-semibold tracking-tight">Pricing FAQ</h2>
          <dl className="mt-10 flex flex-col gap-6">
            {faq.map((f) => (
              <div key={f.q} className="rounded-2xl border border-border/60 bg-background p-6">
                <dt className="font-medium">{f.q}</dt>
                <dd className="mt-2 text-sm text-muted-foreground">{f.a}</dd>
              </div>
            ))}
          </dl>
        </div>
      </section>
    </>
  );
}
