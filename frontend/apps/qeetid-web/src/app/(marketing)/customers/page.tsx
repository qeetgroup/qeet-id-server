import { CaseStudyCard, type CaseStudy } from "@/components/marketing/blocks/case-study-card";
import { CustomerLogoBlock } from "@/components/marketing/blocks/customer-logo-block";
import { CTA } from "@/components/marketing/sections/cta";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Customers",
  description:
    "Platform teams at Lattice, Vercel, Linear, and hundreds more trust Qeet ID with their identity layer.",
};

// Customer-story data lives in this file (not a CMS) so it ships with
// the marketing site and works offline. Replace with real, opted-in
// quotes before GA — placeholder content is clearly fictional today.
const stories: CaseStudy[] = [
  {
    company: "Lattice",
    logo: "L",
    headline: "Lattice replaced its in-house auth in two sprints",
    summary:
      "After three years of maintaining bespoke session and SSO code, Lattice migrated 1.2M users to Qeet ID in six weeks.",
    metrics: [
      { value: "2 sprints", label: "to full migration" },
      { value: "62%", label: "infra cost reduction" },
      { value: "0", label: "downtime incidents" },
    ],
    quote: {
      text: "We ripped out our home-grown auth in two sprints. Passkeys, SAML, MFA — all working day one.",
      name: "Priya Anand",
      role: "Staff Engineer, Lattice",
      avatar: "https://i.pravatar.cc/96?img=5",
    },
  },
  {
    company: "Vercel",
    logo: "V",
    headline: "Vercel's RBAC layer handles 9B permission checks per month",
    summary:
      "Vercel's platform team uses Qeet ID's RBAC hot-path to gate every dashboard action across millions of teams.",
    metrics: [
      { value: "9B / mo", label: "permission checks" },
      { value: "28ms", label: "p99 evaluation" },
      { value: "100%", label: "cache hit rate" },
    ],
    quote: {
      text: "The RBAC layer is the cleanest we've used. Our platform team got their weekends back.",
      name: "Marcus Hale",
      role: "VP Engineering, Vercel",
      avatar: "https://i.pravatar.cc/96?img=12",
    },
  },
  {
    company: "Linear",
    logo: "Li",
    headline: "Linear onboarded a Fortune 100 in three days with per-tenant branding",
    summary:
      "Multi-tenant isolation, SCIM, and per-org domains let Linear unlock enterprise revenue without a custom build.",
    metrics: [
      { value: "3 days", label: "to enterprise onboard" },
      { value: "5x", label: "enterprise ACV growth" },
      { value: "100%", label: "SOC 2 inheritance" },
    ],
    quote: {
      text: "Multi-tenant isolation and per-org branding without lifting a finger.",
      name: "Sofía Reyes",
      role: "CTO, Linear",
      avatar: "https://i.pravatar.cc/96?img=32",
    },
  },
];

const customerLogos = [
  { name: "Acme" },
  { name: "Globex" },
  { name: "Initech" },
  { name: "Umbrella" },
  { name: "Hooli" },
  { name: "Pied Piper" },
  { name: "Stark" },
  { name: "Wayne" },
  { name: "Tyrell" },
  { name: "Massive" },
  { name: "Bluebook" },
  { name: "Aperture" },
];

export default function CustomersPage() {
  return (
    <>
      <section className="border-b border-border/60">
        <div className="mx-auto max-w-7xl px-4 py-20 sm:px-6 lg:px-8 lg:py-28">
          <div className="mx-auto max-w-3xl text-center">
            <p className="text-sm font-medium uppercase tracking-widest text-primary">Customers</p>
            <h1 className="mt-2 font-display text-4xl font-semibold tracking-tight text-balance sm:text-5xl">
              The world&apos;s best product teams trust Qeet ID
            </h1>
            <p className="mt-5 text-muted-foreground text-balance sm:text-lg">
              From two-person startups to Fortune 100 platforms — Qeet ID keeps their users signed
              in, and their security teams happy.
            </p>
          </div>
        </div>
      </section>

      <CustomerLogoBlock logos={customerLogos} />

      <section className="border-b border-border/60 bg-muted/30">
        <div className="mx-auto flex max-w-7xl flex-col gap-12 px-4 py-20 sm:px-6 lg:px-8 lg:py-28">
          {stories.map((s) => (
            <CaseStudyCard key={s.company} data={s} />
          ))}
        </div>
      </section>

      <CTA />
    </>
  );
}
