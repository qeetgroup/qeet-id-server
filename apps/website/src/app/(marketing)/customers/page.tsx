import type { Metadata } from "next";

import { CaseStudyCard } from "@/components/marketing/blocks/case-study-card";
import { CustomerCard } from "@/components/marketing/blocks/customer-card";
import { CustomerLogoBlock } from "@/components/marketing/blocks/customer-logo-block";
import { Reveal, Stagger, StaggerItem } from "@/components/marketing/motion";
import { PageHero } from "@/components/marketing/page-hero";
import { Section, SectionHeader } from "@/components/marketing/section";
import { CTA } from "@/components/marketing/sections/cta";
import { stories } from "@/lib/customers";

export const metadata: Metadata = {
  title: "Customers",
  description:
    "How platform, fintech, healthcare, and marketplace teams ship secure identity on Qeet ID — passkeys, SSO, SCIM, RBAC, and a tamper-evident audit trail.",
};

// Representative team archetypes — generic wordmarks, not claims about named
// customers (see lib/customers.ts).
const customerLogos = [
  { name: "Northwind" },
  { name: "Meridian" },
  { name: "Atlas" },
  { name: "Cedar" },
  { name: "Tidewater" },
  { name: "Lumen" },
  { name: "Beacon" },
  { name: "Harbor" },
  { name: "Vela" },
  { name: "Cobalt" },
  { name: "Summit" },
  { name: "Ridgeline" },
];

export default function CustomersPage() {
  const [featured, ...rest] = stories;

  return (
    <>
      <PageHero
        eyebrow="Customers"
        title="Teams of every shape"
        titleAccent="ship identity on Qeet ID"
        subtitle="From developer platforms to regulated fintech and healthcare — see how teams replace bespoke auth, satisfy compliance, and keep users signed in. Every story below is a representative composite, not a claim about a named customer."
      />

      <CustomerLogoBlock eyebrow="Representative segments we build for" logos={customerLogos} />

      {/* Featured case study */}
      {featured && (
        <Section muted>
          <SectionHeader
            align="left"
            eyebrow="Featured story"
            title="Two sprints to retire"
            titleAccent="home-grown auth"
            subtitle="A developer-platform team consolidated onto Qeet ID and deleted the service they'd maintained for years."
          />
          <Reveal className="mt-10">
            <CaseStudyCard data={featured} featured />
          </Reveal>
        </Section>
      )}

      {/* Story grid */}
      <Section>
        <SectionHeader
          eyebrow="More stories"
          title="Outcomes across"
          titleAccent="every segment"
          subtitle="Each tile links to the full challenge → solution → results write-up."
        />
        <Stagger staggerDelay={0.06} className="mt-12 grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
          {rest.map((story) => (
            <StaggerItem key={story.company} className="h-full">
              <CustomerCard story={story} />
            </StaggerItem>
          ))}
        </Stagger>
      </Section>

      <CTA />
    </>
  );
}
