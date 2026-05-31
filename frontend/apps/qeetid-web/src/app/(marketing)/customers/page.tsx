import { CaseStudyCard } from "@/components/marketing/blocks/case-study-card";
import { CustomerLogoBlock } from "@/components/marketing/blocks/customer-logo-block";
import { CTA } from "@/components/marketing/sections/cta";
import { stories } from "@/lib/customers";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Customers",
  description:
    "Platform teams at Lattice, Vercel, Linear, and hundreds more trust Qeet ID with their identity layer.",
};

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
          {stories.map((s, i) => (
            <CaseStudyCard key={s.company} data={s} featured={i === 0} />
          ))}
        </div>
      </section>

      <CTA />
    </>
  );
}
