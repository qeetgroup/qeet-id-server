import { ButtonLink } from "@/components/marketing/button-link";
import { CTA } from "@/components/marketing/sections/cta";
import { Avatar, AvatarFallback, AvatarImage } from "@qeetid/ui";
import { ArrowRightIcon, QuoteIcon } from "lucide-react";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Customers",
  description:
    "Platform teams at Lattice, Vercel, Linear, and hundreds more trust Qeetid with their identity layer.",
};

const stories = [
  {
    company: "Lattice",
    logo: "L",
    headline: "Lattice replaced its in-house auth in two sprints",
    summary:
      "After three years of maintaining bespoke session and SSO code, Lattice migrated 1.2M users to Qeetid in six weeks.",
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
      "Vercel's platform team uses Qeetid's RBAC hot-path to gate every dashboard action across millions of teams.",
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

const logos = [
  "Acme",
  "Globex",
  "Initech",
  "Umbrella",
  "Hooli",
  "Pied Piper",
  "Stark",
  "Wayne",
  "Tyrell",
  "Massive",
  "Bluebook",
  "Aperture",
];

export default function CustomersPage() {
  return (
    <>
      <section className="border-b border-border/60">
        <div className="mx-auto max-w-7xl px-4 py-20 sm:px-6 lg:px-8 lg:py-28">
          <div className="mx-auto max-w-3xl text-center">
            <p className="text-sm font-medium uppercase tracking-widest text-primary">Customers</p>
            <h1 className="mt-2 font-display text-4xl font-semibold tracking-tight text-balance sm:text-5xl">
              The world&apos;s best product teams trust Qeetid
            </h1>
            <p className="mt-5 text-muted-foreground text-balance sm:text-lg">
              From two-person startups to Fortune 100 platforms — Qeetid keeps their users signed
              in, and their security teams happy.
            </p>
          </div>

          <div className="mt-14 grid grid-cols-3 items-center gap-x-8 gap-y-6 sm:grid-cols-4 lg:grid-cols-6">
            {logos.map((name) => (
              <span
                key={name}
                className="text-center font-display text-lg font-medium tracking-tight text-muted-foreground/70"
              >
                {name}
              </span>
            ))}
          </div>
        </div>
      </section>

      <section className="border-b border-border/60 bg-muted/30">
        <div className="mx-auto flex max-w-7xl flex-col gap-12 px-4 py-20 sm:px-6 lg:px-8 lg:py-28">
          {stories.map((s, i) => (
            <article
              key={s.company}
              className="grid gap-8 rounded-3xl border border-border/60 bg-background p-8 lg:grid-cols-[1.4fr_1fr] lg:p-12"
            >
              <div className="flex flex-col gap-6">
                <div className="flex items-center gap-3">
                  <span className="grid size-10 place-items-center rounded-lg bg-foreground font-display text-lg font-semibold text-background">
                    {s.logo}
                  </span>
                  <span className="text-sm font-medium uppercase tracking-widest text-muted-foreground">
                    {s.company}
                  </span>
                </div>
                <h2 className="font-display text-2xl font-semibold tracking-tight text-balance sm:text-3xl">
                  {s.headline}
                </h2>
                <p className="text-muted-foreground">{s.summary}</p>
                <dl className="grid grid-cols-3 gap-4">
                  {s.metrics.map((m) => (
                    <div key={m.label} className="rounded-xl border border-border/60 p-4">
                      <dt className="text-xs text-muted-foreground">{m.label}</dt>
                      <dd className="mt-1 font-display text-xl font-semibold tracking-tight">
                        {m.value}
                      </dd>
                    </div>
                  ))}
                </dl>
                <ButtonLink
                  variant="outline"
                  className="w-fit"
                  href={`/customers/${s.company.toLowerCase()}`}
                >
                  Read the full story <ArrowRightIcon className="size-4" />
                </ButtonLink>
              </div>
              <figure className="flex flex-col gap-6 rounded-2xl bg-muted/40 p-6">
                <QuoteIcon className="size-6 text-primary" />
                <blockquote className="text-base leading-relaxed text-foreground/90 sm:text-lg">
                  &ldquo;{s.quote.text}&rdquo;
                </blockquote>
                <figcaption className="mt-auto flex items-center gap-3">
                  <Avatar className="size-10">
                    <AvatarImage src={s.quote.avatar} alt={s.quote.name} />
                    <AvatarFallback>{s.quote.name.charAt(0)}</AvatarFallback>
                  </Avatar>
                  <div className="flex flex-col">
                    <span className="text-sm font-medium">{s.quote.name}</span>
                    <span className="text-xs text-muted-foreground">{s.quote.role}</span>
                  </div>
                </figcaption>
              </figure>
            </article>
          ))}
        </div>
      </section>

      <CTA />
    </>
  );
}
