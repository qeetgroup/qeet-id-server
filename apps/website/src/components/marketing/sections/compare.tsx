import { ArrowRightIcon } from "lucide-react";
import Link from "next/link";

import { ButtonLink } from "@/components/marketing/button-link";
import { SpotlightCard } from "@/components/marketing/effects/spotlight-card";
import { Reveal, Stagger, StaggerItem } from "@/components/marketing/motion";
import { Section, SectionHeader } from "@/components/marketing/section";

/**
 * Homepage compare teaser — links out to the full, verified head-to-head
 * comparison pages under `/compare/{slug}`. Kept intentionally light (no
 * comparison table) so the homepage stays scannable.
 */
const competitors = [
  { slug: "auth0", name: "Auth0", category: "Enterprise CIAM" },
  { slug: "clerk", name: "Clerk", category: "Developer-first auth" },
  { slug: "workos", name: "WorkOS", category: "Enterprise-readiness APIs" },
  { slug: "stytch", name: "Stytch", category: "Passwordless + fraud" },
];

export function Compare() {
  return (
    <Section id="compare">
      <SectionHeader
        eyebrow="Compare"
        title="How Qeet ID"
        titleAccent="stacks up"
        subtitle="Honest, side-by-side comparisons against the platforms you've probably already evaluated — verified against what we actually ship, gaps included."
      />

      <Stagger staggerDelay={0.08} className="mt-16 grid gap-5 sm:grid-cols-2 lg:grid-cols-4">
        {competitors.map((c) => (
          <StaggerItem key={c.slug} className="h-full">
            <SpotlightCard className="h-full rounded-[1.75rem]">
              <Link
                href={`/compare/${c.slug}`}
                className="group flex h-full flex-col justify-between gap-8 rounded-[1.75rem] border border-border/60 bg-card p-6 shadow-[inset_0_1px_0_rgba(255,255,255,0.5)] transition-[transform,border-color,box-shadow] duration-500 ease-[cubic-bezier(0.16,1,0.3,1)] hover:-translate-y-1 hover:border-brand/50 hover:shadow-xl hover:shadow-black/5 focus-ring-brand dark:shadow-[inset_0_1px_0_rgba(255,255,255,0.06)]"
              >
                <div className="flex items-center justify-between gap-3">
                  <span className="text-[10px] font-medium uppercase tracking-[0.18em] text-brand-text">
                    {c.category}
                  </span>
                  <span
                    aria-hidden
                    className="grid size-8 shrink-0 place-items-center rounded-full bg-brand/10 text-brand transition-transform duration-500 ease-[cubic-bezier(0.32,0.72,0,1)] group-hover:translate-x-0.5 group-hover:-translate-y-px group-hover:scale-105"
                  >
                    <ArrowRightIcon className="size-4" />
                  </span>
                </div>
                <h3 className="font-display text-lg font-semibold tracking-tight">
                  Qeet ID <span className="text-muted-foreground">vs.</span> {c.name}
                </h3>
              </Link>
            </SpotlightCard>
          </StaggerItem>
        ))}
      </Stagger>

      <Reveal className="mt-10 text-center">
        <ButtonLink variant="ghost" href="/compare">
          See all comparisons <ArrowRightIcon className="size-4" />
        </ButtonLink>
      </Reveal>
    </Section>
  );
}
