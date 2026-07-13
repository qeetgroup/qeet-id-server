import { cn } from "@qeetrix/ui";
import { ArrowRightIcon, CheckIcon } from "lucide-react";

import { BezelCard } from "@/components/marketing/blocks/bezel-card";
import { ButtonLink } from "@/components/marketing/button-link";
import { tiers } from "@/components/marketing/data/pricing";
import { BorderBeam } from "@/components/marketing/effects/border-beam";
import { Reveal, Stagger, StaggerItem } from "@/components/marketing/motion";
import { Section, SectionHeader } from "@/components/marketing/section";

/**
 * Condensed homepage pricing — the three tiers from the shared pricing data,
 * linking out to the full `/pricing` page (with its calculator and comparison).
 */
export function Pricing() {
  return (
    <Section muted id="pricing">
      <SectionHeader
        eyebrow="Pricing"
        title="Simple pricing."
        titleAccent="Real free tier."
        subtitle="Free up to 5,000 MAU, no card required. Predictable per-MAU pricing as you grow — no tier-jump surprises."
      />

      <div className="relative mt-16">
        {/* Soft brand halo behind the featured (center) tier for depth. */}
        <div
          aria-hidden
          className="pointer-events-none absolute left-1/2 top-1/2 size-152 max-w-full -translate-x-1/2 -translate-y-1/2 rounded-full bg-[radial-gradient(circle,var(--color-brand)/0.12,transparent_60%)] blur-3xl"
        />
        <Stagger staggerDelay={0.1} className="relative grid gap-6 lg:grid-cols-3 lg:items-center">
          {tiers.map((t) => (
            <StaggerItem key={t.name} className="h-full">
              <BezelCard
                featured={t.featured}
                shellClassName={cn(
                  "transition-transform duration-500 ease-[cubic-bezier(0.16,1,0.3,1)] hover:-translate-y-1.5",
                  t.featured && "lg:scale-[1.04]",
                )}
                className="gap-6 p-7 shadow-xl shadow-black/5"
              >
                {t.featured && (
                  <BorderBeam
                    size={280}
                    duration={9}
                    colorFrom="var(--brand-500)"
                    colorTo="var(--brand-300)"
                  />
                )}
                <div className="flex items-center justify-between">
                  <h3 className="font-display text-xl font-semibold tracking-tight">{t.name}</h3>
                  {t.featured && (
                    <span className="rounded-full bg-(image:--brand-gradient) px-2.5 py-0.5 text-xs font-medium text-brand-foreground shadow-sm shadow-brand/30">
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
              </BezelCard>
            </StaggerItem>
          ))}
        </Stagger>
      </div>

      <Reveal className="mt-10 text-center">
        <ButtonLink variant="ghost" href="/pricing">
          See full pricing &amp; calculator <ArrowRightIcon className="size-4" />
        </ButtonLink>
      </Reveal>
    </Section>
  );
}
