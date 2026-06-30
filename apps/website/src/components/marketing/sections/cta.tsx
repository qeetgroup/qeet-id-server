import { ArrowRightIcon, CheckCircle2Icon } from "lucide-react";

import { ButtonLink } from "../button-link";
import { BorderBeam } from "@/components/marketing/effects/border-beam";
import { Orb } from "@/components/marketing/effects/orb";
import { MagneticButton, Reveal, Stagger, StaggerItem, WordReveal } from "@/components/marketing/motion";
import { SIGN_UP_URL } from "@/lib/links";

const trust = ["No credit card", "5,000 MAU free", "SOC 2 · GDPR ready"];

export function CTA() {
  return (
    <section className="border-b border-border/60 px-4 py-20 sm:px-6 lg:px-8 lg:py-28">
      <Reveal className="mx-auto max-w-5xl">
        {/* Gradient border ring — muted opacity so corners aren't harsh */}
        <div className="relative overflow-hidden rounded-3xl bg-linear-to-br from-amber-400/30 via-brand/20 to-orange-600/15 p-px shadow-2xl shadow-brand/20">
          <BorderBeam
            size={320}
            duration={11}
            colorFrom="var(--brand-200)"
            colorTo="var(--brand-foreground)"
          />
          {/* Inner card */}
          <div className="relative overflow-hidden rounded-[calc(1.5rem-1px)] bg-card">
            <Orb
              className="left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2"
              size={700}
              opacity={0.65}
            />

            <div className="relative mx-auto flex max-w-3xl flex-col items-center px-6 py-20 text-center sm:px-10 lg:py-24">
              <h2 className="font-display text-4xl font-semibold leading-[1.05] tracking-tight text-balance sm:text-6xl">
                <span className="relative block overflow-hidden">
                  <WordReveal text="Start building today." initialDelay={0.1} />
                </span>
                <span className="relative block overflow-hidden">
                  <WordReveal
                    text="Free for developers."
                    wordClassName="text-gradient-brand"
                    initialDelay={0.32}
                  />
                </span>
              </h2>

              <Stagger
                staggerDelay={0.1}
                delayChildren={0.5}
                className="flex flex-col items-center gap-8"
              >
                <StaggerItem>
                  <p className="mt-6 max-w-xl text-base text-muted-foreground text-balance sm:text-lg">
                    5,000 monthly active users on the house. Production-grade auth, no credit card,
                    no time limit.
                  </p>
                </StaggerItem>

                <StaggerItem className="flex w-full flex-col items-center gap-3 sm:w-auto sm:flex-row">
                  <MagneticButton strength={0.35} className="w-full sm:w-auto">
                    <ButtonLink
                      size="lg"
                      href={SIGN_UP_URL}
                      className="h-11 w-full px-5 sm:w-auto"
                    >
                      Create your account
                      <ArrowRightIcon className="size-4" />
                    </ButtonLink>
                  </MagneticButton>
                  <ButtonLink
                    size="lg"
                    variant="outline"
                    href="/contact"
                    className="h-11 w-full px-5 sm:w-auto"
                  >
                    Talk to sales
                  </ButtonLink>
                </StaggerItem>

                <StaggerItem>
                  <ul className="flex flex-wrap items-center justify-center gap-x-6 gap-y-2 text-sm text-muted-foreground">
                    {trust.map((t) => (
                      <li key={t} className="flex items-center gap-1.5">
                        <CheckCircle2Icon aria-hidden className="size-4 text-brand" />
                        {t}
                      </li>
                    ))}
                  </ul>
                </StaggerItem>
              </Stagger>
            </div>
          </div>
        </div>
      </Reveal>
    </section>
  );
}
