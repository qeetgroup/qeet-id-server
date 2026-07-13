import { CheckCircle2Icon } from "lucide-react";

import { ArrowCta } from "@/components/marketing/blocks/arrow-cta";
import { Eyebrow } from "@/components/marketing/blocks/eyebrow";
import { BorderBeam } from "@/components/marketing/effects/border-beam";
import { Orb } from "@/components/marketing/effects/orb";
import { ShapeGrid } from "@/components/marketing/effects/shape-grid";
import {
  MagneticButton,
  Reveal,
  Stagger,
  StaggerItem,
  WordReveal,
} from "@/components/marketing/motion";
import { SIGN_UP_URL } from "@/lib/links";

const trust = ["No credit card", "5,000 MAU free", "SOC 2 · GDPR ready"];

export function CTA() {
  return (
    <section className="border-b border-border/60 px-4 py-28 sm:px-6 lg:px-8 lg:py-40">
      <Reveal className="mx-auto max-w-5xl">
        {/* Double-bezel finale — a brand-gradient tray cradling the inner card. */}
        <div className="relative rounded-[2.25rem] bg-linear-to-br from-amber-400/40 via-brand/25 to-orange-600/20 p-1.5 shadow-2xl shadow-brand/25">
          <div className="relative overflow-hidden rounded-[1.875rem] bg-card shadow-[inset_0_1px_0_rgba(255,255,255,0.6)] dark:shadow-[inset_0_1px_0_rgba(255,255,255,0.06)]">
            {/* Faint animated grid texture — bookends the hero, faded to the edges. */}
            <div className="pointer-events-none absolute inset-0 opacity-50 mask-[radial-gradient(ellipse_at_center,black,transparent_72%)]">
              <ShapeGrid direction="diagonal" speed={0.35} squareSize={40} shape="square" />
            </div>
            <Orb
              className="left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2"
              size={700}
              opacity={0.6}
            />
            <BorderBeam
              size={320}
              duration={11}
              colorFrom="var(--brand-300)"
              colorTo="var(--brand-foreground)"
            />

            <div className="relative mx-auto flex max-w-3xl flex-col items-center px-6 py-24 text-center sm:px-10 lg:py-28">
              <Eyebrow>Get started</Eyebrow>

              <h2 className="mt-6 font-display text-4xl font-semibold leading-[1.03] tracking-tight text-balance sm:text-6xl lg:text-6xl">
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
                    <ArrowCta href={SIGN_UP_URL} className="h-12 w-full justify-center sm:w-auto">
                      Create your account
                    </ArrowCta>
                  </MagneticButton>
                  <ArrowCta
                    href="/contact"
                    variant="outline"
                    className="h-12 w-full justify-center sm:w-auto"
                  >
                    Talk to sales
                  </ArrowCta>
                </StaggerItem>

                <StaggerItem>
                  <ul className="flex flex-wrap items-center justify-center gap-2.5">
                    {trust.map((t) => (
                      <li
                        key={t}
                        className="flex items-center gap-1.5 rounded-full border border-border/60 bg-background/60 px-3 py-1 text-xs font-medium text-muted-foreground backdrop-blur-sm"
                      >
                        <CheckCircle2Icon aria-hidden className="size-3.5 text-brand" />
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
