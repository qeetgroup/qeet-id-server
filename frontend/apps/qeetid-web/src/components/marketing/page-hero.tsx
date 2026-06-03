import type { ReactNode } from "react";

import { Aurora } from "@/components/marketing/effects/aurora";
import { DotPattern } from "@/components/marketing/effects/dot-pattern";
import { Reveal, Stagger, StaggerItem, WordReveal } from "@/components/marketing/motion";

type PageHeroProps = {
  /** Short brand eyebrow above the title, e.g. "Security". */
  eyebrow: string;
  /**
   * Full headline text. Pass `gradientFrom` to clip-text the trailing words in
   * the brand gradient (rendered as a second `WordReveal` line). If omitted, the
   * whole title renders as a single word-reveal line.
   */
  title: string;
  /**
   * Optional trailing phrase rendered on its own line with the brand gradient
   * applied via `wordClassName` (per the WordReveal API — the gradient must live
   * on the transformed word spans, never the clip-text container).
   */
  titleAccent?: string;
  /** Muted supporting copy below the title. */
  subtitle?: ReactNode;
  /** Optional CTA row (e.g. `<ButtonLink>`s), revealed after the subtitle. */
  cta?: ReactNode;
  /** Extra content under the CTA (badges, trust row, etc.). */
  children?: ReactNode;
  /** Left-align instead of the default centered layout. */
  align?: "center" | "left";
};

/**
 * Reusable premium page hero: brand-tinted Aurora + DotPattern background, a
 * brand eyebrow, a word-by-word `WordReveal` title (optional gradient accent
 * line), a muted subtitle, and optional CTA / trust content. Server-rendered
 * shell; the motion primitives inside are the only client islands and are all
 * reduced-motion-safe.
 */
export function PageHero({
  eyebrow,
  title,
  titleAccent,
  subtitle,
  cta,
  children,
  align = "center",
}: PageHeroProps) {
  const centered = align === "center";

  return (
    <section className="relative overflow-hidden border-b border-border/60">
      {/* Brand-tinted background — Aurora reads --aurora-* (warm); dots fade to edges. */}
      <Aurora className="opacity-80" />
      <DotPattern className="opacity-20 [mask-image:radial-gradient(ellipse_at_top,black,transparent_75%)] dark:opacity-30" />

      <div className="relative mx-auto max-w-7xl px-4 py-20 sm:px-6 lg:px-8 lg:py-28">
        <div
          className={
            centered
              ? "mx-auto flex max-w-3xl flex-col items-center text-center"
              : "flex max-w-3xl flex-col items-start text-left"
          }
        >
          <Reveal duration={0.5}>
            <p className="text-sm font-medium uppercase tracking-widest text-brand-text">
              {eyebrow}
            </p>
          </Reveal>

          <h1 className="mt-3 font-display text-4xl font-semibold leading-[1.05] tracking-tight text-balance sm:text-5xl lg:text-6xl">
            <WordReveal text={title} className="block" initialDelay={0.1} />
            {titleAccent && (
              <WordReveal
                text={titleAccent}
                className="block"
                wordClassName="text-gradient-brand"
                initialDelay={0.28}
              />
            )}
          </h1>

          {(subtitle || cta || children) && (
            <Stagger
              staggerDelay={0.1}
              delayChildren={titleAccent ? 0.5 : 0.4}
              className={
                centered ? "flex flex-col items-center gap-8" : "flex flex-col items-start gap-8"
              }
            >
              {subtitle && (
                <StaggerItem>
                  <p className="mt-5 max-w-2xl text-muted-foreground text-balance sm:text-lg">
                    {subtitle}
                  </p>
                </StaggerItem>
              )}

              {cta && (
                <StaggerItem
                  className={
                    centered
                      ? "flex w-full flex-col items-center gap-3 sm:w-auto sm:flex-row"
                      : "flex w-full flex-col items-start gap-3 sm:w-auto sm:flex-row"
                  }
                >
                  {cta}
                </StaggerItem>
              )}

              {children && <StaggerItem>{children}</StaggerItem>}
            </Stagger>
          )}
        </div>
      </div>
    </section>
  );
}
