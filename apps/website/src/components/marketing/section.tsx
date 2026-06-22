import { cn } from "@qeetrix/ui";
import type { ReactNode } from "react";

import { Reveal, WordReveal } from "@/components/marketing/motion";

type SectionProps = {
  children: ReactNode;
  className?: string;
  /** Apply the muted band background (alternating sections). */
  muted?: boolean;
  /** Inner container className override (defaults to a 7xl padded shell). */
  innerClassName?: string;
  /** HTML id for in-page anchors. */
  id?: string;
  /** Optional aria-label for the section landmark. */
  "aria-label"?: string;
};

/**
 * Standard marketing section band: full-bleed `<section>` with the shared
 * border + optional muted background, wrapping a centered max-w container.
 * Matches the visual rhythm of the existing premium sections.
 */
export function Section({
  children,
  className,
  muted,
  innerClassName,
  id,
  "aria-label": ariaLabel,
}: SectionProps) {
  return (
    <section
      id={id}
      aria-label={ariaLabel}
      className={cn("border-b border-border/60", muted && "bg-muted/30", className)}
    >
      <div
        className={cn(
          "mx-auto max-w-7xl px-4 py-20 sm:px-6 lg:px-8 lg:py-28",
          innerClassName,
        )}
      >
        {children}
      </div>
    </section>
  );
}

type SectionHeaderProps = {
  /** Optional small eyebrow above the heading. */
  eyebrow?: string;
  /** Heading text. */
  title: string;
  /** Trailing phrase rendered with the brand gradient via WordReveal. */
  titleAccent?: string;
  /** Supporting copy under the heading. */
  subtitle?: ReactNode;
  /** Center the header (default) or left-align it. */
  align?: "center" | "left";
  className?: string;
};

/**
 * Reveal-animated section heading with an optional eyebrow, brand-gradient
 * accent phrase, and subtitle. Reuses `WordReveal` for the accent so the
 * gradient lives on the transformed word spans (per its API).
 */
export function SectionHeader({
  eyebrow,
  title,
  titleAccent,
  subtitle,
  align = "center",
  className,
}: SectionHeaderProps) {
  const centered = align === "center";
  return (
    <Reveal
      className={cn(
        centered ? "mx-auto max-w-2xl text-center" : "max-w-2xl text-left",
        className,
      )}
    >
      {eyebrow && (
        <p className="text-sm font-medium uppercase tracking-widest text-brand-text">{eyebrow}</p>
      )}
      <h2 className="mt-2 font-display text-3xl font-semibold tracking-tight text-balance sm:text-4xl">
        {title}
        {titleAccent && (
          <>
            {" "}
            <WordReveal text={titleAccent} wordClassName="text-gradient-brand" initialDelay={0.25} />
          </>
        )}
      </h2>
      {subtitle && <p className="mt-4 text-muted-foreground text-balance sm:text-lg">{subtitle}</p>}
    </Reveal>
  );
}
