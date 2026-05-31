import { cn } from "@qeetrix/ui";

/**
 * Customer logo block: a curated grid (not a marquee) suitable for
 * hero sections, feature pages, and the customers page header. Use
 * this when the goal is to show *which* customers; use `<LogoCloud>`
 * (the scrolling marquee) when the goal is to convey breadth.
 *
 * Logos accept either a textual wordmark or an `image` URL — wordmarks
 * keep the marketing site image-budget low.
 */
export interface CustomerLogo {
  /** Display name (also used for `alt` if an image is supplied). */
  name: string;
  /** Optional image URL (e.g. `/logos/lattice.svg`). */
  image?: string;
}

export interface CustomerLogoBlockProps {
  /** Optional eyebrow text rendered above the grid. */
  eyebrow?: string;
  /** Optional headline rendered below the eyebrow. */
  headline?: string;
  /** Logos to display, in render order. */
  logos: CustomerLogo[];
  /** Tailwind classes appended to the outer `<section>`. */
  className?: string;
  /**
   * How many columns to show at each breakpoint. Defaults to a
   * sensible 3 / 4 / 6 progression.
   */
  columns?: {
    base?: number;
    sm?: number;
    lg?: number;
  };
}

function columnsClass(c?: number, prefix?: string) {
  if (!c) return "";
  const px = prefix ? `${prefix}:` : "";
  // Tailwind safelist note: these strings appear verbatim so JIT picks
  // them up. Add a new column count to the project's safelist if you
  // pass a value outside 1–6.
  const lookup: Record<number, string> = {
    1: `${px}grid-cols-1`,
    2: `${px}grid-cols-2`,
    3: `${px}grid-cols-3`,
    4: `${px}grid-cols-4`,
    5: `${px}grid-cols-5`,
    6: `${px}grid-cols-6`,
  };
  return lookup[c] ?? "";
}

export function CustomerLogoBlock({
  eyebrow,
  headline,
  logos,
  className,
  columns = { base: 3, sm: 4, lg: 6 },
}: CustomerLogoBlockProps) {
  return (
    <section className={cn("border-b border-border/60", className)}>
      <div className="mx-auto max-w-7xl px-4 py-14 sm:px-6 lg:px-8">
        {(eyebrow || headline) && (
          <div className="mx-auto mb-10 max-w-2xl text-center">
            {eyebrow && (
              <p className="text-xs font-medium uppercase tracking-widest text-muted-foreground">
                {eyebrow}
              </p>
            )}
            {headline && (
              <h2 className="mt-3 font-display text-2xl font-semibold tracking-tight sm:text-3xl">
                {headline}
              </h2>
            )}
          </div>
        )}
        <div
          className={cn(
            "grid items-center gap-x-8 gap-y-6",
            columnsClass(columns.base),
            columnsClass(columns.sm, "sm"),
            columnsClass(columns.lg, "lg"),
          )}
        >
          {logos.map((l) =>
            l.image ? (
              // eslint-disable-next-line @next/next/no-img-element
              <img
                key={l.name}
                src={l.image}
                alt={l.name}
                className="mx-auto h-8 w-auto opacity-70 transition-opacity hover:opacity-100"
                loading="lazy"
              />
            ) : (
              <span
                key={l.name}
                className="text-center font-display text-lg font-medium tracking-tight text-muted-foreground/70 transition-colors hover:text-foreground"
              >
                {l.name}
              </span>
            ),
          )}
        </div>
      </div>
    </section>
  );
}
