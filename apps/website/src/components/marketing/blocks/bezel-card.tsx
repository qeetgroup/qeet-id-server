import { cn } from "@qeetrix/ui";
import type { ReactNode } from "react";

/**
 * Double-bezel ("machined hardware") enclosure: a glass plate sitting in an
 * aluminium tray. An outer shell with a hairline ring + faint fill holds an
 * inner core with a concentric (smaller) radius and a top inset highlight, so
 * cards read as physical objects rather than flat rectangles.
 *
 * Radii are concentric by construction: outer 1.75rem, inner 1.375rem (outer
 * minus the 0.375rem / p-1.5 shell padding).
 */
type BezelCardProps = {
  children: ReactNode;
  /** Inner core classes (background, padding, layout). */
  className?: string;
  /** Outer shell classes. */
  shellClassName?: string;
  /** Warm-tinted shell + ring for the highlighted item in a set. */
  featured?: boolean;
};

export function BezelCard({ children, className, shellClassName, featured }: BezelCardProps) {
  return (
    <div
      className={cn(
        "h-full rounded-[1.75rem] p-1.5 ring-1 transition-colors duration-500",
        featured
          ? "bg-brand/8 ring-brand/40 shadow-lg shadow-brand/15 dark:bg-brand/12 dark:ring-brand/50"
          : "bg-foreground/3 ring-black/6 dark:bg-white/3 dark:ring-white/10",
        shellClassName,
      )}
    >
      <div
        className={cn(
          "relative flex h-full flex-col overflow-hidden rounded-[1.375rem] bg-card shadow-[inset_0_1px_0_rgba(255,255,255,0.65)] dark:shadow-[inset_0_1px_0_rgba(255,255,255,0.06)]",
          className,
        )}
      >
        {children}
      </div>
    </div>
  );
}
