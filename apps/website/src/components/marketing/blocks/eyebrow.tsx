import { cn } from "@qeetrix/ui";
import type { ReactNode } from "react";

/**
 * Premium eyebrow tag — a microscopic pill badge that precedes major headings,
 * with a glowing brand dot. Replaces bare uppercase labels for a more crafted,
 * enterprise feel. Sits on a faint glass fill so it reads on any section band.
 */
export function Eyebrow({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-2 rounded-full border border-border/70 bg-background/60 py-1 pl-2.5 pr-3 text-[10px] font-medium uppercase tracking-[0.2em] text-muted-foreground backdrop-blur-sm",
        className,
      )}
    >
      <span
        aria-hidden
        className="size-1.5 rounded-full bg-brand shadow-[0_0_8px_var(--brand-500)]"
      />
      {children}
    </span>
  );
}
