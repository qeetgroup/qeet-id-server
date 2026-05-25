import { cn } from "@/lib/cn";
import type { CSSProperties } from "react";

type BorderBeamProps = {
  className?: string;
  size?: number;
  duration?: number;
  delay?: number;
  colorFrom?: string;
  colorTo?: string;
};

export function BorderBeam({
  className,
  size = 220,
  duration = 8,
  delay = 0,
  colorFrom = "var(--color-fd-primary)",
  colorTo = "#22d3ee",
}: BorderBeamProps) {
  return (
    <div
      aria-hidden
      style={
        {
          "--beam-size": `${size}px`,
          "--beam-duration": duration,
          "--beam-delay": `-${delay}s`,
          "--beam-from": colorFrom,
          "--beam-to": colorTo,
        } as CSSProperties
      }
      className={cn(
        "pointer-events-none absolute inset-0 rounded-[inherit] [border:1px_solid_transparent] [mask-clip:padding-box,border-box] [mask-composite:intersect] [mask-image:linear-gradient(transparent,transparent),linear-gradient(black,black)]",
        "after:absolute after:aspect-square after:w-[var(--beam-size)] after:animate-border-beam after:[offset-anchor:90%_50%] after:[offset-path:rect(0_auto_auto_0_round_var(--beam-size))] after:[background:linear-gradient(to_left,var(--beam-from),var(--beam-to),transparent)] after:[animation-delay:var(--beam-delay)]",
        className,
      )}
    />
  );
}
