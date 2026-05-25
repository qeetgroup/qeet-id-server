import type { ComponentPropsWithoutRef, CSSProperties } from "react";
import { cn } from "@/lib/cn";

type RippleProps = ComponentPropsWithoutRef<"div"> & {
  mainCircleSize?: number;
  mainCircleOpacity?: number;
  numCircles?: number;
};

export function Ripple({
  mainCircleSize = 210,
  mainCircleOpacity = 0.24,
  numCircles = 8,
  className,
  ...props
}: RippleProps) {
  return (
    <div className={cn("pointer-events-none absolute inset-0 select-none", className)} {...props}>
      {Array.from({ length: numCircles }, (_, i) => {
        const size = mainCircleSize + i * 70;
        const opacity = mainCircleOpacity - i * 0.03;

        return (
          <div
            key={`ripple-${size}`}
            className="absolute animate-ripple rounded-full border bg-fd-foreground/10 shadow-xl"
            style={
              {
                "--i": i,
                width: `${size}px`,
                height: `${size}px`,
                opacity,
                animationDelay: `${i * 0.06}s`,
                borderStyle: "solid",
                borderWidth: "1px",
                borderColor: "color-mix(in oklab, var(--color-fd-foreground) 18%, transparent)",
                top: "50%",
                left: "50%",
                transform: "translate(-50%, -50%) scale(1)",
              } as CSSProperties
            }
          />
        );
      })}
    </div>
  );
}
