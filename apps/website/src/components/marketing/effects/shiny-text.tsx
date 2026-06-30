import { cn } from "@qeetrix/ui";
import type { CSSProperties, ReactNode } from "react";

type ShinyTextProps = {
  children: ReactNode;
  className?: string;
  speed?: number;
  disabled?: boolean;
};

/** Sweeps a white shimmer highlight over any text. Adapts to any text color. */
export function ShinyText({ children, className, speed = 3, disabled = false }: ShinyTextProps) {
  return (
    <span className={cn("relative inline-block overflow-hidden", className)}>
      {children}
      {!disabled && (
        <span
          aria-hidden
          className="pointer-events-none absolute inset-0"
          style={
            {
              backgroundImage:
                "linear-gradient(110deg, transparent 25%, rgba(255,255,255,0.28) 50%, transparent 75%)",
              backgroundSize: "300% 100%",
              animation: `shimmer ${speed}s linear infinite`,
            } as CSSProperties
          }
        />
      )}
    </span>
  );
}
