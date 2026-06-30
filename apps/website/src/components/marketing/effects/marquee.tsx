import { cn } from "@qeetrix/ui";
import type { CSSProperties, ReactNode } from "react";

type MarqueeProps = {
  children: ReactNode;
  className?: string;
  reverse?: boolean;
  pauseOnHover?: boolean;
  vertical?: boolean;
  repeat?: number;
  duration?: number; // seconds
  gap?: string; // any CSS length
};

export function Marquee({
  children,
  className,
  reverse = false,
  pauseOnHover = false,
  vertical = false,
  repeat = 4,
  duration = 40,
  gap = "2rem",
}: MarqueeProps) {
  return (
    <div
      className={cn("group flex overflow-hidden", vertical ? "flex-col" : "flex-row", className)}
      style={
        {
          "--marquee-duration": `${duration}s`,
          "--marquee-gap": gap,
          gap,
        } as CSSProperties
      }
    >
      {Array.from({ length: repeat }).map((_, i) => (
        <div
          // Static repeats have no stable source id.
          key={i}
          className={cn(
            "flex shrink-0 justify-around",
            vertical ? "animate-marquee-vertical flex-col" : "animate-marquee flex-row",
            reverse && "direction-[reverse]",
            pauseOnHover && "group-hover:paused",
          )}
          style={{ gap }}
          aria-hidden={i > 0}
        >
          {children}
        </div>
      ))}
    </div>
  );
}
