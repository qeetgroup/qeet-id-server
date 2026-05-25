import { cn } from "@/lib/cn";
import type { CSSProperties, ReactNode } from "react";

type MarqueeProps = {
  children: ReactNode;
  className?: string;
  reverse?: boolean;
  pauseOnHover?: boolean;
  repeat?: number;
  duration?: number;
  gap?: string;
};

export function Marquee({
  children,
  className,
  reverse = false,
  pauseOnHover = false,
  repeat = 4,
  duration = 40,
  gap = "2rem",
}: MarqueeProps) {
  return (
    <div
      className={cn("group flex flex-row overflow-hidden", className)}
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
            "flex shrink-0 flex-row justify-around animate-marquee",
            reverse && "[animation-direction:reverse]",
            pauseOnHover && "group-hover:[animation-play-state:paused]",
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
