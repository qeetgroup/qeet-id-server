import { cn } from "@qeetid/ui";
import type * as React from "react";

export function BrandHero({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      className={cn("relative hidden bg-muted md:block dark:brightness-[0.85]", className)}
      {...props}
    >
      <svg
        xmlns="http://www.w3.org/2000/svg"
        viewBox="0 0 800 1000"
        preserveAspectRatio="xMidYMid slice"
        className="absolute inset-0 h-full w-full"
        aria-hidden="true"
      >
        <defs>
          <linearGradient id="brand-hero-gradient" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stopColor="#0a0a0a" />
            <stop offset="100%" stopColor="#262626" />
          </linearGradient>
        </defs>
        <rect width="800" height="1000" fill="url(#brand-hero-gradient)" />
        <g fill="#ffffff" fillOpacity="0.06">
          <circle cx="120" cy="160" r="220" />
          <circle cx="680" cy="820" r="260" />
        </g>
        <g fill="#ffffff" textAnchor="middle" style={{ fontFamily: "var(--font-display)" }}>
          <text x="400" y="500" fontSize="92" fontWeight="700" letterSpacing="-2">
            Q.E.E.T ID
          </text>
          <text
            x="400"
            y="560"
            fontSize="26"
            fontWeight="500"
            fillOpacity="0.85"
            style={{ fontFamily: "var(--font-ui)" }}
          >
            Admin Console
          </text>
        </g>
      </svg>
    </div>
  );
}
