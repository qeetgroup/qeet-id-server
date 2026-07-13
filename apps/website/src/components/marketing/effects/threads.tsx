import { cn } from "@qeetrix/ui";
import type { CSSProperties } from "react";

type ThreadsProps = {
  className?: string;
  color?: string;
};

const threadPaths = [
  "M -200,60 C 100,40 300,80 500,55 S 900,35 1400,60",
  "M -200,110 C 50,95 250,125 550,105 S 950,85 1400,115",
  "M -200,165 C 120,148 320,175 580,158 S 950,140 1400,168",
  "M -200,225 C 80,212 280,238 520,220 S 900,200 1400,228",
  "M -200,285 C 130,270 330,298 600,278 S 1000,260 1400,288",
  "M -200,345 C 60,332 260,358 540,338 S 950,320 1400,348",
  "M -200,400 C 100,385 300,415 580,395 S 980,375 1400,405",
];

const durations = [14, 11, 16, 13, 15, 12, 17];
const delays = [0, 2.5, 1, 3.5, 0.5, 2, 1.5];

export function Threads({ className, color = "rgba(242,109,14,0.1)" }: ThreadsProps) {
  return (
    <div
      aria-hidden
      className={cn("pointer-events-none absolute inset-0 overflow-hidden", className)}
    >
      <svg
        viewBox="0 0 1200 460"
        preserveAspectRatio="xMidYMid slice"
        className="absolute inset-0 h-full w-full"
      >
        {threadPaths.map((d, i) => (
          <path
            key={i}
            d={d}
            fill="none"
            stroke={color}
            strokeWidth="1.5"
            strokeLinecap="round"
            strokeDasharray="8 20"
            style={
              {
                animation: `thread-flow ${durations[i]}s linear ${delays[i]}s infinite`,
              } as CSSProperties
            }
          />
        ))}
      </svg>
    </div>
  );
}
