import { cn } from "@qeetrix/ui";
import type { CSSProperties } from "react";

type OrbProps = {
  className?: string;
  color?: string;
  size?: number;
  opacity?: number;
};

/** Glowing radial orb — place absolutely with centering transforms. */
export function Orb({
  className,
  color = "var(--brand-500)",
  size = 600,
  opacity = 0.85,
}: OrbProps) {
  return (
    <div
      aria-hidden
      className={cn("pointer-events-none absolute", className)}
      style={{ width: size, height: size, opacity } as CSSProperties}
    >
      {/* Outer ambient pulse ring */}
      <div
        className="absolute inset-0 rounded-full"
        style={{
          background: `radial-gradient(circle at center, ${color}25 0%, ${color}08 50%, transparent 70%)`,
          animation: "orb-pulse 5s ease-in-out infinite",
        }}
      />
      {/* Core glow body */}
      <div
        className="absolute inset-[10%] rounded-full blur-3xl"
        style={{
          background: `radial-gradient(circle at 40% 35%, ${color}55 0%, ${color}20 50%, transparent 70%)`,
        }}
      />
      {/* Inner specular highlight */}
      <div
        className="absolute inset-[32%] rounded-full blur-xl"
        style={{
          background: `radial-gradient(circle at 38% 32%, rgba(255,255,255,0.25) 0%, ${color}35 55%, transparent 78%)`,
        }}
      />
    </div>
  );
}
