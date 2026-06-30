"use client";

import { useRef } from "react";
import { motion, useInView } from "motion/react";
import { Reveal, WordReveal } from "@/components/marketing/motion";

// Hub-and-spoke: 5 nodes at 72° intervals, radius 155 from centre (400, 230)
const CX = 400;
const CY = 230;
const R = 155;

const spokes = [
  { id: "app", label: "Your App", angle: -90, accent: "#22d3ee", delay: 0 },
  { id: "console", label: "Admin Console", angle: -18, accent: "#a78bfa", delay: 0.15 },
  { id: "providers", label: "Identity Providers", angle: 54, accent: "#f59e0b", delay: 0.3 },
  { id: "sdk", label: "APIs & SDKs", angle: 126, accent: "#34d399", delay: 0.45 },
  { id: "events", label: "Audit & Events", angle: 198, accent: "#f87171", delay: 0.6 },
].map((s) => ({
  ...s,
  x: CX + R * Math.cos((s.angle * Math.PI) / 180),
  y: CY + R * Math.sin((s.angle * Math.PI) / 180),
}));

function labelAnchor(x: number): "middle" | "start" | "end" {
  if (x < CX - 40) return "end";
  if (x > CX + 40) return "start";
  return "middle";
}

function labelDy(y: number): number {
  return y < CY ? -32 : 42;
}

export function Architecture() {
  const ref = useRef<HTMLDivElement>(null);
  const inView = useInView(ref, { once: true, margin: "-100px 0px" });

  return (
    <section className="border-b border-border/60">
      <div ref={ref} className="mx-auto max-w-7xl px-4 py-20 sm:px-6 lg:px-8 lg:py-28">
        <Reveal className="mx-auto max-w-2xl text-center">
          <p className="text-sm font-medium uppercase tracking-widest text-brand-text">
            Architecture
          </p>
          <h2 className="mt-2 font-display text-3xl font-semibold tracking-tight text-balance sm:text-5xl">
            <WordReveal text="One platform." className="block" />
            <WordReveal
              text="Complete identity."
              className="block text-muted-foreground"
              initialDelay={0.28}
            />
          </h2>
          <p className="mt-4 text-base text-muted-foreground text-balance">
            A single trust boundary for every authentication event, authorization decision, and
            audit trail — across all your apps.
          </p>
        </Reveal>

        <div className="mt-14 flex justify-center">
          <svg
            viewBox="0 0 800 460"
            className="w-full max-w-2xl"
            aria-label="Qeet ID platform architecture: hub-and-spoke diagram"
            role="img"
          >
            <defs>
              <pattern id="arch-grid" x="0" y="0" width="40" height="40" patternUnits="userSpaceOnUse">
                <path
                  d="M 40 0 L 0 0 0 40"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="0.4"
                  opacity="0.08"
                />
              </pattern>
              <radialGradient id="center-glow" cx="50%" cy="50%" r="50%">
                <stop offset="0%" stopColor="#F26D0E" stopOpacity="0.35" />
                <stop offset="100%" stopColor="#F26D0E" stopOpacity="0" />
              </radialGradient>
            </defs>

            <rect width="800" height="460" fill="url(#arch-grid)" />

            {/* Connection lines — draw in on scroll */}
            {spokes.map((s) => (
              <motion.line
                key={`line-${s.id}`}
                x1={CX}
                y1={CY}
                x2={s.x}
                y2={s.y}
                stroke={s.accent}
                strokeWidth="1.5"
                strokeLinecap="round"
                strokeOpacity="0.55"
                strokeDasharray={R}
                initial={{ strokeDashoffset: R }}
                animate={inView ? { strokeDashoffset: 0 } : {}}
                transition={{ duration: 0.75, delay: s.delay, ease: "easeOut" }}
              />
            ))}

            {/* Center ambient glow */}
            <circle cx={CX} cy={CY} r="64" fill="url(#center-glow)" />

            {/* Center node */}
            <motion.g
              initial={{ scale: 0, opacity: 0 }}
              animate={inView ? { scale: 1, opacity: 1 } : {}}
              transition={{ duration: 0.5, ease: [0.21, 0.47, 0.32, 0.98] }}
              style={{ transformOrigin: `${CX}px ${CY}px` }}
            >
              <circle cx={CX} cy={CY} r="42" fill="#F26D0E" fillOpacity="0.12" />
              <circle cx={CX} cy={CY} r="30" fill="#F26D0E" fillOpacity="0.2" />
              <circle cx={CX} cy={CY} r="20" fill="#F26D0E" />
              <text
                x={CX}
                y={CY + 42}
                textAnchor="middle"
                fill="currentColor"
                fontSize="13"
                fontWeight="600"
                fontFamily="var(--font-display, sans-serif)"
                opacity="0.9"
              >
                Qeet ID
              </text>
            </motion.g>

            {/* Spoke nodes */}
            {spokes.map((s) => (
              <motion.g
                key={s.id}
                initial={{ scale: 0, opacity: 0 }}
                animate={inView ? { scale: 1, opacity: 1 } : {}}
                transition={{ duration: 0.4, delay: s.delay + 0.5, ease: [0.21, 0.47, 0.32, 0.98] }}
                style={{ transformOrigin: `${s.x}px ${s.y}px` }}
              >
                <circle
                  cx={s.x}
                  cy={s.y}
                  r="26"
                  fill="none"
                  stroke={s.accent}
                  strokeWidth="1"
                  strokeOpacity="0.4"
                />
                <circle cx={s.x} cy={s.y} r="17" fill={s.accent} fillOpacity="0.12" />
                <circle
                  cx={s.x}
                  cy={s.y}
                  r="17"
                  fill="none"
                  stroke={s.accent}
                  strokeWidth="1.5"
                />
                <text
                  x={s.x}
                  y={s.y + labelDy(s.y)}
                  textAnchor={labelAnchor(s.x)}
                  fill="currentColor"
                  fontSize="11"
                  fontWeight="500"
                  opacity="0.75"
                >
                  {s.label}
                </text>
              </motion.g>
            ))}
          </svg>
        </div>
      </div>
    </section>
  );
}
