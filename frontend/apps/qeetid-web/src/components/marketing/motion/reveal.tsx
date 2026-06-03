"use client";

import { motion, useReducedMotion } from "motion/react";
import type { ReactNode } from "react";

type RevealProps = {
  children: ReactNode;
  className?: string;
  /** Delay in seconds before the animation starts. */
  delay?: number;
  /** Duration of the animation in seconds. */
  duration?: number;
  /** Pixel distance to rise from. */
  distance?: number;
  /** Custom cubic-bezier easing; defaults to a soft "out-expo"-ish curve. */
  ease?: [number, number, number, number];
};

/**
 * In-view fade + rise. Fires once when the element scrolls into view (with a
 * -10% margin so it triggers a beat after the edge appears). This is the general
 * workhorse reveal for sections/cards; `FadeRise` is the lighter-weight default.
 * Reduced-motion users get the final state with no transform/opacity animation.
 */
export function Reveal({
  children,
  className,
  delay = 0,
  duration = 0.6,
  distance = 16,
  ease = [0.16, 1, 0.3, 1],
}: RevealProps) {
  const reduce = useReducedMotion();

  if (reduce) {
    return <div className={className}>{children}</div>;
  }

  return (
    <motion.div
      className={className}
      initial={{ opacity: 0, y: distance }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: "-10% 0px" }}
      transition={{ duration, delay, ease }}
    >
      {children}
    </motion.div>
  );
}
