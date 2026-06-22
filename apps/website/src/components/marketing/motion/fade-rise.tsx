"use client";

import { motion, useReducedMotion } from "motion/react";
import type { ReactNode } from "react";

type FadeRiseProps = {
  children: ReactNode;
  className?: string;
  /** Delay in seconds before the animation starts. */
  delay?: number;
  /** Duration of the animation in seconds. */
  duration?: number;
  /** Pixel distance to translate from. */
  distance?: number;
};

/**
 * Fade in + small rise on scroll-into-view. Fires once per element. The viewport
 * trigger is offset upward 10% so the animation starts a beat after the element
 * begins entering — feels less mechanical than firing the moment the edge appears.
 * Reduced-motion users get the final state with no animation.
 *
 * Ported from qeet-in (src/components/motion/FadeRise.tsx).
 */
export function FadeRise({
  children,
  className,
  delay = 0,
  duration = 0.6,
  distance = 12,
}: FadeRiseProps) {
  const reduce = useReducedMotion();

  if (reduce) {
    return <div className={className}>{children}</div>;
  }

  return (
    <motion.div
      className={className}
      initial={{ opacity: 0, y: distance }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: "0px 0px -10% 0px" }}
      transition={{ duration, delay, ease: [0.16, 1, 0.3, 1] }}
    >
      {children}
    </motion.div>
  );
}
