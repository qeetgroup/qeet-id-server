"use client";

import { motion, useReducedMotion, useScroll, useSpring } from "motion/react";

type ScrollProgressProps = {
  className?: string;
};

/**
 * Fixed top-of-page reading-progress bar. Scales on the X axis with overall page
 * scroll (via `useScroll` → spring-smoothed `scaleX`) and is filled with the
 * brand gradient. Reduced-motion users get the same bar without the spring
 * smoothing (it still tracks scroll, just instantly). Decorative → aria-hidden.
 */
export function ScrollProgress({ className }: ScrollProgressProps) {
  const reduce = useReducedMotion();
  const { scrollYProgress } = useScroll();
  const smooth = useSpring(scrollYProgress, {
    stiffness: 140,
    damping: 24,
    restDelta: 0.001,
  });
  const scaleX = reduce ? scrollYProgress : smooth;

  return (
    <motion.div
      aria-hidden
      style={{ scaleX }}
      className={
        "fixed inset-x-0 top-0 z-60 h-0.75 origin-left bg-(image:--brand-gradient) " +
        (className ?? "")
      }
    />
  );
}
