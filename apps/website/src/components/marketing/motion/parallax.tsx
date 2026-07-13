"use client";

import { motion, useReducedMotion, useScroll, useTransform } from "motion/react";
import { type ReactNode, useRef } from "react";

type ParallaxProps = {
  children: ReactNode;
  className?: string;
  /**
   * Total travel in pixels across the element's scroll pass. The element moves
   * from +offset to -offset as it travels through the viewport. Keep it gentle.
   */
  offset?: number;
};

/**
 * Scroll-linked vertical parallax. Translates the element on the Y axis as it
 * passes through the viewport, driven by `useScroll`/`useTransform` (no rAF of
 * our own — Motion owns the frame loop). Reduced-motion users get a static,
 * untranslated wrapper.
 */
export function Parallax({ children, className, offset = 40 }: ParallaxProps) {
  const reduce = useReducedMotion();
  const ref = useRef<HTMLDivElement>(null);

  // Hooks must run unconditionally; we just ignore the output when reduced.
  const { scrollYProgress } = useScroll({
    target: ref,
    offset: ["start end", "end start"],
  });
  const y = useTransform(scrollYProgress, [0, 1], [offset, -offset]);

  if (reduce) {
    return (
      <div ref={ref} className={className}>
        {children}
      </div>
    );
  }

  return (
    <motion.div ref={ref} className={className} style={{ y }}>
      {children}
    </motion.div>
  );
}
