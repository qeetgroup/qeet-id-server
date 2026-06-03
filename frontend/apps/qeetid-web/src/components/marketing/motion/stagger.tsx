"use client";

import { motion, useReducedMotion, type Variants } from "motion/react";
import type { ReactNode } from "react";

type StaggerProps = {
  children: ReactNode;
  className?: string;
  /** Seconds between each child's entrance. */
  staggerDelay?: number;
  /** Delay in seconds before the first child begins. */
  delayChildren?: number;
  /** Trigger only the first time the container enters the viewport. */
  once?: boolean;
};

type StaggerItemProps = {
  children: ReactNode;
  className?: string;
  /** Pixel distance each item rises from. */
  distance?: number;
  /** Per-item duration in seconds. */
  duration?: number;
};

/**
 * Container that staggers the entrance of its `StaggerItem` children when it
 * scrolls into view. Pair `Stagger` with `StaggerItem` — the container owns the
 * timing, each item owns its own transform. Reduced-motion users get static
 * children (no variants, no transform).
 */
export function Stagger({
  children,
  className,
  staggerDelay = 0.08,
  delayChildren = 0,
  once = true,
}: StaggerProps) {
  const reduce = useReducedMotion();

  if (reduce) {
    return <div className={className}>{children}</div>;
  }

  const container: Variants = {
    hidden: {},
    show: {
      transition: { staggerChildren: staggerDelay, delayChildren },
    },
  };

  return (
    <motion.div
      className={className}
      variants={container}
      initial="hidden"
      whileInView="show"
      viewport={{ once, margin: "-10% 0px" }}
    >
      {children}
    </motion.div>
  );
}

/**
 * A single staggered child. Must be rendered inside a `Stagger` so it inherits
 * the container's `hidden`/`show` orchestration. Reduced-motion users get a
 * plain wrapper.
 */
export function StaggerItem({
  children,
  className,
  distance = 16,
  duration = 0.5,
}: StaggerItemProps) {
  const reduce = useReducedMotion();

  if (reduce) {
    return <div className={className}>{children}</div>;
  }

  const item: Variants = {
    hidden: { opacity: 0, y: distance },
    show: {
      opacity: 1,
      y: 0,
      transition: { duration, ease: [0.16, 1, 0.3, 1] },
    },
  };

  return (
    <motion.div className={className} variants={item}>
      {children}
    </motion.div>
  );
}
