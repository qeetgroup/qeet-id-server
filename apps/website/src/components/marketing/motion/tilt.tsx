"use client";

import { motion, useMotionValue, useReducedMotion, useSpring, useTransform } from "motion/react";
import { type PointerEvent, type ReactNode, useRef } from "react";

type TiltProps = {
  children: ReactNode;
  className?: string;
  /** Maximum tilt in degrees at the card's edges. */
  max?: number;
  /** CSS perspective applied to the wrapper. */
  perspective?: number;
};

/**
 * Subtle 3D tilt toward the pointer on hover. Tracks the cursor across the
 * element and rotates on X/Y (spring-smoothed), resetting on leave. No-ops for
 * touch pointers and for reduced-motion users (static wrapper). Wrap a card.
 */
export function Tilt({ children, className, max = 8, perspective = 800 }: TiltProps) {
  const reduce = useReducedMotion();
  const ref = useRef<HTMLDivElement>(null);

  // -0.5..0.5 normalized pointer position within the element.
  const px = useMotionValue(0);
  const py = useMotionValue(0);
  const rotateX = useSpring(useTransform(py, [-0.5, 0.5], [max, -max]), {
    stiffness: 200,
    damping: 20,
  });
  const rotateY = useSpring(useTransform(px, [-0.5, 0.5], [-max, max]), {
    stiffness: 200,
    damping: 20,
  });

  if (reduce) {
    return <div className={className}>{children}</div>;
  }

  const handleMove = (e: PointerEvent<HTMLDivElement>) => {
    if (e.pointerType !== "mouse") return;
    const el = ref.current;
    if (!el) return;
    const rect = el.getBoundingClientRect();
    px.set((e.clientX - rect.left) / rect.width - 0.5);
    py.set((e.clientY - rect.top) / rect.height - 0.5);
  };

  const reset = () => {
    px.set(0);
    py.set(0);
  };

  return (
    <motion.div
      ref={ref}
      className={className}
      style={{ rotateX, rotateY, transformPerspective: perspective }}
      onPointerMove={handleMove}
      onPointerLeave={reset}
    >
      {children}
    </motion.div>
  );
}
