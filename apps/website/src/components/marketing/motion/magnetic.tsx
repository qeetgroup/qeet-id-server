"use client";

import { motion, useMotionValue, useReducedMotion, useSpring } from "motion/react";
import { type PointerEvent, type ReactNode, useRef } from "react";

type MagneticButtonProps = {
  children: ReactNode;
  className?: string;
  /**
   * How far the element drifts toward the pointer, as a fraction of the
   * pointer's offset from center. 0.3 = subtle, 1 = sticks to the cursor.
   */
  strength?: number;
};

/**
 * Pointer-follow "magnetic" wrapper — the element eases toward the cursor while
 * hovered and springs back on leave. No-ops for touch (coarse) pointers and for
 * reduced-motion users, where it renders a plain wrapper. Use it around a
 * Button/link; it does not render its own interactive element.
 */
export function MagneticButton({ children, className, strength = 0.3 }: MagneticButtonProps) {
  const reduce = useReducedMotion();
  const ref = useRef<HTMLDivElement>(null);

  const x = useMotionValue(0);
  const y = useMotionValue(0);
  const springX = useSpring(x, { stiffness: 200, damping: 18, mass: 0.4 });
  const springY = useSpring(y, { stiffness: 200, damping: 18, mass: 0.4 });

  if (reduce) {
    return <div className={className}>{children}</div>;
  }

  const handleMove = (e: PointerEvent<HTMLDivElement>) => {
    // Ignore touch/pen — magnetism only makes sense for a hovering mouse.
    if (e.pointerType !== "mouse") return;
    const el = ref.current;
    if (!el) return;
    const rect = el.getBoundingClientRect();
    const relX = e.clientX - (rect.left + rect.width / 2);
    const relY = e.clientY - (rect.top + rect.height / 2);
    x.set(relX * strength);
    y.set(relY * strength);
  };

  const reset = () => {
    x.set(0);
    y.set(0);
  };

  return (
    <motion.div
      ref={ref}
      className={className}
      style={{ x: springX, y: springY, display: "inline-block" }}
      onPointerMove={handleMove}
      onPointerLeave={reset}
    >
      {children}
    </motion.div>
  );
}
