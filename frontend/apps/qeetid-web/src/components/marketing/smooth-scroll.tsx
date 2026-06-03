"use client";

import { useReducedMotion } from "motion/react";
import { useEffect, type ReactNode } from "react";

import Lenis from "lenis";

type SmoothScrollProps = {
  children: ReactNode;
};

/**
 * Lenis-powered smooth scrolling for the marketing pages. Drives Lenis from our
 * own rAF loop (`autoRaf: false`) so we own teardown cleanly. Does NOTHING when
 * the user prefers reduced motion — it just renders children, leaving native
 * scroll untouched. Mount once, high in the marketing layout, wrapping the page.
 *
 * `children` is a server-rendered slot (the supported Next.js interleaving
 * pattern), so wrapping it here does not force the page tree to be client-side.
 */
export function SmoothScroll({ children }: SmoothScrollProps) {
  const reduce = useReducedMotion();

  useEffect(() => {
    if (reduce) return;

    const lenis = new Lenis({
      duration: 1.1,
      // Soft "out-expo"-style easing for a premium, weighty feel.
      easing: (t) => Math.min(1, 1.001 - 2 ** (-10 * t)),
      smoothWheel: true,
      autoRaf: false,
    });

    let rafId = 0;
    const raf = (time: number) => {
      lenis.raf(time);
      rafId = requestAnimationFrame(raf);
    };
    rafId = requestAnimationFrame(raf);

    return () => {
      cancelAnimationFrame(rafId);
      lenis.destroy();
    };
  }, [reduce]);

  return <>{children}</>;
}
