"use client";

import { motion, useReducedMotion } from "motion/react";
import type { CSSProperties } from "react";

type WordRevealProps = {
  text: string;
  className?: string;
  /**
   * Classes applied to each word span (not the container). Use this for
   * gradient/clip-text styling (e.g. "text-gradient-brand"): applying a
   * `background-clip: text` gradient to the container would be clipped away by
   * the per-word `transform`, rendering the words invisible — so the gradient
   * must live on the (transformed) word spans themselves.
   */
  wordClassName?: string;
  /** Per-word stagger in seconds. */
  staggerDelay?: number;
  /** Delay before the first word begins. */
  initialDelay?: number;
  /** Per-word animation duration. */
  duration?: number;
  /** Pixel distance each word translates from. */
  distance?: number;
};

// Bulletproof visually-hidden style for the screen-reader copy — does not rely
// on the `.sr-only` utility being present/generated in this app's CSS.
const visuallyHidden: CSSProperties = {
  position: "absolute",
  width: 1,
  height: 1,
  padding: 0,
  margin: -1,
  overflow: "hidden",
  clip: "rect(0, 0, 0, 0)",
  whiteSpace: "nowrap",
  borderWidth: 0,
};

function classes(...parts: Array<string | undefined>) {
  return parts.filter(Boolean).join(" ");
}

/**
 * Word-by-word reveal for display headlines. Each non-whitespace token fades +
 * rises into place with a small stagger. The full sentence is rendered
 * visually-hidden (for screen readers) while the animated words are
 * `aria-hidden`, so AT reads one phrase instead of enumerating word spans.
 * Reduced-motion users get the plain text. Pass gradient/clip-text styling via
 * `wordClassName` (see note above).
 *
 * Ported from qeet-in (src/components/motion/WordReveal.tsx).
 */
export function WordReveal({
  text,
  className,
  wordClassName,
  staggerDelay = 0.06,
  initialDelay = 0.15,
  duration = 0.7,
  distance = 18,
}: WordRevealProps) {
  const reduce = useReducedMotion();

  if (reduce) {
    // No animation: render the phrase once, applying both container + word
    // styling (so a gradient still shows) — no duplicate, no hidden copy.
    return <span className={classes(className, wordClassName)}>{text}</span>;
  }

  const tokens = text.split(/(\s+)/);
  let wordIndex = 0;

  return (
    <span className={className}>
      <span style={visuallyHidden}>{text}</span>
      <span aria-hidden="true">
        {tokens.map((tok, i) => {
          if (/^\s+$/.test(tok)) {
            return <span key={i}>{tok}</span>;
          }
          const myIndex = wordIndex++;
          return (
            <motion.span
              key={i}
              className={classes("inline-block will-change-transform", wordClassName)}
              initial={{ opacity: 0, y: distance }}
              animate={{ opacity: 1, y: 0 }}
              transition={{
                duration,
                delay: initialDelay + myIndex * staggerDelay,
                ease: [0.16, 1, 0.3, 1],
              }}
            >
              {tok}
            </motion.span>
          );
        })}
      </span>
    </span>
  );
}
