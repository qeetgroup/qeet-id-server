"use client";

import { cn } from "@qeetrix/ui";
import { motion, useReducedMotion } from "motion/react";

type BlurTextProps = {
  text: string;
  className?: string;
  /** Initial delay in seconds before the first word animates. */
  delay?: number;
  /** Stagger delay per word in seconds. */
  wordDelay?: number;
};

/** Reveals text word-by-word with a blur-in + rise entrance. */
export function BlurText({ text, className, delay = 0, wordDelay = 0.05 }: BlurTextProps) {
  const reduceMotion = useReducedMotion();
  const words = text.split(" ");

  if (reduceMotion) {
    return <span className={cn("inline", className)}>{text}</span>;
  }

  return (
    <span className={cn("inline", className)} aria-label={text}>
      {words.map((word, i) => (
        <motion.span
          key={`${word}-${i}`}
          initial={{ opacity: 0, filter: "blur(12px)", y: 6 }}
          animate={{ opacity: 1, filter: "blur(0px)", y: 0 }}
          transition={{
            duration: 0.5,
            delay: delay + i * wordDelay,
            ease: [0.21, 0.47, 0.32, 0.98],
          }}
          className="inline-block"
          aria-hidden
          style={{ marginRight: "0.25em" }}
        >
          {word}
        </motion.span>
      ))}
    </span>
  );
}
