"use client";

import { useEffect, useState } from "react";

type CyclingTextProps = {
  items: string[];
  /** ms between cycles */
  interval?: number;
  /** ms for crossfade duration */
  fadeMs?: number;
  className?: string;
};

/**
 * Rotates through a list of strings with a crossfade.
 * Used inside the docs hero search bar to suggest queries.
 */
export function CyclingText({ items, interval = 2800, fadeMs = 280, className }: CyclingTextProps) {
  const [index, setIndex] = useState(0);
  const [visible, setVisible] = useState(true);

  useEffect(() => {
    if (items.length < 2) return;
    const id = setInterval(() => {
      setVisible(false);
      const swap = setTimeout(() => {
        setIndex((i) => (i + 1) % items.length);
        setVisible(true);
      }, fadeMs);
      return () => clearTimeout(swap);
    }, interval);
    return () => clearInterval(id);
  }, [items.length, interval, fadeMs]);

  return (
    <span
      className={className}
      style={{
        opacity: visible ? 1 : 0,
        transition: `opacity ${fadeMs}ms ease`,
      }}
    >
      {items[index]}
    </span>
  );
}
