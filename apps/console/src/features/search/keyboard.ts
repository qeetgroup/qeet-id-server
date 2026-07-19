// Keyboard utilities for the universal search palette.
// Pure functions — no DOM dependency so they are safe to unit-test in Node.

export type NavigationDirection = "up" | "down";

/**
 * Clamp an index within [0, totalItems - 1].
 * Returns 0 when totalItems is 0.
 */
export function clampHighlight(index: number, totalItems: number): number {
  if (totalItems === 0) return 0;
  return Math.min(totalItems - 1, Math.max(0, index));
}

/**
 * Move the highlight index by one step, clamped at the list boundaries
 * (no wrapping — matches the Linear / GitHub command-palette style).
 */
export function moveHighlight(
  current: number,
  direction: NavigationDirection,
  totalItems: number,
): number {
  if (direction === "down") return clampHighlight(current + 1, totalItems);
  return clampHighlight(current - 1, totalItems);
}
