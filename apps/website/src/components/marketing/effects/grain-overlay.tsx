/**
 * Global film-grain layer. A single fixed, non-interactive plane of fractal
 * noise blended over the whole page at very low opacity — the subtle physical
 * texture that separates "expensive" surfaces from flat digital ones. Fixed +
 * pointer-events-none per the perf guardrails (no scroll repaints, no blur).
 */
const NOISE =
  "url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='160' height='160'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.8' numOctaves='2' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E\")";

export function GrainOverlay() {
  return (
    <div
      aria-hidden
      className="pointer-events-none fixed inset-0 z-30 opacity-[0.035] mix-blend-soft-light dark:opacity-[0.06] dark:mix-blend-overlay"
      style={{ backgroundImage: NOISE }}
    />
  );
}
