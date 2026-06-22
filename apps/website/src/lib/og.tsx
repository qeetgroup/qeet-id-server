/**
 * Shared builder for the site's branded Open Graph / Twitter cards.
 *
 * Used by every file-based `opengraph-image.tsx` route. Because these images
 * are produced by Satori (`next/og` `ImageResponse`), the usual styling layers
 * are unavailable:
 *
 *   - NO Tailwind / `@qeetrix/ui` — inline `style` objects only.
 *   - Only flexbox layout (no CSS grid), and a subset of CSS properties.
 *   - Fonts must be embedded; we deliberately do NOT fetch over the network at
 *     render time (offline build). `next/og` ships a Geist fallback font that
 *     it applies automatically, so we keep a system/Geist font stack and let
 *     that fallback render the text — no local font file path to go stale.
 *
 * Brand tokens are duplicated as literals here (Satori can't read CSS vars):
 * core brand `#F26D0E`, plus the warm hero gradient from `globals.css`.
 */
import { ImageResponse } from "next/og";

/** Canonical OG card dimensions — re-exported by each route's `size`. */
export const OG_SIZE = { width: 1200, height: 630 } as const;
export const OG_CONTENT_TYPE = "image/png";

/** Brand literals mirrored from `src/app/globals.css` (Satori can't read CSS vars). */
const BRAND = {
  core: "#F26D0E",
  amber: "#F59E0B",
  ember: "#EA580C",
  /** Page background — deep warm-tinted near-black. */
  bg: "#0B0A09",
  ink: "#FAFAF9",
  muted: "#A8A29E",
} as const;

export interface OgCardOptions {
  /** Small uppercase label above the title, e.g. "Engineering" / "Pricing". */
  eyebrow?: string;
  /** The headline. Required — this is the focal point of the card. */
  title: string;
  /** Optional supporting line under the title. */
  description?: string;
  /** Optional footer tag list (e.g. blog post tags), rendered as pills. */
  tags?: string[];
}

/**
 * Builds a 1200×630 branded ImageResponse from a title/eyebrow/description.
 * Returns the `ImageResponse` directly so callers can `return ogCard(...)`.
 */
export function ogCard({ eyebrow, title, description, tags }: OgCardOptions): ImageResponse {
  // Clamp absurdly long titles so they never overflow the card.
  const safeTitle = title.length > 120 ? `${title.slice(0, 117)}…` : title;
  const safeDescription =
    description && description.length > 180 ? `${description.slice(0, 177)}…` : description;
  // Scale the headline down a touch for long titles so wrapping stays elegant.
  const titleFontSize = safeTitle.length > 64 ? 60 : safeTitle.length > 40 ? 70 : 82;

  return new ImageResponse(
    (
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          width: "100%",
          height: "100%",
          padding: "80px",
          background: BRAND.bg,
          color: BRAND.ink,
          fontFamily:
            "Geist, 'Geist Sans', system-ui, -apple-system, 'Segoe UI', sans-serif",
          position: "relative",
        }}
      >
        {/* Warm brand glow, anchored top-right (the hero gradient mood). */}
        <div
          style={{
            position: "absolute",
            top: -260,
            right: -200,
            width: 760,
            height: 760,
            borderRadius: "9999px",
            background: `radial-gradient(circle, ${BRAND.core}66 0%, ${BRAND.ember}22 45%, transparent 70%)`,
          }}
        />
        {/* Top brand hairline. */}
        <div
          style={{
            position: "absolute",
            top: 0,
            left: 0,
            right: 0,
            height: 8,
            background: `linear-gradient(90deg, ${BRAND.amber} 0%, ${BRAND.core} 45%, ${BRAND.ember} 100%)`,
          }}
        />

        {/* Wordmark row. */}
        <div style={{ display: "flex", alignItems: "center", gap: 18 }}>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              width: 56,
              height: 56,
              borderRadius: 14,
              background: `linear-gradient(135deg, ${BRAND.amber} 0%, ${BRAND.core} 45%, ${BRAND.ember} 100%)`,
              color: "#FFFFFF",
              fontSize: 34,
              fontWeight: 700,
            }}
          >
            Q
          </div>
          <div style={{ display: "flex", fontSize: 32, fontWeight: 600, letterSpacing: -0.5 }}>
            Qeet&nbsp;ID
          </div>
        </div>

        {/* Spacer pushes content to the lower two-thirds. */}
        <div style={{ display: "flex", flex: 1 }} />

        {eyebrow ? (
          <div
            style={{
              display: "flex",
              fontSize: 24,
              fontWeight: 600,
              letterSpacing: 4,
              textTransform: "uppercase",
              color: BRAND.core,
              marginBottom: 22,
            }}
          >
            {eyebrow}
          </div>
        ) : null}

        <div
          style={{
            display: "flex",
            fontSize: titleFontSize,
            fontWeight: 700,
            lineHeight: 1.05,
            letterSpacing: -1.5,
            maxWidth: 1000,
          }}
        >
          {safeTitle}
        </div>

        {safeDescription ? (
          <div
            style={{
              display: "flex",
              marginTop: 28,
              fontSize: 30,
              lineHeight: 1.35,
              color: BRAND.muted,
              maxWidth: 940,
            }}
          >
            {safeDescription}
          </div>
        ) : null}

        {tags && tags.length > 0 ? (
          <div style={{ display: "flex", gap: 12, marginTop: 34 }}>
            {tags.slice(0, 4).map((tag) => (
              <div
                key={tag}
                style={{
                  display: "flex",
                  padding: "8px 18px",
                  borderRadius: 9999,
                  border: `1px solid ${BRAND.core}55`,
                  color: BRAND.ink,
                  fontSize: 22,
                  letterSpacing: 1,
                  textTransform: "uppercase",
                }}
              >
                {tag}
              </div>
            ))}
          </div>
        ) : null}
      </div>
    ),
    { ...OG_SIZE },
  );
}
