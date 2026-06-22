import { ImageResponse } from "next/og";

import { OG_CONTENT_TYPE, OG_SIZE } from "@/lib/og";

// Site-wide default Open Graph / Twitter card (brand orange #F26D0E on a deep
// warm-black gradient). Per-route segments shadow this by adding their own
// `opengraph-image.tsx`. Generated at build time + statically cached; no
// runtime/network dependency (Satori falls back to the bundled Geist font).
//
// This is the marquee card, so it keeps a bespoke layout (wordmark + headline
// + trust badges) rather than the generic `ogCard` template used elsewhere.

export const alt = "Qeet ID — One Identity. Every Platform.";
export const size = OG_SIZE;
export const contentType = OG_CONTENT_TYPE;

export default async function Image() {
  return new ImageResponse(
    (
      <div
        style={{
          width: "100%",
          height: "100%",
          display: "flex",
          flexDirection: "column",
          background: "#0B0A09",
          color: "#FAFAF9",
          padding: 80,
          fontFamily: "Geist, 'Geist Sans', system-ui, -apple-system, sans-serif",
          position: "relative",
        }}
      >
        {/* Warm brand glow, top-right. */}
        <div
          style={{
            position: "absolute",
            top: -260,
            right: -200,
            width: 760,
            height: 760,
            borderRadius: "9999px",
            background:
              "radial-gradient(circle, #F26D0E66 0%, #EA580C22 45%, transparent 70%)",
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
            background: "linear-gradient(90deg, #F59E0B 0%, #F26D0E 45%, #EA580C 100%)",
          }}
        />

        {/* Wordmark */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 18,
            fontSize: 36,
            fontWeight: 600,
            letterSpacing: -0.5,
          }}
        >
          <div
            style={{
              width: 56,
              height: 56,
              borderRadius: 14,
              background:
                "linear-gradient(135deg, #F59E0B 0%, #F26D0E 45%, #EA580C 100%)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              fontWeight: 700,
              fontSize: 34,
              color: "#FFFFFF",
            }}
          >
            Q
          </div>
          Qeet ID
        </div>

        {/* Headline. Satori requires every multi-child div to declare
            display: flex, so we use a column-flex container with two spans. */}
        <div
          style={{
            display: "flex",
            flexDirection: "column",
            marginTop: 96,
            fontSize: 84,
            fontWeight: 700,
            letterSpacing: -2,
            lineHeight: 1.04,
            maxWidth: 1000,
          }}
        >
          <span>One identity.</span>
          <span>Every platform.</span>
        </div>

        {/* Subhead */}
        <div
          style={{
            display: "flex",
            marginTop: 30,
            fontSize: 28,
            color: "#A8A29E",
            maxWidth: 900,
            lineHeight: 1.3,
          }}
        >
          SSO · MFA · Passkeys · RBAC · Audit. Open-source identity for modern teams.
        </div>

        {/* Footer */}
        <div
          style={{
            marginTop: "auto",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            fontSize: 22,
            color: "#78716C",
          }}
        >
          <div style={{ display: "flex" }}>qeetid.com</div>
          <div style={{ display: "flex", gap: 16 }}>
            <span>SOC 2</span>
            <span style={{ opacity: 0.5 }}>·</span>
            <span>GDPR</span>
            <span style={{ opacity: 0.5 }}>·</span>
            <span>Self-hostable</span>
          </div>
        </div>
      </div>
    ),
    { ...size },
  );
}
