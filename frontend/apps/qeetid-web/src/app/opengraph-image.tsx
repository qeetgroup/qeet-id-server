import { ImageResponse } from "next/og";

// Site-wide default Open Graph / Twitter card. Per-route segments can
// shadow this by adding their own `opengraph-image.tsx`. Generated at
// build time + statically cached; no runtime dependency.

export const alt = "Qeet ID — One Identity. Every Platform.";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

export default async function Image() {
  return new ImageResponse(
    (
      <div
        style={{
          width: "100%",
          height: "100%",
          display: "flex",
          flexDirection: "column",
          background: "linear-gradient(135deg, #0f172a 0%, #1e293b 60%, #312e81 100%)",
          color: "#fff",
          padding: 80,
          fontFamily: "system-ui, -apple-system, sans-serif",
        }}
      >
        {/* Wordmark */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 16,
            fontSize: 36,
            fontWeight: 600,
            letterSpacing: -0.5,
          }}
        >
          <div
            style={{
              width: 48,
              height: 48,
              borderRadius: 12,
              background:
                "linear-gradient(135deg, #818cf8 0%, #4f46e5 50%, #1e1b4b 100%)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              fontWeight: 700,
              fontSize: 28,
            }}
          >
            Q
          </div>
          Qeet ID
        </div>

        {/* Headline. Satori (the renderer behind ImageResponse) requires
            every multi-child div to declare display: flex, so we use a
            column-flex container with two text spans instead of a <br>. */}
        <div
          style={{
            display: "flex",
            flexDirection: "column",
            marginTop: 80,
            fontSize: 78,
            fontWeight: 700,
            letterSpacing: -2,
            lineHeight: 1.05,
            maxWidth: 1000,
          }}
        >
          <span>One identity.</span>
          <span>Every platform.</span>
        </div>

        {/* Subhead */}
        <div
          style={{
            marginTop: 30,
            fontSize: 28,
            color: "#cbd5e1",
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
            color: "#94a3b8",
          }}
        >
          <div>qeetid.com</div>
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
