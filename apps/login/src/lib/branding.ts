// Per-tenant branding, delivered inline by GET /v1/oauth/login-context so the
// hosted login can render the tenant's brand on first paint (no second
// round-trip). Every field is optional; when absent we fall back to the default
// Qeet brand. The raw wire shape is snake_case (see the Go loginContext handler).

import type { CSSProperties } from "react";

export type Branding = {
  logoUrl?: string;
  primaryColor?: string;
  secondaryColor?: string;
};

export type BrandingDTO = {
  logo_url?: string;
  primary_color?: string;
  secondary_color?: string;
} | null;

export function normalizeBranding(dto?: BrandingDTO): Branding | undefined {
  if (!dto) return undefined;
  const b: Branding = {};
  if (dto.logo_url) b.logoUrl = dto.logo_url;
  if (dto.primary_color) b.primaryColor = dto.primary_color;
  if (dto.secondary_color) b.secondaryColor = dto.secondary_color;
  return Object.keys(b).length ? b : undefined;
}

// brandingVars maps a tenant's brand colors onto the @qeetrix/ui design-token
// CSS custom properties, so buttons, links, focus rings, and the brand panel
// all pick up the tenant color with no component changes. Applied via `style`
// on a wrapper element, so it cascades to descendants and overrides both the
// light and dark `:root`/.dark token values for that subtree. Returns {} when
// there's nothing to override (default Qeet look).
export function brandingVars(b?: Branding): CSSProperties {
  if (!b?.primaryColor) return {};
  const primary = b.primaryColor;
  const vars: Record<string, string> = {
    "--primary": primary,
    "--primary-foreground": readableForeground(primary),
    "--ring": primary,
    // Brand-panel gradient anchors (consumed by the auth shell).
    "--qeet-brand": primary,
    "--qeet-brand-2": b.secondaryColor ?? primary,
  };
  return vars as CSSProperties;
}

// readableForeground returns near-black or white depending on the perceived
// luminance of a hex brand color, so label text on the brand color stays
// legible. Falls back to white for non-hex inputs (e.g. named/oklch colors),
// which is the safe default for saturated brand colors.
function readableForeground(color: string): string {
  const rgb = hexToRgb(color);
  if (!rgb) return "#ffffff";
  const [r, g, b] = rgb.map((c) => {
    const s = c / 255;
    return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
  }) as [number, number, number];
  const luminance = 0.2126 * r + 0.7152 * g + 0.0722 * b;
  return luminance > 0.5 ? "#0a0a0a" : "#ffffff";
}

function hexToRgb(hex: string): [number, number, number] | null {
  const raw = hex.trim().replace(/^#/, "");
  const full =
    raw.length === 3
      ? raw
          .split("")
          .map((c) => c + c)
          .join("")
      : raw;
  if (!/^[0-9a-fA-F]{6}$/.test(full)) return null;
  return [
    parseInt(full.slice(0, 2), 16),
    parseInt(full.slice(2, 4), 16),
    parseInt(full.slice(4, 6), 16),
  ];
}
