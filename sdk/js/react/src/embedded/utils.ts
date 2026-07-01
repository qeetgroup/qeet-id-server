import type { Appearance, AppearanceVariables } from "./types.js";

/** Map AppearanceVariables to --qeetid-* CSS custom properties. */
export function applyAppearance(appearance?: Appearance): Record<string, string> {
  const vars: Record<string, string> = {};
  const v = appearance?.variables;
  if (!v) return vars;
  if (v.colorPrimary) vars["--qeetid-color-primary"] = v.colorPrimary;
  if (v.colorBackground) vars["--qeetid-color-background"] = v.colorBackground;
  if (v.colorText) vars["--qeetid-color-text"] = v.colorText;
  if (v.colorTextMuted) vars["--qeetid-color-text-muted"] = v.colorTextMuted;
  if (v.colorBorder) vars["--qeetid-color-border"] = v.colorBorder;
  if (v.borderRadius) vars["--qeetid-border-radius"] = v.borderRadius;
  if (v.fontFamily) vars["--qeetid-font-family"] = v.fontFamily;
  return vars;
}
