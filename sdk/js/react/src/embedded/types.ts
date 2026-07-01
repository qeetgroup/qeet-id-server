/** CSS-variable overrides applied to prebuilt components. */
export interface AppearanceVariables {
  /** Primary brand color (hex or oklch). */
  colorPrimary?: string;
  /** Background color of the card/modal. */
  colorBackground?: string;
  /** Default text color. */
  colorText?: string;
  /** Muted/secondary text color. */
  colorTextMuted?: string;
  /** Border color. */
  colorBorder?: string;
  /** Border radius applied to cards. */
  borderRadius?: string;
  /** Font family for body text. */
  fontFamily?: string;
}

/** Element-level className overrides for fine-grained styling. */
export interface AppearanceElements {
  card?: string;
  formField?: string;
  formLabel?: string;
  formInput?: string;
  button?: string;
  buttonPrimary?: string;
  buttonSecondary?: string;
  dividerText?: string;
  headerTitle?: string;
  headerSubtitle?: string;
  footerLink?: string;
  socialButton?: string;
  errorMessage?: string;
}

export type AppearanceTheme = "light" | "dark" | "system";

export interface Appearance {
  /** Color scheme preference. Default "system". */
  theme?: AppearanceTheme;
  /** CSS variable overrides (map to --qeetid-* custom properties). */
  variables?: AppearanceVariables;
  /** Per-element className overrides (merged with internal classes). */
  elements?: AppearanceElements;
}
