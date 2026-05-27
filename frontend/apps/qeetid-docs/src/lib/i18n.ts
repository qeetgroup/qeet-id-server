/**
 * Docs internationalisation scaffold.
 *
 * Today the docs ship in English only and content lives at
 * `content/docs/**`. This file declares the language table that
 * fumadocs will read once we're ready to ship a second locale.
 *
 * Migration steps when adding a new language (e.g. Japanese):
 *
 *   1. Move existing English content from `content/docs/...` to
 *      `content/docs/en/...` (use `git mv` to preserve history).
 *   2. Add the translated tree under `content/docs/ja/...` mirroring
 *      the English structure 1:1.
 *   3. Add `"ja"` to LANGUAGES below.
 *   4. Wrap the docs route in a `[lang]` dynamic segment and add a
 *      locale switcher to the docs header.
 *
 * fumadocs has first-class i18n support (see https://fumadocs.dev/docs/headless/internationalization);
 * this scaffold makes the wiring explicit so the move is mechanical.
 */
export const DEFAULT_LANGUAGE = "en" as const;

export const LANGUAGES = [
  { code: "en", name: "English" },
  // Add additional languages here when content lands under
  // `content/docs/<code>/`. Roadmap calls out the eventual 10-language
  // set; we'll add them one at a time as translations finish.
] as const;

export type LanguageCode = (typeof LANGUAGES)[number]["code"];

export function isLanguageEnabled(code: string): code is LanguageCode {
  return LANGUAGES.some((l) => l.code === code);
}
