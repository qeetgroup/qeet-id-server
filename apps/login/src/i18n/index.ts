import i18n from "i18next";
import LanguageDetector from "i18next-browser-languagedetector";
import { initReactI18next } from "react-i18next";

import common from "./locales/en/common.json";
import consent from "./locales/en/consent.json";
import device from "./locales/en/device.json";
import loggedOut from "./locales/en/loggedOut.json";
import login from "./locales/en/login.json";
import recovery from "./locales/en/recovery.json";
import signup from "./locales/en/signup.json";

// Languages the UI ships catalogs for. Adding a locale is a two-step change:
//  1. drop `src/i18n/locales/<lng>/*.json` (mirror the `en` namespaces),
//  2. add the code here and register it in `resources` below.
// Everything else (the `t()` calls) picks it up automatically.
export const SUPPORTED_LANGUAGES = ["en"] as const;
export type SupportedLanguage = (typeof SUPPORTED_LANGUAGES)[number];

// Human-readable label per language. Keyed by the same codes as
// SUPPORTED_LANGUAGES so a new locale only needs one entry.
export const LANGUAGE_LABELS: Record<SupportedLanguage, string> = {
  en: "English",
};

// Static resources. Bundling them (rather than HTTP-loading) keeps init
// synchronous, which matters under SSR: i18next is ready at import time,
// so the first server render already has translations and there is no
// async gate before React mounts.
const resources = {
  en: {
    common,
    login,
    consent,
    device,
    loggedOut,
    recovery,
    signup,
  },
} as const;

if (!i18n.isInitialized) {
  i18n
    .use(initReactI18next)
    .use(LanguageDetector)
    .init({
      resources,
      fallbackLng: "en",
      supportedLngs: SUPPORTED_LANGUAGES as unknown as string[],
      defaultNS: "common",
      interpolation: {
        // React already escapes interpolated values, so i18next must not.
        escapeValue: false,
      },
      detection: {
        order: ["localStorage", "navigator"],
        lookupLocalStorage: "qeetid.lang",
        caches: ["localStorage"],
      },
    });
}

export default i18n;
