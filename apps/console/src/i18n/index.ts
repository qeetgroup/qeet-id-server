import i18n from "i18next";
import LanguageDetector from "i18next-browser-languagedetector";
import { initReactI18next } from "react-i18next";

import common from "./locales/en/common.json";
import oidc from "./locales/en/oidc.json";
import saml from "./locales/en/saml.json";
import rbac from "./locales/en/rbac.json";
import device from "./locales/en/device.json";
import signingKeys from "./locales/en/signingKeys.json";
import consent from "./locales/en/consent.json";
import auth from "./locales/en/auth.json";
import users from "./locales/en/users.json";
import dashboard from "./locales/en/dashboard.json";
import settings from "./locales/en/settings.json";
import security from "./locales/en/security.json";
import organizations from "./locales/en/organizations.json";
import groups from "./locales/en/groups.json";
import invitations from "./locales/en/invitations.json";
import developer from "./locales/en/developer.json";
import account from "./locales/en/account.json";
import compliance from "./locales/en/compliance.json";
import authFlow from "./locales/en/authFlow.json";

import hiCommon from "./locales/hi/common.json";
import hiOidc from "./locales/hi/oidc.json";
import hiSaml from "./locales/hi/saml.json";
import hiRbac from "./locales/hi/rbac.json";
import hiDevice from "./locales/hi/device.json";
import hiSigningKeys from "./locales/hi/signingKeys.json";
import hiConsent from "./locales/hi/consent.json";
import hiAuth from "./locales/hi/auth.json";
import hiUsers from "./locales/hi/users.json";
import hiDashboard from "./locales/hi/dashboard.json";

import frCommon from "./locales/fr/common.json";
import frOidc from "./locales/fr/oidc.json";
import frSaml from "./locales/fr/saml.json";
import frRbac from "./locales/fr/rbac.json";
import frDevice from "./locales/fr/device.json";
import frSigningKeys from "./locales/fr/signingKeys.json";
import frConsent from "./locales/fr/consent.json";
import frAuth from "./locales/fr/auth.json";
import frUsers from "./locales/fr/users.json";
import frDashboard from "./locales/fr/dashboard.json";

import deCommon from "./locales/de/common.json";
import deOidc from "./locales/de/oidc.json";
import deSaml from "./locales/de/saml.json";
import deRbac from "./locales/de/rbac.json";
import deDevice from "./locales/de/device.json";
import deSigningKeys from "./locales/de/signingKeys.json";
import deConsent from "./locales/de/consent.json";
import deAuth from "./locales/de/auth.json";
import deUsers from "./locales/de/users.json";
import deDashboard from "./locales/de/dashboard.json";

import esCommon from "./locales/es/common.json";
import esOidc from "./locales/es/oidc.json";
import esSaml from "./locales/es/saml.json";
import esRbac from "./locales/es/rbac.json";
import esDevice from "./locales/es/device.json";
import esSigningKeys from "./locales/es/signingKeys.json";
import esConsent from "./locales/es/consent.json";
import esAuth from "./locales/es/auth.json";
import esUsers from "./locales/es/users.json";
import esDashboard from "./locales/es/dashboard.json";

import ptCommon from "./locales/pt/common.json";
import ptOidc from "./locales/pt/oidc.json";
import ptSaml from "./locales/pt/saml.json";
import ptRbac from "./locales/pt/rbac.json";
import ptDevice from "./locales/pt/device.json";
import ptSigningKeys from "./locales/pt/signingKeys.json";
import ptConsent from "./locales/pt/consent.json";
import ptAuth from "./locales/pt/auth.json";
import ptUsers from "./locales/pt/users.json";
import ptDashboard from "./locales/pt/dashboard.json";

import jaCommon from "./locales/ja/common.json";
import jaOidc from "./locales/ja/oidc.json";
import jaSaml from "./locales/ja/saml.json";
import jaRbac from "./locales/ja/rbac.json";
import jaDevice from "./locales/ja/device.json";
import jaSigningKeys from "./locales/ja/signingKeys.json";
import jaConsent from "./locales/ja/consent.json";
import jaAuth from "./locales/ja/auth.json";
import jaUsers from "./locales/ja/users.json";
import jaDashboard from "./locales/ja/dashboard.json";

import zhCommon from "./locales/zh/common.json";
import zhOidc from "./locales/zh/oidc.json";
import zhSaml from "./locales/zh/saml.json";
import zhRbac from "./locales/zh/rbac.json";
import zhDevice from "./locales/zh/device.json";
import zhSigningKeys from "./locales/zh/signingKeys.json";
import zhConsent from "./locales/zh/consent.json";
import zhAuth from "./locales/zh/auth.json";
import zhUsers from "./locales/zh/users.json";
import zhDashboard from "./locales/zh/dashboard.json";

// Languages the UI ships catalogs for. Adding a locale is a two-step change:
//  1. drop `src/i18n/locales/<lng>/*.json` (mirror the `en` namespaces),
//  2. add the code here and register it in `resources` below.
// Everything else (the switcher, the `t()` calls) picks it up automatically.
export const SUPPORTED_LANGUAGES = ["en", "hi", "fr", "de", "es", "pt", "ja", "zh"] as const;
export type SupportedLanguage = (typeof SUPPORTED_LANGUAGES)[number];

// Human-readable label per language, shown in the switcher. Keyed by the
// same codes as SUPPORTED_LANGUAGES so a new locale only needs one entry.
export const LANGUAGE_LABELS: Record<SupportedLanguage, string> = {
  en: "English",
  hi: "हिन्दी",
  fr: "Français",
  de: "Deutsch",
  es: "Español",
  pt: "Português",
  ja: "日本語",
  zh: "中文",
};

// Static resources. Bundling them (rather than HTTP-loading) keeps init
// synchronous, which matters under SSR: i18next is ready at import time,
// so the first server render already has translations and there is no
// async gate before React mounts.
// New namespaces (settings, security, organizations, groups, invitations,
// developer, account) are English-only. Other locales fall back to "en" via
// fallbackLng — this is the intentional professional rollout strategy.
const newNs = { settings, security, organizations, groups, invitations, developer, account, compliance, authFlow };

const resources = {
  en: { common, oidc, saml, rbac, device, signingKeys, consent, auth, users, dashboard, ...newNs },
  hi: { common: hiCommon, oidc: hiOidc, saml: hiSaml, rbac: hiRbac, device: hiDevice, signingKeys: hiSigningKeys, consent: hiConsent, auth: hiAuth, users: hiUsers, dashboard: hiDashboard },
  fr: { common: frCommon, oidc: frOidc, saml: frSaml, rbac: frRbac, device: frDevice, signingKeys: frSigningKeys, consent: frConsent, auth: frAuth, users: frUsers, dashboard: frDashboard },
  de: { common: deCommon, oidc: deOidc, saml: deSaml, rbac: deRbac, device: deDevice, signingKeys: deSigningKeys, consent: deConsent, auth: deAuth, users: deUsers, dashboard: deDashboard },
  es: { common: esCommon, oidc: esOidc, saml: esSaml, rbac: esRbac, device: esDevice, signingKeys: esSigningKeys, consent: esConsent, auth: esAuth, users: esUsers, dashboard: esDashboard },
  pt: { common: ptCommon, oidc: ptOidc, saml: ptSaml, rbac: ptRbac, device: ptDevice, signingKeys: ptSigningKeys, consent: ptConsent, auth: ptAuth, users: ptUsers, dashboard: ptDashboard },
  ja: { common: jaCommon, oidc: jaOidc, saml: jaSaml, rbac: jaRbac, device: jaDevice, signingKeys: jaSigningKeys, consent: jaConsent, auth: jaAuth, users: jaUsers, dashboard: jaDashboard },
  zh: { common: zhCommon, oidc: zhOidc, saml: zhSaml, rbac: zhRbac, device: zhDevice, signingKeys: zhSigningKeys, consent: zhConsent, auth: zhAuth, users: zhUsers, dashboard: zhDashboard },
} as const;

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

export default i18n;
