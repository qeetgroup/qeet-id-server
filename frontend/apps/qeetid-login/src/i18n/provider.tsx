"use client";

import { I18nextProvider } from "react-i18next";

// Importing `./index` runs `i18n.init(...)` as a side effect (guarded so it
// only happens once). Because the `en` resources are bundled statically, init
// is synchronous and there is no async gate before children mount.
import i18n from "./index";

/**
 * Wraps the app in the shared i18next instance. This is a Client Component so
 * it can hold the React context; the root `layout.tsx` stays a Server
 * Component and renders this provider around `{children}` (the standard
 * App Router pattern for context providers).
 */
export function I18nProvider({ children }: { children: React.ReactNode }) {
  return <I18nextProvider i18n={i18n}>{children}</I18nextProvider>;
}
