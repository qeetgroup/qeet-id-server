# i18n (qeetid-login)

English-only internationalization scaffold built on
[`i18next`](https://www.i18next.com/) + [`react-i18next`](https://react.i18next.com/),
with language detection via `i18next-browser-languagedetector`. It mirrors the
[`qeetid-admin` i18n setup](../../../qeetid-admin/src/i18n/README.md) — same
libraries, same init options (`fallbackLng: "en"`, `supportedLngs: ["en"]`,
`defaultNS: "common"`, `escapeValue: false`, detector `localStorage` key
`qeetid.lang`) — so the two apps stay consistent. It is designed so that adding
a locale later is a drop-in JSON change with no edits to the screens that
already use `t()`.

## Layout

```
src/i18n/
  index.ts            initializes the shared i18next instance (exported default)
  provider.tsx        "use client" <I18nProvider> wrapping children in <I18nextProvider>
  README.md           this file
  locales/
    en/
      common.json     cross-screen strings: generic error, scope labels, provider names, fallbacks
      login.json      /login — sign-in form, passkey, social divider
      consent.json    /consent — OAuth authorize-access screen
      device.json     /device — device-flow entry, authorize, and terminal states
      loggedOut.json  /logged-out — post-logout message
```

Each top-level JSON file is an i18next **namespace**. Keys are grouped by the
sub-area of the screen (e.g. `device.entry.*`, `device.authorize.*`,
`device.terminal.*`) to keep them discoverable and avoid collisions. Shared,
cross-screen strings live in `common` — notably:

- `common:scopes.<scope>` — human-readable OIDC scope descriptions, used by
  both `/consent` and `/device`.
- `common:providers.<id>` — social-provider display names (proper nouns).
- `common:errors.generic` — the shared "something went wrong" fallback.
- `common:fallbacks.*` — `application` ("An application") and `signYouIn`.

## Using translations in a component

The screens are Client Components (`"use client"`), so they call the hook
directly:

```tsx
import { useTranslation } from "react-i18next";

function MyScreen() {
  const { t } = useTranslation("login"); // pick the namespace
  return <h1>{t("title")}</h1>; // key is namespace-relative
}
```

- `common` is the default namespace. From any other namespace, reach shared
  strings with the `common:` prefix, e.g. `t("common:errors.generic")` or
  `t("common:scopes.openid")`.
- **Interpolation:** `t("titleTo", { client })`. `escapeValue` is off because
  React already escapes, so interpolated values render verbatim.
- **Dynamic keys with a fallback:** scope and provider labels are looked up by
  a runtime value and fall back to the raw value if unknown, e.g.
  `t(\`common:scopes.${s}\`, { defaultValue: s })`.

## Where it is initialized

`src/i18n/index.ts` runs its `i18n.init(...)` at import time (guarded by
`i18n.isInitialized` so it runs once across the server and client module
graphs). Because the `en` resources are bundled statically, init is synchronous
and there is no async gate before React mounts.

`src/i18n/provider.tsx` is a Client Component that side-effect-imports
`./index` and wraps `children` in `<I18nextProvider i18n={i18n}>`. The root
Server-Component `src/app/layout.tsx` renders `<I18nProvider>` around
`{children}` (inside `ThemeProvider`) — the standard App Router pattern for
context providers: the layout stays a Server Component, and only the provider
crosses the client boundary.

## Adding a new locale

1. Create `src/i18n/locales/<lng>/` and copy every namespace JSON from `en`,
   translating the values (keep the keys identical).
2. In `src/i18n/index.ts`:
   - import the new namespace files,
   - add `<lng>` to `SUPPORTED_LANGUAGES`,
   - add a label to `LANGUAGE_LABELS`,
   - register the namespaces under `resources.<lng>`.

The detector persists the choice to `localStorage` under `qeetid.lang`.

Do **not** localize IDs, developer/debug strings, or values that come from the
API (e.g. `client_id`, the user code) — only human-facing UI copy.
