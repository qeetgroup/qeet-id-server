# i18n (qeetid-admin)

English-only internationalization scaffold built on
[`i18next`](https://www.i18next.com/) + [`react-i18next`](https://react.i18next.com/),
with language detection via `i18next-browser-languagedetector`. It is designed
so that adding a locale later is a drop-in JSON change — no code edits to the
screens that already use `t()`.

## Layout

```
src/i18n/
  index.ts            initializes the shared i18next instance (exported default)
  README.md           this file
  locales/
    en/
      common.json     cross-screen buttons & labels (save, cancel, delete, status, …)
      oidc.json       OIDC / OAuth client screens
      saml.json       SAML IdP service-provider screen
      rbac.json       Access Tester + group-roles
      device.json     device authorizations
      signingKeys.json signing keys (JWKS)
      consent.json    OAuth consent grants
      auth.json       login-method policy screens (password, …)
      users.json      users list + create/edit/set-password sheets
```

Each top-level JSON file is an i18next **namespace**. Keys are grouped by the
sub-area of the screen (e.g. `oidc.list.*`, `oidc.create.*`, `users.table.*`)
to keep them discoverable and avoid collisions.

## Using translations in a component

```tsx
import { useTranslation } from "react-i18next";

function MyScreen() {
  const { t } = useTranslation("oidc");          // pick the namespace
  return <h1>{t("list.registeredTitle")}</h1>;   // key is namespace-relative
}
```

- `common` is the default namespace, so `t("actions.save")` works without
  passing a namespace. From any other namespace, reach shared strings with the
  `common:` prefix, e.g. `t("common:actions.cancel")`.
- **Interpolation:** `t("oidc.list.appCount", { count })`. `escapeValue` is off
  because React already escapes, so interpolated values render verbatim.
- **Pluralization:** define `key_one` / `key_other` and call with `{ count }`;
  i18next picks the right form (see `users.list.membersSubtitle`).
- **Rich text:** keys containing tags like `<strong>…</strong>` are rendered
  with the `<Trans>` component (`react-i18next`) so the markup stays in the
  catalog instead of the JSX. Map each tag to a React element via
  `components={{ strong: <span className="…" /> }}`.

## Adding a new locale

1. Create `src/i18n/locales/<lng>/` and copy every namespace JSON from `en`,
   translating the values (keep the keys identical).
2. In `src/i18n/index.ts`:
   - import the new namespace files,
   - add `<lng>` to `SUPPORTED_LANGUAGES`,
   - add a label to `LANGUAGE_LABELS`,
   - register the namespaces under `resources.<lng>`.

The language switcher in the sidebar footer reads `SUPPORTED_LANGUAGES` /
`LANGUAGE_LABELS`, so the new locale appears automatically. The detector
persists the choice to `localStorage` under `qeetid.lang`.

## Where it is initialized

`src/i18n/index.ts` runs its `i18n.init(...)` at import time and is imported
once at the top of `src/router.tsx` (the module both the SSR and client
entries call to build the router). Because the `en` resources are bundled
statically, init is synchronous and SSR-safe — there is no async gate before
React mounts.

## Incremental retrofit

Only the newly-added screens plus a couple of key existing flows
(`users/index.tsx`, `auth/login-methods/password.tsx`) have been migrated to
`t()`. The remaining ~70 screens are intentionally left with hardcoded English
copy for incremental migration. To localize another screen:

1. Pick or add a namespace JSON under `locales/en/`.
2. Add the screen’s user-facing strings as grouped keys.
3. Replace the literals with `t("…")` via `useTranslation("<ns>")`.

Do **not** localize IDs, developer/debug strings, or values that come from the
API — only human-facing UI copy.
