# Sprint 17 — Prebuilt UI Components (#23) + Hosted Login UI (#24) ⏳XL

| | |
|---|---|
| **Window** | 2027-02-15 → 2027-03-05 (3 weeks, ⏳XL) |
| **Theme** | Clerk-grade drop-in components + a forkable hosted login app |
| **Depends on** | Sprint 16 (SDKs), Sprints 1–15 (the flows the UI drives) |
| **Closes** | Gap **#23** (prebuilt UI components), **#24** (hosted login UI) |
| **Status** | ⬜ Not started |

**Why:** Clerk's moat is `<SignIn/>`, `<UserProfile/>`, `<OrganizationSwitcher/>` — auth in 15 minutes. WorkOS/Zitadel ship a forkable hosted login app. Qeet ID has a great internal admin UI and a 36-component library, but **nothing customer-facing**. This closes the integration-surface gap.

---

## Part A — 🧪 Test the newly-built feature (E2E)

### 🧪 SCENARIO 17.1 — Drop-in React components (#23)
- **Steps:** in a fresh React/Next app, wrap with `<QeetidProvider>`, drop `<QeetidSignIn/>`, `<QeetidSignUp/>`, `<UserButton/>`, `<UserProfile/>`, `<OrganizationSwitcher/>`.
- **Expect:** full auth (password, passkey, social, magic link, MFA, SSO) works with zero custom code; theming via tokens/branding.
- **Pass:** [ ] sign-in/up incl. MFA + passkeys + social + SSO [ ] org switching [ ] profile self-management [ ] honors tenant branding [ ] accessible (keyboard/screen-reader) [ ] SSR-safe.

### 🧪 SCENARIO 17.2 — Headless hooks
- **Pass:** [ ] `useUser`, `useSession`, `useSignIn`, `useOrganization`, `useOrgSwitcher` expose state for fully custom UIs [ ] permissions available in-session (no extra round-trip).

### 🧪 SCENARIO 17.3 — Hosted login UI (#24)
- **Steps:** point an OIDC client's login at the hosted app; complete the full flow (incl. SSO/SCIM-provisioned user, MFA, recovery).
- **Pass:** [ ] hosted flow handles every auth method [ ] per-tenant branding/custom-domain [ ] forkable (Next.js app you can self-host + customize) [ ] localized.

**Part A exit:** a sample app integrates auth in <15 min using components; the hosted app handles all methods.

---

## Part B — Build: components + hosted UI

### Design / changes
**Frontend**
- New package `packages/qeetid-react` (built on `@qeetid/sdk` from Sprint 16 + the existing `qeetid-ui` primitives):
  - Components: `QeetidProvider`, `SignIn`, `SignUp`, `UserButton`, `UserProfile`, `OrganizationSwitcher`, `OrganizationProfile`, `CreateOrganization`, `MFAEnrollment`, `ConnectedAccounts` (D11), `ConnectedAgents` (D7), `RecoverySetup` (D3).
  - Hooks: `useUser`, `useSession`, `useSignIn`, `useSignUp`, `useOrganization`, `useOrgSwitcher`, `usePermissions`.
  - Theming: CSS variables + tenant branding; light/dark; full a11y.
- New app `apps/qeetid-login` (Next.js, forkable, like Zitadel Login v2 / WorkOS AuthKit): hosted login/registration/recovery/MFA/SSO, per-tenant branding + custom domains, i18n. Drives the OIDC `/authorize` consent + login.
- (Optional) `packages/qeetid-react-native` for mobile passkeys/secure storage — stretch.

**Backend**
- Minimal additions: a login-session API for the hosted app (Zitadel Session-v2 style) if not already covered; consent screen (from Sprint 4) wired into the hosted app.

**Docs**
- `content/docs/components/*` (per component), `content/docs/hosted-ui.mdx`, `content/docs/customization/theming.mdx`, a 15-minute quickstart.

### Acceptance criteria
- [ ] A new app gets full auth (all methods) via components with no custom flow code.
- [ ] Hooks support fully headless/custom UIs; permissions in-session.
- [ ] Hosted login app handles every method, is per-tenant branded, custom-domain capable, and forkable.
- [ ] Components are accessible, SSR-safe, themeable, localized.

---

## Definition of Done
- [ ] Part A: component + hooks + hosted-UI scenarios pass; 15-min quickstart verified.
- [ ] Part B: `qeetid-react` package + `qeetid-login` app shipped; backend login-session/consent wired.
- [ ] `components/*`, `hosted-ui.mdx`, `customization/theming.mdx` published; docs no longer reference unbuilt UI.
- [ ] Roadmap: #23, #24 checked; status ✅; changelog filled.

## Changelog
| Date | Change |
|---|---|
| 2026-05-29 | Sprint defined. |
