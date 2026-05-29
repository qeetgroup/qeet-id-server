# Qeet ID — Embeddable Auth UI Components (White-Label)

### 1. Document Information

|  |  |
| --- | --- |
| **Document Name** | Embeddable Auth UI Components (White-Label) |
| **Project Name** | Qeet ID |
| **Parent Company** | Qeet Group |
| **Subsidiary** | Qeet ID (Standalone) |
| **Document Version** | v1.0 |
| **Prepared By** | UX Designer |
| **Date** | May 19, 2026 |
| **Status** | Draft — Pending Stakeholder Sign-off |

---

### 2. Purpose & Scope

This document specifies the **white-label** layer of Qeet ID — the surface the customer's end users see, which can be heavily branded to look like the customer's product without compromising security, accessibility, or platform integrity.

The capability is **non-negotiable** per Phase 1 Stakeholder Findings: *"The login and authentication UI components must be fully customizable — white-label capability is non-negotiable for enterprise customers."* It is one of the three areas where Qeet ID deliberately beats Firebase Auth and where it must match Auth0 / Clerk / Kinde (per Competitive Analysis §11).

The document defines: the white-label strategy and the customer / Qeet ID boundary; the embeddable component architecture; the exhaustive brand customisation surface; the locked design elements and why; the spec for each embeddable widget (Login, Signup, MFA, Account Settings); the alternative hosted-auth-page model; the customisation preview UX; brand validation; white-label limits; and the tenant branding storage model (linking to Phase 2 [Database Design](../phase-2/Qeet%20ID%20%E2%80%94%20Database%20Design%20%26%20Data%20Model.md)).

The audience is the UX Designer, Frontend Engineering Lead, SDK Engineering team, Email Template Designer, Marketing Lead, and the Tenant Service / Branding Service engineering team.

This document depends on every Phase 3 document so far and on Phase 2 [Multi-Tenancy §4.7](../phase-2/Qeet%20ID%20%E2%80%94%20Multi-Tenancy%20Architecture.md) (tenant branding config storage), [Microservices §4.6](../phase-2/Qeet%20ID%20%E2%80%94%20Microservices%20Decomposition%20%26%20Service%20Boundaries.md) (Tenant Service owns `tenant_branding`), and [Database Design §5.1](../phase-2/Qeet%20ID%20%E2%80%94%20Database%20Design%20%26%20Data%20Model.md) (the `tenant_branding` entity).

---

### 3. White-Label Strategy

### 3.1 Three Customer Patterns

Customers choose one of three integration patterns depending on how much control they want and how much they want to operate themselves.

| Pattern | What the customer does | What the customer gets | When to choose |
| --- | --- | --- | --- |
| **Hosted Auth Pages** (default) | Redirects users to `acme.qeetify.com/login` (or custom domain `login.acme.com`) | Qeet ID-rendered, brand-customised login pages. Zero frontend code for auth. | Default for most customers. Arjun's MVP path. |
| **Embeddable Widgets** | Drops `<QeetifyLogin />` into their React/Next.js/Flutter app | Pre-built component renders inside the customer's app | Customers who want auth in-page (modal or inline) and a single visual identity |
| **Headless SDK** | Calls Qeet ID APIs directly; renders everything themselves | Full UI control; tokens via SDK | Customers with extreme design needs or unusual auth UI |

Most of this document covers patterns 1 and 2; the Headless SDK is documented in the SDK reference ([Phase 3 Doc 7 §10](Qeet ID%20%E2%80%94%20Developer%20Portal%20Design%20Specification.md)).

### 3.2 The Boundary

**Qeet ID owns:** the security model (which factors are required), the user experience integrity (passkey-first; never `alg: none`), the accessibility baseline (WCAG 2.1 AA), the protocol correctness (PKCE mandatory, refresh rotation on, etc.).

**The customer owns:** the brand (logo, colour, font from approved set, border radius range, background, optional CSS class), the copy in a small set of localisable strings (welcome message, footer attribution if Enterprise), the domain.

The boundary is what makes white-label safe. A customer cannot accidentally make their login page inaccessible, insecure, or off-brand-from-the-Qeet ID-platform.

---

### 4. Brand Customisation Surface

The exhaustive list. Every customisable element is a semantic token override or a content slot.

### 4.1 Tokens the Tenant Can Override

| Token | Range | Validation |
| --- | --- | --- |
| `color.action.primary` (and derived hover/active) | Any hex | Auto-validates 4.5:1 contrast with `color.text.on-brand` |
| `color.action.passkey` | Any hex (defaults to primary) | Same |
| `color.surface.brand-subtle` | Auto-derived from primary | n/a |
| `color.text.link` | Any hex | 4.5:1 with `surface.canvas` AND `surface.default` |
| `font.family.sans` | From approved set: Inter, IBM Plex Sans, Source Sans 3, Roboto, Open Sans, system-default | Closed list |
| `radius.brand-base` | 2–12px | Clamped |
| Logo (light + dark variants) | SVG or PNG ≥256×256 | Format check |
| Background pattern / image (login page) | Image or solid colour | Optional contrast validation against text |

### 4.2 Per-Plan Customisation

| Customisation | Free | Growth | Enterprise |
| --- | --- | --- | --- |
| Logo | ✓ | ✓ | ✓ |
| Primary colour | ✓ | ✓ | ✓ |
| Accent colour | ✓ | ✓ | ✓ |
| Font family (from approved set) | – | ✓ | ✓ |
| Border radius | ✓ | ✓ | ✓ |
| Background image | – | ✓ | ✓ |
| Custom domain (CNAME) | – | ✓ | ✓ |
| Email template branding | ✓ (limited) | ✓ | ✓ |
| Footer attribution removable ("Powered by Qeet ID") | – | – | ✓ |
| Custom CSS injection (sandboxed) | – | – | ✓ |
| Per-application branding override | – | ✓ | ✓ |

Free-tier customers always show "Powered by Qeet ID" in the footer; Growth and Enterprise may suppress it (the latter as a contractual right; the former as a self-serve toggle).

### 4.3 Content Slots

Customers can override the following copy via the dashboard Branding screen, subject to character bounds:

| Slot | Default | Max chars |
| --- | --- | --- |
| Login page title | "Sign in to {tenant_name}" | 60 |
| Signup page title | "Create your account" | 60 |
| Welcome screen body | "Welcome to {tenant_name}." | 200 |
| Magic-link sent body | "We sent a sign-in link to {email}." | 200 |
| Footer Privacy link URL | (Qeet ID privacy policy) | 200 |
| Footer Terms link URL | (Qeet ID ToS) | 200 |
| Footer attribution (Enterprise) | "Powered by Qeet ID" | 60 (or hidden) |

---

### 5. Locked Design Elements (and Why)

The locked surface is what keeps the customer's branding from making the platform un-Qeet ID. The locks are enforced at the token-loader level and (for the embeddable widgets) at the component level.

| Element | Locked because |
| --- | --- |
| Spacing scale | Layout integrity depends on rhythm consistency |
| Type scale ratios | Hierarchy relies on consistent ratios |
| Motion durations and easings | Reduced-motion preference + consistency |
| Z-index ordering | Functional correctness |
| Contrast-critical defaults (text, focus ring, errors) | Cannot drop below WCAG AA |
| Required UI elements (passkey button placement) | Passkey-first is a brand principle (P-02) |
| Required affordances (error message positions, focus indicators, "Use another method" links) | Accessibility and security |
| Iconography stroke and size scale | Visual cohesion |
| Footer Qeet ID attribution (Free / Growth) | Brand integrity; commercial fairness |
| Auth-flow security elements (anti-enumeration screens, rate-limit feedback) | Security policy |
| Auth-flow IA (the ten flows in [Doc 5](Qeet ID%20%E2%80%94%20End-User%20Authentication%20Flow%20Designs.md)) | Conformance; the customer can rearrange visible options but not the underlying screen sequence |

A customer requesting a *deeper* customisation than this surface allows is told (politely) that the customisation is locked and why — almost always for an accessibility, security, or conformance reason.

---

### 6. Embeddable Component Architecture

### 6.1 Distribution

| Platform | Package | Components |
| --- | --- | --- |
| React | `@qeetify/react` | `QeetifyProvider`, `LoginButton`, `LoginWidget`, `SignupWidget`, `MFASetupWidget`, `AccountSettingsWidget`, headless hooks |
| Next.js | `@qeetify/nextjs` | The above + App Router / Pages Router integration helpers + middleware |
| Vue (v1.2) | `@qeetify/vue` | Vue equivalents |
| Flutter | `qeetify_flutter` pub package | Equivalents adapted for Flutter |

Web embeddable widgets are also distributed as **a single hosted JS bundle** that customers can drop in via `<script src="https://cdn.qeetify.com/widgets/v1/qeetify.js" />` and then `Qeetify.mount('#login', { ... })` — for customers without a build pipeline.

### 6.2 Configuration Model

Each widget accepts a configuration object:

```js
Qeetify.mount('#login', {
  domain: 'acme.qeetify.com',
  clientId: 'client_app_42',
  redirectUri: window.location.origin + '/callback',

  // Branding is loaded from the tenant — but can be locally overridden:
  theme: 'auto' | 'light' | 'dark',
  appearance: {
    // Token-level overrides; subject to the lock list in §5
  },

  // Behavioural config:
  variants: ['passkey', 'social', 'magic-link', 'password'],   // ordered list of visible methods
  socialProviders: ['google', 'github'],                        // subset

  // Event hooks:
  onLoginSuccess: (user) => {...},
  onLoginError: (err) => {...},
});
```

### 6.3 Hosted vs Embedded

Hosted Auth Pages and Embedded Widgets share the **same components and the same tokens** (per [Doc 3 §3](Qeet ID%20%E2%80%94%20Component%20Library%20Specification.md)). A customer who starts with hosted pages and migrates to embedded widgets later does not see UX regressions — the same React components render in both cases.

---

### 7. Embeddable Login Widget

The flagship widget. A customer's React app renders:

```jsx
<QeetifyProvider domain={...} clientId={...}>
  <LoginWidget variant="inline" />
</QeetifyProvider>
```

### 7.1 Variants

| Variant | Render |
| --- | --- |
| `inline` | A flush-mounted login card; no overlay |
| `modal` | A modal dialog with the login card inside; opens via `useLoginModal()` hook |
| `redirect` | The customer clicks "Sign in" → redirect to hosted login page → callback (same as hosted pattern; this option exists for API parity) |

### 7.2 Anatomy

Identical to the hosted login page (per [Doc 5 §6](Qeet ID%20%E2%80%94%20End-User%20Authentication%20Flow%20Designs.md)): tenant logo + heading + email field + passkey button + social buttons + alternative method links + footer.

### 7.3 Event Hooks

| Hook | Fires when |
| --- | --- |
| `onLoginSuccess(user)` | User authenticated; tokens issued |
| `onLoginError(error)` | Login failed; error includes `code` and `requestId` |
| `onSignupRequest()` | User clicks "Create one" |
| `onPasswordReset()` | User clicks "Forgot password?" |

### 7.4 Customisation Injection Points

- Override the title via `appearance.titleText`.
- Provide a custom React node for the footer via `appearance.footerSlot` (subject to the rule that Free / Growth must include "Powered by Qeet ID").
- Override the order of visible authentication methods via `variants` array.

### 7.5 Locked Behaviour

- The passkey button cannot be removed if `variants` includes any method (passkey-first per P-02).
- The error message position cannot be moved.
- Focus management (focus traps in modal variant) cannot be disabled.

---

### 8. Embeddable Signup Widget

Mirrors the Login Widget. `<SignupWidget variant="inline|modal|redirect" />`. Same configuration model and event hooks.

---

### 9. Embeddable MFA Setup Widget

A widget the customer embeds in their *post-login* account-setup flow to prompt enrolment.

```jsx
<MFASetupWidget
  required={true}                       // user cannot skip
  preferredFactors={['passkey', 'totp']}
  onEnrollSuccess={(factor) => {...}}
  onSkip={() => {...}}                  // ignored if required={true}
/>
```

Renders the registration ceremonies from [Doc 5 F-01 Step 3](Qeet ID%20%E2%80%94%20End-User%20Authentication%20Flow%20Designs.md) (passkey) or sub-flows for TOTP / SMS / Email OTP.

---

### 10. Embeddable Account Settings Widget

The most-customised widget. A drop-in account portal showing passkeys, MFA, sessions, profile, preferences.

```jsx
<AccountSettingsWidget
  sections={['profile', 'security', 'preferences', 'data', 'delete']}
/>
```

Customers can subset the sections shown.

---

### 11. Hosted Auth Pages (Default Pattern)

For customers who don't want to embed anything, Qeet ID hosts the pages at `{tenant}.qeetify.com/login` (or the custom domain). The customer:

1. Configures the OAuth client redirect URI in the dashboard.
2. Redirects the user to `/oauth/authorize?...`.
3. Receives the callback with the auth code.

No frontend code; no widget to integrate. This is Arjun's MVP path — 5 minutes to first auth.

The hosted pages are the **same React components** as the embedded widgets, server-side rendered into Qeet ID-served HTML.

### 11.1 Custom Domain Path

When a customer sets up a custom domain (Phase 3 Doc 6 §17), the hosted pages move from `acme.qeetify.com` to `login.acme.com`. The customer's users never see "qeetify" in the URL. Configurable per tenant in the Branding screen.

---

### 12. Customisation Preview UX

Per [Doc 6 §16](Qeet ID%20%E2%80%94%20Admin%20Dashboard%20Design%20Specification.md), the dashboard Branding screen has a **live-preview pane** that updates in real time as the admin changes brand tokens.

Implementation:
- The Branding form on the left.
- An iframe on the right rendering `https://{tenant}.qeetify.com/login?preview=1` with overridden brand tokens passed via `postMessage`.
- The iframe updates within 150ms of any change (no full reload).
- Device toggle (desktop / tablet / mobile) lets the admin see the change across breakpoints.
- Theme toggle (light / dark) lets the admin verify both.

### 12.1 Preview Test Cases

The preview runs against canonical screens by default: Login page, Signup page, MFA challenge, Account portal home. The admin can switch between them.

---

### 13. Brand Validation (Automated Contrast Checks)

When the admin saves a brand configuration, three validations run (per [Doc 2 §15.3](Qeet ID%20%E2%80%94%20Design%20System%20Foundations%20%26%20Tokens.md)):

### 13.1 Contrast Validation

The platform computes the contrast ratio between every brand-derived text-on-surface pair. Any pair below AA blocks save with a specific message:

> ⚠ Primary colour and white button text contrast is **3.8:1**. WCAG AA requires 4.5:1 for normal text. Try a darker primary colour. [Suggest accessible shade] → `#1d4ed8` (4.6:1).

The "Suggest accessible shade" CTA picks the closest hue-preserved colour that meets AA.

### 13.2 Visibility Validation

If the primary against page background is <3:1, a warning (not a block):

> ⚠ Your primary colour is hard to see against the page background. Buttons may be hard to spot. Consider a higher-contrast colour.

### 13.3 Brand-Confusion Validation

If the primary is dangerously close to the platform error / warning colours, a soft warning:

> Your primary colour resembles the platform's error colour. Users may misread error states.

---

### 14. White-Label Limits Documentation

A public docs page (`/docs/guides/branding-limits`) documents exactly what is and is not customisable, with the rationale. This page is the single source of truth when a customer asks "why can't I change X?"

---

### 15. Tenant Branding Storage Model

Stored in the `tenant_branding` table (Phase 2 [Database §5.1](../phase-2/Qeet%20ID%20%E2%80%94%20Database%20Design%20%26%20Data%20Model.md)):

```
   tenant_branding
   ────────────────────────────────────────────
   tenant_id              uuid PK
   primary_color          text
   accent_color           text
   passkey_color          text (nullable)
   link_color             text
   border_radius_base     smallint (2–12)
   font_family            text (enum)
   logo_light_url         text
   logo_dark_url          text
   background_image_url   text (nullable)
   background_solid       text (nullable)
   footer_text            text (nullable)
   footer_url             text (nullable)
   custom_domain          text (nullable)
   custom_css_url         text (nullable, Enterprise only)
   updated_at, updated_by
```

Branding assets live in S3 (`qeetify-branding-{region}` bucket; Phase 2 Infrastructure §12). The bucket is signed-URL accessed by the hosted login pages and the embeddable widgets.

### 15.1 Cache Behaviour

Brand config is cached in Redis (Phase 2 NFR CA-03) at the Tenant Service with a 5-minute TTL. Saves invalidate the cache synchronously. The hosted login pages and the widgets always have current brand within 5 minutes.

---

### 16. Email Template Branding

Per [Doc 6 §18](Qeet ID%20%E2%80%94%20Admin%20Dashboard%20Design%20Specification.md), the customer can brand transactional emails:

| Element | Customisable |
| --- | --- |
| Logo (light variant typically) | ✓ |
| Primary colour | ✓ |
| Sender name ("Acme via Qeet ID" or "Acme") | ✓ |
| Reply-to address | ✓ |
| Footer text | ✓ |
| Body copy | partially (per-template translatable strings) |

Custom HTML email templates are deferred to v1.2 (most customers do not need it; the brandable defaults suffice).

---

### 17. Custom CSS (Enterprise Only)

Enterprise customers can supply a custom CSS URL. The hosted login pages load it in a *sandboxed* stylesheet — it can:

- Customise non-critical visual properties (additional decoration).
- Override colours within the documented token list.

It cannot:

- Override `position`, `display`, `z-index` of accessibility-critical elements.
- Hide required UI elements (passkey button, error messages, focus rings).
- Set `outline: none` on interactive elements.
- Use `!important` to override locked tokens.

The sandbox is enforced at CSS parse time — disallowed rules are silently stripped (with a warning surfaced in the dashboard).

Custom CSS is a contractual permission, not a self-serve toggle, and changes go through an Enterprise SLA review.

---

### 18. Per-Application Branding Override

Growth and Enterprise tenants can override the tenant-wide brand on a per-OAuth-client basis. Useful when a single tenant runs multiple visually distinct apps under one organisation.

The Application Detail screen ([Doc 6 §12.7](Qeet ID%20%E2%80%94%20Admin%20Dashboard%20Design%20Specification.md)) has a Branding tab that, if set, overrides the tenant default at OAuth `/authorize` time.

---

### 19. SDK-Level Theme API

For deeper React customisation, `@qeetify/react` exposes a `ThemeProvider`:

```jsx
<QeetifyProvider domain={...} clientId={...}>
  <ThemeProvider tokens={customTokens}>
    <LoginWidget />
  </ThemeProvider>
</QeetifyProvider>
```

`customTokens` accepts the Tier-2 semantic tokens documented in [Doc 2 §5.4](Qeet ID%20%E2%80%94%20Design%20System%20Foundations%20%26%20Tokens.md). Validation runs at runtime — invalid tokens throw with descriptive errors.

---

### 20. Performance Budget for Widgets

| Metric | Target |
| --- | --- |
| Widget JS bundle (gzip) | <60 KB |
| Time to interactive (TTI) of inline widget on a 3G mobile connection | <2 s |
| Lighthouse score on the customer's page where the widget is mounted | minimal impact (<3 points reduction) |

The widget is **lazy-loaded by default** — the core React app loads first; the LoginWidget code-splits and loads on render.

---

### 21. Accessibility Inheritance

The widgets inherit every accessibility commitment from [Doc 9](Qeet ID%20%E2%80%94%20Accessibility%20Compliance%20Plan%20%28WCAG%202.1%20AA%29.md). Customers do not need to make the widgets accessible — they already are. The accessibility statement on the Qeet ID public site covers customer applications that use the widgets unmodified.

---

### 22. Open Design Decisions From This Document

| # | Question | Owner | Target |
| --- | --- | --- | --- |
| OD-WL-01 | Brandable approved font family list — Inter + IBM Plex + Source Sans + Roboto + Open Sans vs broader | UX + Marketing | Phase 3 Week 2 |
| OD-WL-02 | Custom CSS sandboxing depth (strict allow-list vs deny-list) | Frontend + Security | Phase 3 Week 4 |
| OD-WL-03 | Per-application branding at MVP vs v1.1 | Product + UX | Phase 3 Week 3 |
| OD-WL-04 | Footer attribution removal — Enterprise contract vs all paid plans | Sales + Product | Phase 3 Week 2 |
| OD-WL-05 | Custom domain DNS-validation mechanism (live polling vs scheduled check) | Frontend + Infrastructure | Phase 3 Week 4 |
| OD-WL-06 | Whether Vue / Svelte / Angular SDKs ship at MVP or v1.2 | SDK Eng + Product | Phase 3 Week 2 |

---

### 23. Cross-References

- Design tokens consumed: [Design System Foundations & Tokens](Qeet ID%20%E2%80%94%20Design%20System%20Foundations%20%26%20Tokens.md) §5, §15
- Components composed: [Component Library Specification](Qeet ID%20%E2%80%94%20Component%20Library%20Specification.md) — Auth Layout, Login form widgets
- Flow choreography: [End-User Authentication Flow Designs](Qeet ID%20%E2%80%94%20End-User%20Authentication%20Flow%20Designs.md)
- Branding dashboard UX: [Admin Dashboard Design Specification §16](Qeet ID%20%E2%80%94%20Admin%20Dashboard%20Design%20Specification.md)
- Custom Domain wizard: [Admin Dashboard Design Specification §17](Qeet ID%20%E2%80%94%20Admin%20Dashboard%20Design%20Specification.md)
- Tenant branding storage: [Phase 2 Database Design §5.1](../phase-2/Qeet%20ID%20%E2%80%94%20Database%20Design%20%26%20Data%20Model.md)
- Multi-tenancy isolation: [Phase 2 Multi-Tenancy Architecture](../phase-2/Qeet%20ID%20%E2%80%94%20Multi-Tenancy%20Architecture.md)
- Accessibility commitments: [Accessibility Compliance Plan (WCAG 2.1 AA)](Qeet ID%20%E2%80%94%20Accessibility%20Compliance%20Plan%20%28WCAG%202.1%20AA%29.md)
- Tenant Service: [Phase 2 Microservices §4.6](../phase-2/Qeet%20ID%20%E2%80%94%20Microservices%20Decomposition%20%26%20Service%20Boundaries.md)

---

### 24. Approvals & Sign-off

| Role | Name | Signature | Date |
| --- | --- | --- | --- |
| UX Designer |  |  |  |
| Frontend Engineering Lead |  |  |  |
| SDK Engineering Lead |  |  |  |
| Email Template Designer |  |  |  |
| Marketing Lead |  |  |  |
| Security Architect (custom CSS sandbox) |  |  |  |
| Accessibility Lead |  |  |  |
| Product Manager |  |  |  |
| Solution Architect (cross-phase consistency) |  |  |  |

---

*This document is version controlled. Visual updates in Figma do not require re-sign-off; changes to the customisable / locked surfaces (§4, §5), the widget API (§6.2), the brand validation rules (§13), or the custom CSS sandbox (§17) require UX Designer + Frontend Lead + Security Architect review.*

---

**Qeet ID — Authenticate Everything.** *A Qeet Group Company*
