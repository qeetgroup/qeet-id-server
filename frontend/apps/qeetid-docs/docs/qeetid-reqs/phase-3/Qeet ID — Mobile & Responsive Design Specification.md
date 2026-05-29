# Qeet ID — Mobile & Responsive Design Specification

### 1. Document Information

|  |  |
| --- | --- |
| **Document Name** | Mobile & Responsive Design Specification |
| **Project Name** | Qeet ID |
| **Parent Company** | Qeet Group |
| **Subsidiary** | Qeet ID (Standalone) |
| **Document Version** | v1.0 |
| **Prepared By** | UX Designer |
| **Date** | May 19, 2026 |
| **Status** | Draft — Pending Stakeholder Sign-off |

---

### 2. Purpose & Scope

This document defines the responsive strategy, breakpoint system, per-surface mobile behaviour, touch-target standards, gesture support, mobile-specific UX patterns, native-app considerations, performance budgets on mobile, offline behaviour, and mobile-browser quirks for every Qeet ID-owned surface.

Mobile is not the same as small-desktop ([P-08 IA-08](Qeet ID%20%E2%80%94%20Information%20Architecture%20%26%20Navigation.md)). The strategy is **mobile-first for end-user authentication flows** (per stakeholder finding: *"the majority of end-user logins happen on mobile devices"*) and **desktop-first for admin and developer surfaces** (Sandra and Daniel operate at desktop; Arjun reads docs at desktop during integration).

NFR scope: responsive 320px – 2560px (UX-05); latest two versions of Chrome, Edge, Safari, Firefox on desktop; iOS Safari and Chrome Android latest two versions on mobile (UX-06 / UX-07).

The audience is the UX Designer, Frontend Engineering Lead, Mobile (Flutter) SDK Lead, QA Lead.

This document depends on every Phase 3 document so far, on Phase 1 [NFR §12.1](../phase-1/Qeet%20ID%20%E2%80%94%20Non-Functional%20Requirements%20%28NFR%29.md) (responsiveness), and on Phase 2 [Microservices Decomposition](../phase-2/Qeet%20ID%20%E2%80%94%20Microservices%20Decomposition%20%26%20Service%20Boundaries.md) (Hosted Login Pages, Flutter SDK consumers).

---

### 3. Responsive Strategy

### 3.1 Per-Surface Strategy

| Surface | Strategy | Rationale |
| --- | --- | --- |
| End-User Authentication Pages | **Mobile-first** | Majority of end-user logins are mobile (Stakeholder Findings 7.5) |
| Embeddable Widgets | Mobile-first | Embedded inside customer mobile apps and websites |
| Admin Dashboard | **Desktop-first**; tablet adapted; mobile read-only emergency view | Sandra and Daniel operate at desktop |
| Developer Portal | **Responsive** (fully usable on mobile, optimised at desktop) | Arjun reads docs on desktop; sometimes on phone |
| Security Trust Center | Responsive | Omar may read it on any device |
| Status Page | Responsive | Anyone checks the status on any device |
| Marketing surfaces | Responsive | Owned by Marketing |
| Email Templates | Mobile-first | Most email open events are on mobile |

### 3.2 Why Different Strategies

A mobile-first dashboard would force Sandra to operate the audit log viewer in a viewport too small for the density her work needs. A desktop-first login page would force the majority of users into a layout that's been retrofitted from desktop and shows it. Each surface optimises for its primary persona's primary device.

---

### 4. Breakpoint System

Recap of [Doc 2 §8](Qeet ID%20%E2%80%94%20Design%20System%20Foundations%20%26%20Tokens.md):

| Token | Range | Columns | Page gutter | Typical device |
| --- | --- | --- | --- | --- |
| `breakpoint.mobile` | 320px – 639px | 4 | 16px | Phones (portrait) |
| `breakpoint.tablet` | 640px – 1023px | 8 | 24px | Tablets, phones (landscape) |
| `breakpoint.desktop` | 1024px – 1439px | 12 | 32px | Laptops |
| `breakpoint.wide` | 1440px – 2560px | 12 | 48px | Large desktops, ultrawide |

The lower bound (320px) is iPhone SE (1st gen) — the smallest viewport we commit to supporting. The upper bound (2560px) is a common 27" / 30" monitor at native resolution.

### 4.1 Mobile Subset Ranges

Within mobile (320–639px), specific device targets the QA team validates:

| Device | Viewport | Notes |
| --- | --- | --- |
| iPhone SE (2nd gen) | 375×667 | Common Apple lower bound |
| iPhone 14/15 | 390×844 | Modern Apple standard |
| iPhone 14 Pro Max | 430×932 | Large Apple |
| Pixel 6 | 412×915 | Common Android standard |
| Galaxy S22 | 360×800 | Common Android |
| Galaxy Fold (folded) | 280×653 | Below our 320 floor — exception; we degrade gracefully |
| iPad Mini | 768×1024 | Tablet floor |

### 4.2 Tablet Range — Special Handling

Tablets (640–1023px) are *between* phone and desktop. They are too big for one-column phone layouts and too small for full desktop layouts. Per surface:

| Surface | Tablet behaviour |
| --- | --- |
| Auth pages | Mobile layout, centered (no need for desktop chrome) |
| Dashboard | Side nav collapses to icon-only; content uses desktop layout with reduced margins |
| Developer Portal | Left nav stays; right TOC collapses to a popover |

---

### 5. Per-Surface Responsive Behaviour

### 5.1 End-User Authentication Pages

**Composition** — the Auth Layout template ([Doc 3 §7.1](Qeet ID%20%E2%80%94%20Component%20Library%20Specification.md)) — a centred card on the brand background.

**Mobile (320–639px):**
- Card: full-width minus 16px margins; top-aligned (NOT vertically centred — keyboard would push content off-screen).
- Tenant logo: 32–40px height.
- Inputs: 44px height (`lg` size).
- Primary button: full-width, 52px (`xl`).
- Vertical stack of social buttons.
- Footer Privacy + ToS + Qeet ID attribution: stacked.

**Tablet (640–1023px):**
- Card: max-width 440px, centered horizontally; vertically centered if viewport height ≥600px.
- Same content as mobile.

**Desktop (≥1024px):**
- Card: max-width 440px, vertically centered.
- Background image (if tenant-configured) visible around card.

### 5.2 Admin Dashboard

**Desktop (≥1024px) — Primary:**
- Side nav 240px (expanded) or 56px (icon-only collapsed).
- Topbar 56px.
- Content max 1280px.

**Tablet (640–1023px):**
- Side nav collapses to icon-only by default (user can expand).
- Topbar 56px.
- Content uses full width minus 24px margins.

**Mobile (320–639px) — Read-Only Emergency View:**
- Topbar: logo + tenant switcher + hamburger + cmd-K + avatar.
- Side nav becomes a drawer (opened from hamburger).
- Most screens function read-only.
- Data tables become **card-list views** — each row becomes a card.
- Configuration screens (SAML wizard, SCIM, Branding, Custom Domain) show "Open on desktop for the best experience" inline banner with a "Send link to my desktop" affordance (the user is emailed a magic link that opens the screen in their desktop session).

This emergency-view model is Sandra's expected mobile use case (approve a deploy from her phone during an incident; view audit events to confirm something; quickly suspend a user).

### 5.3 Developer Portal

**Desktop (≥1024px) — Primary:**
- Documentation Layout: 240px left nav + 720px content + 240px right TOC.

**Tablet (640–1023px):**
- Left nav stays as drawer (or collapsible inline if width permits).
- Right TOC collapses to a popover affordance ("On this page ▾").

**Mobile (320–639px):**
- Left nav drawer.
- Right TOC sticky popover at the bottom of the viewport.
- Code blocks wrap (no horizontal scroll — every code block respects the viewport width).
- Tabs collapse to a "Code in: React ▾" selector.

### 5.4 Status Page, Trust Center, Public Roadmap, Changelog, Pricing

All responsive, optimised for both desktop and mobile reading. The status page's component matrix collapses to a vertical list on mobile; the recent-incidents list remains the same shape.

---

### 6. Mobile Navigation Pattern

### 6.1 Auth Pages: No Navigation

End-user auth pages have no nav anywhere — including mobile. The flow is linear.

### 6.2 Dashboard Mobile: Hamburger Drawer

```
   ┌─────────────────────────────────────────────┐
   │  [≡]  Acme Corp ▾                 [Q] [@]  │     (topbar)
   ├─────────────────────────────────────────────┤
   │                                             │
   │   (content area)                            │
   │                                             │
   └─────────────────────────────────────────────┘

   On hamburger tap — drawer slides in from left:
   ┌─────────────────────────────────────────────┐
   │  ╳  Identity                                │
   │     Users · Roles · Groups · Invitations    │
   │  Federation                                 │
   │     SSO · SCIM · Social                     │
   │  Applications                               │
   │     OAuth · API Keys · Webhooks             │
   │  Security                                   │
   │     Audit · Events · MFA · …                │
   │  Settings                                   │
   │  …                                          │
   └─────────────────────────────────────────────┘
```

**Why hamburger and not bottom tab bar.** The dashboard has 6+ top-level sections (per [Doc 4 §6](Qeet ID%20%E2%80%94%20Information%20Architecture%20%26%20Navigation.md)) — too many for a bottom tab bar. A hamburger drawer is the established pattern for dashboards of this scale.

### 6.3 Developer Portal Mobile: Two Drawers

```
   ┌─────────────────────────────────────────────┐
   │  [≡]  Quickstart                  [Q]  [⇣] │     (topbar)
   ├─────────────────────────────────────────────┤
   │                                             │
   │   ## Quickstart                              │
   │   …                                          │
   │                                             │
   │  [⇣ On this page]                          │     (bottom sticky)
   └─────────────────────────────────────────────┘
```

- Left hamburger opens the docs tree drawer.
- The "On this page" affordance at the bottom-right opens the TOC popover (the same content as the desktop right rail).

### 6.4 Marketing & Trust Center Mobile

Top nav collapses to logo + hamburger. The hamburger drawer holds the main nav links and the "Sign in / Sign up" CTAs.

---

### 7. Touch Target Standards

Per WCAG 2.5.5 (AAA) and Apple/Material guidelines, all touch targets at mobile breakpoints are at minimum **44×44pt** (iOS) or **48×48dp** (Material). Qeet ID chooses **44×44 CSS pixels** as the platform minimum.

| Component | Mobile touch target |
| --- | --- |
| Button (any size) | 44×44 minimum (`lg` and `xl` Button sizes meet this natively; `sm` and `md` get inflated touch padding on mobile) |
| Input | 44×44 (use `lg` size on mobile) |
| Checkbox / Radio | Input 20×20 visual; touch area inflated to 44×44 (clickable padding) |
| Toggle | 44×24 visual; touch area 44×44 |
| Avatar (interactive) | 44×44 minimum tap area |
| Icon-only button | 44×44 minimum |
| Tab in Tab Group | 44×44 vertical |
| Pagination buttons | 44×44 |
| Row action `⋯` menu trigger | 44×44 |
| Close button (modal, drawer) | 44×44 |

### 7.1 Spacing Between Targets

Per WCAG 2.5.8 Target Size (Minimum) (Level AA in WCAG 2.2 — Qeet ID proactively meets it): adjacent touch targets have at least 8px spacing between them at mobile breakpoints. Where spacing cannot be guaranteed (e.g., a row of pagination dots), each target is inflated to 44×44.

---

### 8. Gesture Support

Qeet ID uses standard gestures only — no exotic or app-specific gestures.

| Gesture | Where supported |
| --- | --- |
| Tap | Universal |
| Long press | Reveals context menu on data table row (mobile) |
| Swipe-to-dismiss | Mobile drawer (swipe right closes left drawer); Toast (swipe up/right dismisses) |
| Swipe between tabs | Code Tab Group on mobile (swipe between languages) |
| Pull-to-refresh | Mobile data lists (Users, Audit logs in mobile view) |
| Pinch-to-zoom | Not disabled (Qeet ID never sets `user-scalable=no` per [NFR AX-* accessibility](../phase-1/Qeet%20ID%20%E2%80%94%20Non-Functional%20Requirements%20%28NFR%29.md)) |

Every gesture has a non-gesture equivalent (per WCAG 2.5.1) — long press has a `⋯` button; swipe-to-dismiss has an explicit close button.

---

### 9. Mobile-Specific UX Patterns

### 9.1 Bottom Sheet vs Drawer

| Pattern | Where used | Why |
| --- | --- | --- |
| **Bottom sheet** | Mobile user-action menus on data table rows (suspending a user, viewing sessions) | Easy thumb reach; familiar pattern (iOS, Android) |
| **Drawer (right)** | Detail views (user detail) on mobile when the user taps a row | Same surface as desktop, adapted to viewport |
| **Drawer (left)** | Hamburger main navigation | Standard pattern |
| **Modal** | Confirmation dialogs (delete user, revoke session) | Same as desktop |

### 9.2 Sticky Bottom Action Bar

Long form screens on mobile have a sticky bottom action bar with the primary CTA:

```
   ┌─────────────────────────────────────────────┐
   │  [content scrolls]                          │
   │                                             │
   │                                             │
   ├─────────────────────────────────────────────┤
   │           [Save changes]      [Cancel]      │     (sticky, 56px)
   └─────────────────────────────────────────────┘
```

The CTA is always visible without scrolling. Used in the Auth Layout's "Continue" button on long forms (rare; most auth forms are short).

### 9.3 Mobile Navigation Decision per Surface

| Surface | Pattern |
| --- | --- |
| Dashboard | Hamburger → drawer |
| Developer Portal | Hamburger → drawer + bottom TOC popover |
| Marketing | Hamburger → drawer |
| Trust Center | Hamburger → drawer |
| Status page | No navigation (single page) |
| Account portal (`/auth/account`) | Hamburger → drawer (smaller content tree than dashboard) |

A bottom tab bar is **not** the right pattern for any Qeet ID surface at MVP — none have 3–5 top-level destinations of equal frequency.

---

### 10. Native Mobile App Considerations

The Flutter SDK (`qeetify_flutter`) lets Maya, Daniel, and Arjun build mobile apps that use Qeet ID. The UX considerations here are for the *customer's mobile app*, not for Qeet ID-owned surfaces.

### 10.1 Native vs Web View Authentication

When a customer's native mobile app needs to authenticate a user, two options:

| Option | Description | Recommended for |
| --- | --- | --- |
| **System browser (preferred)** | Open the hosted login page in the device's default browser via `ASWebAuthenticationSession` (iOS) or Custom Tabs (Android) | All customers — gives passkey conditional UI, biometric authentication, system-wide credential sync |
| **Embedded WebView** | Open inside the app via `WebView` | Not recommended — fails passkey UX; flagged by Google's policies; deprecated in iOS |
| **Native UI via Flutter widgets** | Use `QeetifyLoginButton` from the Flutter SDK; auth happens via system browser | Customers who want native UI for the button trigger but system browser for the ceremony |

The Flutter SDK's documentation makes the system-browser approach the default. The Flutter `QeetifyLoginButton` component opens `ASWebAuthenticationSession` / Custom Tabs under the hood.

### 10.2 Deep Linking Standards

For OAuth redirects back into the mobile app, Qeet ID follows the standard pattern:

| Platform | Pattern |
| --- | --- |
| iOS | Universal Links — `https://app.acme.com/oauth/callback` |
| Android | App Links — `https://app.acme.com/oauth/callback` |
| Fallback | Custom scheme (`acmeapp://oauth/callback`) — for legacy / when universal links unavailable |

The Quickstart for Flutter walks through configuring deep linking. Custom scheme is supported but the docs lead with Universal/App Links (safer).

### 10.3 Biometric Authentication on Flutter SDK

Flutter Apps can integrate Qeet ID with platform biometrics:

- **Passkey ceremony** runs in the system browser via the WebAuthn API.
- **Local re-auth** (e.g., "Use Face ID to confirm this purchase") uses platform APIs (LocalAuthentication on iOS, BiometricPrompt on Android) wrapped by the Flutter SDK.
- The latter is a step-up signal sent to Qeet ID; it does not replace the Qeet ID session.

### 10.4 Mobile App SDK Components

The Flutter SDK ships with components mirroring the React library where possible:

- `QeetifyProvider` (top-level)
- `QeetifyLoginButton`
- `QeetifyLoginScreen` (a full screen embedding the hosted login)
- `QeetifyAccountScreen`
- `useQeetify` hook

---

### 11. Performance Budget on Mobile

Per Phase 1 [NFR §4.4 Latency Budget](../phase-1/Qeet%20ID%20%E2%80%94%20Non-Functional%20Requirements%20%28NFR%29.md): end-to-end login p95 ≤800ms, with mobile network variability accounting for ~400ms of that budget.

### 11.1 Mobile Performance Targets

| Metric | Mobile target | Desktop target |
| --- | --- | --- |
| Auth page first-contentful-paint (FCP) | <1.5s on 3G | <800ms on broadband |
| Auth page largest-contentful-paint (LCP) | <2.5s on 3G | <1.5s |
| Auth page time-to-interactive (TTI) | <3s on 3G | <1.5s |
| Passkey login end-to-end | <5s on 3G (UX-01) | <2s on broadband |
| Embedded widget mount (after host JS loaded) | <500ms | <200ms |

### 11.2 Mobile-Specific Performance Techniques

| Technique | Where used |
| --- | --- |
| **Inline critical CSS** | Hosted login pages — first paint without external stylesheet round-trip |
| **System fonts as fallback** | While Inter loads, system sans-serif renders (FOUT, not FOIT) |
| **Image optimisation** | AVIF / WebP with fallback; responsive `srcset` per breakpoint |
| **JS bundle splitting** | Auth widgets lazy-load after host app paint |
| **Preconnect to OAuth callbacks** | Hosted login pages preconnect to the relying-party origin |
| **Server-side rendering** | Hosted login pages and docs SSG'd at the edge |
| **Service worker (post-MVP)** | Cache static assets; offline read for docs (v1.2 target) |

### 11.3 Bundle Size Budgets

| Bundle | Budget (gzipped) | Owner |
| --- | --- | --- |
| Hosted login page JS | <30 KB | Frontend |
| Embeddable React widget (`LoginWidget`) | <60 KB | SDK |
| Embeddable Flutter widget | n/a (compiled) | SDK |
| Admin dashboard initial chunk | <120 KB | Frontend |
| Admin dashboard per-route chunk | <40 KB average | Frontend |
| Developer portal page JS | <40 KB | Frontend |

CI enforces budgets; PRs that exceed the budget require a written waiver in the PR description.

---

### 12. Offline Behaviour

Qeet ID is an online product — authentication requires the server. Offline behaviour at MVP is:

- **Hosted login pages:** If offline at load time, the page shows an offline banner: "You're offline. Reconnect to sign in." When connectivity returns, the page reloads automatically.
- **Admin dashboard:** If the user is mid-task and connectivity drops, an offline banner appears at the top: "You're offline. Changes will not be saved." When connectivity returns, the banner clears; unsaved changes remain in the form for the user to retry submission.
- **Developer portal:** v1.2 will add a service worker for offline doc reads. At MVP, the docs require connectivity (a small allowed concession given the priority).

---

### 13. Mobile Browser Quirks

### 13.1 iOS Safari

| Quirk | Mitigation |
| --- | --- |
| Address bar grows/shrinks on scroll, changing viewport height | `100vh` not used for full-screen layouts; `100dvh` (dynamic viewport height) used where supported with `100vh` fallback |
| Date pickers use native (iOS-specific) UI | Date Picker component uses native input on iOS for `<input type="date">` |
| `position: sticky` quirks in older Safari versions | Tested on latest two Safari major versions; older versions degrade to non-sticky |
| `autocomplete="one-time-code"` triggers iOS SMS auto-fill | Used on OTP Input (Doc 3 §5.9) |

### 13.2 Android Chrome

| Quirk | Mitigation |
| --- | --- |
| Address bar / IME push viewport unpredictably | Use `window.visualViewport` API where available for accurate viewport tracking |
| SMS auto-paste via `autocomplete="one-time-code"` + Web OTP API | Used on OTP Input |
| Variable font rendering on older Android versions | Inter Static-weight fallback for Android < 12 |

### 13.3 Universal

- **`<meta name="viewport">`**: `<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">`. Notably, *not* `user-scalable=no` — that would break accessibility (WCAG 1.4.4 Resize Text).
- **Theme-colour**: `<meta name="theme-color">` set to brand primary so the browser chrome (Chrome address bar, iOS status bar tint) matches the brand.

---

### 14. Mobile-Specific Component Behaviour

Recap of mobile-specific component overrides from [Doc 3](Qeet ID%20%E2%80%94%20Component%20Library%20Specification.md):

| Component | Mobile override |
| --- | --- |
| Button | `lg` or `xl` size on mobile auth pages; touch padding inflates `sm`/`md` to 44px touch target |
| Input | `lg` size on mobile; `autoComplete` and `inputmode` natively activate appropriate keyboards |
| Social Login Buttons | Vertical stack always (no horizontal even on tablet) |
| OTP Input | Numeric keyboard; auto-paste from SMS; auto-submit on 6 digits |
| Modal | Full-width minus 16px margins on mobile; no max-width |
| Drawer | Right drawer becomes bottom sheet on mobile for action menus; remains right drawer for detail views |
| Data Table | Becomes card-list view on mobile |
| Code Tab Group | Tabs collapse to a "Code in: React ▾" selector on mobile; swipe between languages |
| Tab Group | Horizontally scrollable; current tab indicator visible |
| Date Picker | Native input on iOS; custom popover on Android (better date range support) |
| Tooltip | Long-press triggers instead of hover (with non-tooltip alternative for critical info, per AP-08) |
| Toast | Bottom-centred on mobile; bottom-right on desktop |

---

### 15. Mobile Testing Strategy

| Testing | When | Tools |
| --- | --- | --- |
| Real-device testing | Every release | iPhone SE, iPhone 15, Pixel 6, Galaxy S22 (in-house lab) |
| Cloud device testing | Weekly | BrowserStack, Sauce Labs, or LambdaTest (OD-MR-01) |
| Network throttling | Pre-release | DevTools Slow 3G + Fast 3G profiles |
| Touch target audit | Per component PR | Automated check on `min-width` / `min-height` ≥44px in `mobile-min` media query |
| Cross-orientation | Every release | QA walkthrough |
| Mobile screen reader | Per [Doc 9 §16.2](Qeet ID%20%E2%80%94%20Accessibility%20Compliance%20Plan%20%28WCAG%202.1%20AA%29.md) | VoiceOver, TalkBack |

---

### 16. Open Design Decisions From This Document

| # | Question | Owner | Target |
| --- | --- | --- | --- |
| OD-MR-01 | Cloud device testing — BrowserStack vs Sauce Labs vs LambdaTest | QA Lead | Phase 3 Week 3 |
| OD-MR-02 | Service worker for offline docs at MVP vs v1.2 | Frontend + Tech Writing | Phase 3 Week 3 |
| OD-MR-03 | Mobile dashboard "Open on desktop" feature — magic-link-style transfer vs just deep-link copy | UX + Engineering | Phase 3 Week 4 |
| OD-MR-04 | Flutter SDK passkey support — fallback when ASWebAuthenticationSession unavailable | SDK Eng + UX | Phase 3 Week 4 |
| OD-MR-05 | Galaxy Fold (folded 280px) — explicit support vs graceful degradation only | UX + QA | Phase 3 Week 4 |

---

### 17. Cross-References

- Breakpoint definitions: [Design System Foundations & Tokens](Qeet ID%20%E2%80%94%20Design%20System%20Foundations%20%26%20Tokens.md) §8
- Components with mobile behaviour: [Component Library Specification](Qeet ID%20%E2%80%94%20Component%20Library%20Specification.md)
- Mobile IA patterns: [Information Architecture & Navigation](Qeet ID%20%E2%80%94%20Information%20Architecture%20%26%20Navigation.md) §10.4
- End-user flow mobile differences: [End-User Authentication Flow Designs](Qeet ID%20%E2%80%94%20End-User%20Authentication%20Flow%20Designs.md) §28
- Admin dashboard mobile: [Admin Dashboard Design Specification](Qeet ID%20%E2%80%94%20Admin%20Dashboard%20Design%20Specification.md) §33
- Developer portal mobile: [Developer Portal Design Specification](Qeet ID%20%E2%80%94%20Developer%20Portal%20Design%20Specification.md) §23
- Touch-target accessibility: [Accessibility Compliance Plan](Qeet ID%20%E2%80%94%20Accessibility%20Compliance%20Plan%20%28WCAG%202.1%20AA%29.md) §7
- NFR responsiveness: [Phase 1 NFR §12.1](../phase-1/Qeet%20ID%20%E2%80%94%20Non-Functional%20Requirements%20%28NFR%29.md)

---

### 18. Approvals & Sign-off

| Role | Name | Signature | Date |
| --- | --- | --- | --- |
| UX Designer |  |  |  |
| Frontend Engineering Lead |  |  |  |
| Mobile (Flutter) SDK Lead |  |  |  |
| QA Lead |  |  |  |
| Accessibility Lead |  |  |  |
| Product Manager |  |  |  |

---

*This document is version controlled. Visual updates in Figma do not require re-sign-off; changes to the per-surface strategy (§3), breakpoint definitions (§4), touch-target standards (§7), or mobile performance budgets (§11) require UX Designer + Frontend Lead + QA Lead review.*

---

**Qeet ID — Authenticate Everything.** *A Qeet Group Company*
