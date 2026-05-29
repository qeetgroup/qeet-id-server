# Qeet ID — End-User Authentication Flow Designs

### 1. Document Information

|  |  |
| --- | --- |
| **Document Name** | End-User Authentication Flow Designs |
| **Project Name** | Qeet ID |
| **Parent Company** | Qeet Group |
| **Subsidiary** | Qeet ID (Standalone) |
| **Document Version** | v1.0 |
| **Prepared By** | UX Designer |
| **Date** | May 19, 2026 |
| **Status** | Draft — Pending Stakeholder Sign-off |

---

### 2. Purpose & Scope

This document is the UX specification for every screen the end user — *not* the admin, *not* the developer — encounters during authentication on Qeet ID-hosted pages. It is the design-team's counterpart to [Phase 2 Authentication Flow Designs](../phase-2/Qeet%20ID%20%E2%80%94%20Authentication%20Flow%20Designs.md), which is the engineering choreography. Phase 2 says *what the system does at each step*; this document says *what the user sees and feels at each step*.

The flows here are the screens behind every persona's end users — the people whose primary measurable outcome is the [Time to First Auth (DSM-01)](Qeet ID%20%E2%80%94%20UX%20Research%20Summary%20%26%20Design%20Principles.md) for the **end user**, not the developer. Arjun's app's user. Maya's app's user. The login screen Sandra's company shows to its workforce. The MFA challenge Omar's CISO peers will scrutinise.

Per [P-02 Passkey-First, Password-Last](Qeet ID%20%E2%80%94%20UX%20Research%20Summary%20%26%20Design%20Principles.md), every flow leads with passkeys. Per [P-03 Mobile-First](Qeet ID%20%E2%80%94%20UX%20Research%20Summary%20%26%20Design%20Principles.md), every screen is designed at 320–639px first. Per [P-08 Errors Are Designed](Qeet ID%20%E2%80%94%20UX%20Research%20Summary%20%26%20Design%20Principles.md), every error state is specified, not improvised.

The audience is the UX Designer, the Frontend Engineering Lead, the Auth Engineering Team (Team Auth), the Accessibility Lead, the QA Lead, and the Localisation Lead.

This document depends on [Phase 2 Authentication Flow Designs](../phase-2/Qeet%20ID%20%E2%80%94%20Authentication%20Flow%20Designs.md) for system choreography, [UX Research Summary & Design Principles](Qeet ID%20%E2%80%94%20UX%20Research%20Summary%20%26%20Design%20Principles.md), [Design System Foundations & Tokens](Qeet ID%20%E2%80%94%20Design%20System%20Foundations%20%26%20Tokens.md), [Component Library Specification](Qeet ID%20%E2%80%94%20Component%20Library%20Specification.md), and [Information Architecture & Navigation §5](Qeet ID%20%E2%80%94%20Information%20Architecture%20%26%20Navigation.md).

---

### 3. Flow Design Principles

The ten Design Principles ([Doc 1 §6](Qeet ID%20%E2%80%94%20UX%20Research%20Summary%20%26%20Design%20Principles.md)) apply universally. The principles below specialise them for authentication flows.

**FP-01 — Passkey-First, Always.** The passkey button is the primary CTA on the login screen. Conditional UI fires on email-field focus. Password is the fallback path. Social login is the secondary path. Magic links are the tertiary path. The order is intentional.

**FP-02 — Fewest Possible Screens.** Every screen the user must traverse to complete authentication is a screen on which they can fail or quit. Eliminate them. A passkey login is one screen. A password+MFA login is two. A magic-link request is two (request + sent confirmation).

**FP-03 — Fastest Possible Path.** Passkey login ≤5s total time (UX-01). Password+MFA login ≤30s median (UX-02). Skeleton screens cover the network latency budget per [P-09](Qeet ID%20%E2%80%94%20UX%20Research%20Summary%20%26%20Design%20Principles.md).

**FP-04 — Graceful Fallback.** If the user's passkey ceremony fails (cancelled, no credential, browser unsupported), the password / social / magic-link options remain available without page reload.

**FP-05 — Never Trap the User.** Every screen has a clear way out — either to complete the flow, change credentials, request help, or return to the relying party. The user is never stuck on a dead screen.

**FP-06 — Anti-Enumeration by Design.** Screen responses do not differentiate "user exists" from "user does not exist" — the magic-link-sent screen, the password-failed screen, the recovery-requested screen all look the same regardless. The screens encode the [Phase 2 Auth Flow §3 anti-enumeration semantics](../phase-2/Qeet%20ID%20%E2%80%94%20Authentication%20Flow%20Designs.md).

**FP-07 — Localised, Always.** Every flow ships in 10 languages at launch (English, Spanish, French, German, Portuguese, Italian, Japanese, Korean, Mandarin, Hindi — NFR IN-02). The structural design is reviewed in the longest expected language (typically German) to confirm no clipping or wrapping accidents.

**FP-08 — Brand-Customisable Within Bounds.** The tenant can brand: logo, primary colour, accent, background, font (from approved set), border radius, footer attribution. The tenant cannot break: spacing, type scale, contrast minimums, required UI elements (passkey button placement, error positions, footer Qeet ID mark on non-Enterprise plans). See [Phase 3 Doc 8](Qeet ID%20%E2%80%94%20Embeddable%20Auth%20UI%20Components%20%28White-Label%29.md).

---

### 4. Flow Inventory

The 18 flows specified in this document, mapped to the corresponding Phase 2 system choreography:

| # | Flow | Phase 2 §reference |
| --- | --- | --- |
| F-01 | Sign-up | Auth Flow §3, §14 |
| F-02 | Login — Passkey conditional UI (autofill) | Auth Flow §11 |
| F-03 | Login — Passkey explicit | Auth Flow §11 |
| F-04 | Login — Password fallback (with optional MFA) | Auth Flow §13 |
| F-05 | Login — Magic link | Auth Flow §14 |
| F-06 | Login — Social (Google, GitHub, Microsoft, Apple) | Auth Flow §3 + Social Bridge |
| F-07 | Cross-device passkey (QR) | Auth Flow §12 |
| F-08 | MFA challenge — TOTP | Auth Flow §15 |
| F-09 | MFA challenge — SMS OTP | Auth Flow §16 |
| F-10 | MFA challenge — Email OTP | Auth Flow §14 (OTP variant) |
| F-11 | MFA challenge — Backup codes | (specialised) |
| F-12 | Step-up authentication | Auth Flow §17 |
| F-13 | Password reset | (extension of recovery) |
| F-14 | Account recovery (lost factors) | Auth Flow §20 |
| F-15 | Email verification | (extension of sign-up) |
| F-16 | Phone verification | (Verification component) |
| F-17 | Account settings — Manage passkeys / MFA / sessions | n/a (account portal) |
| F-18 | Account deletion (GDPR Art. 17) / Data export (GDPR Art. 20) | Microservices §4.5 |

All flows use the **Auth Layout** template ([Component Library §7.1](Qeet ID%20%E2%80%94%20Component%20Library%20Specification.md)), except F-17 (Account settings) and F-18 (which use the Settings Layout).

---

### 5. F-01 — Sign-up Flow

**Trigger.** User clicks "Sign up" or "Create account" from a relying-party application, marketing site, or shared invitation link.

**Goal.** Get a verified user with a registered passkey into the relying-party application as fast as possible. Per [Persona Arjun](Qeet ID%20%E2%80%94%20UX%20Research%20Summary%20%26%20Design%20Principles.md): the developer integrating Qeet ID expects his users to complete this in under 90 seconds.

**Latency expectations:** screen-by-screen render <500ms p95 (NFR PF-08 / PF-09 budgets). Email verification email arrives <30s p95 (Notification Service).

### 5.1 Screen Sequence

```
   [1] Sign-up entry        →   [2] Email verification    →    [3] Passkey      →   [4] Welcome
   "Create your account"        "Check your email"             registration         "You're set."
                                                                prompt
```

### 5.2 Screen [1] — Sign-up Entry

```
   ┌─────────────────────────────────────────┐
   │             [Tenant logo]               │
   │                                         │
   │       ┌────────────────────────┐        │
   │       │                        │        │
   │       │   Create your account  │        │
   │       │                        │        │
   │       │   Email                │        │
   │       │   [____________________│        │
   │       │                        │        │
   │       │   [Continue]           │        │
   │       │                        │        │
   │       │   ─── or ───           │        │
   │       │                        │        │
   │       │   [G Continue Google]  │        │
   │       │   [⌂ Continue GitHub]  │        │
   │       │                        │        │
   │       │   Already have an      │        │
   │       │   account? Sign in →   │        │
   │       │                        │        │
   │       └────────────────────────┘        │
   │                                         │
   │     Powered by Qeet ID · Privacy · ToS  │
   └─────────────────────────────────────────┘
```

**Key UI elements:**
- Tenant logo (24px – 64px range; locked aspect ratio).
- Card title `text.heading-lg` (Component Library §6).
- Email input (`type="email"`, `autoComplete="username"`).
- Primary Button "Continue" (xl size).
- Social login buttons (Google + GitHub at MVP; tenant can configure which appear).
- "Sign in" link is `text.link`.
- Footer: Privacy + ToS + Qeet ID attribution (configurable per plan — see [Doc 8 §6](Qeet ID%20%E2%80%94%20Embeddable%20Auth%20UI%20Components%20%28White-Label%29.md)).

**Behaviour:**
- Email validates on blur (RFC-shape check; no async lookup for anti-enumeration).
- Continue submits POST `/v1/signup` with email + tenant context.
- Anti-enumeration: same screen shown regardless of whether the email is already registered (the next screen is the verification screen either way; if email exists, the server emits a "you already have an account — sign in instead" email).

**Error paths:**

| Trigger | UI |
| --- | --- |
| Invalid email format | Inline error "Enter a valid email address." |
| Empty email | Inline error "Email is required." |
| Rate limited (Guard) | Inline banner "Too many signups from this device. Please wait a few minutes." with `Retry-After` countdown |
| Server error | Page banner with retry button + error code |

**Accessibility:**
- Logo `alt` is the tenant name.
- Email field has visible Label and `autoComplete="username"`.
- Errors are `aria-live="polite"`.
- Tab order: email → Continue → social buttons → Sign-in link.

**Mobile:**
- Card full-width with 16px margins.
- Email keyboard auto-opens on field focus.
- Vertical stack of social buttons.

### 5.3 Screen [2] — Email Verification

```
   ┌─────────────────────────────────────────┐
   │             [Tenant logo]               │
   │       ┌────────────────────────┐        │
   │       │     ✉  (large icon)    │        │
   │       │                        │        │
   │       │  Check your email      │        │
   │       │                        │        │
   │       │  We sent a verification│        │
   │       │  link to               │        │
   │       │  alice@example.com     │        │
   │       │                        │        │
   │       │  The link expires in   │        │
   │       │  15 minutes.           │        │
   │       │                        │        │
   │       │  Didn't get it?        │        │
   │       │  Resend in 23s         │        │
   │       │                        │        │
   │       │  Wrong email?          │        │
   │       │  ← Change email        │        │
   │       │                        │        │
   │       └────────────────────────┘        │
   └─────────────────────────────────────────┘
```

**Behaviour:**
- Same screen shown regardless of email status (anti-enumeration; Phase 2 Auth Flow F-01 §3).
- Resend cooldown 30s, then enabled.
- "Change email" returns to Screen [1] with email pre-filled.
- Auto-progress: if the user clicks the email link in another tab/window, this screen auto-advances to Screen [3] via SSE / polling on the verification status.

**Email contents:** see [§24 Email Template Coordination](#24-email-template-coordination).

### 5.4 Screen [3] — Passkey Registration Prompt

Triggered when the user clicks the email verification link (or auto-advances on Screen [2]).

```
   ┌─────────────────────────────────────────┐
   │             [Tenant logo]               │
   │       ┌────────────────────────┐        │
   │       │     🔑  (passkey icon) │        │
   │       │                        │        │
   │       │  Set up a passkey      │        │
   │       │                        │        │
   │       │  Passkeys are faster   │        │
   │       │  and safer than        │        │
   │       │  passwords. Your       │        │
   │       │  device will create    │        │
   │       │  one for you.          │        │
   │       │                        │        │
   │       │  [🔑 Create a passkey] │        │
   │       │                        │        │
   │       │  Skip — set up later   │        │
   │       │  (you'll need a        │        │
   │       │   password)            │        │
   │       └────────────────────────┘        │
   └─────────────────────────────────────────┘
```

**Behaviour:**
- "Create a passkey" triggers WebAuthn registration ceremony (Phase 2 Auth Flow §10).
- Browser displays its native authenticator picker (Touch ID, Face ID, Windows Hello, hardware key).
- On success → Screen [4].
- "Skip" leads to a password-creation screen (a one-screen sub-flow not pictured here): "Create a password" with confirm field and password-strength meter.

**Why the prompt:** [Phase 1 Persona Omar](Qeet ID%20%E2%80%94%20UX%20Research%20Summary%20%26%20Design%20Principles.md) and the [Design Principle P-02](Qeet ID%20%E2%80%94%20UX%20Research%20Summary%20%26%20Design%20Principles.md). The skip is allowed because some users will register on a device where they cannot create a passkey (a shared library computer, for instance). Skipping does not weaken the security model; the user still has email-based recovery and can register a passkey later.

**Error paths:**

| Trigger | UI |
| --- | --- |
| User cancels native picker | Card returns to prompt; helper text appears: "Passkey not created. You can try again or skip for now." |
| WebAuthn not supported by browser | "Create passkey" button is replaced by "Create a password" — passkey prompt becomes a one-line "Tip: your browser doesn't support passkeys yet. Try Chrome, Safari, Edge, or Firefox latest version." |
| Server-side registration error | Page banner with error code; retry button |
| User has too many passkeys (>10, Protocol PK-06) | Modal: "Passkey limit reached. Remove an existing passkey to add a new one." with link to account settings |

**Accessibility:**
- `🔑` icon has `aria-label="Passkey icon"`.
- "Create a passkey" button has `aria-describedby` pointing to the body text (so SR users hear the benefit text after the button label).
- Skip link is not styled like a button — it's a link, making the primary action visually dominant.

### 5.5 Screen [4] — Welcome

```
   ┌─────────────────────────────────────────┐
   │             [Tenant logo]               │
   │       ┌────────────────────────┐        │
   │       │       ✓  (success)     │        │
   │       │                        │        │
   │       │   You're all set       │        │
   │       │                        │        │
   │       │   Welcome to Acme.     │        │
   │       │                        │        │
   │       │   [Continue to Acme]   │        │
   │       │                        │        │
   │       └────────────────────────┘        │
   └─────────────────────────────────────────┘
```

**Behaviour:**
- "Continue to Acme" redirects to the relying party's post-signup URL.
- Auto-redirects after 3 seconds if the user is idle.
- A subtle confirmation toast appears: "Passkey created. You can manage it in Account Settings."

**Mobile:** identical layout; the auto-redirect timer is reduced to 2 seconds on small viewports (the user has less screen to dwell on).

---

### 6. F-02 — Login: Passkey Conditional UI (Autofill)

This is the *invisible-good* flow — the user sees a single screen, focuses the email field, picks a passkey suggestion from the browser's native UI, and authentication completes. No click on the "Continue with passkey" button required.

### 6.1 Screen

```
   ┌─────────────────────────────────────────┐
   │             [Tenant logo]               │
   │       ┌────────────────────────┐        │
   │       │   Sign in to Acme      │        │
   │       │                        │        │
   │       │   Email                │        │
   │       │   [_______________ ▼]  │   ← native passkey suggestion
   │       │       Alice (passkey) │     appears on field focus
   │       │       Use a passkey   │
   │       │                        │        │
   │       │   [🔑 Continue with    │        │
   │       │    a passkey]          │        │
   │       │                        │        │
   │       │   ─── or ───           │        │
   │       │                        │        │
   │       │   [G Continue Google]  │        │
   │       │   [⌂ Continue GitHub]  │        │
   │       │                        │        │
   │       │   Use a password →     │        │
   │       │   Use a magic link →   │        │
   │       │                        │        │
   │       │   No account?          │        │
   │       │   Create one →         │        │
   │       └────────────────────────┘        │
   └─────────────────────────────────────────┘
```

### 6.2 Behaviour

- On page load, the email Input has `autoComplete="username webauthn"` (mandatory per [Component Library §4.2.1](Qeet ID%20%E2%80%94%20Component%20Library%20Specification.md)).
- JavaScript invokes `navigator.credentials.get({mediation: "conditional", publicKey: {...}})` (Phase 2 Auth Flow §11).
- If the browser has a passkey for this origin, the native autofill suggests it.
- User taps the suggestion → browser native UI prompts for biometric → success → relying-party callback.
- The screen is the same fallback screen for users *without* a passkey. They see the email field, fill it, click "Continue with passkey" if they have a passkey on another device (which prompts cross-device flow F-07); otherwise they fall back to password (F-04) or magic link (F-05) or social login (F-06).

### 6.3 Time Budget

- p95 from page load to authenticated state: ≤5s (NFR UX-01).
- Of which:
  - Network + render: ≤800ms
  - User reads + focuses + picks: ≤3s (the human variable)
  - Biometric + verification + token issue: ≤1s

### 6.4 Error Paths

| Trigger | UI |
| --- | --- |
| Conditional UI not invoked (browser unsupported) | Screen still renders normally — the user clicks "Continue with a passkey" or falls back |
| `navigator.credentials.get()` returns no credential (user has no passkey here) | Silent — no error UI; the user proceeds with password or another method |
| `navigator.credentials.get()` user-cancelled | Silent — no error UI |
| Server verification fails (invalid signature, mismatched challenge, etc.) | Card-top error banner: "We couldn't sign you in with that passkey. Try again or use a different method." Error code shown |

### 6.5 Accessibility

- The autofill suggestion is browser-native; screen readers (NVDA, JAWS, VoiceOver, TalkBack) handle it.
- The "Continue with a passkey" button is the explicit fallback for users who don't trigger autofill — fully keyboard-accessible per Component Library §4.1.
- "Use a password" and "Use a magic link" links are below the social buttons, visually subordinate but reachable.

### 6.6 Mobile

- Native mobile passkey UX is even better than desktop — Touch ID / Face ID picker appears immediately.
- The "Continue with a passkey" button label is unchanged; mobile users tap the button if conditional UI didn't trigger.

---

### 7. F-03 — Login: Passkey Explicit

When the user clicks the "Continue with a passkey" button directly without using conditional UI autofill.

### 7.1 Behaviour

- Click triggers `navigator.credentials.get({mediation: "optional"})` — the browser's standard, modal passkey picker.
- If the user has a passkey on the device, the picker appears immediately.
- If the user does not have a passkey on the device but has one elsewhere, the browser may offer a cross-device hybrid flow — F-07 takes over.
- If the user has no passkey at all, the browser shows "no passkeys found" — Qeet ID catches this and surfaces "It looks like you don't have a passkey here. Try a different sign-in option ↓".

### 7.2 Screen — No Passkey Available State

```
   ┌─────────────────────────────────────────┐
   │       ┌────────────────────────┐        │
   │       │   Sign in to Acme      │        │
   │       │                        │        │
   │       │   No passkey found     │        │
   │       │   on this device.      │        │
   │       │                        │        │
   │       │   [Use a passkey on    │        │
   │       │    another device]     │   → F-07
   │       │   [Continue with       │        │
   │       │    password]           │   → F-04
   │       │   [Send me a magic     │        │
   │       │    link]               │   → F-05
   │       │                        │        │
   │       └────────────────────────┘        │
   └─────────────────────────────────────────┘
```

---

### 8. F-04 — Login: Password Fallback (with optional MFA)

Triggered when the user clicks "Use a password" from the login screen, or when the user clicks "Continue with a passkey" and chooses the password fallback inside the resulting screen.

### 8.1 Screen Sequence

```
   [4.1] Enter password    →    [4.2] MFA challenge (if required)
```

### 8.2 Screen [4.1] — Password Entry

```
   ┌─────────────────────────────────────────┐
   │             [Tenant logo]               │
   │       ┌────────────────────────┐        │
   │       │   Sign in to Acme      │        │
   │       │                        │        │
   │       │   alice@example.com    │ ← pre-filled
   │       │   [Edit]                        │
   │       │                        │        │
   │       │   Password             │        │
   │       │   [_________________👁] │        │
   │       │                        │        │
   │       │   [Continue]           │        │
   │       │                        │        │
   │       │   Forgot password? →   │        │
   │       │   Use a passkey instead│        │
   │       └────────────────────────┘        │
   └─────────────────────────────────────────┘
```

**Behaviour:**
- Password Input with `type="password"`, `autoComplete="current-password"`, show/hide eye toggle.
- "Continue" submits. While the request is in flight, the button shows a loading spinner with text "Verifying…" and the form is disabled.
- "Forgot password?" → F-13.
- "Use a passkey instead" returns to the F-02 screen with email pre-filled.

**Error paths:**

| Trigger | UI |
| --- | --- |
| Wrong password | Inline error "Incorrect email or password." (anti-enumeration: same message regardless of whether the email exists, per Phase 2 Auth Flow §13) |
| Compromised password detected (HIBP) | After successful login, inline notice (non-blocking, dismissible): "We noticed this password has appeared in known data breaches. We recommend changing it." with "Change password" CTA |
| Account locked (5+ failures) | Page banner: "Account locked for 15 minutes after too many sign-in attempts. Try again at 14:47 UTC, or reset your password." |
| Server error | Page banner with error code + retry |

**Anti-enumeration timing:**
- Per Phase 2 IdP Core §8.2, the server has a constant-time path even when the user does not exist. The UI mirrors this: the loading state of "Verifying…" lasts ≥800ms even when the server returns instantly, so the user cannot time-detect the absence of a record.

### 8.3 Screen [4.2] — MFA Challenge (if Required)

If the tenant or user policy requires MFA, the user advances to an MFA challenge screen — F-08 (TOTP), F-09 (SMS), F-10 (Email OTP), or F-11 (Backup codes), depending on the user's enrolled factor and the policy's required strength.

### 8.4 Accessibility

- Password field's show/hide toggle is a Button with `aria-pressed` indicating visibility state.
- The toggle's label changes ("Show password" / "Hide password") for screen readers.

---

### 9. F-05 — Login: Magic Link

### 9.1 Screen Sequence

```
   [5.1] Request magic link    →    [5.2] Magic link sent    →    [user clicks email link]    →    relying-party callback
```

### 9.2 Screen [5.1] — Request

```
   ┌─────────────────────────────────────────┐
   │       ┌────────────────────────┐        │
   │       │   Sign in to Acme      │        │
   │       │                        │        │
   │       │   We'll email you a    │        │
   │       │   sign-in link.        │        │
   │       │                        │        │
   │       │   Email                │        │
   │       │   [____________________│        │
   │       │                        │        │
   │       │   [Send me a link]     │        │
   │       │                        │        │
   │       │   ← Back to all options │        │
   │       └────────────────────────┘        │
   └─────────────────────────────────────────┘
```

### 9.3 Screen [5.2] — Sent Confirmation

This is the **Magic Link Sent State** molecule ([Component Library §5.12](Qeet ID%20%E2%80%94%20Component%20Library%20Specification.md)).

```
   ┌─────────────────────────────────────────┐
   │       ┌────────────────────────┐        │
   │       │     ✉                  │        │
   │       │                        │        │
   │       │   Check your email     │        │
   │       │                        │        │
   │       │   We sent a sign-in    │        │
   │       │   link to              │        │
   │       │   alice@example.com.   │        │
   │       │                        │        │
   │       │   The link expires in  │        │
   │       │   15 minutes.          │        │
   │       │                        │        │
   │       │   Didn't get it?       │        │
   │       │   Resend in 23s        │        │
   │       │                        │        │
   │       │   Use a different      │        │
   │       │   sign-in option →     │        │
   │       └────────────────────────┘        │
   └─────────────────────────────────────────┘
```

### 9.4 Anti-Enumeration

The sent confirmation appears regardless of whether the email is registered. If the email is unknown, no email is sent — but the user sees the same screen. This matches Phase 2 Auth Flow §14.

### 9.5 Email Click → Auto-Authenticate

When the user clicks the link in the email, the browser navigates to `/auth/magic?token=...`. Qeet ID validates the JWT, marks the nonce consumed (Phase 2 IdP Core §10 / Auth Flow §14), establishes the session, and redirects to the relying party's callback URL.

**Edge case — link clicked in a different browser:**

If the user requests the link in Browser A and clicks it in Browser B (e.g., requested on phone, clicks in laptop email), the session is established in Browser B. The original Browser A screen polls and displays: "Signed in from another device. You can close this tab."

### 9.6 Error Paths

| Trigger | UI |
| --- | --- |
| Link expired | Page: "Sign-in link expired. Links are valid for 15 minutes. Request a new one." with "Request new link" CTA |
| Link already used | Page: "This sign-in link has already been used." (Phase 2 §14 single-use) |
| Link tampered | Page: "Invalid sign-in link. Request a new one." |
| Tenant suspended | Page: "Sign-in unavailable. Contact your administrator." (no detailed reason for security) |

---

### 10. F-06 — Login: Social (Google, GitHub, Microsoft, Apple)

### 10.1 Screen Sequence

```
   [Social button click]    →    [Provider's auth screen]    →    [Provider redirects back]    →    [Qeet ID session]
```

### 10.2 Behaviour

- Click on a social Button triggers `GET /v1/oauth/social/{provider}/authorize?...` (Phase 2 Microservices §4.10).
- The user is redirected to the provider (Google, GitHub, Microsoft, Apple).
- The provider's UX is owned by the provider — Qeet ID does not specify it.
- On successful provider auth, the provider redirects back to `GET /v1/oauth/social/{provider}/callback`.
- Qeet ID exchanges the provider token, upserts the user (JIT provisioning), and redirects to the relying-party callback.

### 10.3 Account Linking

If the social-provider email matches an existing Qeet ID user (same email, same tenant), Qeet ID shows an account-link screen:

```
   ┌─────────────────────────────────────────┐
   │   We already have an account for       │
   │   alice@example.com.                    │
   │                                         │
   │   Link your Google account to your      │
   │   existing Acme account?                │
   │                                         │
   │   [Yes, link them]    [Cancel]          │
   └─────────────────────────────────────────┘
```

### 10.4 Error Paths

| Trigger | UI |
| --- | --- |
| User cancels at provider | Returns to the Qeet ID login screen — silent (the user knows they cancelled) |
| Provider error | Page banner: "Couldn't sign in with Google. Try again or use another option." with error code |
| Email already linked to another tenant | Inline: "This account is associated with another organisation. Sign in with a different account." |

### 10.5 Apple Sign In Specifics

Apple HIG mandates specific button styling (rounded corners, exact label). The Social Login Button for Apple respects Apple's brand guidelines exactly, including the "Sign in with Apple" wording (not "Continue with Apple") per Apple's requirements.

---

### 11. F-07 — Cross-Device Passkey (QR)

The user is on a desktop browser without a registered passkey on this device, but they have a passkey on their phone. Standard CTAP 2.2 hybrid transport gives them the path.

### 11.1 Screen Sequence

```
   [Desktop: scan QR]    →    [Phone: tap notification]    →    [Phone: biometric]    →    [Desktop: signed in]
```

### 11.2 Desktop Screen

```
   ┌─────────────────────────────────────────────────────────┐
   │                  [Tenant logo]                          │
   │     ┌────────────────────────────────────┐              │
   │     │  Use a passkey on another device   │              │
   │     │                                    │              │
   │     │     ┌──────────────────┐           │              │
   │     │     │                  │           │              │
   │     │     │     [QR code]    │           │              │
   │     │     │                  │           │              │
   │     │     └──────────────────┘           │              │
   │     │                                    │              │
   │     │  Scan this code with your phone.   │              │
   │     │  Both devices need Bluetooth on.    │              │
   │     │                                    │              │
   │     │  Waiting for your phone…           │              │
   │     │  (spinner)                         │              │
   │     │                                    │              │
   │     │  Use a different sign-in option →  │              │
   │     └────────────────────────────────────┘              │
   └─────────────────────────────────────────────────────────┘
```

### 11.3 Behaviour

- The browser invokes the WebAuthn hybrid transport; the QR contains the CTAP server-data payload.
- Phone scans → user sees a system notification → taps it → biometric prompt → ceremony completes via Bluetooth-proximity-mediated CTAP tunnel.
- Desktop screen advances automatically when the phone completes the ceremony.

### 11.4 Time Budget

The cross-device flow is inherently slower (network + Bluetooth + phone UI). Reasonable bound is ~15 seconds. The screen shows the "Waiting for your phone…" spinner to set expectations.

### 11.5 Error Paths

| Trigger | UI |
| --- | --- |
| Bluetooth off on either device | Inline: "Bluetooth is required. Turn it on and try again." |
| User cancels on phone | Returns to desktop login screen |
| Tunnel timeout (60s) | "Connection timed out. Try again or use a different sign-in option." |
| Browser does not support hybrid transport | The "Use a passkey on another device" affordance is hidden; user proceeds with explicit-passkey or fallback |

### 11.6 Mobile-on-Mobile

If the user is *on their phone* and tries cross-device (e.g., to use a passkey from a different phone), the same flow applies — but the use case is rarer. Most mobile users have their passkey on the device they're using.

---

### 12. F-08 — MFA Challenge: TOTP

### 12.1 Screen

```
   ┌─────────────────────────────────────────┐
   │       ┌────────────────────────┐        │
   │       │   Two-factor auth      │        │
   │       │                        │        │
   │       │   Enter the 6-digit    │        │
   │       │   code from your       │        │
   │       │   authenticator app    │        │
   │       │                        │        │
   │       │   ┌─┐ ┌─┐ ┌─┐ ┌─┐ ┌─┐ ┌─┐ │       │
   │       │   │ │ │ │ │ │ │ │ │ │ │ │ │       │
   │       │   └─┘ └─┘ └─┘ └─┘ └─┘ └─┘ │       │
   │       │                        │        │
   │       │   Use another method → │        │
   │       │   (SMS, email, backup) │        │
   │       └────────────────────────┘        │
   └─────────────────────────────────────────┘
```

### 12.2 Behaviour

- The OTP Input molecule ([Component Library §5.9](Qeet ID%20%E2%80%94%20Component%20Library%20Specification.md)) auto-advances per digit.
- `autoComplete="one-time-code"`; `inputmode="numeric"`; numeric keyboard on mobile.
- Auto-submit when 6 digits are entered.
- A "Verifying…" interstitial appears while the server validates.

### 12.3 Time Budget

- The TOTP code rotates every 30s. The challenge UI shows no countdown (the user has the countdown in their authenticator app).
- The 90-second tolerance window (Protocol TP-04) is invisible to the user — it just means a code that just rotated still works for a few seconds.

### 12.4 Error Paths

| Trigger | UI |
| --- | --- |
| Wrong code | Inline error: "Incorrect code. Try again." Input clears. After 3 failures, exponential backoff message appears: "Too many incorrect codes. Wait 30 seconds." |
| Code expired (after 90s window) | Same as wrong code (user re-enters from authenticator app) |
| User has no TOTP enrolled but the flow expects it | Server falls back to next enrolled factor; user sees that factor's screen instead |

### 12.5 Use Another Method

Clicking the link expands a menu of the user's enrolled MFA methods:

```
   Use another method
   ──────────────────
   ◯ Text message to •••• 7421
   ◯ Email to a••••@example.com
   ◯ Backup code
   ✕ Cancel
```

Selecting a method navigates to the corresponding screen (F-09, F-10, F-11).

---

### 13. F-09 — MFA Challenge: SMS OTP

### 13.1 Screen

```
   ┌─────────────────────────────────────────┐
   │       ┌────────────────────────┐        │
   │       │   Two-factor auth      │        │
   │       │                        │        │
   │       │   We sent a code to    │        │
   │       │   •••• 7421            │        │
   │       │                        │        │
   │       │   ┌─┐┌─┐┌─┐┌─┐┌─┐┌─┐   │        │
   │       │   │ ││ ││ ││ ││ ││ │   │        │
   │       │   └─┘└─┘└─┘└─┘└─┘└─┘   │        │
   │       │                        │        │
   │       │   Didn't get it?       │        │
   │       │   Resend in 22s        │        │
   │       │                        │        │
   │       │   Use another method → │        │
   │       └────────────────────────┘        │
   └─────────────────────────────────────────┘
```

### 13.2 Behaviour

- Code arrives within ~10–30s typical (Twilio SLA via [Phase 2 Notification Service](../phase-2/Qeet%20ID%20%E2%80%94%20Microservices%20Decomposition%20%26%20Service%20Boundaries.md)).
- The OTP code is 6 digits, 10-minute expiry (Protocol SM-02).
- `autoComplete="one-time-code"` enables iOS / Android auto-paste from the SMS notification.
- Resend cooldown 30s.
- Per Protocol SM-04: maximum 5 OTP requests per phone per hour — the screen surfaces this with "You've reached the resend limit. Try again in 1 hour." if hit.

### 13.3 Privacy Note

The phone number is partially masked (`•••• 7421`) — never shown in full on the screen. This is by design (Stakeholder Findings, security review).

### 13.4 Error Paths

| Trigger | UI |
| --- | --- |
| Wrong code | Inline error; clears |
| Expired code (>10 min) | "Code expired. Request a new one." |
| Resend limit hit | "You've requested too many codes. Try again in 1 hour or use another method." |
| Delivery failure (Twilio degraded) | After 60s without arrival: "Trouble delivering the code? Try email instead." |

---

### 14. F-10 — MFA Challenge: Email OTP

Identical structure to F-09 (SMS) but the code is delivered via email. The email is masked (`a••••@example.com`).

Behaviour matches Phase 2 Auth Flow §14 (magic links / email OTP). The OTP variant displays a 6-digit code in the email body; the user types it into the OTP Input.

### 14.1 Magic Link vs Email OTP

Tenants can configure which variant their users see (or both). The magic link is one-click but requires the user to be in their email app; the OTP is more friction but works when the user is on a device that doesn't have their email app handy.

---

### 15. F-11 — MFA Challenge: Backup Codes

Triggered when the user clicks "Use a backup code" from the "Use another method" menu. Backup codes are the recovery affordance when the user has lost access to their primary MFA factor.

### 15.1 Screen

```
   ┌─────────────────────────────────────────┐
   │       ┌────────────────────────┐        │
   │       │   Use a backup code    │        │
   │       │                        │        │
   │       │   Enter one of the     │        │
   │       │   8-character backup   │        │
   │       │   codes you saved when │        │
   │       │   you set up MFA.      │        │
   │       │                        │        │
   │       │   [______-______]      │        │
   │       │                        │        │
   │       │   [Continue]           │        │
   │       │                        │        │
   │       │   No backup codes?     │        │
   │       │   Recover your account →│       │
   │       └────────────────────────┘        │
   └─────────────────────────────────────────┘
```

### 15.2 Behaviour

- Backup code is 10 digits formatted `XXXX-XXXX-XX` (Protocol TP-09).
- Single-use; once used, removed from the user's available backup codes.
- On success, the user is logged in AND shown an account-security banner: "You have 4 backup codes remaining. Generate new ones in Account Settings."

### 15.3 No Backup Codes Path

Leads to F-14 (Account Recovery).

---

### 16. F-12 — Step-Up Authentication

The user is already authenticated but tries an action requiring higher assurance (Phase 2 Auth Flow §17). The relying party returns 401 with required `acr_values=urn:qeetify:acr:3` (passkey-strength).

### 16.1 Screen

```
   ┌─────────────────────────────────────────┐
   │       ┌────────────────────────┐        │
   │       │   Confirm it's you     │        │
   │       │                        │        │
   │       │   To continue, please  │        │
   │       │   confirm with a       │        │
   │       │   passkey.             │        │
   │       │                        │        │
   │       │   [🔑 Use passkey]     │        │
   │       │                        │        │
   │       │   Cancel               │        │
   │       └────────────────────────┘        │
   └─────────────────────────────────────────┘
```

### 16.2 Behaviour

- Step-up does not log the user out. On success, the session ACR is upgraded; the user returns to where they were.
- Cancel returns to the previous page without elevation — the privileged action remains blocked.

### 16.3 Step-Up With Lower Factor

If the user has no passkey but has TOTP, the step-up screen offers TOTP. If they have only password + SMS, step-up offers SMS. The principle (per [Phase 2 Auth Flow §17](../phase-2/Qeet%20ID%20%E2%80%94%20Authentication%20Flow%20Designs.md)): the step-up should use the **strongest available factor**, but never weaker than the original authentication.

---

### 17. F-13 — Password Reset

### 17.1 Screen Sequence

```
   [Request reset]    →    [Reset link sent]    →    [Click email link]    →    [New password]    →    [Auto-login or sign-in screen]
```

### 17.2 Screen — Request Reset

Same shape as F-05 (magic link request): one screen with email input, "Send reset link" CTA. Anti-enumeration: same confirmation regardless of email status.

### 17.3 Screen — New Password

Triggered from the email link.

```
   ┌─────────────────────────────────────────┐
   │       ┌────────────────────────┐        │
   │       │   Reset your password  │        │
   │       │                        │        │
   │       │   New password         │        │
   │       │   [_________________👁] │        │
   │       │   ░░░░░░░░░ Strong     │        │
   │       │                        │        │
   │       │   Confirm new password │        │
   │       │   [_________________👁] │        │
   │       │                        │        │
   │       │   [Save and sign in]   │        │
   │       └────────────────────────┘        │
   └─────────────────────────────────────────┘
```

### 17.4 Password Strength Meter

- Visual bar (1 of 5 segments lit, then 2, etc.).
- Label changes ("Too short" / "Weak" / "Fair" / "Good" / "Strong").
- HIBP compromised-password check runs on blur (Phase 2 IdP Core §7.1).
- Failed compromised check shows an inline warning: "This password has appeared in known data breaches. Choose a different one."

### 17.5 Post-Reset

On success, the user's existing sessions are revoked (Phase 2 IdP Core: password change invalidates sessions for security). The user is auto-logged-in on the current device and redirected to the relying-party callback OR shown the login screen with email pre-filled if no callback is in context.

### 17.6 Reset-While-Logged-In Variant

If a logged-in user changes their password from Account Settings (F-17), the flow is in-app, not via email link. The "Save changes" button revokes other sessions and shows a confirmation toast: "Password changed. You're signed out of other sessions."

---

### 18. F-14 — Account Recovery (Lost Factors)

This flow is invoked when a user cannot authenticate via any of their enrolled factors (lost device, lost passkey, lost phone). It is deliberately high-friction — recovery is the most attacker-targeted flow.

### 18.1 Recovery Triggers

- User clicks "Recover your account" from F-11 (no backup codes).
- User clicks "Forgot all my factors?" from any MFA challenge screen.

### 18.2 Screen Sequence

```
   [Identify]    →    [Verify ownership]    →    [Reset MFA / passkey]    →    [Sign in]
```

### 18.3 Screen [1] — Identify

```
   ┌─────────────────────────────────────────┐
   │       ┌────────────────────────┐        │
   │       │   Recover your account │        │
   │       │                        │        │
   │       │   Enter your account   │        │
   │       │   email. We'll send    │        │
   │       │   recovery instructions│        │
   │       │   if we find an account│        │
   │       │   for it.              │        │
   │       │                        │        │
   │       │   Email                │        │
   │       │   [____________________│        │
   │       │                        │        │
   │       │   [Send instructions]  │        │
   │       │                        │        │
   │       │   ← Back to sign in    │        │
   │       └────────────────────────┘        │
   └─────────────────────────────────────────┘
```

### 18.4 Screen [2] — Verify Ownership

The user clicks the recovery email link and is presented with the verification screen. **Per Phase 2 Auth Flow §20, recovery is not weaker than the user's strongest enrolled factor.** If the user has a passkey on a different device, the recovery requires that passkey (cross-device flow F-07). If the user has TOTP enrolled, recovery requires TOTP.

If the user truly has no factors available (e.g., they lost the only device with their TOTP and they never set up SMS or backup codes), the flow falls back to:

- **Manual review queue** (Phase 2 Auth Flow §20 mentions this as a fallback) — the user submits identity-verification information; an admin reviews and grants recovery within 24–72 hours.

The manual review affordance is hidden by default — most users find their primary factor or use a backup. The "I have no factors available" link appears small and below the primary CTA on Screen [2].

### 18.5 Screen [3] — Reset

After verification, the user can:
- Register a new passkey.
- Reset MFA factors.
- Reset password.

All existing sessions are revoked. A security email is sent: "Your account was recovered. If this wasn't you, contact support immediately."

### 18.6 Open Decision

OD-AF-04 (carried from Phase 2): final UX of the no-factors fallback — manual review queue vs hard-fail. Tracked in the Open Design Decisions Register.

---

### 19. F-15 — Email Verification (Standalone)

This flow runs when:
- A new user signs up (F-01, embedded).
- An existing user changes their email in Account Settings (F-17).

Standalone screen: the user clicks an email link and lands on `/auth/verify-email?token=...`. The screen confirms the verification:

```
   ┌─────────────────────────────────────────┐
   │       ┌────────────────────────┐        │
   │       │   ✓                    │        │
   │       │   Email verified       │        │
   │       │                        │        │
   │       │   You can close this   │        │
   │       │   tab.                 │        │
   │       │   [Continue to Acme]   │        │
   │       └────────────────────────┘        │
   └─────────────────────────────────────────┘
```

### 19.1 Error Paths

| Trigger | UI |
| --- | --- |
| Link expired | "Verification link expired. Request a new one from your account settings." |
| Link tampered | "Invalid verification link." |
| Already verified | "Your email is already verified. You can sign in normally." |

---

### 20. F-16 — Phone Verification

When the user adds a phone number (in Account Settings or during MFA setup):

### 20.1 Screen [1] — Enter Phone

```
   ┌─────────────────────────────────────────┐
   │   Verify your phone                     │
   │                                         │
   │   We'll send you a code by SMS.         │
   │                                         │
   │   Country     [+1 ▾]                    │
   │   Number      [____________]            │
   │                                         │
   │   [Send code]                           │
   └─────────────────────────────────────────┘
```

### 20.2 Screen [2] — Enter Code

Same OTP Input as F-09, but in the context of verification rather than login.

### 20.3 Success

Phone number flagged `verified=true` on the user record (Phase 2 Database §5.2).

---

### 21. F-17 — Account Settings

The user account portal lives at `/auth/account` ([Phase 3 IA §5.1](Qeet ID%20%E2%80%94%20Information%20Architecture%20%26%20Navigation.md)). Uses the Settings Layout template, not the Auth Layout.

### 21.1 Sections

```
   ┌─────────────────────────────────────────────────────────────┐
   │  Account                                                    │
   ├─────────────────┬─────────────────────────────────────────-┤
   │  Profile        │   Your profile                            │
   │  Security       │                                           │
   │  Preferences    │   Name                                    │
   │  Data           │   Email     alice@example.com  [Change]   │
   │  Delete account │   Phone     •••• 7421         [Change]   │
   │                 │   …                                       │
   └─────────────────┴─────────────────────────────────────────-┘
```

### 21.2 Security Section — Passkeys

```
   Passkeys (3 of 10 max)                          [+ Add passkey]

   ┌─────────────────────────────────────────────────────────┐
   │  🔑  iPhone 15 (iCloud Keychain)               ⋯       │
   │      Last used 2 hours ago · synced                    │
   └─────────────────────────────────────────────────────────┘
   ┌─────────────────────────────────────────────────────────┐
   │  🔑  MacBook (Touch ID)                         ⋯       │
   │      Last used yesterday · device-bound                 │
   └─────────────────────────────────────────────────────────┘
   ┌─────────────────────────────────────────────────────────┐
   │  🔑  YubiKey 5C                                 ⋯       │
   │      Last used 3 weeks ago                              │
   └─────────────────────────────────────────────────────────┘
```

Each row's `⋯` menu: Rename · Delete.

Deletion requires step-up authentication (F-12) — deleting a passkey is a security-sensitive action.

### 21.3 Security Section — MFA

Lists enrolled MFA methods (TOTP, SMS, Email OTP, Backup codes). Each can be added, removed, or regenerated (backup codes).

### 21.4 Security Section — Sessions

A list of active sessions across all devices.

```
   Active sessions                                  [Revoke all others]

   ┌─────────────────────────────────────────────────────────┐
   │  ●  MacBook · Chrome 138 · San Francisco, US  (current) │
   │     Signed in 2 hours ago                                │
   └─────────────────────────────────────────────────────────┘
   ┌─────────────────────────────────────────────────────────┐
   │  ○  iPhone · Safari 17 · San Francisco, US              │
   │     Signed in 1 day ago                            [×]   │
   └─────────────────────────────────────────────────────────┘
   ┌─────────────────────────────────────────────────────────┐
   │  ○  Windows · Edge · Berlin, DE                          │
   │     Signed in 5 days ago                           [×]   │
   └─────────────────────────────────────────────────────────┘
```

- Current session marked with a green dot and "(current)" tag — not revocable.
- Other sessions have an `×` icon to revoke. Confirmation modal: "Revoke this session? The user will be signed out immediately."
- "Revoke all others" revokes every session except the current one. Confirmation modal required.

---

### 22. F-18 — Account Deletion & Data Export

### 22.1 Data Export (GDPR Article 20)

Available from Account Settings > Data.

```
   ┌─────────────────────────────────────────────────────────┐
   │  Export your data                                       │
   │                                                         │
   │  Get a copy of your data in JSON format.                │
   │                                                         │
   │  When ready, we'll email you a secure download link.    │
   │  Links expire after 30 days.                            │
   │                                                         │
   │  [Request export]                                       │
   └─────────────────────────────────────────────────────────┘
```

Click triggers an async job (Phase 2 Microservices §4.21 Background Workers). The user is told it may take up to 24 hours. An email arrives with a secure, expiring link.

### 22.2 Account Deletion (GDPR Article 17)

Available from Account Settings > Delete account.

```
   ┌─────────────────────────────────────────────────────────┐
   │  Delete your account                                    │
   │                                                         │
   │  Deletion is permanent.                                 │
   │                                                         │
   │  We will:                                               │
   │   – Sign you out of all devices                         │
   │   – Anonymise your data in audit logs                   │
   │   – Permanently delete your account in 30 days          │
   │                                                         │
   │  Between now and then, you can sign in and cancel       │
   │  the deletion.                                          │
   │                                                         │
   │  Type your email to confirm:                            │
   │  [____________________]                                 │
   │                                                         │
   │  [Delete account]    [Cancel]                           │
   └─────────────────────────────────────────────────────────┘
```

- Requires step-up authentication (F-12).
- Confirmation by typing the email address (high-stakes pattern; Component Library §6.7 Modal variant).
- Per Phase 2 Multi-Tenancy §12.3: 30-day cooling-off period; aligns with GDPR CN-04 30-day deletion SLA.
- During the 30-day window, the user can sign in and cancel deletion.

### 22.3 Post-Deletion

The user receives a confirmation email. After 30 days, the account is hard-deleted (per [Phase 2 Database §10.1 GDPR Right to Erasure](../phase-2/Qeet%20ID%20%E2%80%94%20Database%20Design%20%26%20Data%20Model.md)).

---

### 23. Brand-Customisable Elements per Flow

Per [P-06](Qeet ID%20%E2%80%94%20UX%20Research%20Summary%20%26%20Design%20Principles.md) and [Phase 3 Doc 8](Qeet ID%20%E2%80%94%20Embeddable%20Auth%20UI%20Components%20%28White-Label%29.md), tenants can customise the following on every flow:

| Element | Customisable | Locked |
| --- | --- | --- |
| Tenant logo | ✅ light + dark variants | logo placement |
| Page background | ✅ colour, image, gradient | aspect ratios |
| Primary CTA colour | ✅ (contrast-validated) | shape, padding |
| Accent colour | ✅ | |
| Typography | ✅ from approved family list | scale, line height |
| Border radius | ✅ 2–12px range | extreme values |
| Footer Qeet ID attribution | Enterprise only | required on Free / Growth |
| Welcome screen copy | ✅ subject to character bounds | structural layout |
| Email template branding | ✅ | per Doc 8 §11 |

Per-flow brand override is **not** supported at MVP — a tenant's brand applies to all flows uniformly. Per-flow custom branding (e.g., different theme for sign-up vs login) is OD-EUF-01.

---

### 24. Email Template Coordination

The following emails are sent during these flows (handled by the [Phase 2 Notification Service](../phase-2/Qeet%20ID%20%E2%80%94%20Microservices%20Decomposition%20%26%20Service%20Boundaries.md)):

| Flow | Email |
| --- | --- |
| F-01 Sign-up | Verification email with link + 6-digit fallback code |
| F-01 If email already registered | "You already have an account — sign in instead" with sign-in link |
| F-05 Magic link | Magic link email |
| F-09/F-10 OTP | (SMS or email OTP; OTP variant has email) |
| F-13 Password reset | Reset link email |
| F-14 Account recovery | Recovery instructions |
| F-17 Password changed | Confirmation: "Your password was changed" |
| F-17 New device sign-in | Notification (anomaly: see [Phase 2 Microservices §4.13](../phase-2/Qeet%20ID%20%E2%80%94%20Microservices%20Decomposition%20%26%20Service%20Boundaries.md)) |
| F-18 Account deletion scheduled | Confirmation with deletion date |
| F-18 Account export ready | Secure download link |

Email visual design is owned by the Email Designer + this UX Designer, with localised translation per [Phase 3 Doc 11](Qeet ID%20%E2%80%94%20Internationalization%20%26%20Localization%20Design.md). Templates are brandable per tenant (logo, primary colour, sender name) per [Doc 8 §11](Qeet ID%20%E2%80%94%20Embeddable%20Auth%20UI%20Components%20%28White-Label%29.md).

---

### 25. Localisation Considerations

Every flow ships in 10 languages at launch (NFR IN-02). Specific considerations:

| Concern | Mitigation |
| --- | --- |
| German label expansion (+30%) | Buttons have generous auto-width; tested at the longest expected label |
| CJK character height | Type tokens auto-adjust line-height per [Doc 2 §6.5](Qeet ID%20%E2%80%94%20Design%20System%20Foundations%20%26%20Tokens.md) |
| Hindi (Devanagari) ascender space | Type tokens auto-adjust |
| Date/time formatting | Locale-aware via Intl API; ISO 8601 in any machine-facing context |
| Phone country code default | Auto-detect from browser locale; user can change |
| RTL (Arabic, Hebrew) | Deferred to v1.2 (NFR IN-05); layout is RTL-ready per [Doc 2 §14](Qeet ID%20%E2%80%94%20Design%20System%20Foundations%20%26%20Tokens.md) |
| Number formatting (resend countdown) | Locale-aware ("23s" → German "23 s" → Japanese "23 秒") |

---

### 26. Performance Considerations

| Technique | Where used |
| --- | --- |
| Skeleton screens (cards / form fields) | F-01 [2], F-02 (during conditional UI invoke) |
| Optimistic UI | Account settings — passkey rename, MFA toggle |
| In-place skeleton replacement | All flows — no layout shift on data load |
| Lazy-loaded social provider buttons | F-01, F-02, F-04 |
| Preloaded fonts | Hosted login pages preload Inter Regular + Medium + JetBrains Mono Regular |
| Avoided JS for critical path | Form submission works without JS (progressive enhancement); conditional UI requires JS but the password fallback never does |
| Constant-time response | F-04 password verification; F-13 password reset request — server pads to ≥800ms |

---

### 27. Accessibility Considerations Common to All Flows

Per [Phase 3 Doc 9](Qeet ID%20%E2%80%94%20Accessibility%20Compliance%20Plan%20%28WCAG%202.1%20AA%29.md):

- Every page has a skip-to-content link.
- All inputs have visible labels.
- All errors are programmatically associated and `aria-live="polite"`.
- All buttons have visible focus indicators.
- All modals trap focus and restore on dismiss.
- All flows are fully keyboard-operable.
- All decorative icons are `aria-hidden="true"`; all functional icons have `aria-label`.
- Touch targets ≥44×44pt on mobile.
- Colour is never the sole indicator of state.

---

### 28. Mobile vs Desktop Differences

| Concern | Desktop | Mobile |
| --- | --- | --- |
| Layout | Card centred at viewport centre | Card top-aligned (avoids keyboard pushing content) |
| Touch targets | 36–44px | 44×44px minimum |
| Social buttons | Vertical stack | Vertical stack (no change) |
| Keyboard | Standard | Native input types (`type=email`, `inputmode=numeric`) |
| OTP auto-paste | Available where browser supports | iOS / Android system-level (autoComplete="one-time-code") |
| Conditional UI | Browser-mediated | OS / browser-mediated (often better UX than desktop) |
| Cross-device passkey | Initiator | Often the authenticator (the phone you scan with) |
| Logo size | 48–64px | 32–40px |
| Card max width | 440px | full viewport minus 16px margin |

---

### 29. Open Design Decisions From This Document

| # | Question | Owner | Target |
| --- | --- | --- | --- |
| OD-EUF-01 | Per-flow custom branding (vs uniform tenant branding) at MVP | UX + Product | Phase 3 Week 3 |
| OD-EUF-02 | Final password-strength meter algorithm (zxcvbn vs simple length-based) | UX + Security | Phase 3 Week 2 |
| OD-EUF-03 | Whether the "no backup codes? Recover your account" link is hidden by default or always visible on the backup-code challenge screen | UX + Security | Phase 3 Week 3 |
| OD-EUF-04 | Welcome screen copy ownership — UX-default vs tenant-customisable | UX + Product | Phase 3 Week 3 |
| OD-EUF-05 | Whether F-07 (cross-device QR) is offered to all users by default or requires explicit opt-in (some users find QR flows confusing) | UX | Phase 3 Week 4 |
| OD-EUF-06 | Account-recovery manual-review fallback design (per Phase 2 OQ-AF-04) | UX + Product + Compliance | Phase 3 Week 4 |

---

### 30. Cross-References

- Principles applied throughout: [UX Research Summary & Design Principles](Qeet ID%20%E2%80%94%20UX%20Research%20Summary%20%26%20Design%20Principles.md) §6
- Component-level specifications: [Component Library Specification](Qeet ID%20%E2%80%94%20Component%20Library%20Specification.md) §5.10 (Passkey Button), §5.11 (Social Login Buttons), §5.12 (Magic Link Sent State), §5.9 (OTP Input), §7.1 (Auth Layout)
- Brand-customisation surface: [Embeddable Auth UI Components (White-Label)](Qeet ID%20%E2%80%94%20Embeddable%20Auth%20UI%20Components%20%28White-Label%29.md)
- Accessibility per flow: [Accessibility Compliance Plan (WCAG 2.1 AA)](Qeet ID%20%E2%80%94%20Accessibility%20Compliance%20Plan%20%28WCAG%202.1%20AA%29.md)
- Mobile-specific behaviours: [Mobile & Responsive Design Specification](Qeet ID%20%E2%80%94%20Mobile%20%26%20Responsive%20Design%20Specification.md)
- Localisation: [Internationalization & Localization Design](Qeet ID%20%E2%80%94%20Internationalization%20%26%20Localization%20Design.md)
- System choreography: [Phase 2 Authentication Flow Designs](../phase-2/Qeet%20ID%20%E2%80%94%20Authentication%20Flow%20Designs.md)
- Notification (email/SMS) service: [Phase 2 Microservices §4.16](../phase-2/Qeet%20ID%20%E2%80%94%20Microservices%20Decomposition%20%26%20Service%20Boundaries.md)
- Session lifecycle for the Sessions tab: [Phase 2 IdP Core §6](../phase-2/Qeet%20ID%20%E2%80%94%20Identity%20Provider%20%28IdP%29%20Core%20Engine%20Design.md)
- GDPR Article 17 deletion: [Phase 2 Database Design §10.1](../phase-2/Qeet%20ID%20%E2%80%94%20Database%20Design%20%26%20Data%20Model.md)

---

### 31. Approvals & Sign-off

| Role | Name | Signature | Date |
| --- | --- | --- | --- |
| UX Designer |  |  |  |
| Product Designer |  |  |  |
| Frontend Engineering Lead |  |  |  |
| Team Auth Lead (Backend) |  |  |  |
| Accessibility Lead |  |  |  |
| Localisation Lead |  |  |  |
| QA Lead |  |  |  |
| Security Architect (anti-enumeration & step-up correctness) |  |  |  |
| Solution Architect (cross-phase consistency) |  |  |  |

---

*This document is version controlled. Visual updates in Figma do not require re-sign-off; changes to flow structure (§5–§22), brand-customisation slot points (§23), anti-enumeration semantics (§3 FP-06), or accessibility contracts (§27) require UX Designer + Security Architect + Accessibility Lead review.*

---

**Qeet ID — Authenticate Everything.** *A Qeet Group Company*
