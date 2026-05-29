# Qeet ID — Accessibility Compliance Plan (WCAG 2.1 AA)

### 1. Document Information

|  |  |
| --- | --- |
| **Document Name** | Accessibility Compliance Plan (WCAG 2.1 AA) |
| **Project Name** | Qeet ID |
| **Parent Company** | Qeet Group |
| **Subsidiary** | Qeet ID (Standalone) |
| **Document Version** | v1.0 |
| **Prepared By** | UX Designer + QA Lead |
| **Date** | May 19, 2026 |
| **Status** | Draft — Pending Stakeholder Sign-off |

---

### 2. Purpose & Scope

This document is Qeet ID's accessibility commitment, plan, and testing strategy. WCAG 2.1 AA conformance is **mandatory at launch** (NFR AX-01; Stakeholder Findings 7.5: *"Accessibility is often deprioritized in identity platforms — Qeet ID should target WCAG 2.1 AA compliance at launch."*).

The plan covers every Qeet ID-owned surface: the end-user authentication pages, the embeddable widgets, the admin dashboard, the developer portal, the Security Trust Center, the status page, the email templates, and the marketing pages owned by Qeet ID (those owned by Marketing are governed by an MOU referencing this plan).

The document defines the conformance commitment, the principles, the per-criterion approach to every WCAG 2.1 AA success criterion, the component-level requirements (consolidated from [Doc 3](Qeet ID%20%E2%80%94%20Component%20Library%20Specification.md)), screen-reader support, keyboard navigation standards, focus management, contrast standards, form accessibility, dynamic content, media, cognitive accessibility, testing strategy (automated + manual + user testing + third-party), the public accessibility statement, known limitations and roadmap, and severity classification for accessibility bugs.

The audience is the UX Designer, Accessibility Lead, QA Lead, Frontend Engineering Lead, every engineer who writes UI code, Technical Writer, and Compliance Officer.

This document depends on [Doc 1 Principles](Qeet ID%20%E2%80%94%20UX%20Research%20Summary%20%26%20Design%20Principles.md), [Doc 2 Tokens](Qeet ID%20%E2%80%94%20Design%20System%20Foundations%20%26%20Tokens.md), [Doc 3 Components](Qeet ID%20%E2%80%94%20Component%20Library%20Specification.md), [Doc 4 IA](Qeet ID%20%E2%80%94%20Information%20Architecture%20%26%20Navigation.md), [Doc 5 End-user Flows](Qeet ID%20%E2%80%94%20End-User%20Authentication%20Flow%20Designs.md), [Doc 6 Admin Dashboard](Qeet ID%20%E2%80%94%20Admin%20Dashboard%20Design%20Specification.md), and [Doc 7 Developer Portal](Qeet ID%20%E2%80%94%20Developer%20Portal%20Design%20Specification.md), and Phase 1 [NFR §12.2 / IN-01..08](../phase-1/Qeet%20ID%20%E2%80%94%20Non-Functional%20Requirements%20%28NFR%29.md).

---

### 3. Accessibility Commitment Statement

Qeet ID is committed to the World Wide Web Consortium's Web Content Accessibility Guidelines (WCAG) 2.1, at the **AA conformance level**, across every surface we ship. We commit to:

- **Conformance at launch** — every public surface meets WCAG 2.1 AA before Phase 9 production deployment.
- **Sustained conformance** — every PR is gated by automated accessibility checks; regressions block release.
- **Independent audit** — annual third-party accessibility audit (NFR AX-09).
- **Public accessibility statement** — the statement in §17 below is published at `qeetify.com/accessibility`.
- **Open feedback** — anyone can report an accessibility issue via `accessibility@qeetify.com` and we commit to a response within 5 business days.
- **Progress beyond AA** — we aim, surface by surface, toward WCAG 2.2 conformance and AAA where feasible.

We treat accessibility as a feature, not a checklist (Design Principle [P-05](Qeet ID%20%E2%80%94%20UX%20Research%20Summary%20%26%20Design%20Principles.md)).

---

### 4. Scope of Conformance

| Surface | WCAG 2.1 AA at launch | Notes |
| --- | --- | --- |
| End-user authentication pages | ✅ | Highest priority — Sandra's company's workforce uses these |
| Embeddable widgets (React, Next.js, Flutter) | ✅ | Customers inherit our conformance |
| Hosted login pages (per-tenant) | ✅ | |
| Admin dashboard | ✅ | |
| Developer portal (docs, API, SDKs) | ✅ | |
| Security Trust Center | ✅ | |
| Status page (status.qeetify.com) | ✅ | Independently hosted |
| Public roadmap, changelog, pricing | ✅ | |
| Email templates (transactional) | ✅ | HTML email accessibility (Litmus / Email-on-Acid tested) |
| Marketing pages (owned by Marketing) | Target ✅ — MOU | Marketing commits to the same standard; this plan is the reference |
| Blog | Target ✅ | Includes alt text on imagery, accessible code blocks |

---

### 5. Accessibility Principles — POUR

WCAG organises into four principles: **Perceivable**, **Operable**, **Understandable**, **Robust**. These map onto Qeet ID's design principles ([Doc 1 §6](Qeet ID%20%E2%80%94%20UX%20Research%20Summary%20%26%20Design%20Principles.md)) directly.

| WCAG principle | Means | Maps to Qeet ID principle |
| --- | --- | --- |
| Perceivable | Users can see / hear / feel the UI | Doc 1 P-05, P-09 |
| Operable | Users can use the UI | Doc 1 P-01, P-03, P-04, P-05 |
| Understandable | Users can comprehend the UI | Doc 1 P-07, P-08 |
| Robust | UI is robust across assistive tech | Doc 1 P-05 |

---

### 6. Conformance to Every WCAG 2.1 AA Success Criterion

The table below enumerates every Level A and AA criterion and documents Qeet ID's compliance approach. AAA criteria are out of scope at launch but listed in §15 for the roadmap.

### 6.1 Principle 1 — Perceivable

| SC | Title | Level | Qeet ID approach |
| --- | --- | --- | --- |
| 1.1.1 | Non-text Content | A | Every image, icon, logo has appropriate `alt` text. Decorative icons are `aria-hidden="true"` ([Doc 3 §4.16](Qeet ID%20%E2%80%94%20Component%20Library%20Specification.md)). CAPTCHA challenges include accessible alternatives |
| 1.2.1 | Audio-only / Video-only (Prerecorded) | A | Tutorial videos (when present) have transcripts |
| 1.2.2 | Captions (Prerecorded) | A | All video content captioned |
| 1.2.3 | Audio Description or Media Alternative | A | All meaningful video provides audio description or full text alternative |
| 1.2.4 | Captions (Live) | AA | Live video (if any — quarterly webinar) is captioned |
| 1.2.5 | Audio Description (Prerecorded) | AA | Provided |
| 1.3.1 | Info and Relationships | A | Semantic HTML throughout. Headings hierarchical. Form labels programmatically associated. Tables use `<th>` with `scope` |
| 1.3.2 | Meaningful Sequence | A | DOM order matches visual reading order; verified via screen reader |
| 1.3.3 | Sensory Characteristics | A | Instructions never rely on shape, colour, position alone ("Click the red button below" → "Click 'Save' below") |
| 1.3.4 | Orientation | AA | All surfaces work in portrait + landscape; no orientation-locked rendering |
| 1.3.5 | Identify Input Purpose | AA | `autocomplete` attributes on every relevant input ([Doc 3 §4.2.1](Qeet ID%20%E2%80%94%20Component%20Library%20Specification.md)) |
| 1.4.1 | Use of Colour | A | Colour is never the sole means of conveying information (per [AP-15](Qeet ID%20%E2%80%94%20UX%20Research%20Summary%20%26%20Design%20Principles.md)). Required indicators use icon + word; status uses icon + label; charts use shape + label |
| 1.4.2 | Audio Control | A | No auto-play audio anywhere |
| 1.4.3 | Contrast (Minimum) | AA | Every text-on-surface combination ≥4.5:1; large text and UI components ≥3:1. Verified in [Doc 2 §5.6](Qeet ID%20%E2%80%94%20Design%20System%20Foundations%20%26%20Tokens.md) and at every brand-save (§13) |
| 1.4.4 | Resize Text | AA | Layouts work at 200% zoom without loss of content or function. Tested in CI via a visual-regression suite at 200% zoom |
| 1.4.5 | Images of Text | AA | No images of text used for content (logos and brand marks excepted) |
| 1.4.10 | Reflow | AA | At 320 CSS pixels viewport width (no horizontal scroll), no functional loss. Tested per breakpoint ([Doc 10 §3](Qeet ID%20%E2%80%94%20Mobile%20%26%20Responsive%20Design%20Specification.md)) |
| 1.4.11 | Non-text Contrast | AA | UI components and focus indicators ≥3:1. Verified |
| 1.4.12 | Text Spacing | AA | Layouts withstand line-height 1.5, paragraph-spacing 2×, letter-spacing 0.12em, word-spacing 0.16em without loss |
| 1.4.13 | Content on Hover or Focus | AA | Tooltips dismissable (Esc); hoverable (cursor can move onto them); persistent until dismissed |

### 6.2 Principle 2 — Operable

| SC | Title | Level | Qeet ID approach |
| --- | --- | --- | --- |
| 2.1.1 | Keyboard | A | All functionality reachable by keyboard alone. No keyboard traps |
| 2.1.2 | No Keyboard Trap | A | Focus never gets stuck. Modals trap focus *inside* but Esc exits |
| 2.1.4 | Character Key Shortcuts | A | Single-letter shortcuts (`g u`, `t`, `f`) are turned off in text inputs and configurable per user ([Doc 4 §13.4](Qeet ID%20%E2%80%94%20Information%20Architecture%20%26%20Navigation.md)) |
| 2.2.1 | Timing Adjustable | A | Session idle timeout warning 60s before timeout; user can extend; magic link / OTP cooldowns can be skipped via "Resend" |
| 2.2.2 | Pause, Stop, Hide | A | No moving / blinking content (loading spinners pause when `prefers-reduced-motion`) |
| 2.3.1 | Three Flashes | A | No content flashes more than 3 times per second |
| 2.4.1 | Bypass Blocks | A | Skip-to-content link on every page ([Doc 3 §10 A-10](Qeet ID%20%E2%80%94%20Component%20Library%20Specification.md)) |
| 2.4.2 | Page Titled | A | Every page has a unique, descriptive `<title>` |
| 2.4.3 | Focus Order | A | Tab order matches visual reading order |
| 2.4.4 | Link Purpose (In Context) | A | Link text describes destination. No "click here" links |
| 2.4.5 | Multiple Ways | AA | Dashboard reachable via primary nav + cmd+K + URL; docs reachable via nav + search + URL |
| 2.4.6 | Headings and Labels | AA | Descriptive headings; descriptive labels |
| 2.4.7 | Focus Visible | AA | Visible focus indicator with ≥3:1 contrast against background ([Doc 2 §5.4](Qeet ID%20%E2%80%94%20Design%20System%20Foundations%20%26%20Tokens.md) C-19) |
| 2.5.1 | Pointer Gestures | A | No multi-point or path-based gestures required (a drag-and-drop area also accepts click-to-upload) |
| 2.5.2 | Pointer Cancellation | A | Activation on `mouseup` / `keyup`, not `mousedown` |
| 2.5.3 | Label in Name | A | Accessible name matches visible label |
| 2.5.4 | Motion Actuation | A | No motion gestures required |

### 6.3 Principle 3 — Understandable

| SC | Title | Level | Qeet ID approach |
| --- | --- | --- | --- |
| 3.1.1 | Language of Page | A | `<html lang="...">` set per page |
| 3.1.2 | Language of Parts | AA | `lang="..."` on inline language switches |
| 3.2.1 | On Focus | A | Focus does not trigger context changes |
| 3.2.2 | On Input | A | Input changes do not trigger automatic context changes (form submission requires user action) |
| 3.2.3 | Consistent Navigation | AA | Top nav and side nav consistent across pages |
| 3.2.4 | Consistent Identification | AA | Components with the same function (Save button, Delete button) labelled consistently |
| 3.3.1 | Error Identification | A | Errors identified in text, programmatically associated with the field (`aria-describedby`) |
| 3.3.2 | Labels or Instructions | A | Every input has a visible label |
| 3.3.3 | Error Suggestion | AA | Error messages suggest correction (per [P-08](Qeet ID%20%E2%80%94%20UX%20Research%20Summary%20%26%20Design%20Principles.md)) |
| 3.3.4 | Error Prevention (Legal, Financial, Data) | AA | Destructive actions confirm (type-the-email pattern); legal/financial commit requires explicit consent |

### 6.4 Principle 4 — Robust

| SC | Title | Level | Qeet ID approach |
| --- | --- | --- | --- |
| 4.1.1 | Parsing | A | Valid HTML; verified in CI |
| 4.1.2 | Name, Role, Value | A | All UI components have correct accessible name, role, and state (ARIA where native semantics don't suffice) |
| 4.1.3 | Status Messages | AA | Status messages use `aria-live` regions — toasts, error summaries, OTP arrival, "verifying…" loading states |

---

### 7. Component-Level Accessibility Requirements

Consolidated from [Doc 3 §10](Qeet ID%20%E2%80%94%20Component%20Library%20Specification.md), with per-component detail.

| Component | Accessibility commitment |
| --- | --- |
| Button | `<button>` native; Enter and Space activate; `aria-pressed` for toggle; `aria-busy` during loading; disabled buttons use `aria-disabled` so they remain in focus order |
| Input | `<label for>` associated; `aria-describedby` to helper/error; `aria-invalid` when invalid; `autocomplete` attributes |
| Checkbox / Radio | Native input or full ARIA equivalent; Space toggles; arrow keys within RadioGroup |
| Toggle | `role="switch"`; `aria-checked`; label describes what is being toggled, not the state |
| Select | WAI-ARIA Combobox pattern; arrow keys; Enter selects; Esc closes; typing filters |
| Textarea | Same as Input; resize handle accessible |
| OTP Input | Logical single input for screen readers; auto-paste from clipboard; "Code entered, verifying" announced |
| Passkey Button | Identical to Button; `aria-label` includes "Continue with a passkey" when icon-only on narrow viewport |
| Social Login Buttons | Provider name in label (not just logo); icons `aria-hidden` |
| Tooltip | `aria-describedby` link; never sole information; Esc dismisses |
| Modal / Dialog | `role="dialog"`, `aria-modal`, `aria-labelledby`, focus trap, focus restoration |
| Drawer | Similar to Modal |
| Toast | `role="status"` (info/success) or `role="alert"` (warning/danger) |
| Banner / Alert | Persistent, in-context; `role="alert"` for high-severity |
| Tab Group | WAI-ARIA Tabs pattern; arrow keys navigate; tab activates / Enter activates per `activationMode` |
| Accordion | `aria-expanded` on header buttons; smooth height animation honours reduced motion |
| Data Table | Native `<table>`, `<th scope>`, `aria-sort`, row-action menus accessible |
| Audit Log Row expand | `aria-expanded` on row; expanded content `aria-live="polite"` |
| Stepper | `aria-current="step"`; step status announced |
| Date Picker | Calendar grid keyboard navigable; locale-aware first-day-of-week |
| File Upload | Native `<input type="file">` underneath; keyboard activates file picker |
| Code Block | `role="region"` with `aria-label`; copy button announces "Copied" |
| Code Tab Group | WAI-ARIA Tabs pattern |
| Search Input | `role="searchbox"`; clear button has `aria-label` |
| Empty State | Heading at correct level; primary CTA focusable |
| Loading Skeleton | `aria-busy="true"` on parent; "Loading {context}" announced |

---

### 8. Screen Reader Support

The four screen readers Qeet ID tests against (NFR AX-02):

| Screen reader | Platform | Browser | Test priority |
| --- | --- | --- | --- |
| NVDA | Windows | Firefox + Chrome | High (most-used desktop SR globally) |
| JAWS | Windows | Chrome + Edge | High (enterprise-standard) |
| VoiceOver | macOS, iOS | Safari | High (Apple ecosystem; Mobile end-users) |
| TalkBack | Android | Chrome | High (Mobile end-users) |

Each surface is tested manually against all four before launch (§16) and after every breaking change.

### 8.1 SR-Specific Considerations

- **OTP Input** (Doc 3 §5.9): the multi-box visual + single logical input pattern is verified to behave well with each SR — the SR sees one input with all six digits.
- **Toast notifications**: `aria-live="polite"` is the default; danger toasts use `role="alert"` (assertive) to interrupt SR speech.
- **Modal focus**: when a modal opens, focus moves to the close button or the first interactive element; SR announces the modal title.
- **Audit Log Row expand**: when expanded, the content is announced via `aria-live="polite"`.

---

### 9. Keyboard Navigation Standards

Per [Doc 4 §13](Qeet ID%20%E2%80%94%20Information%20Architecture%20%26%20Navigation.md):

- All interactive elements reachable by Tab.
- Tab order matches visual reading order.
- Skip-to-content link is the first focusable element on every page.
- Modals trap focus; Esc closes.
- Drawers trap focus; Esc closes.
- Menus support arrow keys; Esc closes.
- Tab Groups support arrow keys within the tablist.
- Single-letter shortcuts (`g u`, `t`, `f`, `?`) are disabled inside text inputs and respect `Character Key Shortcuts` (SC 2.1.4) — user can disable them in preferences.

### 9.1 No-Mouse Walkthrough

A formal "no-mouse walkthrough" test is part of the QA process:

- Sign up using only the keyboard.
- Sign in with passkey using only the keyboard.
- Configure SAML using only the keyboard.
- Filter and export audit logs using only the keyboard.
- Brand the login page (with live preview) using only the keyboard.

All five must pass with no functional gaps.

---

### 10. Focus Management

### 10.1 Focus Visible Indicators

Per [Doc 2 §5.4](Qeet ID%20%E2%80%94%20Design%20System%20Foundations%20%26%20Tokens.md): every interactive element has a visible focus ring using `color.border.focused`, with ≥3:1 contrast against any surface it appears on. The ring sits *outside* the visual border (offset 2px) so it never overlaps content.

### 10.2 Focus Order

Visual order ↔ DOM order ↔ Tab order. Verified via screen reader walkthrough (visual layout sometimes diverges from DOM under CSS Grid / Flexbox; designers and engineers verify together).

### 10.3 Focus Trap (Modals, Drawers)

Modals and drawers trap focus within the dialog. The focus moves to the close button or the first interactive element on open. Shift+Tab from the first element wraps to the last; Tab from the last wraps to the first. Esc closes the modal/drawer.

### 10.4 Focus Restoration

When a modal/drawer closes, focus returns to the element that opened it. When a modal is closed by Esc on the modal backdrop, focus returns to the opener. When navigating between pages, focus is set to the page's `<h1>` (read-mode focus restoration).

### 10.5 Skip Links

Every multi-zone page (Auth Layout, Dashboard Layout, Documentation Layout) has a `Skip to content` link as the first focusable element. The link is visually hidden until focused.

---

### 11. Colour Contrast Standards

Verified at token-publish time ([Doc 2 §5.6](Qeet ID%20%E2%80%94%20Design%20System%20Foundations%20%26%20Tokens.md)) and at brand-save time ([Doc 8 §13](Qeet ID%20%E2%80%94%20Embeddable%20Auth%20UI%20Components%20%28White-Label%29.md)). Recap:

- Normal text: 4.5:1 minimum.
- Large text (18pt regular or 14pt bold) + UI components: 3:1 minimum.
- Focus rings: 3:1 minimum against any background they appear on.
- Hover state visual change: must remain perceivable to users with reduced contrast sensitivity (a colour change must also produce a non-colour change — underline, border, etc.).

---

### 12. Form Accessibility

### 12.1 Labels

Every form input has a visible label associated via `htmlFor` / `id`. Floating labels (where the label sits inside the input field until typing begins) are not used — they conflict with placeholders and confuse screen readers.

### 12.2 Required Field Indication

Per `1.4.1 Use of Colour`: the required indicator uses an asterisk **plus** the word "Required" in the helper text — never the asterisk alone, never colour alone.

### 12.3 Error Messages

Errors are programmatically associated with the affected field via `aria-describedby`. The error message is also in an `aria-live="polite"` region so SR users hear the error when it appears. The form-level error summary (Doc 3 §6.14) at the top of the form has links to each affected field — focus moves to the field on link activation.

### 12.4 Validation Timing

- **On blur**: per-field validation (no surprises while typing).
- **On submit**: cross-field validation + server validation.
- Inline errors appear after blur, not on each keystroke (avoids SR over-announcement).

---

### 13. Dynamic Content Announcements

Surfaces that change without user-driven navigation use `aria-live` regions:

| Surface | `aria-live` | Why |
| --- | --- | --- |
| Toast | `polite` (success/info), `assertive` (warning/danger) | Notifications |
| Error summary | `polite` | Errors on submit |
| OTP "verifying…" | `polite` | Loading status after auto-submit |
| Async validation result | `polite` | "Email looks good", "Email already in use" |
| Audit log filter result count | `polite` | "Showing 1–25 of 2,400 events" updates after filter change |
| Loading skeleton on first render | `aria-busy="true"` on the parent region | Loading state |
| Status page incident updates | `polite` | Auto-refresh of recent incidents |

---

### 14. Media Accessibility

| Media type | Requirement |
| --- | --- |
| Tutorial videos | Captions + transcripts (NFR AX-08) |
| Animated illustrations / GIFs | Reduced-motion variant (static image); never auto-play |
| Loading animations | Pause when `prefers-reduced-motion` |
| Charts (analytics dashboard) | Data table view available; colour-blind tested |
| Audio (if any) | Transcript |

---

### 15. Cognitive Accessibility

- **Clear language**: per [Doc 1 §7](Qeet ID%20%E2%80%94%20UX%20Research%20Summary%20%26%20Design%20Principles.md). Short sentences, plain vocabulary, no marketing fluff on technical surfaces.
- **Consistent patterns**: same navigation, same component behaviour across screens (per IA-01).
- **Error prevention**: confirmation dialogs for destructive actions; type-the-email confirmation for very destructive actions (Doc 6 §22.2 account deletion).
- **Generous timeouts**: 60-second warning before idle session timeout; user can extend.
- **Reduced cognitive load**: chunked tasks (the SAML wizard's five steps are five small decisions, not one giant form); progressive disclosure of complexity.
- **Predictable behaviour**: no unsolicited context changes; no auto-navigation; user always initiates major changes.

---

### 16. Accessibility Testing Strategy

### 16.1 Automated Testing

| Tool | Scope | When |
| --- | --- | --- |
| **axe-core** (via @axe-core/react and @axe-core/playwright) | Every component; every PR | On every PR — block on critical issues |
| **Lighthouse Accessibility** | Every public page; every PR | On every PR (CI) |
| **Pa11y** | Every static page | Nightly |
| **Eslint plugin jsx-a11y** | React source code | On every commit |

Targets:
- Lighthouse Accessibility score ≥95 on every public page.
- axe-core reports zero critical or serious issues at PR-merge.

### 16.2 Manual Testing

A QA member walks through each surface manually:

| Walkthrough | Frequency | Tools |
| --- | --- | --- |
| Keyboard-only navigation | Every feature PR + monthly | OS keyboard |
| Screen reader (NVDA + Firefox) | Quarterly + before major releases | NVDA |
| Screen reader (JAWS + Chrome) | Bi-annual | JAWS |
| Screen reader (VoiceOver + Safari) | Quarterly | VoiceOver |
| Screen reader (TalkBack + Chrome Android) | Quarterly on mobile-priority flows | TalkBack |
| Voice-control walkthrough | Bi-annual | Dragon NaturallySpeaking, macOS Voice Control |
| Zoom 200% / 400% | Quarterly | Browser zoom |
| Reduced motion enabled | On every feature PR with motion | OS reduced-motion setting |
| Dark mode walkthrough | Per release | OS theme |
| Forced colours / High contrast | Bi-annual | Windows High Contrast Mode |

### 16.3 User Testing with Assistive Technology Users

Per [Doc 12 Usability Testing Plan §6.3](Qeet ID%20%E2%80%94%20Usability%20Testing%20Plan%20%26%20Findings%20Framework.md), at least one participant per testing round is an assistive-technology user (screen reader, voice control, switch device, keyboard-only).

### 16.4 Annual Third-Party Audit

Per NFR AX-09: an annual audit by a specialised accessibility firm (Deque, TPGi, Tetralogical, or equivalent). The audit covers a sample of pages and produces a remediation report. Findings are tracked through to closure on the same SLA as security findings.

The first audit is scheduled in **Phase 7 (Security Audit & Compliance Certification)** alongside the SOC 2 Type I audit — accessibility findings remediated before launch.

---

### 17. Public Accessibility Statement

The statement published at `qeetify.com/accessibility`:

> # Accessibility at Qeet ID
>
> Qeet ID is committed to ensuring our products are accessible to everyone, including people with disabilities. We aim to conform to the **Web Content Accessibility Guidelines (WCAG) 2.1, level AA** across every surface we ship: end-user authentication pages, the embeddable widgets, the admin dashboard, the developer portal, the Security Trust Center, and the status page.
>
> ## What we do
>
> - We run automated accessibility checks on every code change.
> - We test manually with screen readers (NVDA, JAWS, VoiceOver, TalkBack), keyboard-only, and at high zoom.
> - We engage an independent specialist for an annual audit.
> - We treat accessibility regressions as launch-blocking bugs.
>
> ## Known limitations
>
> *[Listed in §18 below, updated as resolved.]*
>
> ## Report an issue
>
> If you encounter an accessibility issue on any Qeet ID surface, contact `accessibility@qeetify.com`. We commit to a response within five business days and to working with you on a resolution.
>
> ## Conformance reports
>
> Our most recent third-party audit summary is available at `qeetify.com/security/accessibility-audit`.

---

### 18. Known Limitations & Roadmap

At launch, the following known limitations are disclosed in the accessibility statement:

| Limitation | Why | Target resolution |
| --- | --- | --- |
| RTL (Arabic, Hebrew) language support | Per NFR IN-05 deferred to v1.2 | v1.2 |
| Admin dashboard localisation (only English at launch) | Per NFR IN-08 | v1.5 |
| Audit log viewer at 320px mobile viewport — degraded to a card-list view | Density requirements of audit data; full table at this viewport is not legible | Continuous improvement; no specific resolution date |
| Hindi UI may have slight ascender-clipping on some Android devices below font-rendering API 30 | Devanagari rendering varies | Mitigation: extra line-height applied; further fix when Android dependency available |

### 18.1 Beyond AA — AAA Roadmap

| AAA criterion | Target |
| --- | --- |
| 1.4.6 Contrast (Enhanced) — 7:1 normal text | Surface-by-surface; default-mode body text already meets it for most palettes |
| 2.1.3 Keyboard (No Exception) | Audit log row expand and certain Tab Group activations already meet this |
| 2.4.8 Location | Breadcrumbs present on most dashboard screens; v1.1 extension to all |
| 2.4.10 Section Headings | Already in place across docs and dashboard |
| 3.1.5 Reading Level | Plain-language commitment is already in place |

We make no AAA conformance commitment at launch, but several criteria already meet it.

---

### 19. Accessibility Bug Severity Classification

For triage in QA and engineering backlog:

| Severity | Definition | SLA | Examples |
| --- | --- | --- | --- |
| **P1 — Blocker** | Blocks a core user task entirely | Fix before next release | Login form unusable with keyboard; audit log unreadable with screen reader |
| **P2 — Degrades** | Degrades a core task; workaround exists | Fix within 2 weeks | Focus ring missing on a button; SR announcement missing on a state change |
| **P3 — Cosmetic** | Minor inconvenience; no functional barrier | Fix within 6 weeks | Small contrast issue on a low-traffic page; minor ARIA label phrasing |
| **P4 — Polish** | Enhancement opportunity | Backlog | Better screen-reader experience than required |

P1 and P2 are launch-blocking pre-MVP. P3 and P4 are tracked and worked through on an ongoing basis.

---

### 20. Engineering Responsibilities

Every frontend engineer is responsible for accessibility on the code they ship. Specifically:

- Use the Component Library — its accessibility contracts are pre-baked. Bespoke components require an Accessibility Lead review.
- Run axe-core locally before opening a PR. Address all critical issues.
- Test with the keyboard before opening a PR.
- Test with NVDA or VoiceOver before opening a PR on a high-traffic surface.
- File any accessibility bug they discover, even outside their area.
- Reject PRs that introduce accessibility regressions (the axe-core CI check makes this automatic).

The Accessibility Lead is the consult point for ambiguous decisions, ARIA pattern selection, and audit findings.

---

### 21. Cross-References

- Principles applied: [UX Research Summary & Design Principles](Qeet ID%20%E2%80%94%20UX%20Research%20Summary%20%26%20Design%20Principles.md) §6 — particularly P-05
- Tokens that meet contrast: [Design System Foundations & Tokens](Qeet ID%20%E2%80%94%20Design%20System%20Foundations%20%26%20Tokens.md) §5.4, §5.6, §11.4
- Component-level requirements consolidated: [Component Library Specification](Qeet ID%20%E2%80%94%20Component%20Library%20Specification.md) §10
- IA, navigation, keyboard shortcuts: [Information Architecture & Navigation](Qeet ID%20%E2%80%94%20Information%20Architecture%20%26%20Navigation.md) §13
- End-user flow accessibility: [End-User Authentication Flow Designs](Qeet ID%20%E2%80%94%20End-User%20Authentication%20Flow%20Designs.md) §27
- Admin dashboard accessibility: [Admin Dashboard Design Specification](Qeet ID%20%E2%80%94%20Admin%20Dashboard%20Design%20Specification.md)
- Developer portal accessibility: [Developer Portal Design Specification](Qeet ID%20%E2%80%94%20Developer%20Portal%20Design%20Specification.md) §25
- White-label brand validation: [Embeddable Auth UI Components (White-Label)](Qeet ID%20%E2%80%94%20Embeddable%20Auth%20UI%20Components%20%28White-Label%29.md) §13
- Mobile accessibility: [Mobile & Responsive Design Specification](Qeet ID%20%E2%80%94%20Mobile%20%26%20Responsive%20Design%20Specification.md)
- Localisation accessibility: [Internationalization & Localization Design](Qeet ID%20%E2%80%94%20Internationalization%20%26%20Localization%20Design.md)
- Phase 1 NFR §12 mandatory requirements: [Phase 1 NFR](../phase-1/Qeet%20ID%20%E2%80%94%20Non-Functional%20Requirements%20%28NFR%29.md)

---

### 22. Open Design Decisions From This Document

| # | Question | Owner | Target |
| --- | --- | --- | --- |
| OD-AC-01 | Third-party accessibility audit vendor selection (Deque vs TPGi vs Tetralogical) | UX + Compliance | Phase 5 / Phase 7 |
| OD-AC-02 | Whether tutorial videos at launch require captions or are video-free | Tech Writing + UX | Phase 3 Week 3 |
| OD-AC-03 | Voice-control conformance commitment level — A vs AA equivalent | UX + Accessibility Lead | Phase 3 Week 4 |
| OD-AC-04 | Whether to publish a quarterly accessibility report alongside the security advisory | Compliance + UX | Phase 3 Week 3 |

---

### 23. Approvals & Sign-off

| Role | Name | Signature | Date |
| --- | --- | --- | --- |
| UX Designer |  |  |  |
| Accessibility Lead (QA) |  |  |  |
| QA Lead |  |  |  |
| Frontend Engineering Lead |  |  |  |
| Product Manager |  |  |  |
| Compliance Officer |  |  |  |
| Legal Counsel (public accessibility statement) |  |  |  |
| CTO |  |  |  |

---

*This document is version controlled. Visual updates in Figma do not require re-sign-off; changes to the conformance scope (§4), the WCAG criteria approach (§6), the testing strategy (§16), or the public accessibility statement (§17) require Accessibility Lead + UX Designer + Compliance Officer review.*

---

**Qeet ID — Authenticate Everything.** *A Qeet Group Company*
