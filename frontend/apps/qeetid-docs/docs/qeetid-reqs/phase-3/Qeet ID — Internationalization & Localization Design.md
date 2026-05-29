# Qeet ID — Internationalization & Localization Design

### 1. Document Information

|  |  |
| --- | --- |
| **Document Name** | Internationalization & Localization Design |
| **Project Name** | Qeet ID |
| **Parent Company** | Qeet Group |
| **Subsidiary** | Qeet ID (Standalone) |
| **Document Version** | v1.0 |
| **Prepared By** | UX Designer |
| **Date** | May 19, 2026 |
| **Status** | Draft — Pending Stakeholder Sign-off |

---

### 2. Purpose & Scope

This document defines the internationalization (i18n) and localization (l10n) plan for every Qeet ID-owned surface — what is localised at launch, what is deferred, the translation workflow, the string management standards, the layout considerations for translated content, the date/time/number/currency/address/phone formatting standards, the language detection and selection UX, the RTL readiness plan (RTL ships v1.2; design must be RTL-ready Day 1), the cultural considerations, and the boundary with Marketing-owned localised assets.

The scope at launch is defined by [Phase 1 NFR §12.3 (IN-01..IN-08)](../phase-1/Qeet%20ID%20%E2%80%94%20Non-Functional%20Requirements%20%28NFR%29.md):

- **End-user login pages: 10 languages at launch.**
- **Admin dashboard: English at launch; additional languages v1.5.**
- **Developer portal: English only at launch.**
- **Email templates: Localised per user's preferred language.**

The audience is the UX Designer, Localisation Lead, Technical Writer Lead, Frontend Engineering Lead, Email Template Designer, QA Lead.

This document depends on every Phase 3 document so far, on Phase 1 [NFR §12.3 / IN-01..IN-08](../phase-1/Qeet%20ID%20%E2%80%94%20Non-Functional%20Requirements%20%28NFR%29.md), and on Phase 2 [Multi-Tenancy Architecture](../phase-2/Qeet%20ID%20%E2%80%94%20Multi-Tenancy%20Architecture.md) (residency by region implies linguistic expectations).

---

### 3. i18n Scope per Surface

| Surface | Launch | v1.2 | v1.5+ |
| --- | --- | --- | --- |
| End-user authentication pages (hosted + widgets) | **10 languages** | + RTL (Arabic, Hebrew) | continuous |
| Embeddable auth widgets (React, Next.js, Flutter) | **10 languages** | + RTL | continuous |
| Hosted login pages (per-tenant) | **10 languages** | + RTL | continuous |
| Admin dashboard | **English only** | English | + Spanish, French, German, Japanese |
| Developer portal (docs, API, SDKs) | **English only** | English | possibly Japanese (v2.0) |
| Security Trust Center | **English only** | English | English |
| Status page | **English only** | English | English |
| Email templates (transactional) | **10 languages** | + RTL | continuous |
| Marketing pages | Marketing-owned (typically English + 4 — pl Marketing decision) | per Marketing | per Marketing |

### 3.1 The 10 Launch Languages

Per [NFR IN-02](../phase-1/Qeet%20ID%20%E2%80%94%20Non-Functional%20Requirements%20%28NFR%29.md):

| # | Language | BCP 47 tag | Script | Notes |
| --- | --- | --- | --- | --- |
| 1 | English (default; en-US base) | `en` | Latin | Source-of-truth; all other locales translated from this |
| 2 | Spanish (Latin America base) | `es` | Latin | Largest Spanish-speaking audience |
| 3 | French (France base) | `fr` | Latin | |
| 4 | German | `de` | Latin | Highest expansion factor in UI (+30%) |
| 5 | Portuguese (Brazilian base) | `pt-BR` | Latin | |
| 6 | Italian | `it` | Latin | |
| 7 | Japanese | `ja` | Han + Hiragana + Katakana | CJK; vertical metrics shift |
| 8 | Korean | `ko` | Hangul | CJK |
| 9 | Mandarin (Simplified) | `zh-Hans` | Han | Mainland China focus |
| 10 | Hindi | `hi` | Devanagari | South Asia |

### 3.2 The Pragmatic Boundary

Localising the end-user surface but not the admin dashboard is deliberate. End users authenticate in their native language (low context switching cost; high impact). Admin dashboard users (Sandra, Daniel, Maya) are technically literate and overwhelmingly use English-language documentation regardless of UI language. The dashboard adds languages in v1.5 driven by enterprise sales demand.

---

### 4. Translation Workflow

```
   English source string in code
   ┌─────────────────────────────────┐
   │ <Trans id="login.passkey.cta"> │
   │   Continue with a passkey       │
   │ </Trans>                        │
   └────────────────┬────────────────┘
                    │
                    ▼ extract
   ┌─────────────────────────────────┐
   │ messages.en.json                │
   │ {                                │
   │   "login.passkey.cta":          │
   │     "Continue with a passkey"   │
   │ }                                │
   └────────────────┬────────────────┘
                    │
                    ▼ push
   ┌─────────────────────────────────┐
   │ TMS (Translation Management)    │
   │  Crowdin / Lokalise / Phrase    │  ← OD-LO-01
   │  (open decision: pick one)      │
   └────────────────┬────────────────┘
                    │
                    ▼ professional translation + review
   ┌─────────────────────────────────┐
   │ messages.es.json                 │
   │ messages.fr.json                 │
   │ messages.de.json …               │
   └────────────────┬────────────────┘
                    │
                    ▼ pull + bundle
   ┌─────────────────────────────────┐
   │ Production deploy              │
   └─────────────────────────────────┘
```

### 4.1 Translation Process

1. **Author** strings in English in code with stable IDs.
2. **CI extracts** the strings into the source `messages.en.json`.
3. **Push** to the TMS (Translation Management System).
4. **Professional translation** by a vendor (engaged by Localisation Lead; see OD-LO-02 for vendor selection).
5. **Internal review** by native speakers on the Qeet ID team (where available) or by the vendor's second-pass reviewer.
6. **Pull** translated bundles back into the repo.
7. **CI validates** structure (no missing keys, no malformed ICU MessageFormat), bundles by locale, deploys.

### 4.2 Cadence

- New strings added during Phase 4 are translated in batches (weekly cadence).
- Hot fixes (urgent string changes) follow an expedited 24-hour path; the vendor maintains a "rush queue".
- Before launch, all 10 locales are at 100% coverage on end-user surfaces — this is a launch-blocking gate.

### 4.3 Translation Sources of Truth

- **English** is the single source of truth. Other locales are translations of English. No locale is the source — even if a French copywriter writes a better French phrase, the English is updated first.
- **Stable string IDs** are mandatory. Renaming an ID is a breaking change (loses translation history). Removing an ID requires a grace period.

---

### 5. String Management Standards

### 5.1 No Concatenation

Strings are never assembled by concatenation. The wrong way:

```
   const message = "You have " + count + " " + (count === 1 ? "user" : "users");
```

The right way uses ICU MessageFormat (which handles plurals, gender, selections):

```
   "users.count": "{count, plural, one {# user} other {# users}}"
```

### 5.2 ICU MessageFormat

Qeet ID uses ICU MessageFormat (via `formatjs` / `react-intl` on web; via `intl` package on Flutter). Examples:

```
   "audit.events_in_range": "{count, plural, =0 {No events} one {# event} other {# events}} in the last {days, number} days."

   "user.greeting": "{gender, select, female {Hi {name}, glad you're back.} male {Hi {name}, glad you're back.} other {Welcome back, {name}.}}"

   "session.last_seen": "Last seen {time, time, short} on {date, date, long}."
```

### 5.3 Full Sentence Interpolation

Strings are interpolated as full sentences, never as fragments. The wrong way:

```
   "Signed in" + " " + "at " + time + " on " + date
```

The right way:

```
   "session.signed_in_at": "Signed in at {time, time, short} on {date, date, long}."
```

This is mandatory because word order varies wildly across languages — "Signed in" + "at 14:00" + "on 2026-05-19" cannot be reassembled correctly in Japanese.

### 5.4 Context Notes for Translators

Every translatable string can carry a `description` field passed to the translator:

```
   <Trans
     id="login.passkey.cta"
     description="The primary CTA on the login page. Initiates a passkey ceremony. Should imply security and ease."
   >
     Continue with a passkey
   </Trans>
```

Translators see the description in the TMS — critical for distinguishing "Continue" (verb) from "Continue" (button label) in languages where these would translate differently.

### 5.5 Empty / Pseudo / Test Locales

- `messages.en-XA.json` — pseudo-locale that surrounds every translation with brackets and accented characters: `[Çønțîñüé wîțh à pàșskéý]`. Used in CI to detect un-translated hard-coded strings.
- `messages.zz-ZZ.json` — RTL-test pseudo-locale that returns mirrored strings. Used in v1.2 RTL development.

---

### 6. Layout Considerations for Translation

### 6.1 Expansion Factors

| Language | Expansion factor (vs English) |
| --- | --- |
| German | +30% |
| French | +20% |
| Spanish | +20% |
| Italian | +15% |
| Portuguese | +10% |
| Japanese | -30% character count (but tall glyphs) |
| Korean | -25% character count |
| Mandarin | -30% character count |
| Hindi | +15% (Devanagari needs vertical space) |

### 6.2 Design Rules

| Rule | Why |
| --- | --- |
| **Buttons auto-width with generous padding (≥`space.l` on each side)** | German labels +30% must fit |
| **No fixed-width inputs unless the input is fixed-length (OTP, phone country code)** | Long labels would overflow |
| **No text in images** | Cannot translate; per WCAG 1.4.5 |
| **No text in icons** | Same reason |
| **Headings can wrap to two lines on small viewports** | Cannot force one-line in all languages |
| **Tabs and Tags accept multi-line labels at narrow widths** | German "Konfiguration" beats English "Setup" |
| **Tables design column widths for the longest expected language** | Audit log column "Result" → German "Ergebnis" |
| **Translated strings tested in pseudo-locale before launch** | Catches hard-coded strings + clipping |
| **Date/time formatting respects locale** | "May 19, 2026" → "19. Mai 2026" → "2026年5月19日" |

### 6.3 Pseudo-Locale Testing

Before every release, the QA team runs the pseudo-locale (`en-XA`) against the application. Any string that does not change to bracketed-accented form is a hard-coded leak and is fixed before release. Any UI clipping with the expanded pseudo-locale is fixed.

---

### 7. Date, Time, Number Formatting

All formatting is **locale-aware via the JavaScript `Intl` API** (web) and the equivalent in Flutter (`intl` Dart package).

### 7.1 Dates

| Format | Example en | Example de | Example ja |
| --- | --- | --- | --- |
| `short` | 5/19/26 | 19.05.26 | 2026/05/19 |
| `medium` | May 19, 2026 | 19. Mai 2026 | 2026年5月19日 |
| `long` | May 19, 2026 | 19. Mai 2026 | 2026年5月19日 |
| `full` | Monday, May 19, 2026 | Montag, 19. Mai 2026 | 2026年5月19日月曜日 |

Default in UI: `medium`. Audit log timestamps use ISO 8601 UTC (e.g., `2026-05-19T14:32:18Z`) for machine readability + locale-formatted in tooltips on hover.

### 7.2 Times

| Format | Example en | Example de | Example ja |
| --- | --- | --- | --- |
| `short` | 2:32 PM | 14:32 | 14:32 |
| `medium` | 2:32:18 PM | 14:32:18 | 14:32:18 |

Locale-default 12h vs 24h is respected. Users can override in account preferences.

### 7.3 Numbers

| Format | Example en | Example de | Example ja |
| --- | --- | --- | --- |
| Integer | 12,481 | 12.481 | 12,481 |
| Decimal | 12,481.50 | 12.481,50 | 12,481.50 |
| Percent | 8.3% | 8,3 % | 8.3% |

### 7.4 Currency Display

| Currency | Display en | Display de | Display ja |
| --- | --- | --- | --- |
| USD | $148.62 | 148,62 $ | 148.62米ドル |
| EUR | €148.62 | 148,62 € | 148.62ユーロ |
| JPY | ¥14,862 | 14.862 ¥ | ¥14,862 |
| INR | ₹148.62 | 148,62 ₹ | 148.62ルピー |

Currency symbol position (prefix vs suffix), space-before-symbol, decimal separator, thousand separator — all locale-aware.

### 7.5 Phone Numbers

| Country | Format |
| --- | --- |
| US | +1 415 555 7421 |
| DE | +49 30 12345678 |
| JP | +81 3-1234-5678 |
| IN | +91 99876 54321 |

Phone number formatting via `libphonenumber-js` (web) / `libphonenumber_plugin` (Flutter). Storage is always E.164 (per Phase 2 [Database §5.2](../phase-2/Qeet%20ID%20%E2%80%94%20Database%20Design%20%26%20Data%20Model.md)). Display is locale-aware.

### 7.6 Addresses

Address formats vary materially. Qeet ID uses Google's `i18n-address` library for format rules. Form fields adapt per country (United States has "State" with options; Germany has "Bundesland" free-text; Japan has "都道府県" prefecture). Used in billing forms.

---

### 8. Language Detection & Selection

### 8.1 Detection Priority

1. **User preference** (if signed in and has set a preference) — explicitly stored on the user record.
2. **URL parameter** — `?lang=es` for one-off override (developer testing; deep-linked outbound emails).
3. **Browser `Accept-Language` header** — first language code with locale match.
4. **Tenant default language** — set in tenant Settings (e.g., a Brazilian tenant defaults to `pt-BR` for its end users).
5. **Fallback: English (`en`)**.

### 8.2 Language Switcher UI

The end-user auth pages have a language switcher in the footer:

```
   ┌─────────────────────────────────────────────────────────┐
   │  …                                                     │
   │                                                         │
   │  Powered by Qeet ID · Privacy · Terms · [English ▾]    │
   └─────────────────────────────────────────────────────────┘
```

Click opens a popover with the 10 launch languages. Selecting one:
- Sets the language preference cookie (and the user preference if signed in).
- Reloads the page in the chosen language.

### 8.3 Persistence

- **Logged in:** stored on the user record (`users.preferences.language`).
- **Logged out:** stored in a `qf_lang` cookie (1-year TTL, `SameSite=Lax`).
- **Mobile native app:** stored in app preferences, sent to Qeet ID on every authenticated request.

### 8.4 Email Localisation

Emails are sent in the user's preferred language (user record). If preference is unset, the language of the page where the email was triggered is used (e.g., if the user requested a magic link in Spanish, the magic-link email is in Spanish).

---

### 9. RTL Design Considerations

RTL (Arabic, Hebrew, Persian, Urdu) ships in **v1.2** per [NFR IN-05](../phase-1/Qeet%20ID%20%E2%80%94%20Non-Functional%20Requirements%20%28NFR%29.md). However, the design system tokens and component implementations are RTL-ready from Day 1 — this prevents a v1.2 retrofit from being a re-architecture.

### 9.1 RTL Readiness Checklist

| Item | RTL-ready at Day 1? |
| --- | --- |
| Spacing tokens direction-neutral (no `space.left`, `space.right` — use `margin-inline-start` etc.) | ✅ |
| Iconography with directional metadata (`mirror: true` for arrows / chevron-back; `mirror: false` for non-directional icons) | ✅ |
| No fixed-direction shadows (vertical bias only) | ✅ |
| CSS uses logical properties (`padding-inline`, `margin-block`) instead of `left`/`right`/`top`/`bottom` | ✅ |
| Flexbox layouts use logical alignment (`flex-start` / `flex-end` map to start/end of writing direction) | ✅ |
| Numbers and dates remain LTR even inside RTL paragraphs (CSS `unicode-bidi: isolate` on numeric runs) | ✅ |
| Image and logo placement direction-neutral | ✅ |
| No left/right keywords in animation directions (use logical equivalents) | ✅ |
| `direction: rtl` on `<html>` flips layout, no per-component logic | Per-component verification |

### 9.2 RTL v1.2 Plan

When RTL ships:

- `<html dir="rtl">` is set for Arabic/Hebrew users.
- The design system's logical properties already flip layouts.
- Icons with `mirror: true` flip via CSS `transform: scaleX(-1)`.
- Numbers, code blocks, and Latin-script names remain LTR inside RTL paragraphs.
- A QA pass validates each surface.

### 9.3 Hindi (Latin: LTR; Devanagari Script)

Hindi launches as LTR. Devanagari has its own line-height considerations (per [Doc 2 §6.5](Qeet ID%20%E2%80%94%20Design%20System%20Foundations%20%26%20Tokens.md)) but does not require RTL.

---

### 10. Cultural Considerations

### 10.1 Calendar Awareness

- **Gregorian** is the default in all locales at launch.
- **Hijri (Islamic) calendar** for Arabic v1.2 — UI shows both Gregorian and Hijri in date displays.
- **Japanese imperial era** is offered as a display preference (Reiwa/Heisei) for Japanese users in v1.5.

### 10.2 Imagery and Iconography Neutrality

- Avatars (default illustrations) are culturally neutral — no flag colours, no nation-specific imagery.
- Empty-state illustrations are abstract / object-based, not people-based.
- The "passkey" icon uses a key motif universally readable.
- Hand gestures (thumbs-up on docs feedback widget) are universally interpretable; in cultures where thumbs-up is offensive (some Middle Eastern regions, parts of West Africa), the v1.2 release replaces with neutral icons.

### 10.3 Trust Signals per Region

Per Persona Omar §4.5: data residency and compliance certifications matter regionally.

| Region | Trust badge |
| --- | --- |
| US | SOC 2 Type I/II badges |
| EU | GDPR badge + "Hosted in EU" |
| UK | UK GDPR + "Hosted in UK" (v1.2) |
| APAC | PDPA + "Hosted in APAC" (v1.2) |
| India | DPDPA badge (v1.5) |

These appear on the Security Trust Center (per [Doc 7 §17](Qeet ID%20%E2%80%94%20Developer%20Portal%20Design%20Specification.md)) and on the marketing site (Marketing-owned).

### 10.4 Photography & Stock Imagery

Marketing and Trust Center photography (when used) reflects global diversity. Stock photo selection guidelines live in the Marketing brand guide (not in scope for Phase 3 except to set the standard).

---

### 11. Localised Marketing Assets

Marketing-owned localisations (homepage, pricing, customer stories, blog posts) are out of scope for Phase 3 — owned by Marketing's team. The contract at the boundary:

- The design system tokens, the Component Library, and the brand voice (per [Doc 1 §7](Qeet ID%20%E2%80%94%20UX%20Research%20Summary%20%26%20Design%20Principles.md)) are the source-of-truth Marketing builds against.
- The Phase 3 deliverables include reusable patterns Marketing's localised pages can adopt (i.e., Marketing does not reinvent how to localise a header CTA — they consume the Component Library's `Button` with the translated label key).

---

### 12. Right-to-Left & Bi-Directional Text in Auth Flows (v1.2)

When a user with Arabic / Hebrew preference logs in:
- The Auth Layout flips to RTL.
- The logo placement, button alignment, and form field alignment all flip via logical properties.
- Latin-script names (e.g., the email field) remain LTR inside RTL paragraphs via `unicode-bidi: isolate`.
- The hosted login URL stays LTR (URLs are not RTL).
- Numbers in passkey countdown / OTP timer remain LTR.

---

### 13. Translation Quality Assurance

### 13.1 QA Workflow

| Step | Owner | Output |
| --- | --- | --- |
| Vendor translation | Translation Vendor | First draft per locale |
| Vendor second-pass review | Translation Vendor | Reviewed copy |
| Internal review (where Qeet ID has native speakers) | Localisation Lead + reviewer | Approved copy |
| In-context UI review (translator views the actual UI) | Localisation Lead | Verified copy |
| Pseudo-locale regression | QA | Confirmed no hard-coded leaks; no clipping |
| Native-speaker walkthrough | UX + QA | Confirmed UX correctness |

### 13.2 Reviewer Network

Qeet ID maintains a network of native-speaker reviewers (internal staff + contractors) across the 10 launch languages. Each release that touches end-user copy gets a reviewer pass before deploy.

### 13.3 Translation Memory

The TMS maintains translation memory — repeated phrases are translated consistently. New strings that match existing translations propose the existing translation by default.

### 13.4 Glossary

A canonical glossary maintained in the TMS:

| Term | Translation rule |
| --- | --- |
| Qeet ID | Never translated |
| Passkey | Localised consistently (in Mandarin: 通行密钥; in Japanese: パスキー; in Korean: 패스키) |
| OAuth, OIDC, SAML, SCIM | Never translated |
| Sign in / Sign up | Locale-appropriate verbs (de: "Anmelden" / "Registrieren") |
| Security key | Localised consistently |

---

### 14. Translatable String Inventory at Launch

Approximate scale for engineering capacity planning:

| Surface | Strings | Per-locale words |
| --- | --- | --- |
| End-user auth pages | ~250 | ~600 words × 9 non-English locales |
| Embeddable widgets | shared with above | shared |
| Email templates (transactional) | ~80 (across 10 templates) | ~1,500 words × 9 |
| Account portal | ~150 | ~400 words × 9 |
| Total launch translation volume | ~480 strings | ~2,500 words per locale = ~22,500 words across 9 locales |

A reasonable budget for a localisation vendor at professional rates is documented separately (OD-LO-02).

---

### 15. Performance Considerations

### 15.1 Bundle Splitting per Locale

Each locale's translation bundle is a separate JS file, loaded on demand. The hosted login pages load only the user's selected locale (~5 KB additional payload).

### 15.2 Default Bundle

For first paint before locale detection completes, the page renders in English using inline strings, then re-hydrates with the user's locale (no visible flash because the layout is identical for all Latin-script locales).

### 15.3 Font Subsetting

Inter is the platform font. For Japanese/Korean/Mandarin/Hindi, Inter does not include the necessary glyphs. We use:

- **Noto Sans CJK** (Japanese, Korean, Mandarin) — variable-weight subset by locale.
- **Noto Sans Devanagari** (Hindi) — variable-weight subset.

Each script's font bundle is ~80–120 KB gzipped, loaded only when the user's locale needs it. Total mobile budget impact ≤ 150 KB on the heaviest locale.

---

### 16. Accessibility Considerations for Localisation

Localised content meets the same WCAG 2.1 AA standard as English ([Doc 9](Qeet ID%20%E2%80%94%20Accessibility%20Compliance%20Plan%20%28WCAG%202.1%20AA%29.md)). Specific localisation × accessibility intersections:

- `<html lang="es">` set per page (WCAG 3.1.1).
- Mixed-language passages use `lang="..."` (WCAG 3.1.2).
- Screen reader pronunciation: tested per language (NVDA + JAWS + VoiceOver + TalkBack).
- Localised error messages preserve their `aria-live` behaviour.
- Translated dates / times remain parseable by assistive tech.

---

### 17. v1.5 Admin Dashboard Localisation Plan

When the dashboard begins localisation in v1.5, the priorities (driven by enterprise sales demand) are:

1. **German** (largest European enterprise market for Qeet ID).
2. **Japanese** (APAC enterprise expansion).
3. **French** (additional EU coverage).
4. **Spanish** (LATAM).

Other dashboard languages roll out as customer demand justifies.

---

### 18. Open Design Decisions From This Document

| # | Question | Owner | Target |
| --- | --- | --- | --- |
| OD-LO-01 | TMS choice — Crowdin vs Lokalise vs Phrase | Localisation Lead + Engineering | Phase 3 Week 3 |
| OD-LO-02 | Translation vendor selection | Localisation Lead | Phase 3 Week 4 |
| OD-LO-03 | Date format default — `medium` everywhere vs context-aware | UX + Localisation | Phase 3 Week 3 |
| OD-LO-04 | Whether to support Brazilian Portuguese vs European Portuguese vs both | Localisation + Sales | Phase 3 Week 2 |
| OD-LO-05 | Whether to translate the OAuth scope strings (`openid`, `profile`, `email`) shown on the consent screen — or keep them as protocol identifiers | UX + Security | Phase 3 Week 3 |
| OD-LO-06 | RTL launch — v1.2 vs sooner (depends on first Arabic-speaking enterprise customer) | Product + Sales | Phase 3 Week 3 |

---

### 19. Cross-References

- Type system + script handling: [Design System Foundations & Tokens](Qeet ID%20%E2%80%94%20Design%20System%20Foundations%20%26%20Tokens.md) §6.5, §14 RTL Readiness
- Component-level localisation: [Component Library Specification](Qeet ID%20%E2%80%94%20Component%20Library%20Specification.md)
- End-user flow localisation: [End-User Authentication Flow Designs](Qeet ID%20%E2%80%94%20End-User%20Authentication%20Flow%20Designs.md) §25
- Mobile localisation: [Mobile & Responsive Design Specification](Qeet ID%20%E2%80%94%20Mobile%20%26%20Responsive%20Design%20Specification.md)
- Accessibility intersections: [Accessibility Compliance Plan (WCAG 2.1 AA)](Qeet ID%20%E2%80%94%20Accessibility%20Compliance%20Plan%20%28WCAG%202.1%20AA%29.md)
- Email templates: [Admin Dashboard Design Specification §18](Qeet ID%20%E2%80%94%20Admin%20Dashboard%20Design%20Specification.md)
- NFR i18n requirements: [Phase 1 NFR §12.3](../phase-1/Qeet%20ID%20%E2%80%94%20Non-Functional%20Requirements%20%28NFR%29.md)
- Multi-tenancy region pinning: [Phase 2 Multi-Tenancy Architecture](../phase-2/Qeet%20ID%20%E2%80%94%20Multi-Tenancy%20Architecture.md)

---

### 20. Approvals & Sign-off

| Role | Name | Signature | Date |
| --- | --- | --- | --- |
| UX Designer |  |  |  |
| Localisation Lead |  |  |  |
| Frontend Engineering Lead |  |  |  |
| Email Template Designer |  |  |  |
| Technical Writer Lead |  |  |  |
| QA Lead |  |  |  |
| Product Manager |  |  |  |
| Compliance Officer (data residency × language) |  |  |  |

---

*This document is version controlled. Visual updates in Figma do not require re-sign-off; changes to the launch locale scope (§3), translation workflow (§4), string management standards (§5), RTL readiness (§9), or formatting standards (§7) require UX Designer + Localisation Lead + Product Manager review.*

---

**Qeet ID — Authenticate Everything.** *A Qeet Group Company*
