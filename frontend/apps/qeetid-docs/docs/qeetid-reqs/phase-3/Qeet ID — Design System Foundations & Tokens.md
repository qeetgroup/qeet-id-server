# Qeet ID — Design System Foundations & Tokens

### 1. Document Information

|  |  |
| --- | --- |
| **Document Name** | Design System Foundations & Tokens |
| **Project Name** | Qeet ID |
| **Parent Company** | Qeet Group |
| **Subsidiary** | Qeet ID (Standalone) |
| **Document Version** | v1.0 |
| **Prepared By** | UX Designer |
| **Date** | May 19, 2026 |
| **Status** | Draft — Pending Stakeholder Sign-off |

---

### 2. Purpose & Scope

This document defines the *foundations* of the Qeet ID design system — the design tokens (colour, typography, spacing, layout, radius, elevation, motion, iconography, z-index) on which every Qeet ID component, screen, embed, and email is built. Components themselves are specified in [Qeet ID — Component Library Specification](Qeet ID%20%E2%80%94%20Component%20Library%20Specification.md); this document is the layer beneath them.

Tokens are the single source of truth. Hex values, font sizes, pixel spacings, and animation durations do not appear in component specs, in Figma component layers, or in production code — they appear *only* in the token files. This is what makes white-label re-branding (per Principle [P-06](Qeet ID%20%E2%80%94%20UX%20Research%20Summary%20%26%20Design%20Principles.md)) possible, and what makes the light-mode / dark-mode duality and the WCAG AA contrast guarantees verifiable.

The audience is the UX Designer, every Frontend Engineer, the Mobile (Flutter) SDK Lead, the Email Designer / Marketing Designer, and the QA Lead (for visual-regression).

This document depends on [UX Research Summary & Design Principles](Qeet ID%20%E2%80%94%20UX%20Research%20Summary%20%26%20Design%20Principles.md) (the principles tokens must serve) and on Phase 1 NFR §12 (accessibility, mobile, browser, localisation). It is the foundation of every other Phase 3 document.

---

### 3. Design System Philosophy

**DS-01 — Token-Driven.** Every visual value comes from a token. No value is inlined. A change to a token propagates to every component, every screen, every embed, every email automatically.

**DS-02 — Three-Tier Token Architecture.** Tokens come in three tiers: **primitive** (raw values), **semantic** (intent-named values that map to primitives), and **component** (component-specific values that map to semantic). Components never reference primitives directly. White-label re-branding affects semantic tokens; primitives can be added but not silently swapped.

**DS-03 — Theme-Ready by Construction.** Every semantic token has a value in light mode and dark mode. Both themes are first-class — neither is a "tweaked override" of the other.

**DS-04 — Accessibility-Baked.** Every text-on-surface combination is verified against WCAG 2.1 AA contrast (4.5:1 body, 3:1 large text and UI components) at token-definition time, not at component-implementation time.

**DS-05 — Multi-Format Export.** Tokens are authored once and exported to four formats: Figma variables, CSS custom properties, JSON for cross-platform SDKs (notably Flutter and the SDK-rendered widgets), and a Markdown reference for documentation. The single source of truth is `design-tokens/qeetify.tokens.json` in the design system repo.

**DS-06 — Versioned.** The token file is semantically versioned. Breaking changes (renaming a semantic token, removing a primitive) increment the major version and require a migration note. Additive changes increment the minor version.

**DS-07 — Locked Surface for White-Label.** Tenants who white-label Qeet ID cannot change every token — only a documented subset (Phase 3 Doc 8 §4). The locked subset is what keeps accessibility, motion, and layout integrity intact across tenants.

---

### 4. Three-Tier Token Architecture

```
   ┌──────────────────────────────────────────────────────────────────────┐
   │ TIER 1 — PRIMITIVE TOKENS                                            │
   │  Raw values. Numeric. Hexadecimal. Named by what they ARE.           │
   │  e.g.  blue-500: #2563EB                                             │
   │         neutral-100: #F3F4F6                                         │
   │         space-4: 16px                                                │
   │         font-size-3: 16px                                            │
   │         duration-2: 200ms                                            │
   │  Used directly only by Tier 2 (semantic) tokens.                     │
   └──────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
   ┌──────────────────────────────────────────────────────────────────────┐
   │ TIER 2 — SEMANTIC TOKENS                                             │
   │  Intent-named. Map to a primitive.                                   │
   │  e.g.  color.text.primary: { light: neutral-900, dark: neutral-50 }  │
   │         color.surface.elevated: { light: white, dark: neutral-850 }  │
   │         space.gutter: space-4                                        │
   │         radius.control: radius-2                                     │
   │         duration.standard: duration-2                                │
   │  Used by components and by white-label brand overrides.              │
   └──────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
   ┌──────────────────────────────────────────────────────────────────────┐
   │ TIER 3 — COMPONENT TOKENS                                            │
   │  Component-specific. Map to a semantic.                              │
   │  e.g.  button.primary.background.rest: color.action.primary          │
   │         button.primary.background.hover: color.action.primary-hover  │
   │         input.border.focus: color.border.focused                     │
   │  Used inside component definitions only.                             │
   └──────────────────────────────────────────────────────────────────────┘
```

Components reference Tier-3 tokens; Tier-3 tokens map to Tier-2; Tier-2 maps to Tier-1. The chain is never broken — a component does not skip directly to Tier-1.

### 4.1 White-Label Override Tier

A tenant's branding overrides Tier-2 *semantic* tokens, never Tier-1 primitives or Tier-3 component tokens. The override list is documented in [Phase 3 Doc 8 §4](Qeet ID%20%E2%80%94%20Embeddable%20Auth%20UI%20Components%20%28White-Label%29.md). Locked tokens (spacing, type scale ratios, accessibility-critical contrasts, motion) cannot be overridden — this is enforced at the token-loader level.

---

### 5. Color System

### 5.1 Brand Direction (Open Decision)

The exact brand colour direction is tied to OD-UX-02 in the Open Design Decisions Register, pending Qeet Group Marketing input. This document specifies the **structure** of the colour system, not the exact hexadecimal values for the brand scale. The structure is brand-agnostic; once Marketing signs the brand palette, the primitive `brand-*` and `accent-*` ramps populate without changing any downstream semantic or component token.

For working purposes the system assumes:
- A **brand scale** in a confidence-conveying blue / teal family (the category convention; the differentiator is the accent, not the brand).
- An **accent scale** in a slightly warmer family (amber, coral, or orange-leaning) — Qeet ID's modest visual departure from the cool-blue saturation of Auth0 / Okta / Entra (per Competitive Analysis differentiation strategy).
- Neutral, success, warning, danger, info ramps follow standard category practice.

### 5.2 Primitive Palette

The primitive palette is built from twelve named ramps, each with eleven steps (0 lightest → 1000 darkest). The eleven-step scale gives enough resolution for both light-mode and dark-mode placements without re-deriving palettes per theme.

| Ramp | Purpose | Step usage examples |
| --- | --- | --- |
| `neutral` | Backgrounds, surfaces, borders, body text | 0 = pure white; 50–100 = page background light; 850–950 = page background dark; 900 = body text light; 50 = body text dark |
| `brand` | Primary brand colour; primary actions | 500/600 = primary action; 400 = hover light; 700 = active dark |
| `accent` | Secondary brand colour; highlights, illustrations | 500/600 = accent action; 100 = subtle accent surface |
| `success` | Affirmative status | 500 = success action; 100 = success surface |
| `warning` | Caution status | 500 = warning action; 100 = warning surface |
| `danger` | Destructive status; errors | 500 = danger action; 100 = danger surface |
| `info` | Informational status | 500 = info action; 100 = info surface |
| `passkey` | Brand colour for passkey-related affordances (P-02) | 500 = passkey button; 100 = subtle passkey surface |
| `code-bg` | Code block surface scale | dedicated ramp because code-block backgrounds must be subtly distinct from page surface in both themes |
| `chart-1..6` | Chart series colours (six numbered chart palettes) | 500 of each = chart series; tested for contrast and colour-blindness |

Each ramp is defined in HSL with a perceptually-tuned step (using OKLCH or a similar perceptual model where the design tool allows) to keep visual rhythm consistent across hues.

### 5.3 Naming Convention

Primitive tokens are named `{ramp}-{step}` with step ∈ {0, 50, 100, 200, 300, 400, 500, 600, 700, 800, 900, 950, 1000}. Step 500 is the "anchor" (the most saturated, brand-representative value).

```
   neutral-0    = lightest (typically pure white)
   neutral-50   = page bg (light mode)
   neutral-100
   neutral-200  = subtle border (light mode)
   neutral-300
   neutral-400  = placeholder text
   neutral-500
   neutral-600  = secondary text (light mode)
   neutral-700
   neutral-800
   neutral-850  = elevated surface (dark mode)
   neutral-900  = body text (light mode); page bg (dark mode)
   neutral-950
   neutral-1000 = darkest
```

### 5.4 Semantic Color Tokens

Semantic tokens are the layer components and white-label-overrides operate on. Every semantic token has values for both `light` and `dark` themes.

#### 5.4.1 Text

| Token | Light | Dark | Purpose |
| --- | --- | --- | --- |
| `color.text.primary` | `neutral-900` | `neutral-50` | Body text |
| `color.text.secondary` | `neutral-600` | `neutral-300` | Supporting text, help text |
| `color.text.tertiary` | `neutral-500` | `neutral-400` | Captions, micro-copy |
| `color.text.placeholder` | `neutral-400` | `neutral-500` | Input placeholder |
| `color.text.disabled` | `neutral-400` | `neutral-600` | Disabled controls |
| `color.text.inverse` | `neutral-0` | `neutral-900` | Text on `surface.inverse` |
| `color.text.brand` | `brand-700` | `brand-300` | Brand-coloured headings |
| `color.text.link` | `brand-600` | `brand-300` | Inline links |
| `color.text.link-hover` | `brand-700` | `brand-200` | Inline links hover |
| `color.text.success` | `success-700` | `success-300` | Success status text |
| `color.text.warning` | `warning-700` | `warning-300` | Warning status text |
| `color.text.danger` | `danger-700` | `danger-300` | Error / danger text |
| `color.text.info` | `info-700` | `info-300` | Info status text |
| `color.text.on-brand` | `neutral-0` | `neutral-0` | Text on a brand-500/600 surface |
| `color.text.code` | `accent-700` | `accent-300` | Inline code |

#### 5.4.2 Surface

| Token | Light | Dark | Purpose |
| --- | --- | --- | --- |
| `color.surface.canvas` | `neutral-50` | `neutral-950` | Page background |
| `color.surface.default` | `neutral-0` | `neutral-900` | Card / panel background |
| `color.surface.elevated` | `neutral-0` | `neutral-850` | Floating / modal surface |
| `color.surface.sunken` | `neutral-100` | `neutral-950` | Subtly recessed (e.g., code block) |
| `color.surface.subtle` | `neutral-100` | `neutral-850` | Subtle surface (input rest, table row hover) |
| `color.surface.inverse` | `neutral-900` | `neutral-100` | Tooltip; high-contrast inverse |
| `color.surface.brand-subtle` | `brand-50` | `brand-950` | Subtle brand-tinted surface |
| `color.surface.accent-subtle` | `accent-50` | `accent-950` | Subtle accent-tinted surface |
| `color.surface.success-subtle` | `success-50` | `success-950` | Success banner surface |
| `color.surface.warning-subtle` | `warning-50` | `warning-950` | Warning banner surface |
| `color.surface.danger-subtle` | `danger-50` | `danger-950` | Danger banner surface |
| `color.surface.info-subtle` | `info-50` | `info-950` | Info banner surface |
| `color.surface.passkey-subtle` | `passkey-50` | `passkey-950` | Passkey-affordance subtle surface |
| `color.surface.code` | `code-bg-50` | `code-bg-900` | Code block background |

#### 5.4.3 Border

| Token | Light | Dark | Purpose |
| --- | --- | --- | --- |
| `color.border.default` | `neutral-200` | `neutral-800` | Default divider |
| `color.border.subtle` | `neutral-100` | `neutral-850` | Subtle separator |
| `color.border.strong` | `neutral-300` | `neutral-700` | Card border |
| `color.border.focused` | `brand-500` | `brand-400` | Focus ring |
| `color.border.hover` | `neutral-400` | `neutral-600` | Hover border |
| `color.border.danger` | `danger-500` | `danger-400` | Error field border |
| `color.border.success` | `success-500` | `success-400` | Success field border |
| `color.border.inverse` | `neutral-700` | `neutral-300` | Border on inverse surface |

#### 5.4.4 Action

Action tokens are the foreground colours for buttons, links, and other interactive elements. Each action has rest / hover / active / disabled states.

| Token | Light | Dark | Purpose |
| --- | --- | --- | --- |
| `color.action.primary` | `brand-600` | `brand-500` | Primary CTA background |
| `color.action.primary-hover` | `brand-700` | `brand-400` | Primary CTA hover |
| `color.action.primary-active` | `brand-800` | `brand-300` | Primary CTA active |
| `color.action.primary-disabled` | `neutral-200` | `neutral-800` | Primary CTA disabled |
| `color.action.secondary` | `neutral-0` | `neutral-850` | Secondary CTA background |
| `color.action.secondary-hover` | `neutral-100` | `neutral-800` | Secondary CTA hover |
| `color.action.secondary-active` | `neutral-200` | `neutral-700` | Secondary CTA active |
| `color.action.ghost-hover` | `neutral-100` | `neutral-800` | Ghost button hover surface |
| `color.action.danger` | `danger-600` | `danger-500` | Destructive CTA |
| `color.action.danger-hover` | `danger-700` | `danger-400` | Destructive CTA hover |
| `color.action.passkey` | `passkey-600` | `passkey-500` | Passkey button (P-02) |
| `color.action.passkey-hover` | `passkey-700` | `passkey-400` | Passkey button hover |

#### 5.4.5 Status (decorative — for badges, tags, dots)

| Token | Light | Dark | Purpose |
| --- | --- | --- | --- |
| `color.status.active-dot` | `success-500` | `success-400` | Online / active dot |
| `color.status.idle-dot` | `warning-500` | `warning-400` | Idle |
| `color.status.offline-dot` | `neutral-400` | `neutral-500` | Offline |
| `color.status.error-dot` | `danger-500` | `danger-400` | Error state dot |

### 5.5 Light Mode + Dark Mode Pairing

Every semantic token in §5.4 has a light value and a dark value. The dark theme is **not** a programmatic inversion of light — it is independently authored, often using the same step number across themes (`text.primary` is `neutral-900` in light and `neutral-50` in dark — symmetric), but with deliberate exceptions where perceptual contrast demands them (notably code-block surfaces and chart palettes).

The dark theme defaults to **deep neutral** (close to `neutral-950`) rather than pure black — pure black surfaces produce harsh contrast and visible chromatic aberration on OLED panels.

### 5.6 Contrast Verification Table

The table below enumerates the text-on-surface combinations Qeet ID uses and confirms each meets WCAG 2.1 AA (4.5:1 normal text, 3:1 large text / UI components). Verification is repeated at token-publish time; a failed combination blocks the token release. The table records the **minimum required ratio** and the **target ratio at the chosen primitives**.

| # | Foreground × Background (light) | Required | Confirmed target | OK |
| --- | --- | --- | --- | --- |
| C-01 | `text.primary` × `surface.canvas` | 4.5:1 | ≥ 12:1 | ✅ |
| C-02 | `text.primary` × `surface.default` | 4.5:1 | ≥ 12:1 | ✅ |
| C-03 | `text.primary` × `surface.elevated` | 4.5:1 | ≥ 12:1 | ✅ |
| C-04 | `text.primary` × `surface.subtle` | 4.5:1 | ≥ 11:1 | ✅ |
| C-05 | `text.secondary` × `surface.canvas` | 4.5:1 | ≥ 7:1 | ✅ |
| C-06 | `text.secondary` × `surface.default` | 4.5:1 | ≥ 7:1 | ✅ |
| C-07 | `text.tertiary` × `surface.canvas` | 4.5:1 | ≥ 4.5:1 | ✅ |
| C-08 | `text.placeholder` × `surface.default` | 4.5:1 | ≥ 4.5:1 | ✅ |
| C-09 | `text.on-brand` × `action.primary` | 4.5:1 | ≥ 5.5:1 | ✅ |
| C-10 | `text.on-brand` × `action.danger` | 4.5:1 | ≥ 5.5:1 | ✅ |
| C-11 | `text.link` × `surface.canvas` | 4.5:1 | ≥ 5.5:1 | ✅ |
| C-12 | `text.link` × `surface.default` | 4.5:1 | ≥ 5.5:1 | ✅ |
| C-13 | `text.danger` × `surface.danger-subtle` | 4.5:1 | ≥ 5:1 | ✅ |
| C-14 | `text.success` × `surface.success-subtle` | 4.5:1 | ≥ 5:1 | ✅ |
| C-15 | `text.warning` × `surface.warning-subtle` | 4.5:1 | ≥ 5:1 | ✅ |
| C-16 | `text.info` × `surface.info-subtle` | 4.5:1 | ≥ 5:1 | ✅ |
| C-17 | `text.code` × `surface.code` | 4.5:1 | ≥ 5:1 | ✅ |
| C-18 | `text.inverse` × `surface.inverse` | 4.5:1 | ≥ 12:1 | ✅ |
| C-19 | `border.focused` × `surface.default` (3:1 UI) | 3:1 | ≥ 3.5:1 | ✅ |
| C-20 | `border.default` × `surface.default` (3:1 UI) | 3:1 | ≥ 3:1 | ✅ |

The same table is computed for the dark theme; values differ but the conformance commitment is identical. The verification matrix lives in the design-system repo as a CSV alongside the token file and re-runs in CI on every token PR (Phase 3 Doc 9 §8).

### 5.7 Colour-Blind Considerations

- **Status never relies on colour alone (P-anti-pattern AP-15).** Every status pill includes an icon and / or a label.
- **Chart series** use a palette tested against deuteranopia, protanopia, and tritanopia simulators. Two-series charts use brand + accent (distinguishable across all three). Three-series and beyond use the `chart-1..6` palette with shape + label as additional differentiators.
- **Required-field indicators** use an asterisk + the word "Required" in help text, not the asterisk alone in colour.

---

### 6. Typography System

### 6.1 Type Families

Two roles:

| Role | Family | Fallback stack | Notes |
| --- | --- | --- | --- |
| `font.family.sans` | A geometric / neo-grotesque sans-serif (default reference: **Inter** for its strong web rendering, broad weight set, variable axes, and excellent CJK fallback compatibility) | `Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif` | UI, headings, body |
| `font.family.mono` | A modern monospace (default reference: **JetBrains Mono** — broad weight set, programming ligatures, good unicode support) | `'JetBrains Mono', 'SF Mono', Menlo, Monaco, Consolas, 'Liberation Mono', monospace` | Code, IDs, technical values |

The specific font choice (Inter, JetBrains Mono) is the **default recommendation**; Marketing may substitute alternates within the constraints stated below (variable-axis support, ≥6 weights, broad unicode, generous x-height). White-label customers cannot change the type family (Phase 3 Doc 8 §5).

### 6.2 Type Scale

A modular scale with twelve steps. The scale ratio is **1.125** (a "major second") for compact UI density, with **larger jumps at the heading tier**.

| Step | Token | Size (px) | Line height | Letter spacing | Weight default | Use |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | `text.micro` | 11px | 16px (1.45) | +0.02em | 500 | Micro-copy, footer fine print, table column tags |
| 2 | `text.caption` | 12px | 16px (1.33) | +0.01em | 400 | Captions, helper text |
| 3 | `text.body-sm` | 13px | 20px (1.54) | 0 | 400 | Dense table cells, sidebar items |
| 4 | `text.body` | 14px | 20px (1.43) | 0 | 400 | Default body |
| 5 | `text.body-lg` | 16px | 24px (1.5) | 0 | 400 | Long-form (docs, articles, blog) |
| 6 | `text.body-emphasis` | 16px | 24px (1.5) | 0 | 500 | Body emphasis |
| 7 | `text.heading-sm` | 18px | 24px (1.33) | -0.005em | 600 | h4, h5 |
| 8 | `text.heading` | 20px | 28px (1.4) | -0.01em | 600 | h3 |
| 9 | `text.heading-lg` | 24px | 32px (1.33) | -0.015em | 600 | h2 |
| 10 | `text.title` | 32px | 40px (1.25) | -0.02em | 700 | h1 / page title |
| 11 | `text.display` | 48px | 56px (1.17) | -0.025em | 700 | Marketing display, Trust Center hero |
| 12 | `text.display-lg` | 64px | 72px (1.13) | -0.025em | 700 | Marketing hero (sparingly) |

Code text uses its own dedicated set:

| Token | Family | Size | Line height | Notes |
| --- | --- | --- | --- | --- |
| `text.code-inline` | mono | 13px | 20px | Inline code in body |
| `text.code-block` | mono | 13px | 22px | Block code in docs |
| `text.code-block-sm` | mono | 12px | 20px | Code in dense tables |

### 6.3 Weight, Optical Sizing, and Variable Axes

Inter's variable-weight axis is used. Available weight tokens:

| Token | Weight |
| --- | --- |
| `font.weight.regular` | 400 |
| `font.weight.medium` | 500 |
| `font.weight.semibold` | 600 |
| `font.weight.bold` | 700 |

Inter is loaded with `font-display: swap`. The `wght` variable axis is set on `<html>` so headings and body share the same font file (single network request).

### 6.4 Line Height, Letter Spacing

Line heights are absolute (px) at small sizes and unitless (multipliers) at body size, to avoid compounding line-height issues in nested elements. The scale uses tight line-heights for headings (≤1.4) and generous line-heights for body and long-form (1.5).

Letter spacing tightens slightly at large sizes (-0.025em at display) and opens slightly at small sizes (+0.02em at micro) — a perceptual compensation for size shifts.

### 6.5 Localisation Considerations

| Concern | Adjustment |
| --- | --- |
| CJK characters (Japanese, Korean, Mandarin) | Adopt locale-aware line-height bump: line-height ×1.1 for blocks containing CJK runs. Glyph metrics are wider; pseudo-italic is avoided (Japanese italics can be illegible). |
| Devanagari (Hindi) | Add 0.1em line-height to account for ascender / vowel-mark space above the baseline. Avoid letter-spacing changes that would break shaping. |
| Cyrillic / Greek | Inter covers these well; no special handling. |
| RTL (Arabic, Hebrew) | Deferred to v1.2 per NFR IN-05, but the type scale and weights remain valid; the text-alignment tokens are RTL-ready (§14). |
| Emoji and symbol fallback | System emoji font in the fallback stack. Emoji never used as the sole signifier (AP-15). |

### 6.6 Type Pairings (Reference)

A small set of canonical pairings is documented to keep usage consistent across designers and engineers:

| Context | Heading | Body | Caption |
| --- | --- | --- | --- |
| Dashboard card | `heading` | `body` | `caption` |
| Documentation page | `title` → `heading-lg` → `heading` → `heading-sm` | `body-lg` | `caption` |
| Login page | `heading-lg` (centered card title) | `body` | `caption` |
| Status page incident | `heading` | `body` | `caption` for timestamp |
| Marketing hero | `display` or `display-lg` | `body-lg` | n/a |

---

### 7. Spacing System

### 7.1 Base Unit

The base unit is **4px**. All spacing tokens are multiples of 4. This is a deliberate, conservative choice — common in modern systems (Material 3, Tailwind, Carbon) and ergonomic for designers and engineers alike.

### 7.2 T-Shirt Scale

| Token | Value | Common use |
| --- | --- | --- |
| `space.0` | 0px | Reset |
| `space.xxs` | 2px | Hairline (sub-base) — used sparingly, e.g., icon padding |
| `space.xs` | 4px | Tight inline (badge inner padding) |
| `space.s` | 8px | Compact (small button padding) |
| `space.m` | 12px | Default control vertical padding |
| `space.l` | 16px | Default gutter; card padding |
| `space.xl` | 24px | Section spacing |
| `space.2xl` | 32px | Page gutter |
| `space.3xl` | 48px | Major section break |
| `space.4xl` | 64px | Hero spacing |
| `space.5xl` | 96px | Marketing-page only |

### 7.3 Semantic Spacing Tokens

| Token | Maps to | Use |
| --- | --- | --- |
| `space.gutter` | `space.l` (16px) | Default content gutter |
| `space.control-padding-x` | `space.l` (16px) | Button / input horizontal padding |
| `space.control-padding-y` | `space.s` (8px) | Button / input vertical padding (md) |
| `space.stack` | `space.m` (12px) | Default vertical rhythm between form rows |
| `space.section` | `space.2xl` (32px) | Section break in long pages |
| `space.modal-padding` | `space.xl` (24px) | Modal body padding |
| `space.card-padding` | `space.l` (16px) | Card body padding |
| `space.card-padding-lg` | `space.xl` (24px) | Card body padding (large) |

White-label tenants cannot override spacing — spacing is part of the locked surface (DS-07).

---

### 8. Layout Grid

### 8.1 Grid System

| Breakpoint range | Columns | Column gutter | Margin (page edge) | Notes |
| --- | --- | --- | --- | --- |
| Mobile (320–639px) | 4 | 16px | 16px | Single-column for content; 4-col only for grid composition |
| Tablet (640–1023px) | 8 | 16px | 24px | |
| Desktop (1024–1439px) | 12 | 24px | 32px | Primary breakpoint for admin dashboard |
| Wide (1440–2560px) | 12 | 24px | 48px | Content max-width applies |

### 8.2 Content Max Width

| Surface | Max width | Rationale |
| --- | --- | --- |
| End-user auth pages | 440px (card) | Card-centred composition; consistent regardless of viewport (P-03) |
| Admin dashboard content area | 1280px | Wide enough for dense tables (Sandra's audit log) without becoming uncomfortable to read |
| Documentation main column | 720px | Long-form reading width |
| Documentation page (with right TOC) | 720px + 240px TOC | |
| Marketing hero | 1280px |  |
| Status page | 800px |  |

### 8.3 Layout Patterns

- **Single-column** (auth pages, mobile dashboard, single docs page): one column, max width per §8.2.
- **Dual-zone** (dashboard): sidebar + content. Sidebar collapses below tablet.
- **Triple-zone** (docs): left nav + content + right TOC. TOC collapses to popover below tablet.
- **Card grid** (overview screens, stat dashboards): responsive grid of stat cards. 4-col on desktop, 2-col on tablet, 1-col on mobile.

---

### 9. Border Radius Scale

| Token | Value | Use |
| --- | --- | --- |
| `radius.none` | 0px | Sharp / brutalist accents only |
| `radius.xs` | 2px | Hairline (e.g., focus ring offset) |
| `radius.s` | 4px | Small chips, badges |
| `radius.m` | 6px | Inputs, secondary buttons, small cards |
| `radius.l` | 8px | Primary buttons, cards |
| `radius.xl` | 12px | Modals, popovers |
| `radius.2xl` | 16px | Hero cards, marketing |
| `radius.pill` | 9999px | Pill buttons, avatar wrappers, status pills |
| `radius.circle` | 50% | Circular avatars, dots |

### 9.1 White-Label Override

White-label tenants can override the **base radius token** (`radius.brand-base`) within a constrained range (`2px – 12px`). The override scales all `radius.s..l` proportionally; `radius.pill` and `radius.circle` are immune. This lets a tenant pick "sharp" or "soft" within the design system's tolerance without breaking layout (Phase 3 Doc 8 §5).

---

### 10. Elevation / Shadow Scale

| Level | Token | Light value | Dark value | Use |
| --- | --- | --- | --- | --- |
| 0 | `shadow.none` | none | none | Resting flat |
| 1 | `shadow.rest` | `0 1px 2px rgba(neutral-1000, 0.04), 0 0 0 1px rgba(neutral-1000, 0.05)` | `0 1px 2px rgba(black, 0.4)` | Default card |
| 2 | `shadow.hover` | `0 4px 8px rgba(neutral-1000, 0.06), 0 0 0 1px rgba(neutral-1000, 0.05)` | `0 4px 8px rgba(black, 0.5)` | Card hover; menu |
| 3 | `shadow.popover` | `0 8px 16px rgba(neutral-1000, 0.08), 0 0 0 1px rgba(neutral-1000, 0.05)` | `0 8px 16px rgba(black, 0.55)` | Dropdowns, popovers |
| 4 | `shadow.modal` | `0 24px 48px rgba(neutral-1000, 0.16), 0 0 0 1px rgba(neutral-1000, 0.05)` | `0 24px 48px rgba(black, 0.6)` | Modals, drawers |

In dark mode, shadows are largely **decorative** rather than dimensional — dark on dark fails to convey depth via shadow alone. Border tone (`color.border.strong`) and surface lightening (`surface.elevated` is lighter than `surface.default`) carry depth instead.

---

### 11. Motion & Animation Tokens

### 11.1 Principles

**M-01 — Purposeful, not decorative.** Motion communicates state change. Page transitions, modal entries, focus shifts, and data updates use motion. Decorative animations on idle surfaces do not exist in the system.

**M-02 — Fast by default.** The default duration is 200ms. Anything over 400ms is a deliberate exception (e.g., a deliberately slow celebratory micro-interaction).

**M-03 — Reduced-motion respected.** Users with `prefers-reduced-motion: reduce` receive an instant transition (0ms duration; no transform animation; opacity fades retained at reduced intensity).

**M-04 — Easing communicates intent.** Decelerate (ease-out) for things entering; accelerate (ease-in) for things leaving; standard (ease-in-out) for moves; sharp (cubic-bezier) for emphasised state changes.

### 11.2 Duration Tokens

| Token | Value | Use |
| --- | --- | --- |
| `duration.instant` | 0ms | Reduced motion default; impatient operations |
| `duration.micro` | 100ms | Micro-interactions (button press) |
| `duration.fast` | 150ms | Hover transitions |
| `duration.standard` | 200ms | Default for transitions, modals, drawers |
| `duration.slow` | 300ms | Long transitions (collapsible reveal) |
| `duration.deliberate` | 400ms | Emphasised celebrations (passkey-registered success) |
| `duration.linger` | 600ms | Toasts (visible duration; not the transition) |

### 11.3 Easing Tokens

| Token | Value | Use |
| --- | --- | --- |
| `easing.standard` | `cubic-bezier(0.4, 0.0, 0.2, 1)` | Default for moves |
| `easing.decelerate` | `cubic-bezier(0.0, 0.0, 0.2, 1)` | Entering |
| `easing.accelerate` | `cubic-bezier(0.4, 0.0, 1, 1)` | Leaving |
| `easing.sharp` | `cubic-bezier(0.4, 0.0, 0.6, 1)` | Emphasised state change |
| `easing.linear` | `linear` | Progress bars |

### 11.4 Reduced Motion Implementation

```css
@media (prefers-reduced-motion: reduce) {
  :root {
    --duration-micro:    0ms;
    --duration-fast:     0ms;
    --duration-standard: 0ms;
    --duration-slow:     0ms;
    --duration-deliberate: 0ms;
  }
  *, *::before, *::after {
    transition: none !important;
    animation-duration: 0.01ms !important;
    animation-iteration-count: 1 !important;
    scroll-behavior: auto !important;
  }
}
```

Opacity fades (and only opacity fades) may continue at reduced intensity if a transition would otherwise be jarring (e.g., a toast appearing). This is an accessibility detail enforced in Phase 3 Doc 9.

### 11.5 Motion Inventory

| Surface | Motion | Duration | Easing |
| --- | --- | --- | --- |
| Modal enter | Fade + scale (0.98 → 1) | `standard` | `decelerate` |
| Modal exit | Fade | `fast` | `accelerate` |
| Drawer enter (from right) | Translate-X | `standard` | `decelerate` |
| Drawer exit | Translate-X | `fast` | `accelerate` |
| Dropdown / popover | Fade + 4px translate-Y | `fast` | `decelerate` |
| Toast enter | Fade + 8px translate-Y | `standard` | `decelerate` |
| Toast exit | Fade | `fast` | `linear` |
| Tab switch underline | Translate-X | `standard` | `standard` |
| Accordion expand | Height + opacity | `standard` | `standard` |
| Skeleton shimmer | translateX(-100% → 100%) | 1500ms loop | `linear` |
| Button press | Scale (1 → 0.98 → 1) | `micro` | `sharp` |
| Passkey success | Check-mark stroke draw + fade | `deliberate` | `decelerate` |
| Hover (card lift) | Box-shadow swap | `fast` | `standard` |

---

### 12. Iconography Standards

### 12.1 Icon Library Choice

**Recommended:** [Lucide](https://lucide.dev/) (the maintained Feather fork). Rationale:

- Open source, MIT-licensed, no usage restrictions.
- ~1,500 icons covering every common need; an active community.
- Consistent visual rhythm — 1.5px stroke, 24×24 viewbox.
- Tree-shakeable SVG output for the web; flutter-svg-compatible for Flutter SDK.

**Alternative considered:** [Phosphor Icons](https://phosphoricons.com/). Comparable quality; more visual variants (regular, thin, fill); larger total bundle. Lucide chosen for the smaller surface and stricter stroke consistency. Recorded as open decision OD-DS-01 if Marketing prefers the Phosphor aesthetic.

### 12.2 Icon Sizing Scale

| Token | Size | Use |
| --- | --- | --- |
| `icon.xs` | 12px | Inline with body-sm text |
| `icon.s` | 16px | Inline with body text; default in form controls |
| `icon.m` | 20px | Buttons (alongside text); table actions |
| `icon.l` | 24px | Standalone icon buttons; navigation icons |
| `icon.xl` | 32px | Status pages, illustrations |
| `icon.2xl` | 48px | Empty states, marketing |
| `icon.3xl` | 64px | Hero illustrations |

Stroke widths are not part of the size token — Lucide ships with a 1.5px stroke at 24×24 native, and the SVGs scale crisply at the sizes listed.

### 12.3 Custom Qeet ID Icons

Some Qeet ID-specific concepts have no equivalent in Lucide. These are custom-drawn in the system's visual style (1.5px stroke, 24×24 viewbox, rounded corners, neutral fill behaviour):

| Icon | Use |
| --- | --- |
| `icon.passkey` | Passkey button (P-02); MFA settings |
| `icon.mfa-shield` | MFA configuration screen; security badge |
| `icon.saml-connector` | SAML connection cards |
| `icon.scim-sync` | SCIM configuration; sync status |
| `icon.oidc-connector` | OIDC connection cards |
| `icon.webhook` | Webhook subscriptions |
| `icon.api-key` | API key management |
| `icon.audit-log` | Audit log viewer |
| `icon.tenant` | Tenant switcher |
| `icon.cross-device` | Cross-device passkey QR flow |

Custom icons live in the design system repo and are versioned alongside the token file.

### 12.4 Brand-Asset Icons

Logos for external services Qeet ID integrates with (Google, GitHub, Microsoft, Apple, Entra, Okta, etc.) are used per each provider's brand guidelines. Coloured marks (Google "G", Apple Apple) are used where the provider mandates colour; monochrome where allowed. These are not part of the icon scale — they live in a separate `brand-marks/` directory.

---

### 13. Z-Index Scale

| Token | Value | Use |
| --- | --- | --- |
| `z.base` | 0 | Default flow |
| `z.dropdown` | 1000 | Select / combobox menu |
| `z.sticky` | 1100 | Sticky table header / sticky nav |
| `z.fixed` | 1200 | Fixed elements (page nav) |
| `z.modal-backdrop` | 1300 | Modal scrim |
| `z.modal` | 1400 | Modal content |
| `z.drawer-backdrop` | 1500 | Drawer scrim |
| `z.drawer` | 1600 | Drawer content |
| `z.popover` | 1700 | Popover / tooltip |
| `z.toast` | 1800 | Toast notification |
| `z.command-palette` | 1900 | cmd+K palette (always on top) |
| `z.debug` | 9999 | Development overlay only |

A drawer opens **over** a modal because the use case (open a drawer to confirm a destructive action from inside a setup wizard) requires it. A toast appears over every functional layer because it is a notification; cmd+K appears over everything because it is the navigation primitive of last resort (P-01).

---

### 14. RTL Readiness

Although RTL ships in v1.2 (NFR IN-05), the token system is RTL-ready from Day 1. This is a deliberate cost-now-to-pay-less-later decision.

- **Spacing tokens are direction-neutral.** No `space.left`, no `space.right`. CSS logical properties (`margin-inline-start`, `padding-inline-end`) are the engineering standard.
- **Iconography includes mirror-aware metadata.** Icons with directional meaning (arrow-right, chevron-back) are tagged `mirror: true` so the renderer flips them in RTL. Non-directional icons are tagged `mirror: false`.
- **No fixed-direction shadows.** Shadows are vertically biased (`0 4px 8px ...`), not horizontally biased.

When v1.2 enables RTL, the design system ships an `lang.direction.rtl` flag in token consumption; the same components render correctly without per-locale forks.

---

### 15. Theme Customisation API (Token-Level)

This section summarises which Tier-2 tokens are exposed for white-label customisation. The component-level detail and the dashboard preview UX are in [Phase 3 Doc 8](Qeet ID%20%E2%80%94%20Embeddable%20Auth%20UI%20Components%20%28White-Label%29.md).

### 15.1 Customisable Semantic Tokens

| Token | Customisable | Constraint |
| --- | --- | --- |
| `color.action.primary` | Yes (and the derived `-hover`, `-active`) | Must meet 4.5:1 contrast with `color.text.on-brand`; auto-validated at save (P-06) |
| `color.action.passkey` | Yes (defaults to brand if not overridden) | Same contrast rule |
| `color.surface.brand-subtle` | Auto-derived from primary; not directly settable | Computed at brand-set time |
| `color.text.link` | Yes | Must meet 4.5:1 with `surface.canvas` and `surface.default` |
| `font.family.sans` | Yes — choose from an approved family list | Approved families have variable-axis support, broad unicode, generous x-height |
| `radius.brand-base` | Yes (range 2–12px) | Scales `radius.s..l` proportionally; `pill` / `circle` unchanged |
| Logo (light + dark variants) | Yes | SVG preferred; PNG accepted ≥256×256 |
| Background pattern / image (login page) | Yes (limited slot) | Subject to contrast validation against text colour |

### 15.2 Locked Semantic Tokens

| Token category | Locked because |
| --- | --- |
| Spacing scale | Layout integrity depends on rhythm consistency |
| Type scale ratios | Hierarchy depends on consistent ratio |
| Motion durations and easings | Accessibility (reduced-motion) and consistency |
| Z-index ordering | Functional correctness |
| Contrast-critical defaults | Cannot be overridden below AA |
| Iconography stroke / size scale | Visual cohesion |

### 15.3 Validation at Save Time

The Branding admin screen runs three validations when a tenant saves a brand colour:

1. **Contrast.** `action.primary` vs `text.on-brand` is computed; if < 4.5:1, the form blocks save with: *"Primary colour and text colour contrast is 3.8:1. WCAG AA requires at least 4.5:1 for button labels. Pick a darker primary colour or accept the default white text."* (P-06; Phase 3 Doc 8 §10).
2. **Visibility.** `action.primary` vs `surface.canvas` is computed; if < 3:1, the form warns: *"Your primary colour is hard to see against the page background. Buttons may be hard to spot."*
3. **Brand integrity.** A primary that is dangerously close to the danger palette triggers a soft warning: *"This primary colour resembles the platform's error colour. Users may misread errors as primary actions."*

---

### 16. Token Naming Convention

The pattern is:

```
   {tier}.{category}.{sub-category?}.{role?}.{state?}
```

Examples:

```
   color.text.primary
   color.text.danger
   color.surface.elevated
   color.action.primary
   color.action.primary-hover
   color.border.focused
   space.gutter
   font.family.sans
   font.size.body-lg
   font.weight.semibold
   radius.m
   shadow.modal
   duration.standard
   easing.decelerate
   icon.l
   z.modal
```

Rules:

- Lowercase, hyphen-separated within a segment, dot-separated between segments.
- States are appended as `-hover`, `-active`, `-disabled`, `-focused` rather than nested deeper.
- Semantic tokens never embed primitive values in their name (no `color.action.blue-600`).

---

### 17. Token Export Formats

Tokens are authored in a single source file (`design-tokens/qeetify.tokens.json`, [W3C Design Tokens Format](https://design-tokens.github.io/community-group/format/) compliant) and exported to four downstream formats.

| Format | Consumer | Build step |
| --- | --- | --- |
| Figma variables | Figma library (`qeetify-tokens` shared library) | `tokens-studio` plugin or `style-dictionary` Figma exporter |
| CSS custom properties | Web frontend, embedded widgets, hosted login pages | `style-dictionary` web exporter |
| JSON | Flutter SDK (via code-gen), email-template renderer, marketing site | `style-dictionary` json exporter |
| Markdown reference | This document; documentation site | `style-dictionary` markdown exporter; pulled into docs nightly |

The `style-dictionary` config lives in the design-system repo. CI verifies that every token in the source file has a corresponding output in all four formats, that contrast verification (§5.6) passes, and that no semantic token references a primitive that does not exist.

### 17.1 CSS Custom Property Naming

Lowercase, hyphen-separated, prefixed `--qf-`:

```
   --qf-color-text-primary: ...
   --qf-color-action-primary: ...
   --qf-space-gutter: ...
   --qf-font-size-body: ...
   --qf-radius-m: ...
```

The prefix prevents collision with consumer-provided CSS variables.

### 17.2 Flutter Token Generation

Tokens are code-generated as `QfTokens` Dart constants:

```dart
class QfColors {
  static const textPrimary = Color(0xFF111827);
  static const actionPrimary = Color(0xFF2563EB);
  // ...
}
```

The Flutter SDK consumes these directly (Phase 3 Doc 10 §9).

### 17.3 Versioning & Distribution

| Channel | How |
| --- | --- |
| Figma | Published as a shared library; designers receive update notifications |
| Web | Published as an npm package `@qeetify/design-tokens` |
| Flutter | Published as a pub.dev package `qeetify_design_tokens` |
| Docs | Auto-published nightly to the documentation site |

Semantic versioning; breaking changes carry a migration note.

---

### 18. Open Design Decisions From This Document

| # | Question | Owner | Target |
| --- | --- | --- | --- |
| OD-DS-01 | Final icon library — Lucide vs Phosphor | UX Designer + Marketing | Phase 3 Week 2 |
| OD-DS-02 | Font family ratification (Inter + JetBrains Mono recommended) — Marketing licence review | UX Designer + Marketing + Legal | Phase 3 Week 2 |
| OD-DS-03 | Brand colour palette (depends on OD-UX-02) | UX Designer + Marketing | Phase 3 Week 1 |
| OD-DS-04 | Whether chart palette should ship at MVP or v1.1 (Analytics is MVP per Feature Prio; charts must exist) | UX Designer | Phase 3 Week 2 |
| OD-DS-05 | White-label radius range — 2–12px vs wider 0–16px (impact on layout integrity) | UX Designer + Frontend Lead | Phase 3 Week 3 |

---

### 19. Cross-References

- Principles tokens must serve: [UX Research Summary & Design Principles](Qeet ID%20%E2%80%94%20UX%20Research%20Summary%20%26%20Design%20Principles.md) §6
- Components consuming these tokens: [Component Library Specification](Qeet ID%20%E2%80%94%20Component%20Library%20Specification.md)
- White-label customisation surface: [Embeddable Auth UI Components (White-Label)](Qeet ID%20%E2%80%94%20Embeddable%20Auth%20UI%20Components%20%28White-Label%29.md) §4, §5
- Accessibility verification process: [Accessibility Compliance Plan (WCAG 2.1 AA)](Qeet ID%20%E2%80%94%20Accessibility%20Compliance%20Plan%20%28WCAG%202.1%20AA%29.md) §8
- Mobile breakpoints, touch targets: [Mobile & Responsive Design Specification](Qeet ID%20%E2%80%94%20Mobile%20%26%20Responsive%20Design%20Specification.md) §3
- i18n constraints on type and layout: [Internationalization & Localization Design](Qeet ID%20%E2%80%94%20Internationalization%20%26%20Localization%20Design.md) §4, §5
- NFR accessibility scope: [Phase 1 NFR §12.2 / IN-01..IN-08](../phase-1/Qeet%20ID%20%E2%80%94%20Non-Functional%20Requirements%20%28NFR%29.md)
- Cross-platform SDK token consumers: [Phase 2 Microservices §4.19](../phase-2/Qeet%20ID%20%E2%80%94%20Microservices%20Decomposition%20%26%20Service%20Boundaries.md) (Hosted Login Pages)

---

### 20. Approvals & Sign-off

| Role | Name | Signature | Date |
| --- | --- | --- | --- |
| UX Designer |  |  |  |
| Product Designer |  |  |  |
| Frontend Engineering Lead |  |  |  |
| Mobile (Flutter) SDK Lead |  |  |  |
| Email Template Designer |  |  |  |
| Marketing Lead (brand palette / type) |  |  |  |
| Accessibility Lead (QA) |  |  |  |
| Solution Architect (cross-phase consistency) |  |  |  |

---

*This document is version controlled. Visual updates in Figma do not require re-sign-off; changes to the token architecture (§4), the type scale (§6.2), the spacing scale (§7.2), the elevation scale (§10), the motion principles (§11.1), or the accessibility-critical contrast tokens (§5.4, §5.6) require UX Designer + Frontend Lead + Accessibility Lead review.*

---

**Qeet ID — Authenticate Everything.** *A Qeet Group Company*
