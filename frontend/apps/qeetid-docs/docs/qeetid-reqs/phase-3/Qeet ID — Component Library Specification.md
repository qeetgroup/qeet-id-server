# Qeet ID — Component Library Specification

### 1. Document Information

|  |  |
| --- | --- |
| **Document Name** | Component Library Specification |
| **Project Name** | Qeet ID |
| **Parent Company** | Qeet Group |
| **Subsidiary** | Qeet ID (Standalone) |
| **Document Version** | v1.0 |
| **Prepared By** | UX Designer + Frontend Lead |
| **Date** | May 19, 2026 |
| **Status** | Draft — Pending Stakeholder Sign-off |

---

### 2. Purpose & Scope

This document is the catalogue and contract for every reusable UI component in Qeet ID. It defines what each component is for, how it is composed, what variants and states it supports, its props/API surface, its accessibility behaviour, and its allowed and forbidden usage patterns. Components consume tokens from [Design System Foundations & Tokens](Qeet ID%20%E2%80%94%20Design%20System%20Foundations%20%26%20Tokens.md); screens consume components.

The contract here is binding on both designers (Figma libraries published from these specs) and engineers (React, Flutter, and HTML/CSS implementations of these specs). When Figma and code diverge, this document is the tie-breaker. When this document changes, both Figma and code follow.

The audience is the UX Designer, Product Designer, Frontend Engineering Lead, Mobile (Flutter) SDK Lead, Accessibility Lead, and the QA Lead (for visual-regression and accessibility tests).

This document depends on [UX Research Summary & Design Principles](Qeet ID%20%E2%80%94%20UX%20Research%20Summary%20%26%20Design%20Principles.md) for the principles and [Design System Foundations & Tokens](Qeet ID%20%E2%80%94%20Design%20System%20Foundations%20%26%20Tokens.md) for the token vocabulary. Every component documented here is referenced by name from later Phase 3 documents (5, 6, 7, 8, 10).

---

### 3. Component Library Architecture

### 3.1 Atomic Hierarchy

Components are organised in four tiers, derived from atomic-design conventions but pragmatically scoped:

| Tier | Definition | Examples |
| --- | --- | --- |
| **Atoms** | Smallest functional UI primitives. Cannot be decomposed without losing meaning. | Button, Input, Checkbox, Avatar, Badge, Spinner |
| **Molecules** | Atoms composed for a single purpose. Reused across many screens. | Form Field, Search Input, Code Block, OTP Input, Passkey Button |
| **Organisms** | Molecules composed into self-contained units that own state and behaviour. | Data Table, Audit Log Row, Modal, Toast, Form, Stepper |
| **Templates** | Layout scaffolds — slots for content, navigation, action surfaces. | Auth Layout, Dashboard Layout, Documentation Layout |

Components reference only their direct atomic tier or below. An organism may import atoms and molecules; a molecule does not import an organism. This is enforced in the design library structure and the codebase lint.

### 3.2 Documentation Standard

Every component in §4–§7 is documented with the same eight-section template:

```
   ## Component Name
   1. Purpose
   2. Anatomy
   3. Variants
   4. States
   5. Props / API
   6. Accessibility
   7. Do's & Don'ts
   8. Usage Examples
   (Implementation Notes for Frontend) — optional engineering callouts
```

For concision below, the **Anatomy** sections use ASCII sketches; the **Props** sections use TypeScript-style signatures (translatable to Flutter constructor params); the **Accessibility** sections enumerate ARIA roles, keyboard interactions, focus management, and announcements.

### 3.3 Component Versioning

The component library is published as `@qeetify/ui` (React) and `qeetify_ui` (Flutter pub package). Semantic versioning. Breaking changes (renaming a prop, removing a variant, changing the default behaviour) increment the major version; new variants or props increment the minor. A breaking change requires a migration note and a 12-month deprecation window — consistent with [Phase 2 API Design Standards §13](../phase-2/Qeet%20ID%20%E2%80%94%20API%20Design%20Standards.md) for symmetry across the SDK and the UI library.

### 3.4 Cross-Platform Parity

Components have three implementations: **React** (the primary web library), **Flutter** (the mobile SDK), and **HTML/CSS** (for the hosted login pages and email templates where a JS framework is overkill). Where a platform cannot honour a behaviour (e.g., Flutter has no native popovers in the same DOM sense), the deviation is documented in the component's Implementation Notes section.

### 3.5 Universal State Patterns

Every interactive component supports the following state set unless explicitly noted:

- **default / rest** — idle
- **hover** — pointer over (desktop only)
- **focus** — keyboard focus
- **active / pressed** — being interacted with
- **disabled** — non-interactive (with explanation per AP-04)
- **loading** — async work in progress
- **error** — invalid state, scoped to the component

And every list-shaped or data-loading component supports four universal display states:

- **default** — populated normal
- **empty** — no rows; shows the empty state with primary action (§7)
- **loading** — skeleton placeholder
- **error** — recoverable error state with retry

---

### 4. Atoms

### 4.1 Button

**Purpose.** Trigger an action. The primary interactive primitive in every Qeet ID surface.

**Anatomy:**

```
   ┌───────────────────────────────────────────┐
   │  [Icon-l]  Label                  [Icon-r] │
   └───────────────────────────────────────────┘
       └ optional   └ required   └ optional
```

**Variants:**

| Variant | Visual recipe | When to use |
| --- | --- | --- |
| `primary` | Filled, `action.primary` background, `text.on-brand` label | Primary CTA per screen (one only per surface region) |
| `secondary` | Outlined, `surface.default` bg, `border.default`, `text.primary` label | Secondary actions |
| `ghost` | Transparent bg, hover surface `action.ghost-hover`, `text.primary` label | Tertiary actions in toolbars / table rows |
| `danger` | Filled, `action.danger` bg, `text.on-brand` label | Destructive actions (delete, revoke) |
| `danger-ghost` | Ghost with `text.danger` label | Destructive actions in row toolbars |
| `link` | No background; `text.link` colour; underline on hover | Inline navigational button (rare; usually use Link instead) |

**Sizes:**

| Size | Height | Padding-X | Font | Icon size |
| --- | --- | --- | --- | --- |
| `sm` | 28px | `space.s` (8px) | `text.body-sm` | `icon.s` |
| `md` (default) | 36px | `space.l` (16px) | `text.body` | `icon.s` |
| `lg` | 44px | `space.l` (16px) | `text.body-lg` | `icon.m` |
| `xl` | 52px | `space.xl` (24px) | `text.body-lg` | `icon.m` |

`xl` is reserved for primary CTA on auth screens and marketing surfaces — never in the admin dashboard.

**States:**

`rest`, `hover`, `focus`, `active`, `loading` (spinner replaces left icon; label dims; button remains the same width), `disabled` (with tooltip explaining why), `aria-pressed=true` (toggle variant only).

**Props (React):**

```ts
type ButtonProps = {
  variant?: 'primary' | 'secondary' | 'ghost' | 'danger' | 'danger-ghost' | 'link';
  size?: 'sm' | 'md' | 'lg' | 'xl';
  fullWidth?: boolean;
  iconStart?: ReactNode;
  iconEnd?: ReactNode;
  loading?: boolean;
  loadingText?: string;          // announced to screen readers during loading
  disabled?: boolean;
  disabledReason?: string;       // surfaced as tooltip; required when disabled=true
  onClick?: (e: MouseEvent) => void;
  type?: 'button' | 'submit' | 'reset';
  asChild?: boolean;             // render-as-child pattern; merges props into wrapped element
  // Standard HTML attributes accepted via spread
};
```

**Accessibility:**
- Role: `button` (native `<button>`; if `asChild`-wrapped around an `<a>`, role becomes `link`).
- Keyboard: Enter and Space activate.
- Focus visible: `border.focused` ring outside the visual border.
- Disabled buttons remain in the focus order (set `aria-disabled=true` rather than HTML `disabled`) so screen-reader users can discover them and read the disabled reason.
- Loading state: `aria-busy=true`; `loadingText` announced via the live region.

**Do's & Don'ts:**
- ✅ One `primary` per content region.
- ✅ Use `danger` for destructive actions; the label spells out the consequence ("Delete user").
- ❌ Don't substitute colour for label. *"Save"* / *"Delete"* — never coloured icon alone.
- ❌ Don't hide critical actions inside icon-only `ghost` buttons in dense rows without a tooltip.

**Usage examples:**

```jsx
<Button variant="primary" iconStart={<PasskeyIcon />} onClick={handlePasskey}>
  Continue with a passkey
</Button>

<Button variant="danger" onClick={confirmDelete} loadingText="Deleting…" loading={isDeleting}>
  Delete user
</Button>

<Button variant="ghost" iconStart={<SettingsIcon />} size="sm">
  Settings
</Button>
```

---

### 4.2 Input

**Purpose.** Single-line text entry. Almost every form has at least one.

**Anatomy:**

```
   ┌───────────────────────────────────────────────┐
   │  [icon]  alice@example.com         [suffix-x] │
   └───────────────────────────────────────────────┘
       │       └ value (placeholder when empty)       │
       └ optional prefix icon                          └ optional suffix
```

**Variants by `type`:** `text` (default), `email`, `password` (with show/hide toggle suffix), `number`, `tel`, `url`, `search`.

**Sizes:** `sm` (28px), `md` (36px, default), `lg` (44px). Touch-friendly inputs on mobile are `lg` (44×44pt touch target per P-03 and WCAG 2.5.5).

**States:** `rest`, `focus`, `error`, `disabled`, `readOnly`.

**Props:**

```ts
type InputProps = {
  type?: 'text' | 'email' | 'password' | 'number' | 'tel' | 'url' | 'search';
  size?: 'sm' | 'md' | 'lg';
  value?: string;
  defaultValue?: string;
  placeholder?: string;
  iconStart?: ReactNode;
  suffix?: ReactNode | 'clear' | 'password-toggle' | 'counter';
  invalid?: boolean;
  disabled?: boolean;
  readOnly?: boolean;
  autoComplete?: string;       // mandatory on auth inputs — see §4.2.1
  maxLength?: number;
  onChange?: (e: ChangeEvent<HTMLInputElement>) => void;
  onBlur?: (e: FocusEvent) => void;
  // Pass-through HTML attributes
};
```

**Accessibility:**
- Always paired with a Label via `Form Field` (§5.1) — naked Input usage is rejected in review.
- `aria-invalid=true` when `invalid=true`.
- Helper / error text linked via `aria-describedby` (managed by `Form Field`).
- Password fields use `aria-describedby` to announce password requirements via screen reader without spoken-aloud password chars.
- Native validation messages suppressed; designed error messages used instead.

#### 4.2.1 autoComplete Hints (Mandatory)

Auth-related inputs **must** specify `autoComplete` to enable browser autofill and passkey conditional UI. This is not a recommendation; it is the difference between conditional UI working and not working (Principle [P-02](Qeet ID%20%E2%80%94%20UX%20Research%20Summary%20%26%20Design%20Principles.md)).

| Field | `autoComplete` value | Rationale |
| --- | --- | --- |
| Email at login | `username webauthn` | Triggers conditional UI passkey suggestion |
| Email at signup | `username` | Browser remembers new identity |
| New password | `new-password` | Triggers password manager save prompt |
| Existing password | `current-password` | Triggers password manager fill |
| OTP code | `one-time-code` | iOS / Android auto-paste from SMS |
| Phone number | `tel` |  |
| Given name | `given-name` |  |
| Family name | `family-name` |  |

**Do's & Don'ts:**
- ✅ Use native `<input type="email">` / `type="tel">` so mobile keyboards adapt.
- ❌ Don't disable autofill (`autoComplete="off"`) on auth fields — breaks passkey UI.

---

### 4.3 Label, Helper Text, Error Text

**Purpose.** The three text atoms that accompany every form input. Provided as standalone atoms (rare direct use) and as composed parts of `Form Field` (§5.1).

**Label:**
- Type: `text.body` (default) or `text.body-sm` (dense forms).
- Weight: 500.
- Always associated programmatically with the input it labels (`htmlFor` / `<label for>`).
- Required indicator: an `*` icon **plus** the word "Required" in helper text (never the asterisk alone — AP-15 / NFR AX-06).

**Helper Text:**
- Type: `text.caption`.
- Colour: `text.tertiary`.
- Optional. Used for inline guidance ("8 characters minimum", "We never share your email").

**Error Text:**
- Type: `text.caption`.
- Colour: `text.danger`.
- Icon prefix: `icon.s` warning icon (icon + colour together — AP-15).
- Tone follows P-08 / §7 of Document 1: "Could not verify the code. Try again or request a new one."

**Accessibility:**
- Error text gets `aria-live="polite"` so its appearance is announced.
- Label and error text both linked to the input via `aria-labelledby` and `aria-describedby`.

---

### 4.4 Checkbox

**Purpose.** Single boolean choice from a list of independent options.

**Anatomy:**
```
   [✓] Send me product update emails
   [ ] Send me marketing emails
   [-] (indeterminate — used in "select all" parent rows)
```

**Variants:** standard (single), grouped (presented as a labeled fieldset).

**States:** `unchecked`, `checked`, `indeterminate`, `disabled`, `focus`, `error` (in form validation context).

**Props:**

```ts
type CheckboxProps = {
  checked?: boolean;
  defaultChecked?: boolean;
  indeterminate?: boolean;
  disabled?: boolean;
  invalid?: boolean;
  onChange?: (checked: boolean) => void;
  label: ReactNode;
  helperText?: ReactNode;
};
```

**Accessibility:**
- Native `<input type="checkbox">` underlying.
- `aria-checked="mixed"` for indeterminate.
- Keyboard: Space toggles.
- Touch target: ≥44×44pt including padding (P-03).

---

### 4.5 Radio

**Purpose.** Single choice from a small mutually exclusive set (2–5 options).

**Notes:**
- Always in a `RadioGroup` with a fieldset legend.
- Default to a vertical stack; horizontal only when space is constrained and labels are short.
- For ≥6 options, switch to a Select (§4.8).

**Accessibility:** arrow keys move between options (native browser behaviour); Tab moves to the group, then arrows within.

---

### 4.6 Toggle / Switch

**Purpose.** Immediate on/off state for a setting. Distinct from Checkbox — a Toggle is for **state**, a Checkbox is for **choice**.

**Anatomy:**
```
   ┌─────────┐       ┌─────────┐
   │ ●       │  off  │       ● │  on
   └─────────┘       └─────────┘
```

**When to use Toggle vs Checkbox:**

| Use case | Component |
| --- | --- |
| "Enable SCIM provisioning" — applies immediately | Toggle |
| "Send me product update emails" — applies on form submit | Checkbox |
| "Use passkeys by default" — applies immediately | Toggle |
| "I agree to the Terms of Service" — required for submit | Checkbox |

**Accessibility:**
- Role `switch`; `aria-checked`.
- Keyboard: Space and Enter toggle.
- The visible label states **what is being toggled** ("SCIM provisioning"), not the state ("On / Off"). Screen readers receive both via the live announcement.

---

### 4.7 Select (Single, With Search)

**Purpose.** Choose one value from a list. With search enabled when the list exceeds ~10 items.

**Anatomy:**

```
   ┌───────────────────────────────────────────┐
   │  Selected value                         ▾ │
   └───────────────────────────────────────────┘
   ┌───────────────────────────────────────────┐
   │  🔍  Filter…                              │
   ├───────────────────────────────────────────┤
   │   Option 1                                │
   │   Option 2  (highlighted by keyboard)     │
   │   Option 3                                │
   │   Option 4                                │
   │  …                                         │
   └───────────────────────────────────────────┘
```

**Behaviour:**
- Native `<select>` is **not** used; an accessible custom listbox is implemented (because we need consistent styling, search, multi-line items with secondary text, and keyboard control beyond the native widget).
- The implementation follows the [WAI-ARIA Combobox pattern](https://www.w3.org/WAI/ARIA/apg/patterns/combobox/).

**Props:**

```ts
type SelectProps<T> = {
  options: Array<{ value: T; label: string; description?: string; disabled?: boolean }>;
  value?: T;
  defaultValue?: T;
  placeholder?: string;
  searchable?: boolean;
  disabled?: boolean;
  invalid?: boolean;
  onChange?: (value: T) => void;
  size?: 'sm' | 'md' | 'lg';
};
```

**Accessibility:**
- `role="combobox"` on the trigger, `aria-expanded`, `aria-controls`.
- `role="listbox"` on the panel; `role="option"` on each item.
- Keyboard: ArrowDown opens; Up/Down moves; Enter selects; Esc closes; typing filters (when searchable).
- Selected item announced via `aria-selected`.

---

### 4.8 Combobox (Multi-Select With Search)

**Purpose.** Select multiple values from a list, with search.

**Anatomy:** the Select trigger area shows chips for each selected value with X to remove. The dropdown panel is the same listbox, with checkbox-styled options.

**Notes:**
- Tab moves focus *to* the combobox; subsequent Tab moves out (does not get stuck inside chips).
- Backspace on empty input removes the last chip.
- The "Select all" affordance appears when the panel has more than 10 results.

---

### 4.9 Textarea

**Purpose.** Multi-line text entry.

**Behaviour:**
- Auto-resize on input up to `maxRows` (default 6).
- Manual resize handle disabled by default (CSS `resize: none`); enabled for code-snippet inputs.
- Same accessibility model as Input.

---

### 4.10 Avatar (Single, Group, With Status Indicator)

**Purpose.** Visually represent a user, organisation, or team member.

**Variants:**

| Variant | Use |
| --- | --- |
| `image` | Profile picture URL |
| `initials` | First letter of first + last name (or first two letters of single-word name); colour deterministically derived from name hash |
| `icon` | Default avatar (`icon.user` glyph) when no image / name |
| `group` | Stacked avatars (≤3 visible, +N indicator) |

**Sizes:** `xs` (16px), `sm` (24px), `md` (32px, default), `lg` (40px), `xl` (64px).

**Status indicator:** small coloured dot, bottom-right, using `color.status.*` tokens.

**Accessibility:**
- Decorative when adjacent to the name (e.g., in a user row); `aria-hidden=true`.
- When standalone, `alt` attribute carries the user's name.
- The status dot has its own `aria-label` ("Active", "Idle", "Offline").

---

### 4.11 Badge / Tag / Chip

Three closely related atoms with distinct semantic uses:

| Component | Purpose | Visual |
| --- | --- | --- |
| **Badge** | Status / category marker. Read-only. | Small pill, `surface.{tone}-subtle` bg + `text.{tone}` text |
| **Tag** | Categorisation. Read-only or removable. Used in lists, filters. | `radius.s` pill, `surface.subtle` bg, optional × button |
| **Chip** | Interactive multi-select chip (in a Combobox or filter bar). | Like Tag but with hover, active, and pressed states; always has × |

Badges support tones: `default`, `success`, `warning`, `danger`, `info`, `brand`, `accent`, `passkey`.

---

### 4.12 Tooltip

**Purpose.** Contextual hint or definition that appears on hover/focus.

**Behaviour:**
- Open delay 600ms on hover (per Material 3 / Carbon convention); instant on focus.
- Closes on mouse-out + 200ms, or on Escape.
- Positioned with collision detection (flips when there's no room).

**Accessibility:**
- Element with the tooltip uses `aria-describedby` pointing to the tooltip's id.
- Tooltips are **not** a substitute for visible labels. Icon-only buttons get tooltips in addition to `aria-label`.

**Forbidden:** tooltips for critical information (P-08 / AP-08). Tooltips disappear; critical info must remain visible.

---

### 4.13 Spinner / Loader

**Purpose.** Indeterminate-progress indicator.

**Behaviour:**
- A small rotating arc, 16px / 20px / 24px / 32px sizes.
- Uses `easing.linear`, 1000ms infinite rotation.
- Honours reduced motion: when `prefers-reduced-motion: reduce`, the spinner replaces rotation with a pulse opacity animation.

**Use sparingly.** Skeleton screens (§4.14, §6.13) are preferred for first-render data load (P-09).

---

### 4.14 Progress (Linear, Circular)

**Linear progress:**
- Determinate (with value 0–100) or indeterminate.
- Used for file upload, multi-step wizards (Stepper consumes a Linear Progress under the hood), bulk operations.
- Height 4px (default), 8px (large).

**Circular progress:**
- Used for compact contexts (avatar uploads, inline statuses).
- 16px / 24px / 32px.

**Accessibility:**
- `role="progressbar"`, `aria-valuemin`, `aria-valuemax`, `aria-valuenow` when determinate.
- `aria-busy=true` on the parent container while indeterminate.

---

### 4.15 Divider

**Purpose.** Visual separation between content sections.

**Variants:** `horizontal`, `vertical`. Optional inline label (centred, surrounded by lines).

**Use sparingly.** Whitespace is often preferable. Dividers are appropriate to separate logical sections within a card or panel.

---

### 4.16 Icon Wrapper

**Purpose.** A consistent slot for any icon in the system, with size and colour tokens applied.

**Behaviour:**
- Renders the icon at the chosen size token (`icon.xs..3xl`).
- Sets `aria-hidden=true` by default (decorative); accepts `aria-label` and sets `role="img"` when meaningful on its own.
- Colour inherits via `currentColor` unless `tone` prop is set.

---

### 5. Molecules

### 5.1 Form Field

**Purpose.** The canonical composition of Label + Input + Helper + Error. Almost every form input on Qeet ID uses this molecule.

**Anatomy:**

```
   Email address                                         *Required
   ─────────────────────────────
   ┌─────────────────────────────────────────────┐
   │   alice@example.com                          │
   └─────────────────────────────────────────────┘
   We'll send a verification link to this address.
   (or)
   ⚠  Email address is required.
```

**Composition:**
- Label (top-left, `text.body`, weight 500).
- Required indicator (top-right, "*Required" — icon + word, never icon alone).
- Input (any of the form atoms — Input, Select, Textarea, OTP Input).
- Helper text (caption, below input, `text.tertiary`).
- Error text (caption, below input, `text.danger`, replaces helper when present, `aria-live=polite`).

**Props:**

```ts
type FormFieldProps = {
  label: ReactNode;
  id?: string;                  // auto-generated if absent
  required?: boolean;
  helperText?: ReactNode;
  errorText?: ReactNode;
  hint?: ReactNode;             // alternative to helper — gets aria-describedby
  children: ReactElement;       // the input control
};
```

**Accessibility:**
- `htmlFor` / `id` automatically wired.
- `aria-describedby` automatically linked to helper / error text.
- `aria-invalid` set when `errorText` is present.

---

### 5.2 Search Input

**Purpose.** A specialised Input optimised for search.

**Anatomy:**

```
   ┌──────────────────────────────────────────────┐
   │  🔍  Search users…                  ⌘K  [×]  │
   └──────────────────────────────────────────────┘
```

**Behaviour:**
- Leading search icon.
- Trailing clear button when value is non-empty.
- Optional keyboard-shortcut hint (`⌘K` or `/`).
- Debounce: 300ms by default for server-side search.

**Used by:** every Data Table search slot; global Command Palette (cmd+K); docs search.

---

### 5.3 Code Block

**Purpose.** Display non-editable code with syntax highlighting, copy button, and optional language label.

**Anatomy:**

```
   ┌─────────────────────────────────────────────────────────┐
   │  bash                                            [Copy] │
   ├─────────────────────────────────────────────────────────┤
   │                                                          │
   │  npm install @qeetify/react                              │
   │                                                          │
   └─────────────────────────────────────────────────────────┘
```

**Behaviour:**
- Background: `color.surface.code`.
- Syntax-highlighted via Prism or Shiki (open decision OD-CL-01).
- "Copy" button copies to clipboard; provides a 2s toast confirmation.
- Long lines wrap by default; horizontal scroll disabled (so on mobile the user reads the whole snippet).
- Optional line numbers (off by default).

**Accessibility:**
- `role="region"` with an `aria-label` ("Code: bash").
- Copy button has `aria-label="Copy code to clipboard"`.
- Copied confirmation is announced via the live region.

---

### 5.4 Code Tab Group

**Purpose.** Display the **same** code sample across multiple languages. Used everywhere in the developer portal.

**Anatomy:**

```
   ┌────────────┬───────┬───────┬───────┬─────────┬─────┐
   │  React*    │ Next  │ Node  │ Python│ Flutter │ Go  │
   ├────────────┴───────┴───────┴───────┴─────────┴─────┤
   │                                          [Copy]    │
   │  import { useQeetify } from '@qeetify/react';      │
   │  …                                                  │
   └─────────────────────────────────────────────────────┘
```

**Behaviour:**
- The selected language persists across the page (via URL hash) and across the docs site (via local storage). Arjun reads two docs pages in Node, picks Python on the third — the rest of the site remembers Python.
- The tab order matches the persona-prioritised order: React → Next.js → Node.js → Python → Flutter → Go ([Persona Arjun](../phase-1/Qeet%20ID%20%E2%80%94%20Persona%20Documents%20%26%20Customer%20Journey%20Map.md); Charter §5).
- Auto-selects a sensible default based on browser detection (defaults to React).

**Accessibility:**
- Uses ARIA Tabs pattern: `role="tablist"`, `role="tab"`, `role="tabpanel"`, `aria-selected`, arrow-key navigation.
- Copy button copies the *currently selected* tab's content.

---

### 5.5 Stat Card

**Purpose.** Display a number, a label, and an optional trend indicator.

**Anatomy:**

```
   ┌────────────────────────────┐
   │  Monthly Active Users      │
   │                            │
   │  12,481                    │
   │                            │
   │  ▲ 8.3%  vs last month     │
   └────────────────────────────┘
```

**Variants:** standard, comparison (with delta), sparkline (with mini-chart).

---

### 5.6 Menu / Dropdown

**Purpose.** A list of actions or navigation options anchored to a trigger.

**Behaviour:**
- Opens on click (not hover) — hover-only menus are forbidden (P-03 mobile parity).
- Closes on item click, outside click, Escape.
- Supports section headers, dividers, disabled items, items with leading icons, destructive items (in red).
- Submenus open on right-arrow; close on left-arrow.

**Accessibility:** WAI-ARIA Menu pattern.

---

### 5.7 Date Picker / Date Range Picker

**Purpose.** Select a single date or a date range.

**Behaviour:**
- Calendar grid overlay; keyboard navigation (arrow keys move days, PgUp/PgDn move months).
- Locale-aware first-day-of-week and date format (Phase 3 Doc 11).
- Date Range Picker has presets ("Last 7 days", "Last 30 days", "Last 90 days", "This month", "Custom").

**Used by:** Audit Log filters (Sandra's primary task — Doc 6); analytics filters; report exports.

---

### 5.8 File Upload

**Purpose.** Single or multiple file upload with drag-drop and click-to-browse.

**Anatomy:**

```
   ┌─────────────────────────────────────────────────────┐
   │                                                     │
   │             ⤴   Drop a file or browse               │
   │                                                     │
   │             SVG, PNG up to 5 MB                     │
   │                                                     │
   └─────────────────────────────────────────────────────┘

   After upload:
   ┌─────────────────────────────────────────────────────┐
   │  logo.svg  (12 KB)                          [×]     │
   │  ████████████████████████████████  100%             │
   └─────────────────────────────────────────────────────┘
```

**Used by:** Branding logo upload; bulk user import CSV; SAML metadata import.

**Accessibility:** native `<input type="file">` underlying the styled drop zone; keyboard activation opens the file picker.

---

### 5.9 OTP Input

**Purpose.** Six-digit one-time-code entry, used in MFA challenges and email/SMS OTP login.

**Anatomy:**

```
   ┌───┐ ┌───┐ ┌───┐ ┌───┐ ┌───┐ ┌───┐
   │ 4 │ │ 2 │ │ 7 │ │   │ │   │ │   │
   └───┘ └───┘ └───┘ └───┘ └───┘ └───┘
                       ↑ focus
   Didn't get it? Resend in 23s.
```

**Behaviour:**
- Auto-advance to next digit on input.
- Backspace moves to previous digit (and clears).
- Arrow keys move focus between digits.
- **Paste anywhere** — pasting a 6-digit code anywhere in the group distributes the digits.
- Numeric keyboard on mobile (`inputmode="numeric"`).
- `autoComplete="one-time-code"` on each cell — iOS / Android auto-fill from SMS works.
- Auto-submits when all six digits entered (optional; controllable).

**Accessibility:**
- Single logical input rendered as six boxes for visual clarity; for screen readers, the six boxes are grouped under one programmatic input (assistive tech sees a single field with the entire code).
- "Code entered, verifying…" is announced via live region on auto-submit.
- Resend countdown visible AND announced when complete ("Resend code is now available").

**Implementation Notes:** the six-box visual + one logical input requires a non-trivial implementation. Reference: Adam Argyle's OTP component pattern.

---

### 5.10 Passkey Button

**Purpose.** The specialised primary CTA on every login surface. Per Principle [P-02](Qeet ID%20%E2%80%94%20UX%20Research%20Summary%20%26%20Design%20Principles.md), passkeys are not a feature toggle — they are the default credential.

**Anatomy:**

```
   ┌─────────────────────────────────────────────┐
   │   [🔑 passkey icon]   Continue with a passkey │
   └─────────────────────────────────────────────┘
```

**Behaviour:**
- Primary `xl` button (52px tall on auth pages).
- Icon: `icon.passkey` (custom, drawn in design-system style).
- Background: `color.action.passkey` (the custom passkey-tinted token; defaults to `color.action.primary` if a tenant hasn't overridden).
- Two click behaviours:
  - **Conditional UI active** (browser supports `mediation: conditional` and there's a passkey for this origin): user focuses the email field, browser shows native passkey suggestion. The Passkey Button on this page is then a **fallback** for users without a registered passkey — wording shifts to "Continue with a passkey" (still primary).
  - **Conditional UI unavailable** or explicit-click: clicking the button calls `navigator.credentials.get()` with `mediation: optional`, presenting the platform's UI.

**Accessibility:** as Button; additionally, when `navigator.credentials.get()` is unsupported by the browser, the button is hidden and a helper text appears: "Your browser doesn't support passkeys yet. Try a different sign-in option below."

---

### 5.11 Social Login Buttons

**Purpose.** One-click login via Google, GitHub, Microsoft, Apple. Per Persona [Arjun](Qeet ID%20%E2%80%94%20UX%20Research%20Summary%20%26%20Design%20Principles.md) §4.1, Google + GitHub are non-negotiable for the trial signup.

**Per-provider spec:**

| Provider | Button label | Logo | Background | Notes |
| --- | --- | --- | --- | --- |
| Google | "Continue with Google" | Coloured G mark (per Google brand) | `surface.default` bg, `border.default` | Google brand guidelines mandate the coloured G + white background |
| GitHub | "Continue with GitHub" | Octocat (monochrome) | `surface.default` | Black logo on light theme; white logo on dark |
| Microsoft | "Continue with Microsoft" | 4-tile coloured logo | `surface.default` | Microsoft brand guidelines |
| Apple | "Continue with Apple" | Apple monochrome | `surface.default` (light) / `neutral-900` (dark) | Apple HIG requires specific button styling |

**Layout in flows:**
- On the login screen, the passkey button is primary and the social buttons sit as secondary actions below, in a vertical stack.
- Maximum 4 visible social providers per screen; more would crowd the layout. If more are configured by the tenant, they appear under a "Show more sign-in options" disclosure.

**Accessibility:** as Button; the provider name in the label gives screen-reader users the credential context.

---

### 5.12 Magic Link Sent State

**Purpose.** The interstitial state shown after a user requests a magic link — confirms the link was sent (anti-enumeration: same response whether the email exists or not, per [Phase 2 Auth Flow §14](../phase-2/Qeet%20ID%20%E2%80%94%20Authentication%20Flow%20Designs.md)).

**Anatomy:**

```
   ┌─────────────────────────────────────┐
   │            ✉  (large icon)          │
   │                                     │
   │     Check your email                │
   │                                     │
   │  We sent a sign-in link to          │
   │  alice@example.com.                 │
   │                                     │
   │  The link expires in 15 minutes.    │
   │                                     │
   │  Didn't get it? Resend in 23s       │
   │                                     │
   │  Use a different sign-in option →   │
   └─────────────────────────────────────┘
```

**Behaviour:**
- Same screen shown whether or not the email exists (anti-enumeration).
- Resend cooldown: 30 seconds.
- "Use a different sign-in option" link returns to login screen with email retained.

---

### 5.13 MFA Code Input

**Purpose.** A composed molecule = Form Field + OTP Input + Resend affordance + "Use another method" link. Used in TOTP, SMS, and Email OTP challenges.

**Anatomy:**

```
   Enter the 6-digit code we sent to •••• 7421

   ┌───┐ ┌───┐ ┌───┐ ┌───┐ ┌───┐ ┌───┐
   │   │ │   │ │   │ │   │ │   │ │   │
   └───┘ └───┘ └───┘ └───┘ └───┘ └───┘

   Didn't get it? Resend in 23s.
   Use another method →
```

---

### 6. Organisms

### 6.1 Navigation Bar (Top Nav)

**Purpose.** Persistent top-of-page navigation for the admin dashboard, developer portal, and marketing site.

**Anatomy (Admin Dashboard variant):**

```
   ┌──────────────────────────────────────────────────────────────────────────┐
   │  [Q] Acme Corp ▾   Users  Roles  Apps  SSO  …    🔍 Search …  ⌘K  ⨀⨀ │
   └──────────────────────────────────────────────────────────────────────────┘
       │      └ Tenant switcher              │              │     │
       └ Logo                                │              │     └ User avatar menu
                                             │              └ Command palette hint
                                             └ Global search
```

**Variants:**

| Variant | Composition |
| --- | --- |
| Dashboard | Logo + Tenant Switcher + main nav + global search + cmd-k hint + user menu |
| Docs | Logo + main nav (Docs, API, SDKs, Blog, Pricing) + docs search + theme toggle + Sign in / Sign up |
| Marketing | Logo + main nav (Product, Solutions, Pricing, Resources) + Sign in / Sign up |
| Status / Trust | Logo only + back to qeetify.com |

**Responsive behaviour:** below 1024px, secondary nav items collapse into a hamburger menu (per Doc 10).

---

### 6.2 Side Navigation

**Purpose.** Secondary navigation for the admin dashboard, organised by section. Collapses to icon-only at narrow widths.

**Anatomy:**

```
   ┌──────────────────────┐
   │  ▾ Identity          │
   │     • Users          │
   │     • Roles          │
   │     • Groups         │
   │                      │
   │  ▾ Federation        │
   │     • SSO Connections│
   │     • SCIM           │
   │                      │
   │  ▾ Applications      │
   │     • OAuth Clients  │
   │     • API Keys       │
   │     • Webhooks       │
   │                      │
   │  ▾ Security          │
   │     • Audit Logs     │ ← selected
   │     • MFA Policy     │
   │     • Sessions       │
   │                      │
   │  ▾ Settings          │
   │     • Branding       │
   │     • Custom Domain  │
   │     • Team           │
   │     • Billing        │
   └──────────────────────┘
```

**Behaviour:**
- Sections are collapsible (per persona — Sandra prefers all expanded; Maya prefers them collapsed).
- Section state persists per user.
- The selected leaf has a `4px` left accent bar in `action.primary` colour.
- Role-aware: an L2 team member without permission to access Billing does not see the Billing entry (Phase 3 Doc 6 §3).

**Accessibility:**
- `<nav>` element with `aria-label="Main"`.
- Sections are `<section>` with collapsible headers (`<button aria-expanded>`).
- Current page marked `aria-current="page"`.

---

### 6.3 Tenant Switcher

**Purpose.** Switch between organisations the current user belongs to (a Qeet ID user can be a member of many tenants — Multi-Tenancy §3 MTP-06).

**Anatomy:**

```
   ┌─────────────────────────────────────────┐
   │  Acme Corp ▾                            │
   ├─────────────────────────────────────────┤
   │  🔍  Filter organizations…              │
   ├─────────────────────────────────────────┤
   │  ★ Acme Corp                  (current) │
   │    acme.qeetify.com                     │
   │    1,248 users · Growth                 │
   ├─────────────────────────────────────────┤
   │    Acme R&D                             │
   │    acme-rd.qeetify.com                  │
   │    42 users · Free                      │
   ├─────────────────────────────────────────┤
   │    Acme Enterprise                      │
   │    acme.qeetify.com                     │
   │    8,402 users · Enterprise             │
   ├─────────────────────────────────────────┤
   │  + Create new organization              │
   └─────────────────────────────────────────┘
```

**Behaviour:**
- Search filters as the user types.
- Each row shows tenant name, subdomain (acme.qeetify.com), user count, and plan tier.
- Switching tenants navigates to the same page in the new tenant context (`/dashboard/[old-slug]/users` → `/dashboard/[new-slug]/users`).
- Recently-used tenants surface at the top.

---

### 6.4 Data Table

**Purpose.** The workhorse for every list of resources — users, roles, applications, SSO connections, audit logs, webhooks. Sandra and Daniel live in this component.

**Anatomy:**

```
   ┌──────────────────────────────────────────────────────────────────────────┐
   │  Users                                                  [+ Invite user]  │
   ├──────────────────────────────────────────────────────────────────────────┤
   │  🔍 Search  [Filter ▾] [Status: All ▾] [Source: All ▾]  [Columns ▾] [⤓]  │
   ├─[√]─────────────────────────────────────────────────────────────────────┤
   │  □   User                  Email                Status    Roles    ⋯   │
   ├─────────────────────────────────────────────────────────────────────────┤
   │  □   AB Alice Beck         alice@acme.com       Active    Admin    ⋯   │
   │  □   CD Carol Diaz         carol@acme.com       Active    Member   ⋯   │
   │  ☑   EF Ed Fisher          ed@acme.com          Suspended Viewer   ⋯   │
   │                                                                         │
   │  Showing 1–25 of ~2,400      ◀ Previous · 1 · 2 · 3 · … · Next ▶       │
   └─────────────────────────────────────────────────────────────────────────┘
```

**Features:**

| Feature | Behaviour |
| --- | --- |
| **Sort** | Column headers are clickable; sort indicator visible; multi-column sort with shift-click (advanced) |
| **Filter** | Inline filter bar with type-appropriate filter controls per column |
| **Pagination** | Cursor-based per [Phase 2 API §9](../phase-2/Qeet%20ID%20%E2%80%94%20API%20Design%20Standards.md). Page-size selector (25 / 50 / 100). "Showing 1–25 of ~2,400" — approximate total when count is expensive |
| **Column visibility** | User-controlled show/hide; persists per user |
| **Row actions** | Per-row `⋯` menu and bulk-select toolbar |
| **Bulk select** | Header checkbox selects current page (with "select all matching filters" option when filtered) |
| **Empty state** | Per §6.13 — empty illustration, message, primary action |
| **Loading state** | Skeleton rows (8 rows, full width) on first render; preserved on filter change |
| **Error state** | Error banner inside the table region; "Retry" button |
| **Density** | `comfortable` (default), `compact`, `spacious` — Sandra prefers compact for audit logs |
| **Column resize** | Drag column borders; saved per user |
| **Export** | `⤓` button exports the current view (post-filter, post-sort) to CSV or JSON |
| **Keyboard navigation** | Arrow keys move row focus; Space toggles row selection; Enter opens row detail |

**Accessibility:**
- `<table>` with proper `<thead>`/`<tbody>`/`<th scope="col">`.
- `aria-sort` on sortable headers.
- Row checkbox has accessible label "Select row for {user name}".
- Pagination announced via live region.

---

### 6.5 Audit Log Row (Specialised Row)

**Purpose.** A specialised data-table row designed for the audit log viewer — the most demanding screen in the dashboard.

**Anatomy (collapsed):**

```
   [🛡]   2026-05-19 14:32:18 UTC   auth.login.succeeded   alice@acme.com   passkey   203.0.113.7 (US-CA)  ▾
```

**Anatomy (expanded):**

```
   ▾  2026-05-19 14:32:18 UTC   auth.login.succeeded   alice@acme.com   passkey   203.0.113.7

      Event ID:     evt_01HX5T0Z9Q3V2W7K8FXR3JEYZB
      Tenant:       org_acme
      Actor:        user_8f3a... · alice@acme.com
      Target:       user_8f3a... · alice@acme.com
      Method:       passkey
      AAGUID:       08987058-cadc-4b81-b6e1-d240ac509e93 (iCloud Keychain)
      Session ID:   sess_01HX5T0Z…
      IP:           203.0.113.7 (San Francisco, CA, US)
      User-Agent:   Mozilla/5.0 (Mac …) Chrome/138.0
      Request ID:   req_01HX5T0Z…
      Hash chain:   ✓ Verified

      [Copy event JSON]  [View related events]  [View trace]
```

**Features:**
- Expanded view reveals the full event payload as structured rows + raw JSON tab.
- Hash-chain status indicator (✓ verified or ⚠ verification pending).
- "View related events" filters the table to all events sharing the same `request_id` or `session_id`.
- "View trace" deep-links to the Observability trace UI (Phase 2 Observability §6) for that `request_id`.

**Accessibility:** standard table row + expand button (`aria-expanded`); expanded content is `aria-live="polite"` so screen readers announce details on expand.

---

### 6.6 User Row (Specialised Row)

**Purpose.** A specialised row for the Users data table. Combines Avatar + Name + Email + Status badge + Role tags + Actions.

**Anatomy:**

```
   [AB]   Alice Beck             alice@acme.com           [Active]    Admin, Billing      ⋯
          last seen 2 min ago                              (badge)    (tags, max 3 + N)
```

**Behaviour:**
- Click row → opens user-detail drawer.
- Click `⋯` → row-action menu (Edit, Suspend, Delete, View sessions, View audit trail).
- Role tags overflow into "+N" tag if more than 3.

---

### 6.7 Modal / Dialog

**Purpose.** Block the user's flow to require attention or input. Use sparingly.

**Variants:**

| Variant | When to use |
| --- | --- |
| `confirmation` | Confirm a destructive action ("Delete user?") |
| `informational` | Show information that requires acknowledgement |
| `form` | Capture a small amount of input (e.g., rename a role) |

**Anatomy:**

```
   ┌─────────────────────────────────────────────────────┐
   │  Delete user                                    [×] │
   ├─────────────────────────────────────────────────────┤
   │                                                     │
   │  You're about to permanently delete                 │
   │  alice@acme.com.                                    │
   │                                                     │
   │  This will:                                         │
   │   – Revoke all active sessions                      │
   │   – Remove all role assignments                     │
   │   – Anonymise the user in audit logs                │
   │                                                     │
   │  This action cannot be undone.                      │
   │                                                     │
   │  Type the user's email to confirm:                  │
   │  [____________________________]                     │
   │                                                     │
   ├─────────────────────────────────────────────────────┤
   │                                  [Cancel] [Delete]  │
   └─────────────────────────────────────────────────────┘
```

**Behaviour:**
- Esc closes (unless mid-confirm-typing).
- Focus is trapped (Phase 3 Doc 9 §6).
- Focus restored to trigger on close.
- Backdrop click dismisses for non-destructive variants; *does not* dismiss for destructive (user must explicitly Cancel).
- Page below the modal is `aria-hidden=true` and inert.

**Accessibility:** `role="dialog"`, `aria-labelledby` on the title, `aria-describedby` on the body, `aria-modal=true`.

**Sizes:** `sm` (400px), `md` (560px, default), `lg` (720px), `xl` (1024px).

**Forbidden:** modal-on-modal stacking (AP-03). Open a Drawer over a Modal if you must.

---

### 6.8 Drawer / Side Sheet

**Purpose.** A panel that slides in from the side (right, primarily). Used for detail views (user detail, role detail) and for forms that benefit from preserving the underlying list view.

**Variants:** right (default), left, top, bottom.

**Behaviour:**
- Standard width: 480px (right drawer). Wide variant: 720px.
- Esc closes.
- Focus trapped.
- Drawer can open over a modal (the inverse is not allowed per AP-03).

**Used by:** User detail (Phase 3 Doc 6), role detail, application detail, audit log detail (expanded inline by default, but for very long payloads opens a drawer).

---

### 6.9 Toast / Notification

**Purpose.** Ephemeral confirmation, status, or non-blocking error.

**Anatomy:**

```
   ┌─────────────────────────────────────────────┐
   │  ✓  User invited                       [×] │
   │     Email sent to ed@acme.com.              │
   │                                             │
   │     [Undo]                                  │
   └─────────────────────────────────────────────┘
```

**Tones:** success, info, warning, danger.

**Behaviour:**
- Default duration 5 s; danger persists until dismissed.
- Up to 3 stacked at once (oldest dismissed if a fourth arrives).
- Bottom-right on desktop; bottom-centre on mobile.
- `prefers-reduced-motion` honoured: opacity fade only, no slide.

**Forbidden:** toasts as the sole error surface for actions the user must take (AP-08). For critical errors, additionally surface inline.

**Accessibility:** `role="status"` (success/info) or `role="alert"` (warning/danger); polite live region.

---

### 6.10 Banner / Alert

**Purpose.** In-content, non-ephemeral message — informational, success, warning, danger.

**Anatomy:**

```
   ┌─────────────────────────────────────────────────────────────────────────┐
   │  ⚠   SCIM sync failed for 3 users                                  [×] │
   │      Provisioning failed at 14:32 UTC. Errors: invalid_email (3).      │
   │      View error log  ·  Retry sync                                     │
   └─────────────────────────────────────────────────────────────────────────┘
```

**Variants by tone:** info, success, warning, danger. Each has the corresponding `surface.{tone}-subtle` background, `text.{tone}` icon and title, and `border.{tone}` left border.

**Used by:** dashboard top-of-page banners (subscription alerts, security warnings); per-section warnings (e.g., "Custom domain DNS not propagated yet").

---

### 6.11 Empty State

**Purpose.** The dedicated UI shown when a list, table, or card grid has no data. Per [P-08](Qeet ID%20%E2%80%94%20UX%20Research%20Summary%20%26%20Design%20Principles.md) / AP-05, empty data tables are never bare — they are always a designed teaching moment.

**Anatomy:**

```
   ┌────────────────────────────────────────────────────────────────┐
   │                                                                │
   │                       (illustration slot)                      │
   │                                                                │
   │              No SAML connections yet                           │
   │                                                                │
   │      Connect Microsoft Entra ID, Okta, or any SAML 2.0         │
   │      identity provider to enable enterprise SSO.               │
   │                                                                │
   │       [+ Add SAML connection]    Read the setup guide          │
   │                                                                │
   └────────────────────────────────────────────────────────────────┘
```

**Composition:**
- Optional illustration (centered, max 240×160). The system ships a small library of empty-state illustrations (users, applications, audit logs, SAML, SCIM, webhooks, API keys, billing).
- Title (`text.heading`, sentence case).
- Body (`text.body`, one sentence max).
- Primary CTA (Button `primary`).
- Optional secondary link.

---

### 6.12 Error State

**Purpose.** The dedicated UI for unrecoverable or transient page-level errors.

**Anatomy:** like Empty State, but with an error illustration, an error message, the error code, and a "Try again" primary action.

```
   We couldn't load this page.

   Error code: pg_load_failed
   Request ID: req_01HX5T0Z…

   [Try again]    Contact support
```

The error code and request ID give Daniel (P-08) the inputs needed to file an actionable support ticket.

---

### 6.13 Loading Skeleton

**Purpose.** A placeholder version of content that respects the eventual layout, so the screen doesn't jump on load (CLS = 0).

**Composition:** rounded grey rectangles in the shape of the eventual content. Animation: subtle left-to-right shimmer (1500ms loop, `easing.linear`). Honours reduced motion (becomes a static pulse).

**Used by:** every data-table first render; every dashboard tile first render; every user-detail drawer first render.

---

### 6.14 Form (with Validation, Submit State, Error Summary)

**Purpose.** The container organism for any form. Provides validation orchestration, submit-state management, and accessible error summary.

**Validation patterns:**
- **On blur** for individual fields (debounced 400ms for typing).
- **On submit** for cross-field validation.
- **Server validation** (RFC 7807 errors from [Phase 2 API §11](../phase-2/Qeet%20ID%20%E2%80%94%20API%20Design%20Standards.md)) are surfaced in two places: per-field (when the error has a `field` property) and in the page error summary.

**Error summary:**

```
   ┌─────────────────────────────────────────────────────────────────┐
   │  ⚠  Couldn't save changes                                       │
   │      • Email is required                                         │
   │      • Phone number must be in E.164 format                      │
   │      • Password must be at least 8 characters                    │
   └─────────────────────────────────────────────────────────────────┘
```

The summary appears at the top of the form on submit-with-errors; each listed error is a link that jumps focus to the affected field. This is mandatory for accessibility (Phase 3 Doc 9 §10).

**Submit-state lifecycle:** idle → submitting (button shows spinner; form fields disabled) → success (toast + redirect / inline confirmation) | error (error summary + per-field errors).

---

### 6.15 Card

**Purpose.** A bounded content container with rest-elevation. The default container for grouped content.

**Variants:**

| Variant | Use |
| --- | --- |
| `default` | Content card |
| `interactive` | Hoverable / clickable card (full-card link target) |
| `selectable` | With a leading radio / checkbox for selectability |
| `stat` | A Stat Card composition (§5.5) |

**Behaviour:**
- Default padding `space.l` (16px), large padding `space.xl` (24px).
- Optional header, body, footer.

---

### 6.16 Tab Group

**Purpose.** Switch between related views within the same page.

**Variants:**

| Variant | Use |
| --- | --- |
| `default` | Underlined active tab (used inline) |
| `pills` | Pill-shaped active tab (used in filter chips) |
| `segmented` | Segmented-control style (mobile-friendly) |

**Accessibility:** WAI-ARIA Tabs pattern.

---

### 6.17 Accordion

**Purpose.** Vertically collapsible content sections. Used in long settings screens, FAQ, and the SAML connection multi-section editor.

**Behaviour:**
- Single-expanded (default) or multi-expanded modes.
- Headers are buttons; `aria-expanded` reflects state.
- Smooth height animation (`easing.standard`, `duration.standard`).
- Honours reduced motion.

---

### 6.18 Breadcrumbs

**Purpose.** Show the user's position in nested navigation, with quick links to ancestor screens.

**Anatomy:**

```
   Organizations  /  Acme Corp  /  Users  /  Alice Beck
```

- Each segment is a link except the final (current) segment.
- Truncates middle segments with `…` when constrained.

**Used by:** the dashboard primarily; not used in docs (the docs have a left-nav tree instead).

---

### 6.19 Pagination

**Purpose.** Cursor-based pagination control for Data Table and equivalent organisms.

**Anatomy:**

```
   Showing 1–25 of ~2,400          ◀ Previous · Next ▶
   (or, when totals are cheap)
   Showing 1–25 of 2,406            1 · 2 · 3 · … · 96  ◀ Previous · Next ▶
```

- Page-size selector adjacent: `[25 ▾]`.
- The cursor approach means we don't always have a total; the "approximate" form is the default.

---

### 6.20 Stepper

**Purpose.** Multi-step flow indicator + navigator. Used for SAML Setup Wizard, Custom Domain Setup Wizard, Plan Upgrade Flow.

**Anatomy:**

```
   ●─────────●─────────○─────────○─────────○
   Connect    Map        Test       Activate   Done
   metadata   attributes
   ✓ done    ✓ done    ○ active   ○ pending  ○ pending
```

- Numbered or icon-headed steps.
- Steps can be `pending`, `active`, `done`, `error`.
- Clicking a `done` step navigates back (read-only on a completed step).
- Forward navigation requires the active step's validation to pass.

**Used by:** §6 (Admin Dashboard) wizards.

---

### 7. Templates

### 7.1 Auth Layout

**Purpose.** Centred-card composition for end-user authentication pages — login, signup, MFA challenge, passkey, magic link sent, password reset.

**Anatomy:**

```
   ┌─────────────────────────────────────────────────────────┐
   │                  [Tenant logo]                          │
   │                                                         │
   │              ┌───────────────────────────┐              │
   │              │                           │              │
   │              │       Sign in to Acme     │              │
   │              │                           │              │
   │              │       [Email field]       │              │
   │              │                           │              │
   │              │  [🔑 Continue with passkey]              │
   │              │                           │              │
   │              │  ─── or ───               │              │
   │              │                           │              │
   │              │  [G Continue with Google] │              │
   │              │  [⌂ Continue with GitHub] │              │
   │              │                           │              │
   │              │  Use a different method ↓ │              │
   │              │                           │              │
   │              └───────────────────────────┘              │
   │                                                         │
   │           Powered by Qeet ID · Privacy · Terms          │
   └─────────────────────────────────────────────────────────┘
```

- Card max-width 440px (per Doc 2 §8.2).
- Vertically centred on viewports ≥ 640px; top-aligned on mobile (so the keyboard doesn't push critical content off-screen).
- Background slot (white-label customisable per Doc 8).
- Tenant logo top-centre; locked to a max height.
- Footer carries Qeet ID attribution (configurable per tenant plan; Enterprise can opt out — Doc 8 §6).

---

### 7.2 Dashboard Layout

**Purpose.** The shell of every admin dashboard screen — sidebar + topbar + content + optional right panel.

**Anatomy:**

```
   ┌───────────────────────────────────────────────────────────────────────┐
   │  [Q] Acme Corp ▾   …topnav…    🔍 ⌘K     [user avatar ▾]              │
   ├─────────────────┬─────────────────────────────────────────────────────┤
   │                 │                                                     │
   │   Side          │   ┌───────────────────────────────────────────┐    │
   │   navigation    │   │                                           │    │
   │   sections      │   │   Content area (max width 1280px)         │    │
   │   …             │   │                                           │    │
   │                 │   └───────────────────────────────────────────┘    │
   │                 │                                                     │
   │                 │   (optional right panel slot)                       │
   │                 │                                                     │
   └─────────────────┴─────────────────────────────────────────────────────┘
```

- Sidebar fixed width 240px (240px on collapse: icon-only 56px).
- Topbar fixed 56px.
- Content area scrolls; sidebar and topbar are sticky.
- Below 1024px (per Doc 10), sidebar becomes a drawer.

---

### 7.3 Settings Layout

**Purpose.** Settings-style two-column layout — settings nav + content. Used for tenant settings, user account settings, application settings.

**Anatomy:**

```
   ┌─────────────────┬─────────────────────────────────────────┐
   │  Profile        │   Organization profile                  │
   │  Security       │                                         │
   │  Billing        │   Name [_____________]                  │
   │  Branding       │   Slug [acme]                           │
   │  Team           │   Region [US East 1 ▾]                  │
   │  Compliance     │                                         │
   └─────────────────┴─────────────────────────────────────────┘
```

- The settings nav is a smaller side-nav variant.
- Each row navigates without page reload (in-app routing).

---

### 7.4 Documentation Layout

**Purpose.** Three-zone layout for the developer portal docs.

**Anatomy:**

```
   ┌────────────────┬─────────────────────────────────┬──────────────────┐
   │  Sections      │    Page content                 │   In-page TOC    │
   │  Guides        │                                 │                  │
   │  • Quickstart  │    h1: Quickstart               │   • Install      │
   │  • Concepts    │    h2: Install                  │   • Configure    │
   │  • Guides      │    [code block]                 │   • First login  │
   │  • API Ref     │    h2: Configure                │                  │
   │  • SDKs        │    [code block]                 │                  │
   │  • Migration   │                                 │                  │
   └────────────────┴─────────────────────────────────┴──────────────────┘
```

- Left nav: 240px.
- Content: 720px max width (per Doc 2 §8.2).
- Right TOC: 240px; collapses to a sticky popover below tablet (Doc 10).

---

### 7.5 Status Page Layout

**Purpose.** Public-facing status communication layout. Mirrors the design of the rest of the platform but with no authentication required and a calm, scannable composition.

**Anatomy:**

```
   ┌───────────────────────────────────────────────────────────────────────┐
   │                                                                       │
   │  Qeet ID Status              All systems operational ✓                │
   │                                                                       │
   │  ┌───────────────────────────────────────────────────────────────┐   │
   │  │  Authentication API     ████████████████████  99.99% (90d)    │   │
   │  │  Token Service           ████████████████████  99.98%          │   │
   │  │  Admin Dashboard         ████████████████░░░░  99.91%          │   │
   │  │  …                                                              │   │
   │  └───────────────────────────────────────────────────────────────┘   │
   │                                                                       │
   │  Recent incidents                                                    │
   │  ── nothing in the last 7 days ──                                    │
   │                                                                       │
   │  [Subscribe to updates]                                              │
   └───────────────────────────────────────────────────────────────────────┘
```

- Component status chips (`Operational`, `Degraded performance`, `Partial outage`, `Major outage`, `Maintenance`).
- Per-region status if relevant.
- Timeline of recent incidents (last 90 days).
- Subscribe-by-email and webhook.

Hosted independently per [NFR AV-10](../phase-1/Qeet%20ID%20%E2%80%94%20Non-Functional%20Requirements%20%28NFR%29.md); design system tokens consumed via CDN.

---

### 7.6 Marketing Layout

**Purpose.** A simple, brand-forward layout used for the Security Trust Center, Public Roadmap, Public Changelog, Pricing, and Blog.

**Anatomy:** topnav + hero + content section(s) + footer.

This template is **not** the home page — Marketing owns `/` and `/pricing` design boundaries, but those pages consume this template.

---

### 8. State Patterns Across All Components

The four universal display states are designed once per pattern and replicated across components:

| State | Visual | Component coverage |
| --- | --- | --- |
| **Loading** | Skeleton (preferred) or Spinner | Every data-bearing component |
| **Empty** | Illustration + title + body + CTA per §6.11 | Every list/table/card-grid |
| **Error** | Inline Error State component per §6.12 | Every async region |
| **Success** | Toast + inline confirmation | Every mutation |

A component that fails to ship one of these four states is rejected at design review.

---

### 9. Component Versioning & Migration

- **Major version** bumps are coordinated with Phase 4 release planning. A breaking change is rolled out behind a feature flag in `@qeetify/ui` and announced in the changelog.
- **Deprecation window** is 12 months minimum (matches API deprecation policy per Phase 2 API §13).
- **Migration codemods** are provided where possible for prop / variant renames.

---

### 10. Accessibility Requirements (Cross-Component)

Every interactive component conforms to the requirements below. These are the cross-component baseline; per-component specifics live in §4–§7 and are consolidated for QA in [Accessibility Compliance Plan (WCAG 2.1 AA)](Qeet ID%20%E2%80%94%20Accessibility%20Compliance%20Plan%20%28WCAG%202.1%20AA%29.md).

| # | Requirement |
| --- | --- |
| A-01 | Every interactive element is reachable by keyboard alone. |
| A-02 | Every interactive element has a visible focus indicator with ≥3:1 contrast against its background. |
| A-03 | Touch targets ≥44×44pt on mobile breakpoints; ≥24×24px on desktop with adequate spacing. |
| A-04 | All text meets WCAG AA contrast (4.5:1 body, 3:1 large / UI). |
| A-05 | Components do not rely on colour alone (icon + colour or text + colour). |
| A-06 | Disabled states use `aria-disabled` rather than `disabled` so they remain in the focus order. |
| A-07 | Loading states announce "Loading {context}" via `aria-busy=true`. |
| A-08 | Error messages are programmatically associated with the field via `aria-describedby` and announced via `aria-live=polite`. |
| A-09 | Modals trap focus and restore it on dismiss. |
| A-10 | Skip-to-content link present on every page-level template (Auth, Dashboard, Docs). |
| A-11 | `prefers-reduced-motion` honoured: transitions reduce to opacity-only at minimal intensity. |

---

### 11. Cross-Platform Implementation Notes

| Platform | Library | Notes |
| --- | --- | --- |
| **Web (React, Next.js)** | `@qeetify/ui` — the canonical implementation | Built on Radix UI primitives for accessibility correctness + Tailwind-CSS-in-JS token consumption |
| **Web (HTML/CSS)** | Hosted login pages and email templates use a smaller subset rendered server-side | No JavaScript dependency for the critical login path; progressive enhancement only |
| **Flutter** | `qeetify_ui` pub package | Mirrors the React API where possible (Button, Input, FormField, OTPInput, PasskeyButton); platform-native widgets where appropriate (Date Picker uses Material/Cupertino) |
| **iOS (future SDK)** | Not at MVP — SwiftUI component set planned for v1.2 | Token consumption via JSON export |
| **Android (future SDK)** | Not at MVP — Jetpack Compose planned for v1.2 | Token consumption via JSON export |

The library is **opinionated, not exhaustive**. Customer applications using the SDK can wrap or compose Qeet ID components, but the components themselves do not expose every internal slot — that would defeat the consistency benefit.

---

### 12. Open Design Decisions From This Document

| # | Question | Owner | Target |
| --- | --- | --- | --- |
| OD-CL-01 | Syntax highlighting library — Prism vs Shiki | Frontend Lead + Tech Writing | Phase 3 Week 3 |
| OD-CL-02 | Final React primitive library — Radix UI vs Ark UI vs build | Frontend Lead | Phase 3 Week 2 |
| OD-CL-03 | Data Table state-table-cell granularity (header-sticky on mobile?) | UX Designer + Frontend Lead | Phase 3 Week 4 |
| OD-CL-04 | Whether the Combobox supports virtualisation at MVP (for very large option lists like SCIM groups) | Frontend Lead | Phase 3 Week 3 |
| OD-CL-05 | Empty-state illustration style (line illustrations vs flat coloured) — depends on brand direction OD-UX-02 | UX Designer + Marketing | Phase 3 Week 2 |
| OD-CL-06 | Stepper navigation on mobile — horizontal scroll vs vertical stack vs progress dots | UX Designer | Phase 3 Week 4 |

---

### 13. Cross-References

- Principles components must serve: [UX Research Summary & Design Principles](Qeet ID%20%E2%80%94%20UX%20Research%20Summary%20%26%20Design%20Principles.md) §6
- Tokens components consume: [Design System Foundations & Tokens](Qeet ID%20%E2%80%94%20Design%20System%20Foundations%20%26%20Tokens.md)
- Component-level accessibility consolidated: [Accessibility Compliance Plan (WCAG 2.1 AA)](Qeet ID%20%E2%80%94%20Accessibility%20Compliance%20Plan%20%28WCAG%202.1%20AA%29.md)
- Mobile-specific component constraints: [Mobile & Responsive Design Specification](Qeet ID%20%E2%80%94%20Mobile%20%26%20Responsive%20Design%20Specification.md)
- i18n constraints on components: [Internationalization & Localization Design](Qeet ID%20%E2%80%94%20Internationalization%20%26%20Localization%20Design.md)
- Components composed in flows: [End-User Authentication Flow Designs](Qeet ID%20%E2%80%94%20End-User%20Authentication%20Flow%20Designs.md), [Admin Dashboard Design Specification](Qeet ID%20%E2%80%94%20Admin%20Dashboard%20Design%20Specification.md), [Developer Portal Design Specification](Qeet ID%20%E2%80%94%20Developer%20Portal%20Design%20Specification.md)
- White-label slot points: [Embeddable Auth UI Components (White-Label)](Qeet ID%20%E2%80%94%20Embeddable%20Auth%20UI%20Components%20%28White-Label%29.md)
- API errors consumed by Form: [Phase 2 API Design Standards §11](../phase-2/Qeet%20ID%20%E2%80%94%20API%20Design%20Standards.md)
- Audit log row data shape: [Phase 2 Database Design §5](../phase-2/Qeet%20ID%20%E2%80%94%20Database%20Design%20%26%20Data%20Model.md)

---

### 14. Approvals & Sign-off

| Role | Name | Signature | Date |
| --- | --- | --- | --- |
| UX Designer |  |  |  |
| Product Designer |  |  |  |
| Frontend Engineering Lead |  |  |  |
| Mobile (Flutter) SDK Lead |  |  |  |
| Accessibility Lead (QA) |  |  |  |
| QA Lead (visual regression) |  |  |  |
| Solution Architect (cross-phase consistency) |  |  |  |

---

*This document is version controlled. Visual updates in Figma do not require re-sign-off; changes to a component's props/API surface (§4–§7), accessibility contract (§10), or addition/removal of variants and states require UX Designer + Frontend Lead + Accessibility Lead review. Adding a new component requires this document to be updated in the same PR as the Figma library.*

---

**Qeet ID — Authenticate Everything.** *A Qeet Group Company*
