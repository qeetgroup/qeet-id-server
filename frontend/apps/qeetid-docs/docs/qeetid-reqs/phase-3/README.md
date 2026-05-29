# Phase 3 — UI/UX Design

Welcome to the Qeet ID Phase 3 baseline. This directory contains the twelve design Markdown documents that define how Qeet ID looks, feels, and behaves, along with the supporting Open Design Decisions Register, Phase 3 Exit Checklist, and Design-to-Engineering Handoff Brief.

Phase 3 refines the Phase 1 Discovery & Requirements baseline and the Phase 2 System Design & Architecture baseline into specifications a Figma library, a frontend codebase, and a usability research stream can build against.

The documents here are **specifications, not visual artefacts.** Figma is the visual source of truth. These Markdown files capture the design system rules, component contracts, flow logic, interaction patterns, accessibility requirements, and the decisions that engineering and design must align on.

Read Phase 1 and Phase 2 first; this directory presumes that context.

The documents are designed to be read in order — each one builds on its predecessors. The UX Research Summary & Design Principles document is the anchor; everything else operationalises it.

---

## 1. Document Index

| # | Document | Owner | Purpose |
| --- | --- | --- | --- |
| 1 | [Qeet ID — UX Research Summary & Design Principles](Qeet ID%20%E2%80%94%20UX%20Research%20Summary%20%26%20Design%20Principles.md) | UX Designer + Product Manager | Anchors Phase 3 — persona briefs, competitive UX audit, the 10 design principles, voice & tone, anti-patterns, success metrics. |
| 2 | [Qeet ID — Design System Foundations & Tokens](Qeet ID%20%E2%80%94%20Design%20System%20Foundations%20%26%20Tokens.md) | UX Designer | The token system — colour, typography, spacing, layout grid, radius, elevation, motion, iconography, z-index — with light/dark mode contrast verification and white-label override surfaces. |
| 3 | [Qeet ID — Component Library Specification](Qeet ID%20%E2%80%94%20Component%20Library%20Specification.md) | UX Designer + Frontend Lead | The catalogue of every component — atoms, molecules, organisms, templates — with anatomy, variants, states, props/API, accessibility contracts, and do's / don'ts. |
| 4 | [Qeet ID — Information Architecture & Navigation](Qeet ID%20%E2%80%94%20Information%20Architecture%20%26%20Navigation.md) | UX Designer + Product Manager | Site maps for every surface, URL structure, tenant context model in routing, search architecture, keyboard shortcuts. |
| 5 | [Qeet ID — End-User Authentication Flow Designs](Qeet ID%20%E2%80%94%20End-User%20Authentication%20Flow%20Designs.md) | UX Designer | The 18 MVP end-user flows — sign-up, login (passkey conditional/explicit/cross-device, password+MFA, magic link, social), MFA challenges (TOTP, SMS, Email, Backup codes), step-up, password reset, account recovery, account settings, GDPR data export & deletion. |
| 6 | [Qeet ID — Admin Dashboard Design Specification](Qeet ID%20%E2%80%94%20Admin%20Dashboard%20Design%20Specification.md) | UX Designer + Product Designer | Screen-by-screen specs for the dashboard — overview, users, roles, applications, SAML / OIDC / SCIM, audit logs (the heaviest design), security events, webhooks, API keys, branding & custom domain, email templates, team & admin tiers, billing, compliance documents. |
| 7 | [Qeet ID — Developer Portal Design Specification](Qeet ID%20%E2%80%94%20Developer%20Portal%20Design%20Specification.md) | UX Designer + Technical Writer | The Quickstart (under 5 minutes to first auth), Concepts, Guides, API Reference, SDK Reference, Migration Guides, status page, public roadmap, public changelog, Security Trust Center, community, blog, pricing. |
| 8 | [Qeet ID — Embeddable Auth UI Components (White-Label)](Qeet ID%20%E2%80%94%20Embeddable%20Auth%20UI%20Components%20%28White-Label%29.md) | UX Designer | The white-label strategy — embeddable widgets, hosted auth pages, custom domain, brand customisation surface (and what's locked and why), brand validation. |
| 9 | [Qeet ID — Accessibility Compliance Plan (WCAG 2.1 AA)](Qeet ID%20%E2%80%94%20Accessibility%20Compliance%20Plan%20%28WCAG%202.1%20AA%29.md) | UX Designer + QA Lead | The conformance plan — every WCAG 2.1 AA success criterion, component-level requirements, screen-reader strategy, focus management, testing approach (automated + manual + third-party + AT users), public accessibility statement. |
| 10 | [Qeet ID — Mobile & Responsive Design Specification](Qeet ID%20%E2%80%94%20Mobile%20%26%20Responsive%20Design%20Specification.md) | UX Designer | Per-surface responsive strategy, breakpoints, touch targets, gestures, native-app considerations (Flutter SDK), mobile performance budgets, offline behaviour, browser quirks. |
| 11 | [Qeet ID — Internationalization & Localization Design](Qeet ID%20%E2%80%94%20Internationalization%20%26%20Localization%20Design.md) | UX Designer | Localisation scope (10 launch languages for end-user; English-only admin and docs), translation workflow, layout for translated content, date/time/currency/phone formatting, language detection, RTL readiness for v1.2. |
| 12 | [Qeet ID — Usability Testing Plan & Findings Framework](Qeet ID%20%E2%80%94%20Usability%20Testing%20Plan%20%26%20Findings%20Framework.md) | UX Designer + Product Manager | Testing philosophy, per-phase scope, participant recruitment per persona, scenarios, success metrics, findings template, severity classification, iteration cadence. |

---

## 2. Supporting Files

| File | Purpose |
| --- | --- |
| [Open-Design-Decisions-Register.md](Open-Design-Decisions-Register.md) | All open design decisions surfaced during Phase 3 generation — Phase 1 / Phase 2 carry-forwards plus per-document opens. Owner and target resolution date for each. |
| [Phase-3-Exit-Checklist.md](Phase-3-Exit-Checklist.md) | The Solution Architect + UX Designer's gate for declaring Phase 3 complete and ready for Phase 4. |
| [Design-to-Engineering-Handoff-Brief.md](Design-to-Engineering-Handoff-Brief.md) | A 2-page summary the Frontend Engineering Lead uses as the Phase 4 starting point. |

---

## 3. How to Use This Phase 3 Baseline

### For UX Designers and Product Designers

Read documents 1 and 2 first — they ground every later decision. Then read 3 (Components) and 4 (IA). Then dive into the surface you're working on (5, 6, 7, or 8).

### For Frontend Engineers and SDK Engineers

Read the Design-to-Engineering Handoff Brief first. Then read documents 2 (Tokens) and 3 (Components) — these define your engineering contracts. Then read the surface-specific doc you're implementing (5, 6, 7, 8, or 10).

### For Technical Writers

Read documents 1 (Principles), 7 (Developer Portal), and 11 (i18n). The Quickstart page (Doc 7 §6) is your most-iterated artefact.

### For QA and Accessibility Engineers

Read documents 9 (Accessibility) and 12 (Usability Testing) first. Then read the surface-specific docs you'll test against.

### For Product Managers

Read documents 1 and 12. These set the principles and the success metrics. Then skim the surface-specific docs to understand persona priorities.

### For Marketing

Read documents 1 (Voice & Tone in §7) and 2 (Tokens) — these are your inputs for the marketing site. The pricing-page and Security Trust Center sections in documents 7 are your collaboration points.

---

## 4. Cross-Document Reading Map

```
                ┌─────────────────────────────────────┐
                │  1. UX Research & Design Principles │  ◀── (anchor)
                └──────────────┬──────────────────────┘
                               │ informs
   ┌───────────────────────────┴──────────────────────────────┐
   ▼                           ▼                              ▼
┌────────────────┐    ┌─────────────────────┐    ┌────────────────────────┐
│ 2. Design      │ ──▶│ 3. Component        │    │ 4. Information         │
│    System &    │    │    Library          │    │    Architecture &      │
│    Tokens      │    │    Specification    │    │    Navigation          │
└────────────────┘    └──────────┬──────────┘    └──────────┬─────────────┘
                                 │                          │
       ┌─────────────────────────┴──────────────────────────┘
       │
       ▼
┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐
│ 5. End-User Auth │    │ 6. Admin         │    │ 7. Developer     │
│    Flow Designs  │    │    Dashboard     │    │    Portal        │
└──────────────────┘    └──────────────────┘    └──────────────────┘
       │
       ▼
┌──────────────────┐
│ 8. White-Label   │
│    Components    │
└──────────────────┘

   Cross-cutting:
   ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
   │ 9. Accessibility │  │ 10. Mobile &     │  │ 11. i18n &       │  │ 12. Usability    │
   │    (WCAG 2.1 AA) │  │     Responsive   │  │     Localization │  │     Testing      │
   └──────────────────┘  └──────────────────┘  └──────────────────┘  └──────────────────┘
```

Every arrow above represents a cross-document dependency that is explicitly linked in the text.

---

## 5. Phase 3 Standards

All documents in this Phase 3 baseline:

- Open with a standard Document Information table.
- Close with the standard footer:
  > *This document is version controlled. Visual updates in Figma do not require re-sign-off, but changes to [scope of change] require [reviewers].*
  >
  > **Qeet ID — Authenticate Everything.** *A Qeet Group Company*
- Use numbered sections matching Phase 1/2 style.
- Use tables for matrices, component specs, comparisons, per-persona priorities, and any structured data.
- Use ASCII diagrams for screen flows, IA, layout sketches — no external image links (visual artefacts live in Figma).
- Use semantic token names (action-primary, surface-elevated) rather than hex values — exact tokens defined in Document 2.
- Reference Phase 1 documents explicitly when a design decision flows from them.
- Reference Phase 2 documents when design intersects with architecture.
- Reference other Phase 3 documents for cross-dependencies.
- Surface open decisions rather than invent resolutions.

---

## 6. Persona-Driven Design Allocation

| Surface | Persona lead |
| --- | --- |
| End-User Auth Pages | end users (indirect — all personas' users) |
| Admin Dashboard | Sandra (Enterprise IT Admin) |
| Developer Portal & Docs | Arjun (Solo Developer) |
| White-Label Auth Widgets | Maya (Startup CTO) & Daniel (Mid-Market Eng Lead) |
| Security Trust Center | Omar (CISO) |
| Pricing & Marketing | Maya (with Arjun's needs respected) |

Each surface's design decisions trace to its lead persona's needs first; secondary personas are accommodated without compromising the lead.

---

## 7. The 10 Design Principles (Recap)

The principles from [Document 1 §6](Qeet ID%20%E2%80%94%20UX%20Research%20Summary%20%26%20Design%20Principles.md) govern every design decision in Phase 3:

1. **P-01** — Developer-First by Default
2. **P-02** — Passkey-First, Password-Last
3. **P-03** — Mobile-First for End-User Flows
4. **P-04** — Desktop-First for Admin & Developer Surfaces
5. **P-05** — Accessibility is a Feature, Not a Checklist
6. **P-06** — White-Label Ready, Not White-Label Afterthought
7. **P-07** — Show, Don't Tell (Code Examples > Prose)
8. **P-08** — Errors Are Designed, Not Improvised
9. **P-09** — Speed Is a Design Decision (Perceived Performance)
10. **P-10** — Trust Through Transparency

---

## 8. Phase 3 Status

| Item | Status |
| --- | --- |
| All 12 design documents produced | ✅ |
| Open Design Decisions Register established | ✅ |
| Phase 3 Exit Checklist established | ✅ |
| Design-to-Engineering Handoff Brief established | ✅ |
| Figma library | In progress — designed against these specs |
| Cross-references verified bi-directionally | ✅ (initial pass — re-verified at Phase 3 close) |
| Stakeholder sign-off | Pending |

---

## 9. What Phase 3 Does NOT Cover

This baseline is **Phase 3 only**. The following are explicitly out of scope and live in their own phase deliverables:

- **Phase 4** — Development (code, SDKs, the actual MVP build).
- **Phase 5** — Infrastructure & DevOps execution.
- **Phase 6** — Testing & QA execution (informed by Document 9 testing strategy and Document 12 usability testing).
- **Phase 7** — Security audit and certification.
- **Phase 8** — Beta launch (Document 12 specifies the beta-phase testing plan).
- **Phase 9** — Production deployment.
- **Phase 10** — Post-launch & growth.
- Marketing-owned localised assets (per Document 11 §11).

---

## 10. Contact

Questions about a document → contact the document's owner from the table in §1.
Questions about a design decision → consult the relevant document; if absent, raise with the UX Designer.
Open decision needing resolution → see [Open-Design-Decisions-Register.md](Open-Design-Decisions-Register.md) for owner and target date.
Engineering questions about implementation → start with the [Design-to-Engineering-Handoff-Brief.md](Design-to-Engineering-Handoff-Brief.md).

---

**Qeet ID — Authenticate Everything.** *A Qeet Group Company*
