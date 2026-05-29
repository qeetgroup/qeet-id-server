# Qeet ID — Open Design Decisions Register (Phase 3)

### 1. Document Information

|  |  |
| --- | --- |
| **Document Name** | Open Design Decisions Register |
| **Project Name** | Qeet ID |
| **Parent Company** | Qeet Group |
| **Subsidiary** | Qeet ID (Standalone) |
| **Document Version** | v1.0 |
| **Prepared By** | UX Designer |
| **Date** | May 19, 2026 |
| **Status** | Living document — updated as decisions close |

---

### 2. Purpose

This register collects every open design decision surfaced during Phase 3, plus Phase 1 / Phase 2 carry-forwards that have a Phase-3-touching dimension. Each entry names the question, the owner accountable for resolution, the target resolution date, and a pointer to the document(s) where the question is discussed.

Resolving an open decision typically produces an entry in the Figma library version notes, a doc revision, or an ADR (when architectural). Once a decision closes, the corresponding row is marked `Closed` with a pointer to the resolution.

---

### 3. Register

#### 3.1 Carried Forward From Phase 1 / Phase 2 with a Design Touch

| # | Question | Source | Owner | Target | Status |
| --- | --- | --- | --- | --- | --- |
| OD-PC-01 | Brand colour direction (cool trust blue vs warmer differentiating accent) — pending Qeet Group Marketing | Phase 3 Doc 1; Phase 2 OD-UX-02 | UX Designer + Marketing | Phase 3 Week 1 | Open |
| OD-PC-02 | Font family ratification (Inter + JetBrains Mono recommended) — Marketing licence review | Phase 3 Doc 2; Phase 2 OD-DS-02 | UX + Marketing + Legal | Phase 3 Week 2 | Open |
| OD-PC-03 | Icon library — Lucide vs Phosphor | Phase 3 Doc 2; Phase 2 OD-DS-01 | UX + Marketing | Phase 3 Week 2 | Open |
| OD-PC-04 | Hosted login pages — Qeet ID universal vs SDK-rendered + tenant-hosted | Phase 2 OQ-07 | Product + UX + SA | Phase 3 entry | Open (Phase 3 Doc 5 / Doc 8 progress this) |

#### 3.2 Doc 1 — UX Research & Design Principles

| # | Question | Owner | Target | Status |
| --- | --- | --- | --- | --- |
| OD-UX-01 | Final voice & tone style guide approval (Doc 1 §7) | UX + Marketing | Phase 3 Week 2 | Open |
| OD-UX-02 | Brand voice on marketing pages — same as technical surfaces or differentiated | UX + Marketing | Phase 3 Week 2 | Open |
| OD-UX-04 | Whether audit log search supports natural-language queries at MVP or only structured filters | UX + Product | Phase 3 Week 3 | Open |
| OD-UX-05 | In-product guided onboarding ships at MVP vs v1.1 | Product Manager | Phase 3 Week 2 | Open |

#### 3.3 Doc 2 — Design System Foundations & Tokens

| # | Question | Owner | Target | Status |
| --- | --- | --- | --- | --- |
| OD-DS-01 | Icon library — Lucide vs Phosphor (same as OD-PC-03) | UX + Marketing | Phase 3 Week 2 | Tied to OD-PC-03 |
| OD-DS-02 | Font family — Inter + JetBrains Mono vs alternative | UX + Marketing + Legal | Phase 3 Week 2 | Tied to OD-PC-02 |
| OD-DS-03 | Brand colour palette (depends on OD-PC-01) | UX + Marketing | Phase 3 Week 1 | Tied to OD-PC-01 |
| OD-DS-04 | Chart palette at MVP vs v1.1 (Analytics is MVP) | UX | Phase 3 Week 2 | Open |
| OD-DS-05 | White-label radius range — 2–12px vs 0–16px (impact on layout integrity) | UX + Frontend | Phase 3 Week 3 | Open |

#### 3.4 Doc 3 — Component Library Specification

| # | Question | Owner | Target | Status |
| --- | --- | --- | --- | --- |
| OD-CL-01 | Syntax highlighting — Prism vs Shiki | Frontend + Tech Writing | Phase 3 Week 3 | Open |
| OD-CL-02 | React primitive library — Radix UI vs Ark UI vs build | Frontend Lead | Phase 3 Week 2 | Open |
| OD-CL-03 | Data Table header-sticky behaviour on mobile | UX + Frontend | Phase 3 Week 4 | Open |
| OD-CL-04 | Combobox virtualisation at MVP for large option lists | Frontend Lead | Phase 3 Week 3 | Open |
| OD-CL-05 | Empty-state illustration style (line vs flat coloured) — depends on brand | UX + Marketing | Phase 3 Week 2 | Open |
| OD-CL-06 | Stepper navigation on mobile — horizontal scroll vs vertical stack vs progress dots | UX | Phase 3 Week 4 | Open |

#### 3.5 Doc 4 — Information Architecture & Navigation

| # | Question | Owner | Target | Status |
| --- | --- | --- | --- | --- |
| OD-IA-01 | Docs search — Algolia DocSearch vs in-house Typesense | Tech Writing + Frontend | Phase 3 Week 3 | Open |
| OD-IA-02 | Drawers (user/role detail) get their own URLs at MVP | UX + Frontend | Phase 3 Week 3 | Open |
| OD-IA-03 | Per-tenant favicon at MVP vs v1.2 | Product + UX | Phase 3 Week 2 | Open |
| OD-IA-04 | Tenant slug rename frequency limit | Product + Sales | Phase 3 Week 2 | Open |
| OD-IA-05 | Mobile dashboard "Open on desktop" feature — email magic-link transfer vs deep-link copy | UX + Engineering | Phase 3 Week 4 | Open |
| OD-IA-06 | Dashboard alias `/dashboard/{tenant}/users` at MVP | UX + Frontend | Phase 3 Week 2 | Open |

#### 3.6 Doc 5 — End-User Authentication Flow Designs

| # | Question | Owner | Target | Status |
| --- | --- | --- | --- | --- |
| OD-EUF-01 | Per-flow custom branding (vs uniform tenant branding) at MVP | UX + Product | Phase 3 Week 3 | Open |
| OD-EUF-02 | Password-strength meter — zxcvbn vs simple length-based | UX + Security | Phase 3 Week 2 | Open |
| OD-EUF-03 | "No backup codes? Recover" link — hidden by default or always visible | UX + Security | Phase 3 Week 3 | Open |
| OD-EUF-04 | Welcome screen copy — UX-default vs tenant-customisable | UX + Product | Phase 3 Week 3 | Open |
| OD-EUF-05 | F-07 cross-device QR — default for all users or explicit opt-in | UX | Phase 3 Week 4 | Open |
| OD-EUF-06 | Account-recovery manual-review fallback design (Phase 2 OQ-AF-04) | UX + Product + Compliance | Phase 3 Week 4 | Open |

#### 3.7 Doc 6 — Admin Dashboard Design Specification

| # | Question | Owner | Target | Status |
| --- | --- | --- | --- | --- |
| OD-AD-01 | User detail UI — drawer (overlay) vs full page | UX + Frontend | Phase 3 Week 3 | Open |
| OD-AD-02 | SAML test step — hard-gated vs skippable | UX + Federation | Phase 3 Week 3 | Open |
| OD-AD-03 | Audit log default density — compact vs comfortable | UX + Persona testing | Phase 3 Week 4 | Open |
| OD-AD-04 | Dashboard density preference — user level vs tenant level | UX + Product | Phase 3 Week 3 | Open |
| OD-AD-05 | Customisable side-nav pinning at MVP vs v1.1 | UX + Frontend | Phase 3 Week 3 | Open |
| OD-AD-06 | Saved audit views at MVP vs v1.1 | UX + Product | Phase 3 Week 2 | Open |
| OD-AD-07 | Stripe Elements vs Stripe Checkout for plan upgrade | Frontend + Billing | Phase 3 Week 4 | Open |
| OD-AD-08 | NDA gate on SOC 2 download — modal accept vs separate signed flow | Compliance + UX | Phase 3 Week 3 | Open |

#### 3.8 Doc 7 — Developer Portal Design Specification

| # | Question | Owner | Target | Status |
| --- | --- | --- | --- | --- |
| OD-DP-01 | Auto-populating client_id in Quickstart Step 2 (requires docs-signin integration) | UX + Frontend | Phase 3 Week 3 | Open |
| OD-DP-02 | Try-It panel — default to sandbox vs always sandbox | UX + Security | Phase 3 Week 3 | Open |
| OD-DP-03 | Public roadmap voting at MVP vs v1.1 | Product + DevRel | Phase 3 Week 2 | Open |
| OD-DP-04 | SOC 2 NDA gate — inline acceptance vs docusign-integrated | Compliance + Legal | Phase 3 Week 3 | Open |
| OD-DP-05 | Migration progress UI — in dashboard only vs also in docs | UX + Product | Phase 3 Week 3 | Open |
| OD-DP-06 | Docs feedback widget — anonymous-only vs optional sign-in | UX + DevRel | Phase 3 Week 4 | Open |

#### 3.9 Doc 8 — White-Label Components

| # | Question | Owner | Target | Status |
| --- | --- | --- | --- | --- |
| OD-WL-01 | Brandable approved font family list breadth | UX + Marketing | Phase 3 Week 2 | Open |
| OD-WL-02 | Custom CSS sandboxing depth (allow-list vs deny-list) | Frontend + Security | Phase 3 Week 4 | Open |
| OD-WL-03 | Per-application branding at MVP vs v1.1 | Product + UX | Phase 3 Week 3 | Open |
| OD-WL-04 | Footer attribution removal — Enterprise contract vs all paid plans | Sales + Product | Phase 3 Week 2 | Open |
| OD-WL-05 | Custom domain DNS-validation mechanism | Frontend + Infrastructure | Phase 3 Week 4 | Open |
| OD-WL-06 | Vue / Svelte / Angular SDKs at MVP vs v1.2 | SDK Eng + Product | Phase 3 Week 2 | Open |

#### 3.10 Doc 9 — Accessibility Compliance Plan

| # | Question | Owner | Target | Status |
| --- | --- | --- | --- | --- |
| OD-AC-01 | Third-party audit vendor (Deque vs TPGi vs Tetralogical) | UX + Compliance | Phase 5 / Phase 7 | Open |
| OD-AC-02 | Tutorial videos at launch — captions required or video-free | Tech Writing + UX | Phase 3 Week 3 | Open |
| OD-AC-03 | Voice-control conformance commitment level | UX + Accessibility Lead | Phase 3 Week 4 | Open |
| OD-AC-04 | Quarterly accessibility report alongside security advisory | Compliance + UX | Phase 3 Week 3 | Open |

#### 3.11 Doc 10 — Mobile & Responsive Design

| # | Question | Owner | Target | Status |
| --- | --- | --- | --- | --- |
| OD-MR-01 | Cloud device testing platform — BrowserStack vs Sauce Labs vs LambdaTest | QA Lead | Phase 3 Week 3 | Open |
| OD-MR-02 | Service worker for offline docs at MVP vs v1.2 | Frontend + Tech Writing | Phase 3 Week 3 | Open |
| OD-MR-03 | Mobile dashboard "Open on desktop" — magic-link transfer vs deep-link copy | UX + Engineering | Phase 3 Week 4 | Open (same as OD-IA-05) |
| OD-MR-04 | Flutter SDK passkey fallback when ASWebAuthenticationSession unavailable | SDK Eng + UX | Phase 3 Week 4 | Open |
| OD-MR-05 | Galaxy Fold (folded 280px) — explicit support vs graceful degradation only | UX + QA | Phase 3 Week 4 | Open |

#### 3.12 Doc 11 — Internationalization & Localization

| # | Question | Owner | Target | Status |
| --- | --- | --- | --- | --- |
| OD-LO-01 | TMS choice — Crowdin vs Lokalise vs Phrase | Localisation Lead | Phase 3 Week 3 | Open |
| OD-LO-02 | Translation vendor selection | Localisation Lead | Phase 3 Week 4 | Open |
| OD-LO-03 | Date format default — `medium` everywhere vs context-aware | UX + Localisation | Phase 3 Week 3 | Open |
| OD-LO-04 | Brazilian Portuguese vs European Portuguese vs both | Localisation + Sales | Phase 3 Week 2 | Open |
| OD-LO-05 | Translate OAuth scope strings or keep as protocol identifiers | UX + Security | Phase 3 Week 3 | Open |
| OD-LO-06 | RTL launch — v1.2 vs sooner | Product + Sales | Phase 3 Week 3 | Open |

#### 3.13 Doc 12 — Usability Testing Plan

| # | Question | Owner | Target | Status |
| --- | --- | --- | --- | --- |
| OD-UT-01 | Unmoderated testing tool — Maze vs UserTesting | UX Researcher | Phase 3 Week 2 | Open |
| OD-UT-02 | Session analysis platform — Lookback vs Dovetail | UX Researcher | Phase 3 Week 2 | Open |
| OD-UT-03 | Production session recording — opt-in tenant vs per-user | UX + Compliance | Phase 4 | Open |
| OD-UT-04 | NPS survey tool — Delighted vs Wootric vs Sprig | UX + CS | Phase 8 | Open |
| OD-UT-05 | Diary studies of Daniel-class migration journeys at MVP vs v1.1 | UX + Product | Phase 3 Week 3 | Open |
| OD-UT-06 | Public sharing of usability findings — blog posts at MVP vs v1.1 | UX + Marketing + Legal | Phase 8 | Open |

---

### 4. Resolution Cadence

The UX Designer convenes a **weekly** Open Decisions review with Product Manager during Phase 3. Decisions resolved are marked `Closed` with a pointer to the resolution (Figma library version, doc revision, or ADR).

### 5. Phase 3 Close Gating

Phase 3 cannot be declared complete (per the [Phase-3-Exit-Checklist.md](Phase-3-Exit-Checklist.md)) while any open decision with target "Phase 3 Week X" or "Phase 3 close" remains unresolved. Items targeting later phases (Phase 4, Phase 5, Phase 7, Phase 8, v1.1+) are tracked here for visibility but do not gate Phase 3 close.

---

### 6. Approvals & Sign-off

| Role | Name | Signature | Date |
| --- | --- | --- | --- |
| UX Designer |  |  |  |
| Product Manager |  |  |  |
| Frontend Engineering Lead |  |  |  |
| Localisation Lead |  |  |  |

---

*This document is version controlled. The register is a living artefact — entries added as decisions are surfaced, closed as decisions are made. Phase 3 close requires every Phase-3-targeted entry to be resolved.*

---

**Qeet ID — Authenticate Everything.** *A Qeet Group Company*
