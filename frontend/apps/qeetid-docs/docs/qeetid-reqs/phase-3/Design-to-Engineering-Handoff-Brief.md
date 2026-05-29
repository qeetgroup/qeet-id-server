# Qeet ID — Design-to-Engineering Handoff Brief

### 1. Document Information

|  |  |
| --- | --- |
| **Document Name** | Design-to-Engineering Handoff Brief |
| **Project Name** | Qeet ID |
| **Parent Company** | Qeet Group |
| **Subsidiary** | Qeet ID (Standalone) |
| **Document Version** | v1.0 |
| **Prepared By** | UX Designer + Frontend Engineering Lead |
| **Date** | May 19, 2026 |
| **Status** | Draft — Pending Phase 3 close |

---

### 2. Purpose

This is a **2-page summary** the Frontend Engineering Lead uses as the entry point into Phase 4 (MVP Development). It points to where each design contract lives. It does not duplicate the contracts — it points to them.

If a Phase 4 engineer reads only one Phase 3 document, this is it.

---

### 3. The Bottom Line

Qeet ID ships:

- A **token-driven design system** (Document 2) implemented as `@qeetify/design-tokens` npm package, `qeetify_design_tokens` pub package, and Figma variables.
- A **component library** (Document 3) implemented as `@qeetify/ui` (React + Next.js), `qeetify_ui` (Flutter), and a small HTML/CSS subset for hosted login pages and email templates.
- A set of **screen-level designs** (Documents 5–7) built from those components.
- An **embeddable widget package** (Document 8) — `@qeetify/react`, `@qeetify/nextjs`, `qeetify_flutter` — that wraps the component library for customer apps.
- **Accessibility (Document 9), mobile (Document 10), i18n (Document 11), and testing (Document 12)** plans that apply uniformly across all of the above.

The launch quality bars are:

- **WCAG 2.1 AA conformance** — non-negotiable; blocks release.
- **Time to First Auth ≤5 minutes p50** — measured against the Quickstart funnel.
- **Passkey registration completion ≥70%** of prompted users.
- **Latency budgets** — Doc 2 §7 (`duration.*`), Phase 2 NFR §4.4.
- **Mobile responsiveness** 320–2560px — every screen, every component.
- **10 launch languages** for end-user surfaces — Doc 11.
- **Light + dark theme** — every surface.

---

### 4. Engineering Contracts — Where to Find Them

| Engineering question | Authoritative document |
| --- | --- |
| What colour, font, spacing, radius, motion, z-index values? | [Doc 2 — Design System Foundations & Tokens](Qeet ID%20%E2%80%94%20Design%20System%20Foundations%20%26%20Tokens.md) |
| What component does this design call for, and what props does it expose? | [Doc 3 — Component Library Specification](Qeet ID%20%E2%80%94%20Component%20Library%20Specification.md) |
| Where does this URL go? What's the navigation pattern? | [Doc 4 — Information Architecture & Navigation](Qeet ID%20%E2%80%94%20Information%20Architecture%20%26%20Navigation.md) |
| What screens does the end-user login flow comprise? | [Doc 5 — End-User Authentication Flow Designs](Qeet ID%20%E2%80%94%20End-User%20Authentication%20Flow%20Designs.md) |
| What does the admin dashboard look like screen by screen? | [Doc 6 — Admin Dashboard Design Specification](Qeet ID%20%E2%80%94%20Admin%20Dashboard%20Design%20Specification.md) |
| What does the developer portal look like? | [Doc 7 — Developer Portal Design Specification](Qeet ID%20%E2%80%94%20Developer%20Portal%20Design%20Specification.md) |
| What can customers customise? What's locked? | [Doc 8 — Embeddable Auth UI Components (White-Label)](Qeet ID%20%E2%80%94%20Embeddable%20Auth%20UI%20Components%20%28White-Label%29.md) |
| What's the accessibility contract for this component? | [Doc 3 §10 + Doc 9 — Accessibility Compliance Plan](Qeet ID%20%E2%80%94%20Accessibility%20Compliance%20Plan%20%28WCAG%202.1%20AA%29.md) |
| How does this work on mobile? | [Doc 10 — Mobile & Responsive Design Specification](Qeet ID%20%E2%80%94%20Mobile%20%26%20Responsive%20Design%20Specification.md) |
| How does this work in Spanish / German / Japanese? | [Doc 11 — Internationalization & Localization Design](Qeet ID%20%E2%80%94%20Internationalization%20%26%20Localization%20Design.md) |
| How do we know it works? | [Doc 12 — Usability Testing Plan](Qeet ID%20%E2%80%94%20Usability%20Testing%20Plan%20%26%20Findings%20Framework.md) |
| Why was this design chosen? | [Doc 1 — UX Research Summary & Design Principles](Qeet ID%20%E2%80%94%20UX%20Research%20Summary%20%26%20Design%20Principles.md) |

---

### 5. The Non-Negotiables

Engineering work that violates any of the following is rejected at code review.

| Rule | Source |
| --- | --- |
| Tokens — never hard-coded colour / font-size / spacing / duration in component code | Doc 2 §3 |
| Component library — every interactive UI element uses the published component, not a bespoke one | Doc 3 §3 |
| Accessibility — every PR passes axe-core CI, the keyboard walkthrough, and the no-PII-in-logs check | Doc 9 §16, §20 |
| Passkey-first — every login surface leads with the passkey button; password is a secondary path | Doc 1 P-02; Doc 5 §3 FP-01 |
| Anti-enumeration — login / signup / recovery responses do not differentiate "user exists" vs "user does not" | Doc 5 §3 FP-06 |
| Refresh-token rotation — atomic UPDATE; reuse detection alerts only for the first 30 days post-launch | Phase 2 IdP Core §10.3 |
| Error format — RFC 7807 (`application/problem+json`) with `code` and `requestId` | Phase 2 API §11 |
| Tenant context — derived from JWT claim, never trusted from client headers | Phase 2 Multi-Tenancy §11 |
| URL versioning — `/v1/*`; breaking changes require new major version with 12-month overlap | Phase 2 API §13 |
| OpenAPI 3.1 spec — single source of truth for API reference; CI fails on drift | Phase 2 API §15 |
| Cursor pagination — never offset pagination | Phase 2 API §9 |
| Idempotency-Key support on every state-changing endpoint | Phase 2 API §7 |
| HTTPS-only; HSTS; TLS 1.2 minimum, TLS 1.3 preferred | Phase 2 Security §7 |
| Sandboxed custom CSS (Enterprise) — disallowed rules silently stripped | Doc 8 §17 |

---

### 6. The First Sprint of Phase 4

Recommended sequence for the first sprint:

1. **Set up the token pipeline** — token file → CSS variables, JSON, Dart. Verify in a sample React app.
2. **Implement five atoms first** — Button, Input, Form Field, Label, Helper Text. These unlock everything else.
3. **Implement the Auth Layout template** — and the basic login screen. This proves the end-to-end works.
4. **Wire up the API client** to talk to the staging Token Service (Phase 2 service is in concurrent development).
5. **Run the first end-user auth flow** (passkey conditional UI) end-to-end. Validate the Quickstart works.

After this proof-of-concept sprint, parallelise across:
- Component library completion (Team Frontend).
- Admin dashboard scaffolding (Team Frontend + Team Experience).
- Developer portal (Tech Writing + Team Frontend).
- SDK packages (SDK Engineering).
- Embeddable widgets (SDK Engineering).
- Flutter SDK (Mobile Engineering).

---

### 7. Cross-Phase Dependencies

| Phase 4 work | Depends on Phase 2 / 3 |
| --- | --- |
| Hosted login pages | Phase 2 Auth Service (svc-auth), Token Service (svc-token), Tenant Service (svc-tenant), Microservices §4 |
| Admin dashboard | Every backend microservice |
| Developer portal | OpenAPI spec from Phase 2 API §15; Phase 2 Microservices catalogue |
| SDK packages | Phase 2 API endpoints + this Phase 3 component library |
| Embeddable widgets | Hosted login pages + SDK + Phase 2 Tenant Service branding config |
| Flutter SDK | Phase 2 OAuth flows + this Phase 3 component library (Flutter implementation) |
| Email templates | Phase 2 Notification Service + this Phase 3 §11 i18n |

---

### 8. Critical Performance Budgets

| Surface | TTFB | TTI | JS bundle (gzip) |
| --- | --- | --- | --- |
| Hosted login page | <500ms | <2s on 3G | <30 KB |
| Embeddable login widget | n/a | <500ms after host paint | <60 KB |
| Admin dashboard initial | <500ms (PF-17) | <1.5s | <120 KB |
| Developer portal page | <250ms (PF-20) | <1.5s | <40 KB |
| Embedded React widget code-split | n/a | lazy-load on render | <60 KB |

Each is enforced by CI bundle-size check + Lighthouse CI.

---

### 9. The Quality Bars

Before any Phase 4 PR merges, it must:

- ✅ Pass type check, lint, unit tests.
- ✅ Pass axe-core (no critical / serious issues).
- ✅ Pass keyboard walkthrough (for new components).
- ✅ Match the token system (no hard-coded design values).
- ✅ Match the OpenAPI spec (no client drift).
- ✅ Include tests for tenant isolation (no cross-tenant leakage).
- ✅ Include English source strings extracted to messages file (no hard-coded UI copy).
- ✅ Include visual regression test for affected components.

---

### 10. Phase 4 Backlog Sources

The Phase 4 backlog is sourced from:

- Phase 3 Open Design Decisions Register — every "Phase 3 → Phase 4 carry" item.
- Phase 3 Usability Testing P2 / P3 findings.
- Phase 2 ADRs that flagged Phase 4 work.
- Compliance Matrix Tier 1 requirements not yet implemented.

---

### 11. The Single Source of Truth Hierarchy

When two documents disagree:

1. **Phase 1 NFR / Compliance / Persona / Protocol** — the requirements.
2. **Phase 2 architecture** — the system contract.
3. **This Phase 3 baseline** — the design contract.
4. **Figma library** — the visual artefact (visual updates do not require Phase 3 re-sign-off unless they change a documented contract).
5. **Source code** — implements the above.

If source code disagrees with this document, the source code is wrong. If this document disagrees with Phase 2, this document is wrong. If Phase 2 disagrees with Phase 1, Phase 2 needs an ADR explaining the deviation.

---

### 12. Contacts

| Concern | Contact |
| --- | --- |
| Token system, components, screen designs | UX Designer |
| Implementation, code quality, performance | Frontend Engineering Lead |
| SDK packages | SDK Engineering Lead |
| Flutter SDK | Mobile (Flutter) SDK Lead |
| Accessibility | Accessibility Lead |
| Docs, copy, voice & tone | Technical Writer Lead |
| Localisation | Localisation Lead |
| API contracts (Phase 2) | Backend Engineering Lead |
| Architecture (cross-phase) | Solution Architect |
| Cross-cutting decisions | UX Designer + Frontend Lead (chair) |

---

### 13. Approvals & Sign-off

| Role | Name | Signature | Date |
| --- | --- | --- | --- |
| UX Designer |  |  |  |
| Frontend Engineering Lead |  |  |  |
| Product Manager |  |  |  |
| Solution Architect |  |  |  |

---

*This document is version controlled. It is intentionally brief — when it gets longer than 2 printed pages, the additional detail belongs in one of the 12 Phase 3 documents, not here.*

---

**Qeet ID — Authenticate Everything.** *A Qeet Group Company*
