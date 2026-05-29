# Qeet ID — UX Research Summary & Design Principles

### 1. Document Information

|  |  |
| --- | --- |
| **Document Name** | UX Research Summary & Design Principles |
| **Project Name** | Qeet ID |
| **Parent Company** | Qeet Group |
| **Subsidiary** | Qeet ID (Standalone) |
| **Document Version** | v1.0 |
| **Prepared By** | UX Designer + Product Manager |
| **Date** | May 19, 2026 |
| **Status** | Draft — Pending Stakeholder Sign-off |

---

### 2. Purpose & Scope

This document is the anchor of Phase 3 (UI/UX Design). It distils what Phase 1 told us about users, competitors, and stakeholders into a set of design principles that govern every later Phase 3 deliverable — the design system, component library, information architecture, end-user authentication flows, admin dashboard, developer portal, white-label widgets, accessibility plan, responsive plan, localisation plan, and usability testing plan.

Phase 3 documents that come after this one cite the principles here by name. A design decision in any later document must trace either to a principle in §6, a persona need in §4, a stakeholder finding in §5.1, a competitive position in §5.2, a Non-Functional Requirement, or a Compliance Matrix obligation. A design decision without that lineage is the design equivalent of an architecture decision without an ADR — it is rejected at review.

The audience is the UX Designer, Product Designer, Frontend Lead, Product Manager, Technical Writer, QA Lead, every persona-adjacent stakeholder (Developer Relations, Customer Success, Enterprise Sales), and the CTO.

This document depends on Phase 1 [Persona Documents & Customer Journey Maps](../phase-1/Qeet%20ID%20%E2%80%94%20Persona%20Documents%20%26%20Customer%20Journey%20Map.md), [Stakeholder Map & Interview Findings Report](../phase-1/Qeet%20ID%20%E2%80%94%20Stakeholder%20Map%20%26%20Interview%20Findings%20Report.md), [Competitive Analysis Report & Differentiation Strategy](../phase-1/Qeet%20ID%20%E2%80%94%20Competitive%20Analysis%20Report%20%26%20Differentiation%20Strategy.md), [Non-Functional Requirements](../phase-1/Qeet%20ID%20%E2%80%94%20Non-Functional%20Requirements%20%28NFR%29.md), [Compliance Requirements Matrix](../phase-1/Qeet%20ID%20%E2%80%94%20Compliance%20Requirements%20Matrix.md), and [Feature Prioritization & Product Roadmap](../phase-1/Qeet%20ID%20%E2%80%94%20Feature%20Prioritization%20%26%20Product%20Roadmap.md). It also depends on Phase 2 [Authentication Flow Designs](../phase-2/Qeet%20ID%20%E2%80%94%20Authentication%20Flow%20Designs.md) and [Multi-Tenancy Architecture](../phase-2/Qeet%20ID%20%E2%80%94%20Multi-Tenancy%20Architecture.md).

---

### 3. UX Research Sources

Phase 3 design work is grounded in five concrete research sources, not in opinion or trend-following.

| # | Source | Use |
| --- | --- | --- |
| RS-01 | Phase 1 Persona Documents & Customer Journey Maps | Authoritative persona briefs in §4; journey-stage UX requirements per persona |
| RS-02 | Phase 1 Stakeholder Map & Interview Findings | UX Designer's Section 7.5 brief; Customer Success / Sales / DevRel UX-adjacent concerns |
| RS-03 | Phase 1 Competitive Analysis Report | Auth0 / Okta / Cognito / Entra / Kinde / Hanko / Firebase / Keycloak UX strengths and failure modes |
| RS-04 | Phase 1 NFR §12 (Usability & Accessibility) and Compliance Matrix | Hard requirements that constrain the design space (WCAG 2.1 AA, 10 launch locales, browser support, responsive range) |
| RS-05 | Beta customer interview themes (carried forward to Phase 8 Beta Launch) | Listed here as a planned source — populated in Phase 8; informs v1.1 design iteration, not MVP design |

Sources RS-01..RS-04 are *signed* in Phase 1 and are authoritative today. RS-05 is forward-looking and is named here to make explicit which decisions are deferred until we have production users.

---

### 4. Persona Design Brief

Five personas drive every Phase 3 design decision. The brief below states, in one paragraph, what the design must do for each person and what it must not do. The persona detail is in [Phase 1 Persona Documents](../phase-1/Qeet%20ID%20%E2%80%94%20Persona%20Documents%20%26%20Customer%20Journey%20Map.md); this section is the design-team-facing version.

### 4.1 Arjun — The Solo Developer (24–32)

Arjun ships React / Next.js apps on Vercel, codes in Node.js and Python, and lives in GitHub, Discord, and developer-blog comment threads. His three loudest frustrations are "authentication takes days to build from scratch and weeks to secure properly," "Auth0 and Firebase charge for features Arjun needs before he has revenue," and "configuring OIDC flows, callback URLs, and token validation is overwhelming for a solo dev." Arjun's verbatim ask is: *"I just want auth to work. I don't want to read a 90-page guide before I can show my users a login screen."*

**The design must:** put the working code on the first screen of every Quickstart; default to passkeys + Google as the visible options; expose pricing transparently and prominently before the trial signup ask; produce a confirmable "first login worked" moment within 5 minutes; respect his stack — React, Next.js, Node, Python — as the lead SDK tiles.

**The design must not:** ask for credit card before activation; bury the SDK install or the runnable code; lock examples to an interactive sandbox that breaks copy-paste; ship marketing-heavy doc pages.

### 4.2 Maya — The Startup CTO (28–38)

Maya runs a B2B SaaS engineering team building on React/Next.js, Node or Go, Postgres, and Terraform-on-AWS-or-GCP. Her loudest concerns are "most platforms have per-MAU pricing that becomes unpredictable at growth stage," "choosing the wrong auth tool today means a painful migration later," and "most auth platforms require custom code to handle B2B organization isolation." Verbatim: *"I need auth that I can wire up today and still trust in three years when we're at 10 million users. I don't want to have this conversation again at Series B."*

**The design must:** make multi-tenancy and RBAC visible in the dashboard from the first day of the trial — no "enterprise add-on" reveal later; surface architecture diagrams and capacity claims in the docs alongside code; expose a pricing calculator that supports B2B volume modelling; provide a credible Go SDK in the Quickstart tile set.

**The design must not:** hide enterprise capabilities behind a sales gate; design dashboard screens that imply single-tenant SaaS shape; offer feature comparisons that omit migration story.

### 4.3 Daniel — The Mid-Market Engineering Lead (32–45)

Daniel runs a stack of React, Python and Node services on AWS, with ~200K MAUs already on Firebase Auth. His pains are "moving 200,000 existing users to a new platform without breaking login flows is technically high-risk," "Firebase Auth doesn't support SAML SSO — his biggest customers are asking for it at every renewal," and "no bot detection or anomaly detection at Firebase's basic tier." Verbatim: *"I need a platform that can pass a security review on a Tuesday and close an enterprise deal on a Wednesday. And I need the migration to not be a war story I'm still telling in two years."*

**The design must:** put "Migrate from Firebase Auth" as a first-class link from the homepage and docs; give a migration progress dashboard with phased rollout (5% → 20% → 100%); provide SAML configuration wizards that validate live and never fail silently; produce a Security Trust Center page Daniel can hand to his CISO without writing a covering email.

**The design must not:** require Daniel to file a ticket to obtain the SOC 2 report; surface SAML errors as opaque codes; bury migration tooling under product-marketing copy.

### 4.4 Sandra — The Enterprise IT Admin (38–52)

Sandra lives in Microsoft Entra ID, Active Directory, PowerShell, and the REST API of every identity tool her organisation owns. Her frustrations are "connecting a new CIAM layer to an existing Entra ID infrastructure requires careful SAML/OIDC federation," "without SCIM, user access is managed manually — a source of access over-provisioning and offboarding failure," and "any identity platform that doesn't provide granular audit logs is immediately disqualified." Verbatim: *"I've seen platforms come and go. What I need to know is: will this still be here and supported in five years? And can I show the auditor the logs they're asking for right now?"*

**The design must:** make the audit log viewer best-in-class — searchable, filterable by event-type/actor/target/date, exportable to CSV and JSON, never paginated into uselessness; give SCIM sync a real status surface with errors, not just a "sync enabled" toggle; expose role-based admin permissions (L1 / L2 / L3) so she can scope her L2 team without giving them root; respect her preference for keyboard-driven, density-rich screens.

**The design must not:** apply consumer-friendly sparseness to the admin dashboard at the cost of operator efficiency; truncate audit detail behind hover tooltips; treat SAML / SCIM configuration as an afterthought relative to OAuth.

### 4.5 Omar — The Enterprise CISO (40–55)

Omar runs SIEM, IAM, and PAM tools across multi-cloud, and lands on Qeet ID's Security Trust Center first — long before he ever opens the admin dashboard. His frustrations are "vendors who cannot provide SOC 2 reports, penetration test summaries, or security architecture documentation are immediately disqualified," "no anomaly detection or bot protection in lower-tier auth platforms is unacceptable at enterprise scale," and "for organizations in regulated markets (EU, Middle East, financial services), data residency and sovereignty are non-negotiable." Verbatim: *"Every major breach in the last five years started at the identity layer. My job is to make sure ours doesn't. If your platform can't give me an audit report, a pen test, and a breach notification policy before we sign — we're done."*

**The design must:** give the Security Trust Center the same care given to the admin dashboard; place the SOC 2 report behind a clean NDA gate, not a sales lead form; show data residency by region on a visible map; publish the breach-notification policy and the incident-response process as readable, signed documents; expose the sub-processor list as a single page Omar can subscribe to for change notifications.

**The design must not:** be heavy on marketing on the trust pages; require a sales call to read the security architecture overview; rely on vague language where commitments are needed.

### 4.6 Persona-to-Surface Priority Matrix

| Surface | Arjun | Maya | Daniel | Sandra | Omar |
| --- | --- | --- | --- | --- | --- |
| End-User Auth Pages (login, MFA, passkey) | indirect — his end users | indirect | indirect | indirect | indirect |
| Admin Dashboard | secondary | primary | primary | **primary lead** | tertiary |
| Developer Portal & Docs | **primary lead** | primary | primary | secondary | secondary |
| White-Label Auth Widgets | secondary | primary | primary | secondary | n/a |
| Security Trust Center | secondary | secondary | primary | primary | **primary lead** |
| Pricing & Marketing | primary | **primary lead** | primary | tertiary | tertiary |
| Status Page / Changelog | primary | primary | primary | primary | secondary |

"Primary lead" = the design must optimise for this persona's needs first; trade-offs resolve in their favour. Used heavily in §6 to allocate design weight.

---

### 5. Competitive UX Audit Summary

Phase 1 Competitive Analysis identified the platforms Qeet ID competes with directly. This section restates the findings from a UX lens — what we will learn from, what we will beat, what we will avoid.

### 5.1 Stakeholder Findings — UX-Relevant Quotes

Direct quotes from Section 7.5 of the Stakeholder Findings Report, used verbatim as design constraints:

- *"The developer onboarding experience is the single most important design challenge — if a developer cannot complete their first integration in under 10 minutes, Qeet ID will lose them permanently."*
- *"The admin dashboard must support both technical and non-technical users — IT admins should not need to write code to manage users and roles."*
- *"The login and authentication UI components must be fully customizable — white-label capability is non-negotiable for enterprise customers."*
- *"Accessibility is often deprioritized in identity platforms — Qeet ID should target WCAG 2.1 AA compliance at launch."*
- *"Mobile-first design is essential for authentication flows — the majority of end-user logins happen on mobile devices."*
- *"Build a component library and design system before any frontend development begins."*
- *"Dark mode support should be included from launch."*

UX-adjacent findings from other stakeholders:

- **Customer Success:** *"Onboarding is where most auth platforms lose customers — the first 7 days of a developer's experience are critical."* In-product guided onboarding (not just docs) is named as a requirement.
- **Sales:** Top objection from enterprise prospects is *vendor lock-in risk* — the design must visibly counter this with portability stories on the homepage, docs, and Security Trust Center.
- **Developer Relations:** Generous free tier (10,000 MAUs) and active GitHub / Discord presence must be visible from Day 1 of beta.

### 5.2 Competitor UX Audit

#### Auth0 — Universal Login

**What we learn from Auth0:**
- The "Universal Login" pattern — a hosted, branded auth page that customers can drop into their app — is the right primitive. Qeet ID ships an equivalent (the Hosted Login Pages in Phase 2 §4.19).
- Code-first quickstarts with language tabs are the gold standard for SDK doc structure.
- The Actions / Rules customisation model — extending auth at well-defined hooks — is a powerful pattern we will respect (and ship as v1.5+).

**Where Qeet ID beats Auth0:**
- **Transparent, predictable pricing.** The top Auth0 complaint at scale is surprise billing. Qeet ID publishes simple pricing with a public calculator from Day 1 of beta.
- **Faster Time to First Auth.** Auth0 quickstarts target ~15–30 minutes; Qeet ID targets <5 minutes (UX-01-aligned).
- **Passkey-first defaults.** Auth0 treats passkeys as an opt-in feature. Qeet ID treats them as the recommended primary.
- **Independent roadmap.** Auth0 is part of Okta; Daniel and Maya are sensitive to that. Qeet ID is positioned as standalone-subsidiary with its own roadmap.

#### Okta — Admin Dashboard

**The cautionary tale.** Okta's admin dashboard is the canonical example of an enterprise IAM dashboard that has accreted complexity. From the Competitive Analysis:

- *"UI is dated and not developer-friendly."*
- *"Extremely expensive — pricing escalates rapidly."*
- *"Complex to implement and manage — requires dedicated IT resources."*
- *"Heavy vendor lock-in."*

**What Qeet ID will not do:**
- Layer navigation depths beyond what each persona needs.
- Force common admin tasks (creating an OAuth app, configuring SAML, viewing audit logs) into multi-screen wizards when a single screen would do.
- Ship dated typographic and colour treatments — every surface uses the design system tokens.

**What Qeet ID will do better:**
- Persona-aware density: Sandra gets information-dense screens by default; Arjun and Maya get a lighter default that surfaces complexity progressively.
- Inline guidance in setup wizards (SAML, SCIM, Custom Domain) with live validation rather than the multi-page "submit and pray" pattern.

#### Clerk / Kinde / Hanko — Developer Experience

**What we learn:**
- **Kinde:** Setup under 5 minutes is achievable. Multi-tenancy as a native primitive is a meaningful differentiator. Feature flags integrated into auth is a future direction.
- **Clerk:** Drop-in components with a polished aesthetic resonate with React-first audiences. Conditional UI for passkeys done well.
- **Hanko:** Passwordless-first messaging is on the rise; the design system aesthetic skews towards "developer-grade" rather than "enterprise-grade."

**What Qeet ID learns:** Embeddable React / Next.js components with a small, opinionated API surface is table stakes. We ship our auth widgets in this form (Phase 3 Doc 8).

**Where Qeet ID beats them:** Enterprise depth from Day 1. Kinde and Clerk are excellent at the developer entry but require re-platforming for enterprise (SAML, SCIM at scale, audit, compliance). Qeet ID ships enterprise depth at MVP.

#### AWS Cognito — The Negative Benchmark

Used in the Competitive Analysis as the platform Qeet ID positions itself against most directly: *"Everything AWS Cognito should have been — and everything it's not."*

**What Qeet ID will avoid:**
- Documentation that is dense, API-centric, and assumes deep AWS-IAM literacy.
- A console that requires multiple navigation hops to perform routine tasks.
- UI patterns coupled to a specific cloud vendor.
- Inconsistent UX between flows (Cognito's Hosted UI vs SDK-rendered flows feel like different products).

**What Qeet ID will do instead:**
- A single information architecture across the dashboard, with consistent navigation, consistent table behaviour, consistent empty/error/loading states.
- Documentation that opens with runnable code in six SDK languages on the same page.
- Universal Login pages that look, feel, and behave identically to the SDK-rendered widgets — same components, same tokens.

#### Microsoft Entra — Admin Complexity

**What Qeet ID will avoid:** dense, Microsoft-licensing-coupled admin navigation; documentation aimed at Microsoft consultants; UI that assumes the operator has Entra-specific mental models.

**What Qeet ID learns:** at the very top of the admin dashboard, enterprise customers need a clear, predictable tenant switcher, role view, and audit access. Entra gets these structurally right; the UI surface around them is where complexity has accreted.

#### Firebase Auth — Cloud-Coupling Lock-In

**What Qeet ID will not do:**
- Tie dashboard UX to AWS-specific concepts (Cognito's pattern of leaking Cognito User Pool concepts into the dashboard).
- Hide the migration story.

**What Qeet ID will do:** make "Migrate from Firebase Auth" a top-level navigation item in the docs, with a dashboard that walks Daniel through the phased migration (5% → 20% → 100%) in-product.

#### Keycloak — Self-Hosted Open Source

**What Qeet ID will not do:**
- Inherit Keycloak's realm-first navigation pattern. Tenancy is an architectural primitive at Qeet ID, not an admin-UI artefact.
- Ship a dated component aesthetic.

**What Qeet ID will do:** present a fully managed surface that nonetheless feels familiar to engineers who have used Keycloak — the protocol terminology is the same, the configuration semantics are the same, but the experience is modern.

### 5.3 Competitive Positioning Summary for Phase 3

| Dimension | Bar to clear (best competitor) | Qeet ID target |
| --- | --- | --- |
| Time to First Auth (TTFA) | Kinde ~5 min | <5 min |
| Quickstart code quality | Auth0 + Clerk | Match or exceed |
| Admin dashboard density | Okta (positive density, dated UI) | Match density, modern UI |
| Audit log UX | Okta / Splunk-tier | Splunk-tier + integrated |
| White-label customisation | Auth0 / Clerk | Match + brand validation feedback |
| Passkey UX | Hanko + Clerk | Best-in-class (conditional UI, cross-device QR) |
| Documentation | Auth0 / Stripe | Stripe-tier |
| Pricing transparency | Stripe | Match |
| Security Trust Center | Stripe / Linear | Match |
| Accessibility | Most competitors fail | WCAG 2.1 AA from launch |

---

### 6. The 10 Core Design Principles

These ten principles govern every Phase 3 design decision. Each is referenced by short name (P-01..P-10) throughout the rest of Phase 3.

### P-01 — Developer-First by Default

The single loudest signal from Phase 1 is that developer experience determines adoption (Stakeholder Findings Section 7.5; Persona Arjun; Persona Maya). Every design surface — including the admin dashboard and the Security Trust Center — is built on the assumption that someone technical may need to read it. Plain language is preferred; technical language is precise; no surface is dumbed down at the cost of accuracy.

**Concretely:** Every Quickstart page opens with copy-paste runnable code, not prose. Every dashboard screen is reachable in 2 clicks or fewer from a global command palette (cmd+K). API references use OpenAPI specs as source-of-truth (Phase 2 [API Design Standards](../phase-2/Qeet%20ID%20%E2%80%94%20API%20Design%20Standards.md) §15). Error states show the underlying error code, not a generic "something went wrong."

**Rationale:** Arjun's verbatim ask — *"I just want auth to work"* — and Maya's evaluation behaviour both demand that the design respects technical fluency. Time spent making the design "friendly" at the cost of accuracy is time the user spends in a competitor's docs instead.

### P-02 — Passkey-First, Password-Last

Passkeys are not a feature flag, not a toggle in the dashboard, not an opt-in for enterprise customers. They are the platform's default credential. Every login page, every signup page, every SDK quickstart, every demo, every marketing screenshot leads with the passkey button. Password remains a fallback path — always available, never hidden — but never the default.

**Concretely:** The hosted login page's conditional UI invokes `navigator.credentials.get({mediation: "conditional"})` on focus of the email field, so a returning passkey user authenticates without ever choosing a method (Phase 2 [Auth Flow §11](../phase-2/Qeet%20ID%20%E2%80%94%20Authentication%20Flow%20Designs.md)). The passkey button is the primary action. The "use a password instead" link is a secondary action.

**Rationale:** Competitive differentiator (Competitive Analysis §11) and a deliberate brand commitment ("The future of authentication is passwordless. Qeet ID is already there."). Reinforces Omar's risk reduction (passkeys are phishing-resistant) and Arjun's preferred UX (one tap on a phone).

### P-03 — Mobile-First for End-User Flows

The majority of end-user logins happen on mobile devices (Stakeholder Findings 7.5). End-user authentication pages — login, signup, MFA, passkey, magic link, password reset — are designed at the 320–639px breakpoint first; tablet and desktop are scaled-up adaptations of the mobile composition, not the other way around.

**Concretely:** Touch targets ≥44×44pt (WCAG 2.5.5 AAA and platform guidelines). Single-column layouts. Sticky bottom action bars where appropriate. Native input types (`type=email`, `type=tel`, `autocomplete` attributes) so mobile keyboards optimise for the field.

**Rationale:** NFR UX-05 (mobile responsive 320px–2560px); stakeholder finding direct quote.

### P-04 — Desktop-First for Admin & Developer Surfaces

The admin dashboard and the developer portal are designed at the desktop breakpoint (≥1024px) first. Sandra and Daniel — the primary admin dashboard users — operate at desktop; Arjun and Maya read docs on desktop while integrating. Mobile is a read-only emergency view of the dashboard (per Persona Sandra's "approve a deploy from her phone" scenario), and a fully readable but not fully interactive view of the docs.

**Concretely:** Dashboard layouts assume ≥1024px and adapt down to a degraded read-only mobile mode below 640px. Documentation is fully responsive but optimised for ≥1024px reading.

**Rationale:** Personas Sandra and Daniel; Stakeholder Findings 7.5; NFR §12.

### P-05 — Accessibility is a Feature, Not a Checklist

WCAG 2.1 AA conformance is a launch-blocking requirement (NFR AX-01; Stakeholder Findings 7.5). The accessibility commitment goes beyond conformance: keyboard-first navigation works for every common task (Sandra's preference); contrast meets AA on every text-on-surface combination in both light and dark modes (verified in Phase 3 Doc 2); screen-reader announcements (NVDA, JAWS, VoiceOver, TalkBack) are scripted, not accidental.

**Concretely:** Every component in the library (Phase 3 Doc 3) ships with its accessibility contract — ARIA roles, keyboard interactions, focus management, announcements. Every form input has a programmatically associated label, helper text, and error text. Modals trap focus and return it on dismiss. Skip links are present on every multi-zone page.

**Rationale:** NFR §12.2 (mandatory at launch); Stakeholder Findings 7.5; competitive differentiator (most identity platforms fail accessibility audits).

### P-06 — White-Label Ready, Not White-Label Afterthought

Enterprise customers must be able to brand the end-user authentication experience to match their own product (Charter §5; Feature scope; Stakeholder Sales finding). The design system separates the brand-customisable surface (logo, primary colour, accent, typography from approved set, border radius range, custom domain, email branding) from the locked surface (spacing, type ratio, accessibility-critical contrasts, required UI elements, motion system).

**Concretely:** The hosted login pages, embeddable widgets, and email templates accept brand tokens from the tenant's branding configuration. The admin dashboard's Branding screen previews changes in real time. Contrast validation runs at save time; below-AA combinations warn the admin and explain the consequence.

**Rationale:** Stakeholder Findings 7.5 direct quote: *"white-label capability is non-negotiable for enterprise customers."* Phase 3 Doc 8 is dedicated to this surface.

### P-07 — Show, Don't Tell (Code Examples > Prose)

Documentation pages, dashboard help, and API references show the working artefact (the code, the JSON, the rendered widget) before describing it. Arjun and Maya scan; they do not read. The first element on every Quickstart page is a code block in their language.

**Concretely:** Quickstart pages open with a six-language tab block. API reference endpoints open with a request example and a response example, then the parameters table. Error documentation shows the exact error response shape before the explanation. Configuration screens show the live preview alongside the form.

**Rationale:** Persona Arjun (*"I just want auth to work"*); Persona Maya (technical scan behaviour); Competitive Analysis (Stripe-tier docs as the bar).

### P-08 — Errors Are Designed, Not Improvised

Every error state in every flow is a designed surface. Errors are not the absence of success; they are an opportunity to recover. Error messages include: what happened (plain language), the error code (so a developer can search the docs), the affected field or scope (highlighted in context), the recovery action (a button or link), and a link to relevant documentation.

**Concretely:** Form-field errors appear inline, programmatically associated with the field. Page-level errors use the standard Banner / Alert component (Phase 3 Doc 3). API-side errors surface RFC 7807 problem+json fields including `code` and `docs_url` (Phase 2 [API Design Standards §11](../phase-2/Qeet%20ID%20%E2%80%94%20API%20Design%20Standards.md)). SAML and SCIM error states show the exact protocol-level failure (Daniel's verbatim need: *"never fail silently"*).

**Rationale:** Persona Daniel (verbatim: SAML errors must be specific); Persona Sandra (audit clarity); P-01 (developer-first); Competitive analysis (Cognito's opaque errors are the canonical anti-pattern).

### P-09 — Speed Is a Design Decision (Perceived Performance)

Performance budgets from Phase 2 NFR are non-negotiable (PF-01..PF-20). Beyond raw latency, perceived performance is a design responsibility: skeleton screens preferred over spinners on the first render of any dashboard view; optimistic UI updates on mutations where rollback is safe; in-place skeleton replacement (no layout shift) on data load; deferred loading of below-the-fold content on doc pages.

**Concretely:** Every dashboard screen ships a skeleton state in the Component Library (Phase 3 Doc 3). Every data table uses cursor-based pagination (Phase 2 [API §9](../phase-2/Qeet%20ID%20%E2%80%94%20API%20Design%20Standards.md)) so paging is constant-time. Every image and font is preloaded or lazy-loaded by design intent.

**Rationale:** NFR PF-17 (admin dashboard TTFB), PF-20 (dev portal TTFB), UX-01 (passkey login <5s), UX-02 (password + MFA <30s); competitive position (Okta's slow dashboard is the cautionary tale).

### P-10 — Trust Through Transparency

Authentication is a trust product. Qeet ID's design surfaces are the medium of that trust. The Security Trust Center is built like a product, not a marketing page. The status page is real, live, and customer-subscribable. The changelog is honest about breaking changes. The audit log is exportable in full to the customer's SIEM. Pricing is published with a calculator.

**Concretely:** Omar's persona drives the Security Trust Center design (Phase 3 Doc 7). Status, changelog, roadmap, sub-processor list, breach notification policy, incident response process, DPA template are all visible at canonical URLs without sales gates. The SOC 2 report is downloadable on NDA acceptance, not on a sales-team callback.

**Rationale:** Persona Omar verbatim; Stakeholder Sales finding (*"vendor lock-in" is the top objection — countered by transparency*); Competitive differentiator ("transparent, predictable pricing" is in the differentiation strategy).

---

### 7. Design Tone & Voice Guidelines

The Qeet ID voice is *"developer talking to developer."* Confident, technical, direct. Avoids hype. Avoids product-marketing prose on technical surfaces (and reserves marketing voice for marketing pages).

| Quality | Yes | No |
| --- | --- | --- |
| Tone | Confident; direct; respects the reader's time | Cute; chatty; hype-driven |
| Length | Short. One idea per sentence. | Run-on; nested clauses |
| Vocabulary | Standard technical terms (SAML, SCIM, OIDC, scope, claim, JWKS, mTLS) without re-explanation in primary nav | Avoiding technical terms; circumlocution |
| Punctuation | Plain. Sentence case in UI labels. | Excessive exclamation; ALL CAPS; gratuitous emoji |
| Examples in docs | Realistic — `org_acme`, `user_8f3...`, `tenant.example.com` | `foo`, `bar`, `XXXXXXXX` |
| Error voice | Plain past tense ("We could not verify the code.") | Cutesy ("Oops!"); blame-the-user ("You did this wrong.") |

### 7.1 Empty State Voice

Empty states open with a one-line statement of what is empty and a single primary action. Optional secondary text is one sentence at most.

> Sandra opens the SAML connections list with no connections configured.
> Empty state title: **No SAML connections yet.**
> Body: Connect Microsoft Entra ID, Okta, or any SAML 2.0 IdP to enable enterprise SSO.
> Primary action: **Add SAML connection** (button)
> Secondary link: Read the SAML setup guide

### 7.2 Error Voice

Daniel hits a SAML metadata import failure.
> Error title: **Could not parse metadata XML.**
> Body: The metadata at `https://login.acme.example/metadata` returned `<saml:EntityDescriptor>` with no `SingleSignOnService` element. Add a `SingleSignOnService` binding to the IdP metadata and try again. (Error code: `saml_metadata_missing_sso_endpoint`).
> Action: **Retry import** · Read SAML troubleshooting guide

### 7.3 Success Voice

Maya completes her first tenant configuration.
> Success title: **Tenant `acme` is live.**
> Body: Test the integration with the React SDK or the Node SDK to see your first login.
> Primary action: **Open Quickstart** · Secondary: Invite a teammate

### 7.4 Anti-Examples

- *"Whoops! Looks like something went a bit sideways. 🙈 Try again or shoot us a message!"* — violates P-08; violates tone; violates accessibility (emoji as sole indicator).
- *"You have not yet configured any single sign-on connections. To configure SAML or OIDC, click 'Add Connection' below to begin the configuration wizard."* — verbose; tells the user what the button says.
- *"Authentication, simplified."* — marketing voice on a technical surface.

---

### 8. Design Anti-Patterns — What Qeet ID Will Never Do

The anti-pattern list below is enforced in design review. Each entry is a thing Qeet ID designers will refuse to ship.

**AP-01 — Hidden critical actions.** Common actions (revoke API key, view audit log, configure SAML, view billing) must be reachable in ≤2 clicks from any persona's normal context. Burying them in setting drawers is rejected.

**AP-02 — Friendly-but-vague errors.** "Something went wrong" without an error code and a recovery path is rejected. See P-08.

**AP-03 — Modal-on-modal stacking.** A modal opening another modal is rejected. Use a drawer-over-modal pattern or restructure the flow.

**AP-04 — Disabled buttons without explanation.** A disabled button must have a tooltip or inline message explaining why it is disabled (so the user can fix it).

**AP-05 — Empty data tables without primary actions.** A list with no rows must show an empty state with an actionable primary CTA (see §7.1).

**AP-06 — Confirmation dialogs for safe actions.** "Are you sure you want to view this?" is rejected. Confirmation is reserved for irreversible or high-impact actions.

**AP-07 — Inline editing without explicit save.** Auto-save is fine for genuinely safe operations (e.g., note fields); critical configuration changes (SAML, SCIM, role definitions) require explicit submission.

**AP-08 — Toast notifications as the only error surface.** Toasts are ephemeral. Errors that the user must act on appear in-context (form-field error, page banner), not solely in a toast.

**AP-09 — Pagination by page number with unknown total.** Cursor pagination is the platform standard (Phase 2 API §9). "Page 1 of ???" is rejected.

**AP-10 — Sample data with `foo` / `bar`.** Use realistic placeholder data — `org_acme`, `alice@example.com`, `user_01HX...` — so users can mentally map to their own.

**AP-11 — Locking customisation that should be free.** Branding (logo, primary colour) must be available to all paid tiers, not Enterprise-only. Charging for whitelabel-light is a known competitor pattern Qeet ID will not replicate.

**AP-12 — Marketing copy on technical surfaces.** Dashboard screens, docs, status pages, and security pages use neutral, technical voice. Marketing voice lives on `/`, `/pricing`, and the blog.

**AP-13 — Asking for credit card before activation.** The free tier requires no payment method (Charter §5). Asking blocks Arjun's trial.

**AP-14 — Multi-screen wizards for single-form tasks.** A SAML connection is a five-section configuration, but it is one screen with sections, not five sequential screens with a back button. The exception is the literal multi-step provisioning wizard (Custom Domain Setup, where DNS propagation gates the next step).

**AP-15 — Sole-color signalling.** Status, error, and required-field indicators never rely on colour alone (NFR AX-06).

---

### 9. Design Success Metrics

The metrics below are how Phase 3 declares success. Each is tracked from launch.

| # | Metric | Launch target | 6-month target | 12-month target | Source |
| --- | --- | --- | --- | --- | --- |
| DSM-01 | Time to First Auth (TTFA) | <10 min | <7 min | <5 min | NFR DSAT §5.5; KPI 5.5 |
| DSM-02 | Passkey registration completion (of prompted users) | >70% | >75% | >80% | NFR UX-03 |
| DSM-03 | Password reset completion rate | >90% | >92% | >94% | NFR UX-04 |
| DSM-04 | Developer Satisfaction Score (DSAT, out of 5) | 4.0 | 4.3 | 4.5 | Business Goals §5.5 |
| DSM-05 | Documentation Satisfaction | 4.0 | 4.3 | 4.5 | Business Goals §5.5 |
| DSM-06 | WCAG 2.1 AA conformance | 100% | 100% | 100% | NFR AX-01 |
| DSM-07 | Admin dashboard page-level satisfaction (per-page thumbs-up rate) | >70% | >75% | >80% | Phase 3 measurement |
| DSM-08 | Audit log search success rate (Sandra's primary task) | >95% | >97% | >98% | Phase 3 measurement |
| DSM-09 | SAML setup wizard completion rate (Daniel's primary task) | >85% | >90% | >92% | Phase 3 measurement |
| DSM-10 | Security Trust Center "found what I needed" rate | >85% | >90% | >92% | Phase 3 measurement |

### 9.1 Measurement Mechanism

| Metric class | Captured how |
| --- | --- |
| Behavioural funnel (DSM-01, DSM-02, DSM-03, DSM-09) | Product analytics events emitted by the relevant flows; sampled per Phase 2 [Observability §11](../phase-2/Qeet%20ID%20%E2%80%94%20Observability%20Architecture.md) |
| Survey (DSM-04, DSM-05) | In-product satisfaction survey at session-end of relevant flows |
| Page-level signal (DSM-07, DSM-10) | Per-page thumbs-up / thumbs-down on docs and dashboard help (Phase 3 Doc 7 §15) |
| Audit (DSM-06) | Continuous axe-core in CI plus annual third-party audit (Phase 3 Doc 9) |

---

### 10. Open Design Decisions From This Document

The decisions below cannot be resolved from Phase 1 or Phase 2 alone. They are surfaced here and tracked in [Open-Design-Decisions-Register.md](Open-Design-Decisions-Register.md).

| # | Question | Owner | Target |
| --- | --- | --- | --- |
| OD-UX-01 | Final voice & tone style guide approval (this doc §7) | UX Designer + Marketing | Phase 3 Week 2 |
| OD-UX-02 | Brand colour direction: cooler trust-blue vs warmer differentiating teal/orange accent — pending Qeet Group Marketing | UX Designer + Marketing | Phase 3 Week 1 |
| OD-UX-03 | Brand voice: whether the same voice applies on the homepage and pricing page (marketing surfaces) | UX Designer + Marketing | Phase 3 Week 2 |
| OD-UX-04 | Whether the audit log search supports natural language queries at MVP or only structured filters | UX Designer + Product | Phase 3 Week 3 |
| OD-UX-05 | Whether the in-product guided onboarding (Customer Success ask) ships at MVP or v1.1 | Product Manager | Phase 3 Week 2 |

---

### 11. Cross-References

- Persona detail and customer journeys: [Phase 1 Persona Documents & Customer Journey Maps](../phase-1/Qeet%20ID%20%E2%80%94%20Persona%20Documents%20%26%20Customer%20Journey%20Map.md)
- Stakeholder UX findings (Section 7.5): [Phase 1 Stakeholder Map & Interview Findings](../phase-1/Qeet%20ID%20%E2%80%94%20Stakeholder%20Map%20%26%20Interview%20Findings%20Report.md)
- Competitor positioning: [Phase 1 Competitive Analysis](../phase-1/Qeet%20ID%20%E2%80%94%20Competitive%20Analysis%20Report%20%26%20Differentiation%20Strategy.md)
- Accessibility, mobile, and i18n constraints: [Phase 1 NFR §12](../phase-1/Qeet%20ID%20%E2%80%94%20Non-Functional%20Requirements%20%28NFR%29.md)
- MVP feature inventory: [Phase 1 Feature Prioritization](../phase-1/Qeet%20ID%20%E2%80%94%20Feature%20Prioritization%20%26%20Product%20Roadmap.md)
- Authentication flow choreography (engineering source-of-truth): [Phase 2 Authentication Flow Designs](../phase-2/Qeet%20ID%20%E2%80%94%20Authentication%20Flow%20Designs.md)
- Tenancy model that shapes the dashboard's tenant switcher: [Phase 2 Multi-Tenancy Architecture](../phase-2/Qeet%20ID%20%E2%80%94%20Multi-Tenancy%20Architecture.md)
- API contract that shapes the dashboard's behaviour and the documentation: [Phase 2 API Design Standards](../phase-2/Qeet%20ID%20%E2%80%94%20API%20Design%20Standards.md)
- Subsequent Phase 3 documents that operationalise this one: Doc 2 (Design System), Doc 3 (Components), Doc 4 (IA), Doc 5 (End-user flows), Doc 6 (Admin Dashboard), Doc 7 (Developer Portal), Doc 8 (White-Label), Doc 9 (Accessibility), Doc 10 (Responsive), Doc 11 (i18n), Doc 12 (Usability Testing)

---

### 12. Approvals & Sign-off

| Role | Name | Signature | Date |
| --- | --- | --- | --- |
| UX Designer |  |  |  |
| Product Designer |  |  |  |
| Product Manager |  |  |  |
| Frontend Engineering Lead |  |  |  |
| Technical Writer Lead |  |  |  |
| Developer Relations Lead |  |  |  |
| Customer Success Lead |  |  |  |
| Marketing Lead (voice & brand alignment) |  |  |  |
| Solution Architect (cross-Phase consistency) |  |  |  |
| CTO |  |  |  |

---

*This document is version controlled. Visual updates in Figma do not require re-sign-off, but changes to the design principles in §6, the persona briefs in §4, the success metrics in §9, or the anti-pattern list in §8 require Solution Architect, Product Manager, and UX Designer review.*

---

**Qeet ID — Authenticate Everything.** *A Qeet Group Company*
