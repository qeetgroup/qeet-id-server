# Qeet ID — Developer Portal Design Specification

### 1. Document Information

|  |  |
| --- | --- |
| **Document Name** | Developer Portal Design Specification |
| **Project Name** | Qeet ID |
| **Parent Company** | Qeet Group |
| **Subsidiary** | Qeet ID (Standalone) |
| **Document Version** | v1.0 |
| **Prepared By** | UX Designer + Technical Writer |
| **Date** | May 19, 2026 |
| **Status** | Draft — Pending Stakeholder Sign-off |

---

### 2. Purpose & Scope

This document specifies the design of the Qeet ID Developer Portal — the public-facing surface that hosts the documentation, API reference, SDK reference, status page, public roadmap, public changelog, Security Trust Center, blog, pricing page, and community pointers. It is the surface that determines whether Arjun chooses Qeet ID in fifteen minutes or chooses Auth0 in twenty.

Per Phase 1 Stakeholder Findings: *"The developer onboarding experience is the single most important design challenge — if a developer cannot complete their first integration in under 10 minutes, Qeet ID will lose them permanently."* Per [Persona Arjun §4.1](Qeet ID%20%E2%80%94%20UX%20Research%20Summary%20%26%20Design%20Principles.md): *"I just want auth to work. I don't want to read a 90-page guide before I can show my users a login screen."* The Developer Portal is where Arjun decides whether that promise is real.

The competitive bar is set by Stripe's docs, Vercel's docs, and Auth0's quickstarts. The negative benchmark is AWS Cognito and Microsoft Entra documentation. Qeet ID aims at the former.

The audience is the UX Designer, Technical Writer Lead, Developer Relations Lead, Frontend Engineering Lead, SDK Engineering team, Marketing Lead (for Security Trust Center and Pricing), and the Compliance Officer (for Security Trust Center content).

This document depends on every Phase 3 document preceding it ([Doc 1 Principles](Qeet ID%20%E2%80%94%20UX%20Research%20Summary%20%26%20Design%20Principles.md), [Doc 2 Tokens](Qeet ID%20%E2%80%94%20Design%20System%20Foundations%20%26%20Tokens.md), [Doc 3 Components](Qeet ID%20%E2%80%94%20Component%20Library%20Specification.md), [Doc 4 IA](Qeet ID%20%E2%80%94%20Information%20Architecture%20%26%20Navigation.md)) and on Phase 1 [Compliance Matrix §11.2](../phase-1/Qeet%20ID%20%E2%80%94%20Compliance%20Requirements%20Matrix.md) (Security Trust Center content list) and [Phase 2 API Design Standards §17](../phase-2/Qeet%20ID%20%E2%80%94%20API%20Design%20Standards.md) (OpenAPI 3.1 spec as the source of truth for API reference).

---

### 3. Developer Portal Design Principles

**DP-01 — Under 5 Minutes to First Auth.** The Quickstart page is the most-tested, most-iterated, most-loved page on the portal. Everything else exists in service of it.

**DP-02 — Code-First.** Every page that can show working code does so. The first non-trivial element on the Quickstart, on every Guide, on every API Reference endpoint, on every SDK reference method — is runnable code.

**DP-03 — Copy-Paste-Ready.** Every code block has a working copy button. The copied content is *exactly* what runs — no truncated comments, no `<your-id-here>` placeholders unless the placeholder is explicitly required (and then it's commented as such).

**DP-04 — Searchable.** A developer who knows what they want types `cmd+K` (in the dashboard) or `/` (in the portal) and finds it. Search is the universal fallback (per IA-06).

**DP-05 — Versioned.** Docs follow the API. v1, v2 coexist for the 12-month deprecation window (NFR AR-03).

**DP-06 — Language-Agnostic Navigation, Language-Specific Content.** The docs tree does not branch by language; the *code samples within docs* branch by language via the Code Tab Group ([Component Library §5.4](Qeet ID%20%E2%80%94%20Component%20Library%20Specification.md)). One page covers six SDK languages; the user's selected language persists.

**DP-07 — Linkable Headings.** Every H2 and H3 has a stable anchor. Sharing a deep link to a sub-section is a one-click action.

**DP-08 — Migration Front-and-Centre.** "Migrate from Firebase Auth", "Migrate from Auth0", "Migrate from AWS Cognito" are top-level destinations from the homepage and the docs nav. Daniel's verbatim need.

**DP-09 — Transparent.** Status, roadmap, changelog, Security Trust Center are public — no sales gate. Trust is the product.

**DP-10 — Feedback Loop.** Every page has a feedback affordance (per-page thumbs up/down). Doc gaps are surfaced weekly to Technical Writing.

---

### 4. Persona Priorities for the Portal

| Persona | Frequency on portal | Primary destinations |
| --- | --- | --- |
| **Arjun (Solo Developer) — primary lead** | Daily during integration; weekly thereafter | Quickstart, SDK reference, guides for social login + passkeys |
| **Maya (Startup CTO)** | Weekly during eval; less after | Multi-tenancy concept, RBAC concept, pricing, architecture diagrams |
| **Daniel (Mid-Market Eng Lead)** | Heavy during migration; episodic after | Migration guides, SAML guide, SIEM export guide, Security Trust Center |
| **Sandra (Enterprise IT Admin)** | Occasional | SAML guide, SCIM guide, audit export, Security Trust Center |
| **Omar (CISO) — primary lead for Trust Center** | First contact + episodic | Security Trust Center (entirely) |

Design weight: Arjun's needs win for Quickstart, SDK reference, and guides. Daniel's needs win for migration guides. Omar's needs win for the Security Trust Center.

---

### 5. Information Architecture

Recap from [Doc 4 §7.1](Qeet ID%20%E2%80%94%20Information%20Architecture%20%26%20Navigation.md). The portal's top-level surfaces (in nav order):

| Surface | Path | Owner |
| --- | --- | --- |
| Docs | `/docs` | Technical Writer + UX |
| API Reference | `/api` (subset of `/docs/api`) | Technical Writer (auto-generated from OpenAPI) |
| SDKs | `/sdks` | SDK Engineering + Technical Writer |
| Pricing | `/pricing` | Marketing + Product |
| Status | `/status` | SRE |
| Changelog | `/changelog` | DevRel + Product |
| Roadmap | `/roadmap` | Product |
| Security | `/security` (Trust Center) | Compliance + Security + UX |
| Blog | `/blog` | DevRel + Marketing |
| Community | `/community` | DevRel |

Within `/docs`, the sub-tree is per [Doc 4 §7.1](Qeet ID%20%E2%80%94%20Information%20Architecture%20%26%20Navigation.md): Quickstart → Concepts → Guides → API Reference → SDKs → Migration → Examples → Reference.

---

### 6. Quickstart Page — The Most Important Page on the Portal

The Quickstart is where Arjun makes his decision. Every other page on the portal exists to support this one. The goal: from `/docs/quickstart` to "logged in" in five minutes.

### 6.1 Quickstart Structure

Route: `/docs/quickstart` (default) with per-language variants `/docs/quickstart/{react,nextjs,node,python,flutter,go}`.

```
   ┌─────────────────────────────────────────────────────────────────────┐
   │                                                                     │
   │  Quickstart                                                         │
   │  Add authentication to your app in under 5 minutes.                 │
   │                                                                     │
   │  ┌─React*─┬─Next.js─┬─Node.js─┬─Python─┬─Flutter─┬─Go─┐             │
   │  │                                                    │             │
   │  │   1. Install the SDK                               │             │
   │  │                                                    │             │
   │  │   ┌────────────────────────────────────────────┐   │             │
   │  │   │ bash                              [Copy]   │   │             │
   │  │   │ npm install @qeetify/react                 │   │             │
   │  │   └────────────────────────────────────────────┘   │             │
   │  │                                                    │             │
   │  │   2. Get your client ID                            │             │
   │  │                                                    │             │
   │  │   In your Qeet ID dashboard, create an             │             │
   │  │   application. Copy the client ID.                 │             │
   │  │                                                    │             │
   │  │   ┌────────────────────────────────────────────┐   │             │
   │  │   │ .env                              [Copy]   │   │             │
   │  │   │ QEETIFY_DOMAIN=acme.qeetify.com            │   │             │
   │  │   │ QEETIFY_CLIENT_ID=client_app_42            │   │             │
   │  │   └────────────────────────────────────────────┘   │             │
   │  │                                                    │             │
   │  │   3. Wrap your app with the Provider                │             │
   │  │                                                    │             │
   │  │   ┌────────────────────────────────────────────┐   │             │
   │  │   │ tsx                              [Copy]    │   │             │
   │  │   │ import { QeetifyProvider } from '@qee…';   │   │             │
   │  │   │                                            │   │             │
   │  │   │ export function App() {                    │   │             │
   │  │   │   return (                                 │   │             │
   │  │   │     <QeetifyProvider                       │   │             │
   │  │   │       domain={...}                         │   │             │
   │  │   │       clientId={...}                       │   │             │
   │  │   │     >                                      │   │             │
   │  │   │       <YourApp />                          │   │             │
   │  │   │     </QeetifyProvider>                     │   │             │
   │  │   │   );                                       │   │             │
   │  │   │ }                                          │   │             │
   │  │   └────────────────────────────────────────────┘   │             │
   │  │                                                    │             │
   │  │   4. Drop in the login button                       │             │
   │  │                                                    │             │
   │  │   ┌────────────────────────────────────────────┐   │             │
   │  │   │ tsx                              [Copy]    │   │             │
   │  │   │ import { LoginButton } from '@qeetify…';   │   │             │
   │  │   │                                            │   │             │
   │  │   │ <LoginButton>Sign in</LoginButton>         │   │             │
   │  │   └────────────────────────────────────────────┘   │             │
   │  │                                                    │             │
   │  │   5. Try it                                         │             │
   │  │                                                    │             │
   │  │   Run your app. Click Sign in. You'll see          │             │
   │  │   Qeet ID's hosted login.                          │             │
   │  │                                                    │             │
   │  │   ┌────────────────────────────────────────────┐   │             │
   │  │   │ bash                              [Copy]   │   │             │
   │  │   │ npm run dev                                │   │             │
   │  │   └────────────────────────────────────────────┘   │             │
   │  │                                                    │             │
   │  │   ✓ That's it. You have working auth.              │             │
   │  │                                                    │             │
   │  └────────────────────────────────────────────────────┘             │
   │                                                                     │
   │  Where to next                                                      │
   │  ─────────────                                                      │
   │  • Add Google login (1 min)                                         │
   │  • Add passkeys (already enabled by default)                        │
   │  • Add MFA                                                          │
   │  • Multi-tenancy for B2B apps                                       │
   │                                                                     │
   │  ┌────────────────────────────────────────────────────────────┐    │
   │  │  ★ Was this helpful?       👍   👎    Leave feedback       │    │
   │  └────────────────────────────────────────────────────────────┘    │
   └─────────────────────────────────────────────────────────────────────┘
```

### 6.2 Quickstart Design Rules

**Five numbered steps. No more.** Five is the upper bound; cutting one is allowed; adding a sixth requires Technical Writer + UX + Product sign-off.

**Working code at every step.** No prose-only steps. The single exception is Step 2 (getting the client ID from the dashboard), which is a one-paragraph instruction. Every other step is a code block.

**Realistic placeholders.** `client_app_42`, `acme.qeetify.com`, `alice@example.com` — not `XXX-XXX-XXX` or `<your_client_id>`. The realism makes it easier to spot where the user's own values go.

**Language tabs persist.** Selecting "Python" in step 1 means every code block on the page is Python. The selection persists across pages (per [Doc 3 §5.4](Qeet ID%20%E2%80%94%20Component%20Library%20Specification.md)).

**Validation of the dashboard step.** When the user has connected to their dashboard (signed in to docs.qeetify.com with the same account), step 2's code block can auto-populate with the user's actual client ID. (OD-DP-01 — opt-in MVP feature.)

**Where to next is curated.** Three to five next-step links, manually chosen — not algorithmic recommendation.

**Page-level feedback widget at the bottom** (per DP-10).

### 6.3 Time Budget

The Quickstart is the lone surface where the SDK Engineering, Technical Writer, and DevRel teams jointly own the success metric. Every quarter, the team measures: median time on page → median time-to-paste-final-snippet → median time-to-customer-first-login. Target ≤5 minutes p50.

---

### 7. Concepts Page Pattern

Concepts pages explain *why* — Tokens, Sessions, Multi-tenancy, RBAC, Passkeys, MFA, SAML, OIDC, SCIM, Webhooks.

### 7.1 Anatomy

```
   Concepts / Passkeys                                          Last updated: 12 days ago

   What are passkeys?                                              [TOC]
   ─────────────────                                              • What are passkeys?
   A passkey is a credential that replaces a password. Unlike a    • Why Qeet ID is passkey-first
   password, a passkey is cryptographically bound to the website   • How passkeys work
   that created it…                                                • Conditional UI
                                                                   • Cross-device flow
   Why Qeet ID is passkey-first                                    • Compatibility
   ─────────────────                                               • Next steps
   …
```

- Title + heading hierarchy.
- Right rail TOC ([Component Library §7.4](Qeet ID%20%E2%80%94%20Component%20Library%20Specification.md)) auto-generated from H2/H3.
- Inline diagrams (ASCII for technical clarity; SVG for visual ones — the SVGs live in Figma).
- "Last updated" date at the top — visible signal of freshness.
- A "Next steps" section at the bottom links to the matching Guide(s).

---

### 8. Guides Page Pattern

Guides are *how-to* — Add Google login, Add GitHub login, Configure SAML, Migrate from Firebase Auth, etc.

### 8.1 Anatomy

Same structure as the Quickstart, but typically longer and topic-specific. Steps are numbered. Code blocks are language-tabbed. A "Verify it worked" step is mandatory at the end.

### 8.2 Mandatory Sections in Every Guide

| Section | Purpose |
| --- | --- |
| Overview | What you'll do; what you'll need; estimated time |
| Prerequisites | Concrete prerequisites (a Qeet ID account, a Google Cloud account, etc.) |
| Steps | The numbered steps |
| Verify it worked | A concrete test |
| Troubleshooting | Top 3–5 things that typically go wrong, with fixes |
| Related guides | Cross-links |
| Feedback | The thumbs widget |

### 8.3 Migration Guides (Daniel's Surface)

Per [Daniel's verbatim need](Qeet ID%20%E2%80%94%20UX%20Research%20Summary%20%26%20Design%20Principles.md), migration guides are first-class. Each migration guide (Firebase Auth, Auth0, AWS Cognito at MVP — Charter §5):

1. **Why migrate** — what the destination platform gives.
2. **Compatibility map** — what's a 1:1 translation, what needs adaptation.
3. **Migration tool** — link to Qeet ID's user-import API + step-by-step.
4. **Phased rollout plan** — 5% → 20% → 100% with the dashboard's migration progress UI.
5. **Common pitfalls.**
6. **Verify success.**

---

### 9. API Reference

Route: `/api` (alias of `/docs/api`). Generated from the OpenAPI 3.1 spec ([Phase 2 API §15](../phase-2/Qeet%20ID%20%E2%80%94%20API%20Design%20Standards.md)).

### 9.1 Index

A grid of resource groups: Users · Organizations · Roles · OAuth · Sessions · SCIM · SAML · Webhooks · API Keys · Audit.

Each group leads to a list of endpoints, each leading to an endpoint page.

### 9.2 Endpoint Page Anatomy

```
   GET  /v1/users/{user_id}                                  Try it →

   Retrieve a user by ID.

   Path parameters
   ───────────────
   user_id   string   Required.   The user's Qeet ID ID. Format: user_…

   Query parameters
   ────────────────
   include   array of string   Optional.   Comma-separated. Allowed: roles, sessions, metadata.

   ▼ Request

     ┌─curl─┬─React─┬─Node─┬─Python─┬─Flutter─┬─Go─┐
     │                                              │
     │  curl https://api.qeetify.com/v1/users/u… \  │
     │    -H "Authorization: Bearer YOUR_TOKEN"      │
     │                                              │
     └──────────────────────────────────────────────┘

   ▼ Responses

   ★ 200 OK
     ┌─JSON─┐
     │ {                                            │
     │   "id": "user_01HX...",                      │
     │   "tenant_id": "org_acme",                    │
     │   "email": "alice@example.com",               │
     │   …                                           │
     │ }                                              │
     └──────┘

   ★ 401 Unauthorized
   ★ 403 Forbidden
   ★ 404 Not Found
   ★ 429 Rate Limited
```

### 9.3 Try-It Panel

The "Try it →" affordance opens an in-page interactive panel:

```
   ┌────────────────────────────────────────────────────────────────┐
   │  Try GET /v1/users/{user_id}                                   │
   ├────────────────────────────────────────────────────────────────┤
   │  Bearer token   [your token here   _________________]          │
   │                 (use your sandbox token; we won't save it)     │
   │                                                                │
   │  user_id        [user_01HX...]                                 │
   │                                                                │
   │  include        [☐ roles  ☐ sessions  ☐ metadata]              │
   │                                                                │
   │  [Send request]                                                │
   │                                                                │
   │  Response  200 OK · 142ms                                      │
   │  ┌──────────────────────────────────────────────┐              │
   │  │  { … }                                       │              │
   │  └──────────────────────────────────────────────┘              │
   └────────────────────────────────────────────────────────────────┘
```

- Tokens entered here are stored only in the user's browser (session storage), never sent to Qeet ID's analytics.
- A clear "We don't save your token" reassurance is shown.
- Requests target a sandbox endpoint by default (so a careless `DELETE` doesn't nuke production data); a toggle switches to production.

### 9.4 Errors

Every endpoint enumerates its possible error responses with the `code` field from Phase 2 API §11.2. Each error code links to a central `/api/errors/{code}` page.

---

### 10. SDK Reference

Route: `/sdks/{language}`. Per language: React, Next.js, Node.js, Python, Flutter, Go (Charter §5).

### 10.1 SDK Page Anatomy

```
   /sdks/react

   @qeetify/react                                v1.0.0 · 2 days ago
   Bun · npm · pnpm · yarn

   Install
   ───────
   ┌─npm─┬─pnpm─┬─yarn─┬─bun─┐
   │                          │
   │  npm install @qee…       │
   │                          │
   └──────────────────────────┘

   Quick start                                          [Open Quickstart →]

   API
   ───
   QeetifyProvider           Wraps your app. Required.
     Props: domain, clientId, redirectUri, scope, audience
     Children
     [Code example]

   useQeetify                Returns the auth context.
     Returns: { user, isAuthenticated, isLoading, login(), logout() }
     [Code example]

   LoginButton               Pre-styled sign-in button.
     Props: children, variant
     [Code example]

   …
```

### 10.2 SDK Reference Generation

The SDK reference is **partly auto-generated** from the SDK's TypeScript / Python / Go / Dart type definitions, with hand-authored prose. The auto-generated source pulls JSDoc / docstrings / godoc as the prose source-of-truth — the docs always match the SDK code (P-08 / P-10).

---

### 11. Migration Guides — Detail

### 11.1 Firebase Auth → Qeet ID

Route: `/docs/guides/migrate-firebase`.

Mandatory sections:
- Why migrate (the limitations Daniel cited)
- Compatibility map (1:1, adaptation, new capabilities)
- Migration tool (`POST /v1/users/import` batch import)
- Phased rollout (5% → 20% → 100% with the dashboard's migration progress UI)
- Common pitfalls (password hash incompatibility, email-verification status, user IDs)
- Verify success

### 11.2 Auth0 → Qeet ID and AWS Cognito → Qeet ID

Same structure, platform-specific content.

---

### 12. Documentation Search

Per [Doc 4 §7.4, §12](Qeet ID%20%E2%80%94%20Information%20Architecture%20%26%20Navigation.md). The `/` shortcut opens an instant-search overlay. Implementation: Algolia DocSearch or self-hosted Typesense (OD-IA-01).

### 12.1 Search Result UI

```
   ┌─────────────────────────────────────────────────────────────────┐
   │  🔍  pkce                                                       │
   ├─────────────────────────────────────────────────────────────────┤
   │  Docs (4)                                                       │
   │   ─ Quickstart › 3. Wrap your app with the Provider              │
   │   ─ Concepts › Tokens › OAuth 2.0 + PKCE                         │
   │   ─ Guides › Add Google login › PKCE setup                       │
   │   ─ API Reference › /oauth/authorize › PKCE parameters           │
   │                                                                 │
   │  API (1)                                                        │
   │   ─ POST /oauth/token (PKCE)                                    │
   │                                                                 │
   │  SDKs (3)                                                       │
   │   ─ React › useQeetify pkce option                              │
   │   ─ Node.js › PkceHelper class                                  │
   │   ─ Python › pkce utility                                       │
   └─────────────────────────────────────────────────────────────────┘
```

### 12.2 Empty-Search-Result Logging

Searches with zero results are logged anonymously for the Technical Writer team's weekly review (per DP-10 / [Doc 4 §12.4](Qeet ID%20%E2%80%94%20Information%20Architecture%20%26%20Navigation.md)).

---

### 13. Versioning UX

Per [Doc 4 §7.5](Qeet ID%20%E2%80%94%20Information%20Architecture%20%26%20Navigation.md):

- A version selector in the docs top bar: `[v1 (current) ▾]`.
- Older versions render with a yellow banner: "You're viewing the docs for v1, which is older than the current version (v2). [View v2 ↗]."
- Version-aware URLs: `/docs/v1/quickstart`, `/docs/v2/quickstart`.
- The unversioned URL `/docs/quickstart` redirects to the current version.
- Each page in an older version shows a "What changed in v2?" link in the right rail.

---

### 14. Status Page Design

Route: `https://status.qeetify.com` (hosted independently per NFR AV-10).

### 14.1 Anatomy (per [Doc 3 §7.5](Qeet ID%20%E2%80%94%20Component%20Library%20Specification.md))

```
   ┌───────────────────────────────────────────────────────────────────────┐
   │                                                                       │
   │  Qeet ID Status              All systems operational ✓                │
   │                                                                       │
   │  ┌──────────────────────────────────────────────────────────────┐    │
   │  │  Authentication API     ████████████████████  99.99% (90d)   │    │
   │  │  Token Service          ████████████████████  99.98%         │    │
   │  │  Admin Dashboard        ████████████████░░░░  99.91%         │    │
   │  │  Developer Portal       ████████████████████  99.96%         │    │
   │  │  Webhook delivery       ████████████████████  99.95%         │    │
   │  │  SCIM provisioning      ████████████████████  99.97%         │    │
   │  │  SAML federation        ████████████████████  99.96%         │    │
   │  │  Notification (email)   ████████████░░░░░░░░  99.50%         │    │
   │  │  Notification (SMS)     ████████████░░░░░░░░  99.40%         │    │
   │  └──────────────────────────────────────────────────────────────┘    │
   │                                                                       │
   │  Region status                                                       │
   │   US East 1: Operational    EU West 1: Operational                   │
   │                                                                       │
   │  Recent incidents                                                    │
   │  ─────────────                                                       │
   │  May 14 · 09:12 UTC · Resolved · Degraded performance on SMS         │
   │   Notifications · 23 min · [View →]                                  │
   │  May 02 · 14:00 UTC · Resolved · Scheduled maintenance · 12 min      │
   │  …                                                                    │
   │                                                                       │
   │  [Subscribe to updates]   [RSS]   [Webhook]                          │
   └───────────────────────────────────────────────────────────────────────┘
```

### 14.2 Incident Page

Each incident has its own page: `/incidents/{id}`. Anatomy:
- Title + status (Investigating · Identified · Monitoring · Resolved).
- Timeline of updates (most recent first).
- Affected components.
- Affected regions.
- Final post-mortem link (when resolved + 7 days, per NFR IR-07).

### 14.3 Subscriptions

Email, RSS, and webhook subscription channels. Customer SIEM integrations consume the webhook.

---

### 15. Public Roadmap Page

Route: `/roadmap`. A live, public roadmap categorised by Now / Next / Later.

### 15.1 Anatomy

```
   Public roadmap                                       Last updated: 2 days ago

   ┌─Now (in progress)─────────┬─Next (planned)──────────┬─Later (considered)──┐
   │                            │                          │                     │
   │  • v1.1 — Adaptive MFA     │  • v1.2 — APAC / UK      │  • v2.0 — On-prem  │
   │    (risk-based MFA)        │    data residency        │    deployment      │
   │                            │                          │                     │
   │  • v1.1 — Anomaly          │  • v1.2 — Additional     │  • v2.0 — ISO       │
   │    detection improvements  │    social providers      │    27001            │
   │                            │                          │                     │
   │  • v1.1 — Terraform        │  • v1.2 — More SDKs      │  • v2.0 — FGA       │
   │    provider                │    (Vue, Svelte, Swift…) │    (Zanzibar)      │
   │                            │                          │                     │
   │  …                         │  …                       │  …                  │
   └────────────────────────────┴──────────────────────────┴─────────────────────┘

   Vote for what matters most to you   →  Submit feedback
```

### 15.2 Voting & Feedback

Each item is votable (anonymous; no login required for read; sign-in required to vote — anti-abuse). A "Submit feedback" link opens a structured form.

### 15.3 Source of Truth

The roadmap content is sourced from Product's internal Linear / Notion / Jira; an approved subset is mirrored to the public page. (Internal items not yet ready for public sharing are suppressed.)

---

### 16. Public Changelog Page

Route: `/changelog`. Reverse-chronological list of releases.

### 16.1 Anatomy

```
   Changelog

   ┌─2026-05-15 · v1.0.42 ─────────────────────────────────────────────────┐
   │ Features                                                                │
   │  • Conditional UI for passkey login (autofill suggestions on Safari)   │
   │  • Audit log export to Sumo Logic                                      │
   │                                                                         │
   │ Improvements                                                            │
   │  • SAML metadata fetch timeout increased to 10s                        │
   │                                                                         │
   │ Fixes                                                                   │
   │  • Fixed a rare race condition in refresh-token rotation under heavy   │
   │    load (#1248)                                                         │
   │                                                                         │
   │ Breaking changes                                                        │
   │  None.                                                                  │
   │                                                                         │
   │ [Read full notes →]                                                    │
   └─────────────────────────────────────────────────────────────────────────┘

   ┌─2026-05-08 · v1.0.41 ─────────────────────────────────────────────────┐
   │ …                                                                       │
   └─────────────────────────────────────────────────────────────────────────┘
```

### 16.2 Tags

Each entry is tagged: `feature`, `improvement`, `fix`, `deprecation`, `breaking` (per [Phase 2 API §17.4](../phase-2/Qeet%20ID%20%E2%80%94%20API%20Design%20Standards.md)).

### 16.3 RSS

`/changelog.rss` exposes the changelog for syndication; many developers subscribe via Feedly etc.

### 16.4 Voice

The changelog is candid. Bugs are called bugs. Breaking changes are called breaking. Plain language; no marketing fluff. Per [P-10 Trust Through Transparency](Qeet ID%20%E2%80%94%20UX%20Research%20Summary%20%26%20Design%20Principles.md).

---

### 17. Security Trust Center

Route: `/security`. Omar's primary entry point. The page Omar reaches before any sales call.

### 17.1 Landing Page Anatomy

```
   ┌─────────────────────────────────────────────────────────────────────┐
   │  Security at Qeet ID                                                │
   │                                                                     │
   │  Everything you need to evaluate Qeet ID's security posture,        │
   │  on one page, without a sales call.                                 │
   │                                                                     │
   │  All systems operational  ✓        [View status →]                  │
   ├─────────────────────────────────────────────────────────────────────┤
   │  Certifications & reports                                           │
   │                                                                     │
   │  ┌─SOC 2 Type I─┬─Penetration test─┬─OIDC certified─┬─FIDO2 certified┐│
   │  │  Issued 2026 │  Q1 2026 summary │   Foundation   │   Alliance    ││
   │  │  [Download   │   available      │   Basic OP     │   (server)   ││
   │  │  with NDA →] │   [Download]     │                │              ││
   │  └──────────────┴──────────────────┴────────────────┴───────────────┘│
   ├─────────────────────────────────────────────────────────────────────┤
   │  Data residency                                                     │
   │                                                                     │
   │  ┌── World map ──┐                                                  │
   │  │ • US East 1   │  Tenants pin to a region. Data never leaves      │
   │  │ • EU West 1   │  the chosen region in operational traffic.        │
   │  │ (v1.2 + APAC, │                                                   │
   │  │  UK, more)    │                                                   │
   │  └───────────────┘                                                  │
   ├─────────────────────────────────────────────────────────────────────┤
   │  Documents & policies                                               │
   │                                                                     │
   │  [DPA template]        [Sub-processor list]      [Breach notif.]   │
   │  [Incident response]   [Vulnerability discl.]    [CVE advisories]  │
   │  [Architecture]        [Threat model summary]    [Bug bounty]      │
   ├─────────────────────────────────────────────────────────────────────┤
   │  Subscribe to security advisories                                   │
   │  [your email_____________________________________]   [Subscribe]    │
   └─────────────────────────────────────────────────────────────────────┘
```

### 17.2 SOC 2 Download NDA Gate

Click "Download with NDA" opens an inline NDA form:

```
   ┌─────────────────────────────────────────────────────────────────────┐
   │  Download SOC 2 Type I report                                       │
   │                                                                     │
   │  Your name        [____________________]                            │
   │  Company          [____________________]                            │
   │  Email            [____________________]                            │
   │  Role             [____________________]                            │
   │                                                                     │
   │  ☐ I agree to the terms of the [NDA]                                │
   │                                                                     │
   │  [Download report]                                                  │
   └─────────────────────────────────────────────────────────────────────┘
```

- One-click acceptance — no docusign, no callback (per [P-09 / P-10](Qeet ID%20%E2%80%94%20UX%20Research%20Summary%20%26%20Design%20Principles.md) and Persona Omar verbatim).
- Acceptance is logged; the user receives the PDF immediately.

### 17.3 Sub-Processor List

Route: `/security/sub-processors`. A table of every sub-processor (per Phase 1 Compliance Matrix §11.2):

| Sub-processor | Category | Region | DPA status | Last reviewed |
| --- | --- | --- | --- | --- |
| AWS | Cloud infrastructure | Multi-region | Signed | Apr 2026 |
| Stripe | Payment processing | US, EU | Signed | Apr 2026 |
| SendGrid | Transactional email | US | Signed | Mar 2026 |
| Twilio | SMS | US | Signed | Mar 2026 |
| Cloudflare | CDN / WAF | Multi-region | Signed | Mar 2026 |
| Datadog | Observability | US, EU | Signed | Mar 2026 |
| … | | | | |

A subscription form at the top: "Get notified 30 days before any sub-processor change" — required by Compliance CN-10.

### 17.4 Breach Notification Policy

A readable document (HTML, not PDF) detailing Qeet ID's breach response: notification timeline (within 72 hours of awareness per Phase 1 Compliance Matrix §4.2 G-12), how notifications are sent, what information is included, customer obligations.

### 17.5 CVE Advisories

A list of every public security advisory Qeet ID has issued, with date, severity, affected versions, mitigation. Customers subscribe via email or RSS.

### 17.6 Bug Bounty

Public policy: scope, rewards, responsible disclosure terms. Submit form linked to HackerOne / Bugcrowd / Intigriti (OD-SEC-03 from Phase 2).

---

### 18. Community Section

Route: `/community`. Pointer page to community surfaces:

- Discord invite (link to the qeetify Discord)
- GitHub organisation (`github.com/qeetify`)
- Stack Overflow tag (`stackoverflow.com/questions/tagged/qeetify`)
- Public forum (if separate from Discord — TBD by DevRel)

Each surface has a one-paragraph description and a CTA.

---

### 19. Blog Layout

Route: `/blog`. Standard blog index → article. Used for:

- Technical deep-dives (e.g., "How we built passkey conditional UI")
- Product announcements
- Migration case studies
- Compliance and security posts

### 19.1 Article Layout

A Marketing Layout template ([Component Library §7.6](Qeet ID%20%E2%80%94%20Component%20Library%20Specification.md)) with: title, subtitle, author + avatar + date, reading time, body, related posts, share.

---

### 20. Pricing Page Design

Route: `/pricing`. Owned by Marketing but with a Phase 3 contract.

### 20.1 Anatomy

```
   Pricing                                                       Annual / Monthly

   ┌──────────────┬──────────────────────┬──────────────────────┐
   │   Free       │   Growth             │   Enterprise         │
   │   $0         │   $99/mo             │   Custom             │
   │              │   + per-MAU above    │                      │
   │              │   10,000             │                      │
   │              │                       │                      │
   │ [Get started] │ [Start free trial]   │ [Contact sales]      │
   │              │                       │                      │
   │ Includes:    │ Everything in Free,   │ Everything in Growth,│
   │  ✓ 10K MAUs  │ plus:                 │ plus:                │
   │  ✓ Passkey   │  ✓ Unlimited MAUs    │  ✓ SAML SSO          │
   │  ✓ OAuth/OIDC│   (per-MAU pricing)  │  ✓ SCIM provisioning │
   │  ✓ 6 SDKs    │  ✓ Custom domain     │  ✓ Audit log SIEM    │
   │  ✓ React/Next│  ✓ Email branding    │  ✓ 99.99% SLA        │
   │  ✓ etc.      │  ✓ RBAC              │  ✓ Dedicated DB      │
   │              │  ✓ Webhooks          │  ✓ Priority support  │
   │              │  ✓ etc.              │  ✓ etc.              │
   └──────────────┴──────────────────────┴──────────────────────┘

   Pricing calculator
   ──────────────────
   How many MAUs?  [────────────●────────────] 12,000
                    100   1K   10K   50K   100K   500K   1M

   Your estimated monthly cost
     ─ Free includes        10,000 MAUs        $0
     ─ Growth (2,000 over)  $0.02 × 2,000      $40
     ─ Plus base                                $99
   = Total                                     $139 / month

   Annual billing: $139 × 12 × 0.85 = $1,418/year (save 15%)

   [Start free trial]
```

### 20.2 Calculator

A live calculator that updates as the slider moves. Currency-aware (locale-detected; user can override). Annual vs monthly toggle.

### 20.3 Comparison Table

Below the three plan cards: a full feature comparison table showing every feature × plan. ☑ / – / "Add-on" / "Custom".

### 20.4 FAQ

Pricing FAQ at the bottom: How is an MAU counted? Can I change plans mid-cycle? Do you offer non-profit pricing? What about open-source projects?

---

### 21. Per-Page Feedback Pattern

Every doc page, every API page, every SDK page, every Concept page, every Guide page has a feedback widget at the bottom:

```
   ┌───────────────────────────────────────────────────────────────┐
   │  Was this page helpful?                                       │
   │  [👍 Yes]      [👎 No]      [✏ Edit on GitHub]                │
   └───────────────────────────────────────────────────────────────┘
```

Clicking thumbs-down expands an optional comment field:

```
   What was missing? (optional)
   [_____________________________________________]
   [Submit]
```

Feedback is logged anonymously; reviewed weekly by Technical Writing + Developer Relations.

### 21.1 "Edit on GitHub"

Every doc page has an "Edit on GitHub" link that deep-links to the corresponding markdown file in `github.com/qeetify/docs`. Pull requests welcomed.

---

### 22. Light / Dark Theme

The portal supports light mode, dark mode, and system-preference. Theme toggle in the top nav.

### 22.1 Code Blocks

Code blocks in dark mode use a darker `code-bg` token (per [Doc 2 §5.4](Qeet ID%20%E2%80%94%20Design%20System%20Foundations%20%26%20Tokens.md)). Syntax highlighting palette is theme-aware (separate light and dark schemes; both pass AA contrast).

### 22.2 Theme Persistence

Selection persists per user via `localStorage`. The default is system-preference.

---

### 23. Responsive Behaviour

Per [Phase 3 Doc 10 §3](Qeet ID%20%E2%80%94%20Mobile%20%26%20Responsive%20Design%20Specification.md): the developer portal is fully responsive, mobile-readable.

Below 1024px:
- Left nav (docs tree) becomes a drawer triggered from a button.
- Right rail TOC becomes a sticky popover at the bottom of the viewport.
- Code blocks wrap; no horizontal scroll.
- Search overlay covers the full viewport.

---

### 24. Performance Budget

Per Phase 1 [NFR PF-20](../phase-1/Qeet%20ID%20%E2%80%94%20Non-Functional%20Requirements%20%28NFR%29.md): developer portal page load (TTFB) p95 ≤ 250 ms.

Technique:
- Static-generated docs pages (SSG) — every page is pre-rendered.
- Edge-cached at Cloudflare.
- Per-page JS payload <40 KB (gzipped) — the Code Tab Group and Try-It interactive panel are the heaviest, lazy-loaded.
- Fonts preloaded.
- Images optimised (AVIF / WebP with fallback).
- Lighthouse target: ≥95 on every metric.

---

### 25. Accessibility

Per [Phase 3 Doc 9](Qeet ID%20%E2%80%94%20Accessibility%20Compliance%20Plan%20%28WCAG%202.1%20AA%29.md): the portal must meet WCAG 2.1 AA. Specific commitments:

- Code blocks announce their language via `aria-label`.
- Try-It panels are fully keyboard-operable.
- Status indicators on the status page are visual + textual (✓ + "Operational", not colour-only).
- Tables (sub-processor list, comparison table) are properly marked-up with `<th>` and `scope`.
- The TOC is `<nav aria-label="On this page">`.
- Skip-to-content link present on every page.

---

### 26. Open Design Decisions From This Document

| # | Question | Owner | Target |
| --- | --- | --- | --- |
| OD-DP-01 | Auto-populating client_id in Quickstart Step 2 (requires docs-signin integration) | UX + Frontend | Phase 3 Week 3 |
| OD-DP-02 | Try-It panel sandbox vs production toggle — default to sandbox vs always sandbox | UX + Security | Phase 3 Week 3 |
| OD-DP-03 | Public roadmap voting at MVP or v1.1 | Product + DevRel | Phase 3 Week 2 |
| OD-DP-04 | SOC 2 NDA gate — inline acceptance vs docusign-integrated | Compliance + Legal | Phase 3 Week 3 |
| OD-DP-05 | Migration progress UI — in dashboard only vs also in docs | UX + Product | Phase 3 Week 3 |
| OD-DP-06 | Docs feedback widget — anonymous-only vs optional sign-in for reply | UX + DevRel | Phase 3 Week 4 |

---

### 27. Cross-References

- Principles applied: [UX Research Summary & Design Principles](Qeet ID%20%E2%80%94%20UX%20Research%20Summary%20%26%20Design%20Principles.md) §6
- Components composed: [Component Library Specification](Qeet ID%20%E2%80%94%20Component%20Library%20Specification.md) — Code Block (§5.3), Code Tab Group (§5.4), Form (§6.14), Search Input (§5.2), Tab Group (§6.16), Templates (§7.4 Documentation, §7.5 Status, §7.6 Marketing)
- Tokens consumed: [Design System Foundations & Tokens](Qeet ID%20%E2%80%94%20Design%20System%20Foundations%20%26%20Tokens.md) (especially §5 colour, §6 typography)
- IA structure: [Information Architecture & Navigation](Qeet ID%20%E2%80%94%20Information%20Architecture%20%26%20Navigation.md) §7
- Mobile responsiveness: [Mobile & Responsive Design Specification](Qeet ID%20%E2%80%94%20Mobile%20%26%20Responsive%20Design%20Specification.md)
- Localisation: [Internationalization & Localization Design](Qeet ID%20%E2%80%94%20Internationalization%20%26%20Localization%20Design.md) (note: developer portal is English at MVP per NFR IN-08)
- Accessibility: [Accessibility Compliance Plan (WCAG 2.1 AA)](Qeet ID%20%E2%80%94%20Accessibility%20Compliance%20Plan%20%28WCAG%202.1%20AA%29.md)
- API source-of-truth: [Phase 2 API Design Standards §15](../phase-2/Qeet%20ID%20%E2%80%94%20API%20Design%20Standards.md)
- Status page hosting: [Phase 2 Observability §11](../phase-2/Qeet%20ID%20%E2%80%94%20Observability%20Architecture.md)
- Security Trust Center content sources: [Phase 1 Compliance Matrix §11.2](../phase-1/Qeet%20ID%20%E2%80%94%20Compliance%20Requirements%20Matrix.md), [Phase 2 Security Architecture](../phase-2/Qeet%20ID%20%E2%80%94%20Security%20Architecture%20%28Zero%20Trust%29.md)

---

### 28. Approvals & Sign-off

| Role | Name | Signature | Date |
| --- | --- | --- | --- |
| UX Designer |  |  |  |
| Technical Writer Lead |  |  |  |
| Developer Relations Lead |  |  |  |
| Frontend Engineering Lead |  |  |  |
| SDK Engineering Lead |  |  |  |
| Marketing Lead (Pricing + Security Trust Center) |  |  |  |
| Compliance Officer (Security Trust Center) |  |  |  |
| Security Architect (Security Trust Center) |  |  |  |
| Accessibility Lead |  |  |  |
| Product Manager |  |  |  |

---

*This document is version controlled. Visual updates in Figma do not require re-sign-off; changes to the Quickstart structure (§6.2), the API reference layout (§9), the Security Trust Center content (§17), or per-page feedback patterns (§21) require UX Designer + Technical Writer + Developer Relations + (for §17) Compliance Officer review.*

---

**Qeet ID — Authenticate Everything.** *A Qeet Group Company*
