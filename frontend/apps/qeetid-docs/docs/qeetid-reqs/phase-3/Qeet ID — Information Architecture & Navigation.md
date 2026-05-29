# Qeet ID — Information Architecture & Navigation

### 1. Document Information

|  |  |
| --- | --- |
| **Document Name** | Information Architecture & Navigation |
| **Project Name** | Qeet ID |
| **Parent Company** | Qeet Group |
| **Subsidiary** | Qeet ID (Standalone) |
| **Document Version** | v1.0 |
| **Prepared By** | UX Designer + Product Manager |
| **Date** | May 19, 2026 |
| **Status** | Draft — Pending Stakeholder Sign-off |

---

### 2. Purpose & Scope

This document defines the Information Architecture (IA) for every Qeet ID-owned surface. It establishes how content and capability are *organised*, how users *navigate*, how URLs are *structured*, and how the multi-tenant model surfaces in routing. It is the bridge between the design system (which gives us the navigation *components*) and the screen-spec documents that follow (which compose the components into screens).

The IA is the difference between a product Sandra and Daniel can drive efficiently after thirty minutes and a product they need a quarterly training refresh on. It is the difference between Arjun finding his Quickstart in five seconds and giving up to read a competitor's blog. Per [Principle P-01](Qeet ID%20%E2%80%94%20UX%20Research%20Summary%20%26%20Design%20Principles.md), the navigation is shallow when possible, predictable, role-aware, and persona-aware.

The audience is the UX Designer, Product Manager, Frontend Engineering Lead, Technical Writer, Developer Relations, and the Product Designers responsible for the dashboard and developer portal.

This document depends on [UX Research Summary & Design Principles](Qeet ID%20%E2%80%94%20UX%20Research%20Summary%20%26%20Design%20Principles.md) (principles), [Design System Foundations & Tokens](Qeet ID%20%E2%80%94%20Design%20System%20Foundations%20%26%20Tokens.md) (layout grid), [Component Library Specification](Qeet ID%20%E2%80%94%20Component%20Library%20Specification.md) (Navigation Bar, Side Navigation, Tenant Switcher, Breadcrumbs, Tab Group), and on Phase 2 [Multi-Tenancy Architecture](../phase-2/Qeet%20ID%20%E2%80%94%20Multi-Tenancy%20Architecture.md) (tenant routing model) and [API Design Standards §4](../phase-2/Qeet%20ID%20%E2%80%94%20API%20Design%20Standards.md) (URL conventions).

---

### 3. IA Principles

**IA-01 — Predictable.** A user who finds something once can find it again. Navigation positions, labels, and hierarchies are stable across releases. Renaming a top-level section requires a Product + UX sign-off and a deprecation notice.

**IA-02 — Shallow When Possible.** Three-clicks-to-anything is a target, not a slogan. The admin dashboard reaches every routine task in ≤2 clicks from the dashboard home; the developer portal reaches the Quickstart from the public home page in ≤2 clicks.

**IA-03 — Role-Aware.** What an L1 admin sees in the side navigation is a subset of what an L2 admin sees, which is a subset of what an L3 admin sees (Phase 3 Doc 6 §3 enumerates the tiers). Hidden navigation is preferred over disabled navigation — but a one-line explanation appears in the user's settings of *what they cannot see and why*.

**IA-04 — Persona-Aware.** Arjun's first landing in the dashboard offers a Quickstart card; Maya's offers a multi-tenancy overview; Sandra's offers the SAML / SCIM and Audit Logs entry points. These are surfaced by detecting the user's primary role (engineering vs admin vs security), not by asking the user to self-identify.

**IA-05 — Tenancy Is Explicit.** Tenant context is always visible in the dashboard's top navigation (per Multi-Tenancy MTP-01: every screen carries `tenant_id`). The user is never in doubt about which organisation they are editing.

**IA-06 — Search Is the Universal Fallback.** Every surface has a global search reachable from `cmd+K` (Mac) / `ctrl+K` (Win/Linux). When a user cannot find something through navigation, the command palette is the rescue.

**IA-07 — URLs Are Designed.** URLs are bookmarkable, shareable, and human-meaningful. A URL is a contract; once published, it does not change without a redirect.

**IA-08 — Mobile IA Is Not Desktop IA Compressed.** Mobile navigation patterns (bottom tab bar on consumer surfaces, hamburger drawer on the dashboard's read-only emergency view) are designed specifically for mobile, not down-scaled desktop layouts.

---

### 4. Surface Inventory

Qeet ID owns five primary surfaces (the same five enumerated in the Phase 1 Feature Prioritization). Each has its own IA tree but inherits the cross-surface conventions in §10 / §11.

| # | Surface | URL space | Owning persona | Primary navigation pattern |
| --- | --- | --- | --- | --- |
| 1 | End-User Authentication Pages | `/login`, `/signup`, `/auth/...` on tenant domain | End user (indirect) | Linear flow; no nav |
| 2 | Admin Dashboard | `/dashboard/[org-slug]/...` | Sandra (lead) | Top nav + side nav |
| 3 | Developer Portal | `/docs`, `/api`, `/sdks`, `/status`, `/changelog`, `/roadmap`, `/security`, `/blog`, `/pricing` | Arjun (lead) | Top nav + left tree (docs) |
| 4 | Embeddable Auth UI Widgets | Hosted by customer; embedded via SDK | Customer apps | No nav (widget) |
| 5 | Email Templates | Delivered to user inbox | End user | n/a |

The Marketing site (`/`, `/about`, `/contact`, `/customers`, `/careers`) is owned by Marketing, not Phase 3. Phase 3 ensures the design system tokens are consumed correctly on Marketing surfaces; Marketing owns IA for its own pages.

---

### 5. End-User Authentication Pages — IA

End-user authentication is a *flow*, not a *navigation tree*. The user enters from a relying-party application, completes a discrete sequence of steps, and returns to the relying party. There is no "back to home" — the user came from somewhere, and they go back to it.

### 5.1 Site Map

```
   /login                            entry — email/passkey/social/magic-link options
     ├─ /login/passkey               (auto-redirect from /login if passkey chosen)
     ├─ /login/password              (password fallback)
     │    └─ /login/mfa              (after password, if MFA required)
     ├─ /login/magic-link            (magic link request)
     │    └─ /login/magic-link/sent  (confirmation)
     └─ /login/sso                   (enterprise SAML redirect)

   /signup                           email-first signup
     ├─ /signup/verify-email
     ├─ /signup/passkey              (prompt; can skip)
     └─ /signup/welcome              (first-app prompt)

   /auth/recover                     account recovery flow (lost passkey / lost factors)
     ├─ /auth/recover/verify
     └─ /auth/recover/reset

   /auth/reset-password              triggered from email link
     └─ /auth/reset-password/done

   /auth/verify-email                triggered from email link

   /auth/account                     user account portal (under their own subdomain or hosted at qeetify)
     ├─ /auth/account/profile        edit name, email, phone
     ├─ /auth/account/security       passkeys, MFA, password, sessions
     │     ├─ /auth/account/security/passkeys
     │     ├─ /auth/account/security/mfa
     │     └─ /auth/account/security/sessions
     ├─ /auth/account/preferences    language, notifications
     ├─ /auth/account/data           data export (GDPR Art. 20)
     └─ /auth/account/delete         delete account (GDPR Art. 17)

   /auth/logout                      logout endpoint (POST)
```

### 5.2 URL Host Resolution

End-user authentication URLs live on the **tenant's chosen host** — either `{tenant-slug}.qeetify.com` (default) or the tenant's custom domain (e.g., `login.acme.com`) once Custom Domain Setup is complete (Phase 3 Doc 6 §10). Routing is per [Phase 2 Infrastructure §4](../phase-2/Qeet%20ID%20%E2%80%94%20Infrastructure%20%26%20Deployment%20Architecture.md).

### 5.3 Navigation Within the Flow

End-user auth pages have **no top navigation, no side navigation**. The composition is the Auth Layout template ([Component Library §7.1](Qeet ID%20%E2%80%94%20Component%20Library%20Specification.md)) — a centred card on the brand background. The user moves between screens via the screen's own primary and secondary actions.

The single exception is `/auth/account` (the user account portal) which has a settings-style navigation (left nav + content). This is the only end-user surface with navigation, because it is a stay-and-edit surface, not a transit-through-and-leave flow.

### 5.4 Entry Points

| Entry | Comes from |
| --- | --- |
| `/login` | Relying-party application redirects via OAuth `/oauth/authorize` (Phase 2 Auth Flow §3) |
| `/signup` | Marketing CTA, direct link, or tenant-provided signup link |
| `/auth/recover` | "Forgot your passkey?" link on `/login` |
| `/auth/reset-password` | Email link only (with signed JWT) — never directly navigated |
| `/auth/verify-email` | Email link only |
| `/auth/account` | "Account" menu in the relying-party application (linking to Qeet ID-hosted) OR tenant-hosted equivalent |
| `/auth/logout` | Relying party calls `POST /auth/logout`; redirects to relying-party post-logout URI |

### 5.5 Exit Points

Every end-user auth flow ends in one of three exits:

| Exit | Where the user goes |
| --- | --- |
| Successful authentication | OAuth callback URL of the relying-party application |
| Successful signup + first login | Welcome page (`/signup/welcome`) → relying-party application |
| Logout | Post-logout redirect URI declared by the relying party |

---

### 6. Admin Dashboard — IA

Sandra and Daniel live in this surface. Maya configures it during her trial. Arjun checks in occasionally. The IA tree is the single biggest determinant of their day-to-day efficiency. It must be density-friendly (Sandra likes everything visible), keyboard-driven (Sandra and Daniel both), and role-aware (an L2 team member sees less than an L3).

### 6.1 Site Map

```
   /dashboard/[org-slug]
     │
     ├─ /                              Organization Overview (home)
     │
     ├─ /identity
     │     ├─ /users                   Users index
     │     │     └─ /users/[id]        User detail (drawer or page)
     │     ├─ /roles                   Roles index
     │     │     └─ /roles/[id]        Role detail
     │     ├─ /groups                  Groups index
     │     │     └─ /groups/[id]       Group detail
     │     └─ /invitations             Pending invitations
     │
     ├─ /federation
     │     ├─ /sso                     SSO connections (SAML + OIDC)
     │     │     ├─ /sso/saml/new      New SAML connection wizard
     │     │     ├─ /sso/saml/[id]     SAML connection detail
     │     │     ├─ /sso/oidc/new      New OIDC connection wizard
     │     │     └─ /sso/oidc/[id]     OIDC connection detail
     │     ├─ /scim                    SCIM provisioning
     │     │     └─ /scim/[id]         SCIM endpoint detail
     │     └─ /social                  Social login providers
     │
     ├─ /applications
     │     ├─ /                        OAuth Clients (applications) index
     │     │     └─ /[client_id]       Application detail
     │     │           ├─ /general
     │     │           ├─ /credentials
     │     │           ├─ /callbacks
     │     │           ├─ /tokens      Token & JWT settings
     │     │           ├─ /branding
     │     │           └─ /events      Application audit
     │     ├─ /api-keys                API keys management
     │     │     └─ /[id]              API key detail
     │     └─ /webhooks                Webhook subscriptions
     │           └─ /[id]              Webhook detail
     │                 ├─ /deliveries  Delivery history
     │                 └─ /settings
     │
     ├─ /security
     │     ├─ /audit                   Audit log viewer
     │     ├─ /events                  Security events dashboard
     │     ├─ /mfa                     MFA policy
     │     ├─ /password-policy
     │     ├─ /sessions                Active sessions
     │     └─ /anomalies               Anomaly settings
     │
     ├─ /settings
     │     ├─ /profile                 Organisation profile
     │     ├─ /branding                Branding & customisation
     │     │     ├─ /general           logo, colours, fonts
     │     │     ├─ /domain            Custom domain setup
     │     │     └─ /emails            Email template editor
     │     ├─ /team                    Team & admin roles (L1/L2/L3)
     │     │     └─ /[member-id]
     │     ├─ /billing
     │     │     ├─ /                  Plan, MAU usage, invoices
     │     │     ├─ /upgrade           Plan upgrade flow
     │     │     ├─ /payment           Payment method
     │     │     └─ /history           Invoice history
     │     ├─ /compliance              Compliance documents library
     │     │     ├─ /soc2
     │     │     ├─ /dpa
     │     │     ├─ /sub-processors
     │     │     └─ /audit-evidence
     │     └─ /preferences             Notification & UI preferences
     │
     └─ /analytics                     Usage analytics (charts; cross-section)
```

### 6.2 Navigation Pattern

The dashboard uses **top navigation + side navigation** ([Component Library §6.1, §6.2](Qeet ID%20%E2%80%94%20Component%20Library%20Specification.md)).

- **Top navigation** holds: Qeet ID logo, Tenant Switcher, optional top-level section tabs (used sparingly), global search, command palette hint (`⌘K`), user avatar menu.
- **Side navigation** holds: collapsible sections (Identity, Federation, Applications, Security, Settings, Analytics) with their leaf entries. Sections are expanded by default for Sandra-class users; collapsed by default for Arjun-class.

### 6.3 Active-Path Indication

The selected leaf in the side nav has a `4px` left accent bar in `action.primary` colour. The selected section header is in `text.primary` weight 600. Inactive sections are weight 400. Breadcrumbs ([Component Library §6.18](Qeet ID%20%E2%80%94%20Component%20Library%20Specification.md)) show the path from the dashboard root to the current page on every screen except the dashboard home.

### 6.4 Tenant Switcher Placement

The Tenant Switcher ([Component Library §6.3](Qeet ID%20%E2%80%94%20Component%20Library%20Specification.md)) sits at the top-left of the dashboard, immediately after the Qeet ID logo. It is **always visible** — never collapsed even when the side nav is collapsed. The selected tenant's slug appears in every URL after `/dashboard/`, so URLs are tenant-bookmarkable.

### 6.5 Quick-Access Patterns

- **Command palette** (`cmd+K`) opens a global search-and-navigate. It searches: users (by name/email), roles, applications (by name or client_id), recent audit events, settings pages. Selecting a result navigates to it. Used heavily by Sandra (her muscle-memory for finding a user is `cmd+K → "alice"`).
- **Recently-viewed** appears in an empty command palette (the most-recent 5 items the user accessed).
- **Pinned items** can be pinned to the side nav by the user (e.g., Sandra pins "Audit Logs" — it becomes a top-level entry above section headers).
- **Quick actions** in the top-right of every list page (e.g., "Invite user", "Add SAML connection").

### 6.6 Mobile Adaptation

Below 1024px (per [Phase 3 Doc 10 §3](Qeet ID%20%E2%80%94%20Mobile%20%26%20Responsive%20Design%20Specification.md)):

- Top navigation collapses logo + Tenant Switcher + hamburger + cmd+K.
- Side navigation becomes a drawer (opened from hamburger).
- The dashboard becomes the **read-only emergency view** Sandra uses to approve a deploy from her phone: she can view users, view audit logs, view recent events. Configuration (adding a SAML connection, editing branding) shows an "Open on desktop" banner with a "Send link to my desktop" affordance.

### 6.7 Empty-Trial Dashboard

A brand-new tenant's overview screen is densely *guidance-laden*, not empty. It shows a checklist:

- ☐ Create your first application
- ☐ Invite a teammate
- ☐ Set up SSO (SAML or OIDC)
- ☐ Configure MFA policy
- ☐ Brand your login pages

Each item is a one-click jump to the relevant configuration. Completion persists per tenant. Once all are checked, the checklist collapses to "Your setup is complete — view all configuration ↓".

---

### 7. Developer Portal — IA

Arjun lives here. Maya evaluates here. Daniel migrates here. Sandra and Omar visit for protocol and security reference. The portal hosts the developer docs, the API reference, the SDK reference, migration guides, examples, status, roadmap, changelog, Security Trust Center, community, blog, and pricing.

### 7.1 Site Map

```
   /                                  Marketing home (owned by Marketing)
   /pricing                           Pricing page with calculator
   /customers
   /security                          Security Trust Center
        ├─ /security/soc2
        ├─ /security/pen-test
        ├─ /security/data-residency
        ├─ /security/sub-processors
        ├─ /security/dpa
        ├─ /security/breach-policy
        ├─ /security/vdp              Vulnerability Disclosure Policy
        └─ /security/cves             CVE advisory list

   /docs                              Documentation tree
        ├─ /quickstart                Quickstart (the most-loved page)
        │     ├─ /quickstart/react
        │     ├─ /quickstart/nextjs
        │     ├─ /quickstart/node
        │     ├─ /quickstart/python
        │     ├─ /quickstart/flutter
        │     └─ /quickstart/go
        ├─ /concepts                  Concepts
        │     ├─ /concepts/tokens
        │     ├─ /concepts/sessions
        │     ├─ /concepts/multi-tenancy
        │     ├─ /concepts/rbac
        │     ├─ /concepts/passkeys
        │     ├─ /concepts/mfa
        │     ├─ /concepts/saml
        │     ├─ /concepts/oidc
        │     ├─ /concepts/scim
        │     └─ /concepts/webhooks
        ├─ /guides                    How-to guides
        │     ├─ /guides/add-google-login
        │     ├─ /guides/add-github-login
        │     ├─ /guides/add-microsoft-login
        │     ├─ /guides/add-apple-login
        │     ├─ /guides/enable-passkeys
        │     ├─ /guides/configure-saml
        │     ├─ /guides/configure-scim
        │     ├─ /guides/custom-domain
        │     ├─ /guides/branding
        │     ├─ /guides/rbac
        │     ├─ /guides/webhooks
        │     ├─ /guides/migrate-firebase
        │     ├─ /guides/migrate-auth0
        │     ├─ /guides/migrate-cognito
        │     ├─ /guides/multi-tenant-app
        │     └─ /guides/audit-export-siem
        ├─ /api                       API reference (OpenAPI-driven)
        │     ├─ /api/users
        │     ├─ /api/organizations
        │     ├─ /api/roles
        │     ├─ /api/oauth
        │     ├─ /api/sessions
        │     ├─ /api/scim
        │     ├─ /api/saml
        │     ├─ /api/webhooks
        │     ├─ /api/api-keys
        │     ├─ /api/audit
        │     └─ /api/errors
        ├─ /sdks                      SDK reference
        │     ├─ /sdks/react
        │     ├─ /sdks/nextjs
        │     ├─ /sdks/node
        │     ├─ /sdks/python
        │     ├─ /sdks/flutter
        │     └─ /sdks/go
        ├─ /examples                  Runnable example apps
        └─ /reference                 Cheat sheet — claims, scopes, error codes, headers

   /status                            Public status page
   /changelog                         Public changelog
   /roadmap                           Public roadmap
   /blog                              Blog
   /community                         Community hubs
        ├─ /community/discord
        ├─ /community/github
        ├─ /community/forum
        └─ /community/stack-overflow
```

### 7.2 Navigation Pattern

The developer portal uses **top navigation** + per-section context:

- **Top nav** holds: Qeet ID logo, primary sections (Docs · API · SDKs · Pricing · Status · Blog), docs search, theme toggle (light/dark/system), Sign in / Sign up.
- **Docs section** uses the **Documentation Layout** template ([Component Library §7.4](Qeet ID%20%E2%80%94%20Component%20Library%20Specification.md)) — left nav (the docs tree) + content + right TOC.
- **Other sections** (Status, Roadmap, Changelog, Security) use simpler centred layouts.

### 7.3 Docs Tree Behaviour

- The left navigation is a collapsible tree mirroring §7.1.
- Quickstart, Concepts, Guides are sibling top-level entries — not nested under a "Docs" header (the URL already says `/docs`).
- The currently-selected leaf is highlighted; the ancestor sections are auto-expanded.
- A `View on GitHub` link at the bottom of every doc page lets the community contribute (P-10 transparency).

### 7.4 Docs Search

The Docs Search bar (top of the docs left nav) opens an instant-search overlay with results across docs, API reference, SDK reference, and examples. Implementation: Algolia DocSearch or in-house typesense — open decision OD-IA-01.

Results are tab-grouped by source (Docs / API / SDKs / Examples). The user can press Enter on a result or use arrow keys + Enter to navigate.

### 7.5 Versioning

The portal supports versioned docs (per [Phase 2 API Design §13](../phase-2/Qeet%20ID%20%E2%80%94%20API%20Design%20Standards.md): v1 minimum 12-month support window).

- Version selector in the docs top-bar: `[v1 (current) ▾]`.
- Older versions show a yellow banner: "You're viewing the docs for v1, which is older than the current version (v2). [View v2 ↗]."
- Version-aware URLs: `/docs/v1/quickstart`, `/docs/v2/quickstart`. The unversioned URL `/docs/quickstart` redirects to the current version.

### 7.6 Status Page IA

The status page (`/status`) is intentionally one screen — Omar and Daniel should not have to navigate to check whether Qeet ID is up.

```
   /status                            Component matrix + recent incidents + subscribe
   /status/incidents/[id]             Detail of a past or current incident
```

### 7.7 Security Trust Center IA

The Security Trust Center (`/security`) is Omar's primary entry point. Its IA is flat — every key document is a one-click leaf from `/security`.

The landing page holds:
- A current "All systems operational" status line (linked to `/status`).
- A grid of trust documents (SOC 2, pen test, data residency, sub-processors, DPA, breach policy, VDP, CVE advisories).
- Quick access to the security mailing-list subscribe and the SOC 2 NDA gate.

---

### 8. Public Marketing Surfaces — Scope Boundary

Marketing owns `/` (home), `/pricing`, `/customers`, `/about`, `/contact`, `/careers`, and marketing campaign URLs. Phase 3 does not design these screens — Marketing's design team does.

Phase 3 commits the design system tokens, the design principles, the typography, and the component library that Marketing will consume. Marketing is a **stakeholder of** the Phase 3 design system, but the screen designs of marketing pages are out of scope for this document.

The IA contract at the boundary:

- The marketing site's top navigation links to `/docs`, `/security`, `/status`, `/changelog`, `/pricing` — these are the Phase 3-owned doors into the developer portal.
- The "Sign in" / "Sign up" links from marketing go to `/login` and `/signup` on a default Qeet ID tenant (the trial-signup tenant).

---

### 9. URL Structure & Routing Conventions

URLs are designed (IA-07). The rules below align with [Phase 2 API Design Standards §4](../phase-2/Qeet%20ID%20%E2%80%94%20API%20Design%20Standards.md).

### 9.1 Hosting Layout

| Surface | Host pattern | Path |
| --- | --- | --- |
| Marketing & developer portal | `qeetify.com` | `/`, `/docs/*`, `/api/*`, `/sdks/*`, `/status`, `/changelog`, `/roadmap`, `/security`, `/pricing`, `/blog`, `/community` |
| Tenant authentication flows | `{tenant-slug}.qeetify.com` (default) or custom domain | `/login`, `/signup`, `/auth/*` |
| Admin dashboard | `qeetify.com` | `/dashboard/{tenant-slug}/...` |
| Account portal (end user) | `{tenant-slug}.qeetify.com` or custom domain | `/auth/account/...` |
| Status (independent host) | `status.qeetify.com` | `/`, `/incidents/...` |
| Public OIDC discovery | `{tenant-slug}.qeetify.com` | `/.well-known/openid-configuration`, `/.well-known/jwks.json` |
| OAuth endpoints | `{tenant-slug}.qeetify.com` | `/oauth/*` |
| SAML endpoints | `{tenant-slug}.qeetify.com` | `/saml/*` |
| SCIM endpoints | `{tenant-slug}.qeetify.com` | `/scim/v2/*` |

### 9.2 Why Subdomain Routing for Tenants (vs Path)

| Option | Pros | Cons |
| --- | --- | --- |
| Subdomain (`acme.qeetify.com`) | Cookie isolation across tenants; visual tenancy ("I'm in Acme's login"); CNAME-able for custom domains; OIDC `iss` URL matches tenant identity (Protocol DC-01) | Wildcard SSL cert; DNS configuration overhead |
| Path (`qeetify.com/acme/login`) | Single SSL cert; simpler deployment | Cookie cross-tenant risk; can't CNAME; OIDC `iss` ambiguity |

Subdomain is chosen for the same reasons Stripe, Slack, Auth0 chose it: per-tenant cookie scoping, custom-domain CNAME path, and unambiguous OIDC issuer per tenant.

### 9.3 Dashboard URL Pattern

```
   /dashboard/{tenant-slug}/{section}/{subsection?}/{resource_id?}/{subaction?}
   examples:
       /dashboard/acme                                                              (overview)
       /dashboard/acme/identity/users
       /dashboard/acme/identity/users/user_01HX...
       /dashboard/acme/federation/sso/saml/new                                       (wizard)
       /dashboard/acme/federation/sso/saml/conn_01HX...
       /dashboard/acme/applications/client_app_42/credentials
       /dashboard/acme/security/audit?event_type=auth.login.succeeded&actor=user_8f3
       /dashboard/acme/settings/billing/upgrade
```

### 9.4 Identifier Format in URLs

Per [Phase 2 API Design §4.4](../phase-2/Qeet%20ID%20%E2%80%94%20API%20Design%20Standards.md), Qeet ID IDs are prefixed (`user_`, `org_`, `client_`, `key_`, `sess_`, `tok_`, `role_`, etc.). The dashboard URL uses these IDs directly — no opaque numeric IDs, no slug-based identifiers for resources except the tenant slug itself.

### 9.5 Bookmarkability

Every dashboard URL is bookmarkable. State that should persist in the URL:

- Pagination cursor (`?cursor=...`).
- Filter selections (`?status=active&source=scim`).
- Sort order (`?sort=-created_at`).
- Open drawer / detail panel (drawers do not have their own URLs at MVP — they're treated as ephemeral panels over the underlying list; OD-IA-02).

### 9.6 Redirect Hygiene

- `/dashboard` (no tenant) redirects to the user's last-active tenant.
- `/dashboard/{tenant}/users` is the canonical alias for `/dashboard/{tenant}/identity/users` — UX team agreed that "Users" is the most-visited section and deserves a top-level alias.
- Old URLs are preserved with 301 redirects for at least 12 months past any renaming.

---

### 10. Cross-Surface Navigation Patterns

### 10.1 Primary Navigation (Top Nav vs Side Nav)

| Surface | Primary | Secondary |
| --- | --- | --- |
| End-user auth pages | — | — |
| Admin Dashboard | Side nav (with sections) | Top nav for tenant context + global search |
| Developer Portal — Docs | Left nav (docs tree) | Top nav for cross-portal sections |
| Developer Portal — non-docs (Status, Roadmap, Changelog, Security) | Top nav only | — |
| Marketing | Top nav | — |

The decision rule: surfaces with deep hierarchies (≥3 levels) use a persistent side/left navigation; surfaces with shallow hierarchies (≤2 levels) use top navigation only.

### 10.2 Secondary Navigation

- **Tabs** are used for sibling views of the same resource (e.g., on the Application Detail page: General · Credentials · Callbacks · Tokens · Branding · Events). Tabs are the [Tab Group](Qeet ID%20%E2%80%94%20Component%20Library%20Specification.md) component; URLs update as tabs change.
- **Sub-navigation** for the Settings area uses the Settings Layout template (left settings nav + content).
- **Breadcrumbs** are present on every dashboard screen at ≥3 levels deep, never deeper than four crumbs.

### 10.3 Contextual Navigation

- **In-page jump links** (table of contents on doc pages — right rail in the Documentation Layout) appear when a page has ≥3 H2 headings.
- **Related links** appear at the bottom of doc pages — manually curated, not algorithmic.
- **"See also" callouts** appear inline in dashboard help text — e.g., on the SAML setup wizard, a sidebar "Related: SCIM provisioning".

### 10.4 Mobile Navigation Pattern

- **End-user auth pages:** no nav (linear flow).
- **Dashboard mobile:** hamburger menu → drawer with the side nav contents. Topbar has logo + tenant switcher + hamburger + cmd+K + avatar.
- **Docs mobile:** the left nav tree becomes a collapsible drawer triggered from a button at the top of the content area; the right TOC becomes a sticky popover.

Detailed mobile-specific patterns are in [Mobile & Responsive Design Specification §6](Qeet ID%20%E2%80%94%20Mobile%20%26%20Responsive%20Design%20Specification.md).

---

### 11. Tenant Context Model in the UI

The tenant context model in Phase 2 [Multi-Tenancy Architecture §4](../phase-2/Qeet%20ID%20%E2%80%94%20Multi-Tenancy%20Architecture.md) is the *data* model; this section is the *UX* model.

### 11.1 Tenant Switcher Position

Top-left of every dashboard screen. Visible at every breakpoint (does not collapse with side nav).

### 11.2 Multi-Tenant Membership

A user can be a member of many tenants (MTP-06). When the user signs in:

- If they belong to one tenant, they land on that tenant's dashboard.
- If they belong to multiple, they see a tenant selection screen (`/dashboard/select`) listing all their tenants with the same card design as the Tenant Switcher dropdown.
- They can pin a tenant as their default; subsequent sign-ins skip the selection screen.

### 11.3 Tenant Slug in URL

The slug is the human-readable identifier (`acme`) in the URL. The UUID `tenant_id` is the canonical identifier in the API but does not appear in the URL — slugs are easier to read, share, and grep.

A slug change (rare; allowed once per quarter for billing customers) produces 301 redirects from old paths to new.

### 11.4 Tenant Indicators

- The Tenant Switcher displays the **tenant name** and **subdomain** prominently.
- The browser tab title is `{Section} · {Tenant Name} · Qeet ID`. Sandra has eight Qeet ID tabs open across three orgs; the title disambiguates.
- The favicon stays the Qeet ID Q at MVP (per-tenant favicons are a v1.2 Branding extension; OD-IA-03).

### 11.5 Cross-Tenant Awareness

When the active tenant changes, the URL changes (so the user knows). A subtle confirmation toast appears: "Switched to Acme R&D." This is consistent with [Principle P-08](Qeet ID%20%E2%80%94%20UX%20Research%20Summary%20%26%20Design%20Principles.md) (clarity of state changes).

---

### 12. Search Architecture

### 12.1 Two Search Surfaces

| Search | Scope | Trigger | UI |
| --- | --- | --- | --- |
| **Dashboard Global Search** | Users, roles, applications, audit events, settings pages within the current tenant | `cmd+K` / `ctrl+K` or click search field | Command palette overlay |
| **Docs Search** | Docs, API, SDKs, examples (cross-tenant; public content) | `/` or click search field in docs top nav | Inline instant-search overlay |

### 12.2 Dashboard Global Search (Command Palette)

The command palette opens centred over the dashboard, dimming the background. It supports:

- **Search-as-you-type** with 200ms debounce.
- **Tabbed result categories** (Users · Roles · Applications · Audit · Settings).
- **Keyboard navigation:** Up/Down moves; Enter selects; Esc closes.
- **Verbs:** typing `>` prefixes commands (e.g., `> invite user`, `> create application`).
- **Recently visited** when the input is empty.
- **Pinned items** at the top of the empty state.

### 12.3 Docs Search

Implementation candidate: Algolia DocSearch (free for open documentation) or in-house typesense. OD-IA-01.

Behaviour:
- Searches doc title, headings, body text, and code blocks.
- Result rendering shows the heading hierarchy (e.g., "Quickstart · Configure · Add the SDK").
- Selects on Enter or click; arrow keys navigate.

### 12.4 Search Outcome Logging

Searches that produce zero results are logged anonymously and reviewed weekly by the Technical Writer team — informing doc gaps.

---

### 13. Keyboard Navigation & Shortcuts

### 13.1 Global Shortcuts (Dashboard)

| Shortcut | Action |
| --- | --- |
| `cmd+K` / `ctrl+K` | Open command palette |
| `cmd+/` / `ctrl+/` | Show keyboard shortcuts help overlay |
| `g` then `u` | Go to Users |
| `g` then `r` | Go to Roles |
| `g` then `a` | Go to Applications |
| `g` then `s` | Go to SSO connections |
| `g` then `l` | Go to Audit Logs |
| `g` then `b` | Go to Billing |
| `g` then `h` | Go home (dashboard overview) |
| `?` | Open shortcuts overlay (same as cmd+/) |
| `[` `]` | Previous / next tenant in switcher |
| `t` (in data table) | Focus the search field above the table |
| `f` (in data table) | Focus the filter bar |
| `n` (in data table) | Open the "new" affordance for that resource |

Linear-style `g`+letter and Gmail-style single-letter shortcuts are deliberately chosen — they are familiar to Daniel and Sandra (both have used Linear or Gmail extensively), and avoid the modifier-key fatigue of cmd-chord shortcuts.

### 13.2 Docs-Specific Shortcuts

| Shortcut | Action |
| --- | --- |
| `/` | Focus the docs search |
| `←` / `→` | Previous / next page in the docs tree (when not in an input) |
| `t` | Cycle the code-tab language (per [Component Library §5.4](Qeet ID%20%E2%80%94%20Component%20Library%20Specification.md)) |
| `c` | Copy the currently visible code block |

### 13.3 Auth-Page Shortcuts

End-user auth pages do **not** define keyboard shortcuts beyond browser defaults — the audience is heterogeneous and shortcut overlap with browser shortcuts (e.g., `/` in password fields) is risky.

### 13.4 Accessibility Shortcut Conformance

Per [Phase 3 Doc 9 §7](Qeet ID%20%E2%80%94%20Accessibility%20Compliance%20Plan%20%28WCAG%202.1%20AA%29.md):

- All shortcuts can be disabled by the user (WCAG 2.1.4 Character Key Shortcuts).
- Single-letter shortcuts only active outside text inputs.
- The shortcuts overlay (`?` / `cmd+/`) is the canonical discovery surface — never assume the user has seen it.

---

### 14. Onboarding & First-Run IA

A user's *first* visit to the dashboard sees a slightly different IA tree than subsequent visits. Two adaptations:

- The dashboard home is the **empty-trial overview** (§6.7) with the setup checklist.
- The side nav has a "Getting Started" pinned entry at the top, leading to an in-product walkthrough (Customer Success ask — OD-UX-05 closed for MVP if approved, deferred to v1.1 if not).

After the user dismisses the walkthrough or completes setup, the Getting Started entry disappears (with the user able to restore it from Settings > Preferences).

---

### 15. Empty Tenant vs Populated Tenant

The IA is identical in both cases; the difference is at the **screen** level (per Phase 3 Doc 6 §10 Empty States):

- An empty Users list shows the Users empty state with "Invite your first user" CTA.
- An empty Roles list shows the Roles empty state with "Create your first role" CTA.
- An empty SAML connections list shows the SAML empty state with "Add SAML connection" CTA + a link to the SAML setup guide.

The navigation tree does *not* hide sections that are empty — Sandra needs the SAML link to be available the moment she decides to set up SAML; hiding it until "first SAML exists" is a chicken-and-egg failure.

---

### 16. Open Design Decisions From This Document

| # | Question | Owner | Target |
| --- | --- | --- | --- |
| OD-IA-01 | Docs search — Algolia DocSearch vs in-house Typesense | Tech Writing + Frontend | Phase 3 Week 3 |
| OD-IA-02 | Whether drawers (user detail, role detail) get their own URLs at MVP | UX Designer + Frontend Lead | Phase 3 Week 3 |
| OD-IA-03 | Per-tenant favicon at MVP vs v1.2 | Product + UX | Phase 3 Week 2 |
| OD-IA-04 | Tenant slug rename frequency limit — once per quarter vs once per six months | Product + Sales | Phase 3 Week 2 |
| OD-IA-05 | Dashboard mobile read-only emergency view — "Send link to my desktop" via email vs deep-link to desktop SSO continuation | UX + Engineering | Phase 3 Week 4 |
| OD-IA-06 | Whether the dashboard exposes the path-alias `/dashboard/{tenant}/users` (instead of `/dashboard/{tenant}/identity/users`) at MVP | UX + Frontend | Phase 3 Week 2 |

---

### 17. Cross-References

- Principles informing IA shape: [UX Research Summary & Design Principles](Qeet ID%20%E2%80%94%20UX%20Research%20Summary%20%26%20Design%20Principles.md) §6
- Tokens used by navigation components: [Design System Foundations & Tokens](Qeet ID%20%E2%80%94%20Design%20System%20Foundations%20%26%20Tokens.md) §11 (motion), §13 (z-index)
- Navigation components: [Component Library Specification](Qeet ID%20%E2%80%94%20Component%20Library%20Specification.md) §6.1, §6.2, §6.3, §6.16, §6.18, §6.20
- Screen-level designs for the dashboard: [Admin Dashboard Design Specification](Qeet ID%20%E2%80%94%20Admin%20Dashboard%20Design%20Specification.md)
- Screen-level designs for the docs: [Developer Portal Design Specification](Qeet ID%20%E2%80%94%20Developer%20Portal%20Design%20Specification.md)
- Tenant URL hosting: [Phase 2 Infrastructure §4](../phase-2/Qeet%20ID%20%E2%80%94%20Infrastructure%20%26%20Deployment%20Architecture.md)
- Tenant context model: [Phase 2 Multi-Tenancy Architecture §4, §9](../phase-2/Qeet%20ID%20%E2%80%94%20Multi-Tenancy%20Architecture.md)
- API URL conventions: [Phase 2 API Design Standards §4](../phase-2/Qeet%20ID%20%E2%80%94%20API%20Design%20Standards.md)

---

### 18. Approvals & Sign-off

| Role | Name | Signature | Date |
| --- | --- | --- | --- |
| UX Designer |  |  |  |
| Product Designer |  |  |  |
| Product Manager |  |  |  |
| Frontend Engineering Lead |  |  |  |
| Technical Writer Lead (developer portal IA) |  |  |  |
| Developer Relations Lead |  |  |  |
| Solution Architect (URL & routing alignment) |  |  |  |
| Marketing Lead (cross-surface boundary) |  |  |  |

---

*This document is version controlled. Visual updates in Figma do not require re-sign-off; changes to the site maps (§5.1, §6.1, §7.1), URL structure (§9), tenant routing model (§11), or top-level navigation patterns (§10) require UX Designer + Product Manager + Solution Architect review.*

---

**Qeet ID — Authenticate Everything.** *A Qeet Group Company*
