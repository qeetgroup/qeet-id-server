# Qeet ID — Admin Dashboard Design Specification

### 1. Document Information

|  |  |
| --- | --- |
| **Document Name** | Admin Dashboard Design Specification |
| **Project Name** | Qeet ID |
| **Parent Company** | Qeet Group |
| **Subsidiary** | Qeet ID (Standalone) |
| **Document Version** | v1.0 |
| **Prepared By** | UX Designer + Product Designer |
| **Date** | May 19, 2026 |
| **Status** | Draft — Pending Stakeholder Sign-off |

---

### 2. Purpose & Scope

This document specifies the design of the Qeet ID Admin Dashboard — the operational console used daily by tenant administrators. It defines, screen by screen, what every dashboard surface looks like, what it contains, how it behaves, what empty / error / loading states look like, and what bulk-action, export, and keyboard patterns apply.

The Admin Dashboard is Sandra's home. It is where Maya spends her configuration time. It is where Daniel reviews audit logs after a security incident and where he configures SAML for his next enterprise customer. It is, per the [Persona Matrix](Qeet ID%20%E2%80%94%20UX%20Research%20Summary%20%26%20Design%20Principles.md), the lead surface for the Sandra persona. Every screen here is designed in the awareness that Sandra has been doing this kind of work for a decade and will not tolerate inefficiency.

This document depends on every Phase 3 document preceding it ([Doc 1 Principles](Qeet ID%20%E2%80%94%20UX%20Research%20Summary%20%26%20Design%20Principles.md), [Doc 2 Tokens](Qeet ID%20%E2%80%94%20Design%20System%20Foundations%20%26%20Tokens.md), [Doc 3 Components](Qeet ID%20%E2%80%94%20Component%20Library%20Specification.md), [Doc 4 IA](Qeet ID%20%E2%80%94%20Information%20Architecture%20%26%20Navigation.md)) and on Phase 2 architecture, especially [Microservices Decomposition](../phase-2/Qeet%20ID%20%E2%80%94%20Microservices%20Decomposition%20%26%20Service%20Boundaries.md), [Multi-Tenancy Architecture](../phase-2/Qeet%20ID%20%E2%80%94%20Multi-Tenancy%20Architecture.md), [Database Design](../phase-2/Qeet%20ID%20%E2%80%94%20Database%20Design%20%26%20Data%20Model.md), and [Observability Architecture](../phase-2/Qeet%20ID%20%E2%80%94%20Observability%20Architecture.md).

The audience is the UX Designer, Product Designer, Frontend Engineering Lead, Team Identity / Team Federation / Team Guard / Team Experience leads, QA Lead, and Compliance Officer (for audit log viewer review).

---

### 3. Dashboard Design Principles

The ten Design Principles ([Doc 1 §6](Qeet ID%20%E2%80%94%20UX%20Research%20Summary%20%26%20Design%20Principles.md)) apply. The principles below specialise them for the dashboard:

**DP-01 — Role-Aware Density.** Sandra wants more information per screen; Arjun wants less. The dashboard ships a default density (`comfortable`) and exposes a per-user density preference (`spacious` / `comfortable` / `compact`) — Sandra's default after she sets it will be `compact`. Critical surfaces (audit log) default to `compact` regardless.

**DP-02 — Technical and Non-Technical Users Both.** The stakeholder finding is verbatim: *"IT admins should not need to write code to manage users and roles."* Every dashboard screen functions without writing code OR JSON. Where structured input is genuinely required (custom claim mapping, SAML attribute mapping), the structured form is the default — with a JSON view as a power-user toggle.

**DP-03 — Fast Navigation, Always Visible.** Per [Principle P-09](Qeet ID%20%E2%80%94%20UX%20Research%20Summary%20%26%20Design%20Principles.md) and [Doc 4 §13 Keyboard Shortcuts](Qeet ID%20%E2%80%94%20Information%20Architecture%20%26%20Navigation.md), every routine task is one `cmd+K` away. The side nav is *visible*, not hidden behind hamburger menus on desktop. Breadcrumbs are present at every depth ≥3.

**DP-04 — Never Hide Critical Actions.** "Invite user," "Add SAML connection," "Add API key," "View audit logs" are reachable from the corresponding list page's top-right corner — never buried in a settings drawer.

**DP-05 — In-Place Edits Where Safe; Explicit Save Where Not.** Free-text notes auto-save. Configuration changes that affect production behaviour (SAML config, password policy, branding) require explicit "Save changes" with a confirmation toast.

**DP-06 — Show the Source.** Every role assignment, every user attribute, every webhook is labelled with where it came from — `manual` / `scim` / `saml` / `oidc` / `api` (per [Phase 2 Authorization Engine §7](../phase-2/Qeet%20ID%20%E2%80%94%20Authorization%20Engine%20Design.md)). This is non-trivial UX work but it is the difference between an admin who trusts the system and one who does not.

**DP-07 — Audit Trail Is a First-Class Citizen.** Every state-changing action shows an "View in audit log" link in its confirmation toast. Every user-detail screen has an "Audit trail" tab. The audit log is a destination, not an obscurity.

---

### 4. Admin Role Tiers (L1 / L2 / L3)

The role-aware navigation per [Persona Sandra](Qeet ID%20%E2%80%94%20UX%20Research%20Summary%20%26%20Design%20Principles.md) requires explicit admin tiers. The MVP model:

| Tier | Description | Default permissions |
| --- | --- | --- |
| **L1 — Read-Only Admin** | Helpdesk / first-line support. Can see but not change. | `*:read` |
| **L2 — Operator** | Day-to-day admin. Can manage users, roles, sessions, support actions. Cannot change tenant-level configuration (SAML, branding, billing). | `users:*`, `roles:*`, `sessions:*`, `audit:read`, `support:*` |
| **L3 — Tenant Admin** | Full access including billing, branding, custom domain, SAML, SCIM, plan changes. | `*:*` |

Tier labels are visible in the Team & Admin Roles screen (§17). The mapping to Qeet ID Access roles is configurable — defaults above are the templates.

### 4.1 Role-Aware Side Nav

The side navigation hides entries the current admin's role does not include. For example:

- An L1 viewer does not see "Billing", "Branding", "Custom Domain", "Team & Admin Roles" — these require L3.
- An L2 operator sees most of the dashboard except billing and tenant-level config.
- An L3 admin sees everything.

Hidden navigation has a one-line counterpart in Settings → Preferences explaining what was hidden and why (so a confused L2 user is not left wondering whether a feature exists).

---

### 5. Dashboard Persona Priorities

| Persona | Frequency | Primary tasks |
| --- | --- | --- |
| **Sandra (Enterprise IT Admin) — primary lead** | Daily | Audit logs, user lifecycle (SCIM-driven), SAML configuration, MFA policy, audit export to SIEM |
| **Daniel (Mid-Market Eng Lead)** | Weekly | Audit logs (post-incident reviews), SAML setup for new enterprise customers, migration progress dashboard, security events |
| **Maya (Startup CTO)** | Weekly during setup; less after | Applications, RBAC, branding, custom domain, plan management |
| **Arjun (Solo Developer)** | Occasional | API keys, webhook subscriptions, application configuration |
| **Omar (CISO)** | Quarterly | Audit log export, compliance documents, security events review |

These priorities drive screen-by-screen design weighting: the audit log viewer (§14) and SAML wizard (§9) get the most design care.

---

### 6. Organization Overview (Home)

The first screen an admin sees after sign-in. Route: `/dashboard/{tenant}`.

### 6.1 Anatomy

```
   ┌─────────────────────────────────────────────────────────────────────────┐
   │  Acme Corp — Growth · 1,248 MAUs                       (last 30 days)   │
   ├─────────────────────────────────────────────────────────────────────────┤
   │  [Stat: MAUs ▲]   [Stat: Logins ▲]   [Stat: New users ▲]   [Stat: ✓]    │
   │   12,481           48,230             612                  Auth uptime  │
   │   +8.3% MoM        +5% MoM            +12% MoM             99.97% 30d   │
   ├─────────────────────────────────────────────────────────────────────────┤
   │  ⚠  Alerts                                                              │
   │  • 3 SCIM provisioning errors — last at 14:32 UTC          [Resolve →] │
   │  • Custom domain DNS not yet propagated                    [View →]    │
   ├─────────────────────────────────────────────────────────────────────────┤
   │  Recent events                                          View all audit →│
   │  • alice@acme.com signed in via passkey                  2 min ago      │
   │  • Carol Diaz suspended by you                            5 min ago      │
   │  • SAML connection "Entra ID" updated                    1 hour ago      │
   │  • …                                                                     │
   ├─────────────────────────────────────────────────────────────────────────┤
   │  Quick actions                                                          │
   │  [+ Invite user]  [+ Add SAML]  [+ Add application]  [+ Webhook]        │
   └─────────────────────────────────────────────────────────────────────────┘
```

### 6.2 Cards

- **Stat cards** (4 across desktop, 2 on tablet, 1 on mobile) show MAUs, logins, new users, and auth uptime with delta vs previous period.
- **Alerts banner** appears only when there are alerts. Each alert links to its source page with a contextual fix CTA.
- **Recent events** is a 5-row preview from the audit log, filtered to admin-actionable events. Clicking "View all audit" navigates to §14.
- **Quick actions** are the most common new-resource CTAs.

### 6.3 Empty-Trial Variant

For a brand-new tenant, the Overview is replaced by the setup checklist described in [Phase 3 Doc 4 §6.7](Qeet ID%20%E2%80%94%20Information%20Architecture%20%26%20Navigation.md):

```
   Welcome to Qeet ID. Let's get you set up.

   ☐ Create your first application                          (2 min)  [Start →]
   ☐ Invite a teammate                                       (1 min)  [Start →]
   ☐ Set up Single Sign-On (SAML or OIDC)                    (10 min) [Start →]
   ☐ Configure MFA policy                                    (3 min)  [Start →]
   ☐ Brand your login pages                                  (5 min)  [Start →]
   ☐ Set up a custom domain                                  (10 min) [Start →]

   You can hide this checklist in Settings → Preferences.
```

Completion persists per tenant. Once all are checked, the checklist collapses to a one-liner.

### 6.4 Right-Panel Slot (Optional)

On a wide viewport (≥1440px), the Overview reserves a right-side 320px panel for contextual content — at MVP this slot is empty by default; in v1.1 it holds an "in-product onboarding" walkthrough widget.

---

### 7. Users — Index Screen

Route: `/dashboard/{tenant}/identity/users`.

### 7.1 Anatomy

The screen is a Data Table ([Component Library §6.4](Qeet ID%20%E2%80%94%20Component%20Library%20Specification.md)) composed with the User Row ([§6.6](Qeet ID%20%E2%80%94%20Component%20Library%20Specification.md)) row type.

```
   ┌─────────────────────────────────────────────────────────────────────────────┐
   │  Users                                                  [+ Invite user]     │
   ├─────────────────────────────────────────────────────────────────────────────┤
   │  🔍 Search by name or email                                                  │
   │  [Status: All ▾] [Source: All ▾] [Role: All ▾] [MFA: All ▾]                  │
   │                                                          [Columns ▾] [⤓ ⋯]  │
   ├─[√]─────────────────────────────────────────────────────────────────────────┤
   │  □   User                  Email                 Status   Roles    Source    ⋯ │
   ├─────────────────────────────────────────────────────────────────────────────┤
   │  □   AB Alice Beck         alice@acme.com        Active   Admin    SCIM     ⋯ │
   │  □   CD Carol Diaz         carol@acme.com        Active   Member   Manual   ⋯ │
   │  ☑   EF Ed Fisher          ed@acme.com           Susp.    Viewer   SAML     ⋯ │
   │                                                                             │
   │  Showing 1–25 of ~2,400      ◀ Previous · Next ▶                            │
   └─────────────────────────────────────────────────────────────────────────────┘
```

### 7.2 Filters

| Filter | Values |
| --- | --- |
| Status | All, Active, Suspended, Pending verification, Pending deletion |
| Source | All, Manual, SCIM, SAML JIT, OIDC JIT, Self sign-up, API |
| Role | All, plus each role defined in the tenant |
| MFA | All, Enrolled, Not enrolled |
| Last login | Any time, Last 24 h, Last 7 d, Last 30 d, Custom range |

Filters compose; the URL reflects the filter state for shareability.

### 7.3 Bulk Actions

When ≥1 user is selected, a bulk-action bar slides up at the bottom of the table:

```
   ┌─────────────────────────────────────────────────────────────────────────────┐
   │  3 users selected                                                           │
   │  [Suspend]  [Reactivate]  [Assign role…]  [Send password reset]  [⋯]  [×]   │
   └─────────────────────────────────────────────────────────────────────────────┘
```

The `⋯` menu adds: Export selected, Delete (destructive — requires confirmation).

### 7.4 Row Actions Menu

The per-row `⋯` opens: View · Edit · Suspend · Send password reset · View sessions · View audit trail · Delete.

### 7.5 Empty State

```
   No users yet

   Invite your first user, or set up SAML / SCIM to provision automatically.

   [+ Invite user]   Configure SAML / SCIM →
```

### 7.6 Loading & Error States

- **Loading:** 8-row skeleton.
- **Error:** in-table error banner with "Retry" button + error code.

### 7.7 Export

The `⤓` button exports the current view (post-filter, post-sort) to CSV or JSON. For tenants with millions of users, the export is queued (async); the user is told "Your export is being prepared. We'll email you when it's ready."

---

### 8. User Detail Screen

Route: `/dashboard/{tenant}/identity/users/{user_id}`. Opens either as a full page or as a right-side drawer (configurable per user preference — drawer is the default for Sandra-style workflows).

### 8.1 Anatomy

```
   ┌────────────────────────────────────────────────────────────────────────────┐
   │  ←  Users  /  Alice Beck                                            [⋯]    │
   ├────────────────────────────────────────────────────────────────────────────┤
   │                                                                            │
   │   AB    Alice Beck                                          Active         │
   │         alice@acme.com · +1 415 555-7421                                   │
   │         Joined Jan 2026 · user_01HX5T0Z9Q…                                 │
   │                                                                            │
   ├─[Profile]─[Organizations]─[Roles]─[Sessions]─[Audit trail]─[Danger zone]──┤
   │                                                                            │
   │  Profile                                                                   │
   │  Full name        Alice Beck                                  [Edit]       │
   │  Email            alice@acme.com (verified)                   [Edit]       │
   │  Phone            +1 415 555-7421 (verified)                  [Edit]       │
   │  MFA              Passkey, TOTP                                            │
   │  Passkeys         3 registered                                [Manage →]   │
   │  Custom metadata                                                           │
   │   department      Engineering                                              │
   │   employee_id     E-04812                                                  │
   │   external_id     okta_001v3p9z (from SCIM)                                │
   │  Sign-in providers                                                         │
   │   Email / Password · Google · SAML (Entra ID)                              │
   │                                                                            │
   └────────────────────────────────────────────────────────────────────────────┘
```

### 8.2 Tabs

| Tab | Content |
| --- | --- |
| Profile | Identity fields, custom metadata (dynamic per tenant), sign-in providers |
| Organizations | Other tenants this user belongs to (if any) |
| Roles | Effective roles + role-assignment sources (per DP-06) — Manual / SCIM / SAML / OIDC / API; expand each to see the audit trail of when it was assigned |
| Sessions | Active sessions list with revoke per session and "Revoke all" |
| Audit trail | Filtered audit log scoped to this user as actor or target |
| Danger zone | Suspend, Force password reset, Delete (with cooling-off) |

### 8.3 Inline Actions

The header `⋯` menu duplicates Suspend / Delete for keyboard convenience.

### 8.4 Custom Metadata Dynamic Fields

The custom metadata block is dynamic per tenant. The tenant's Tenant Service config defines the schema; the dashboard renders editable fields per schema. Custom fields not in the schema appear as a JSON view at the bottom — "Additional metadata (raw)".

### 8.5 SCIM-Sourced Fields

Fields sourced from SCIM are read-only in the dashboard (and the helper text reads: "Managed by SCIM provider · Edit at the source"). Attempting to edit them surfaces an inline notice.

---

### 9. SAML Connection Setup Wizard

Route: `/dashboard/{tenant}/federation/sso/saml/new`. Perhaps the most-scrutinised dashboard screen — Daniel's verbatim pain point is *"SAML configuration errors without clear error messages."*

### 9.1 Anti-Pattern Note

[Anti-pattern AP-14](Qeet ID%20%E2%80%94%20UX%20Research%20Summary%20%26%20Design%20Principles.md) prohibits multi-screen wizards for single-form tasks. SAML is the deliberate exception: real provisioning requires sequencing (you cannot test the connection before you upload metadata; you cannot finish without a successful test). So the wizard is a [Stepper](Qeet ID%20%E2%80%94%20Component%20Library%20Specification.md) of five gated steps.

### 9.2 Stepper

```
   ● ───── ● ───── ○ ───── ○ ───── ○
   Identify  Connect  Map      Test    Activate
   IdP       metadata attrs    flow
```

### 9.3 Step 1 — Identify IdP

The user picks the IdP from a curated list (Microsoft Entra ID, Okta, Google Workspace, OneLogin, Ping, JumpCloud, "Generic SAML 2.0"). The choice changes the per-step guidance (Entra ID gets Entra-specific screenshots; Generic gets the spec-level descriptions).

```
   What identity provider are you connecting?

   ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
   │  Microsoft  │ │    Okta     │ │   Google    │ │     Ping    │
   │   Entra ID  │ │             │ │  Workspace  │ │             │
   └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘
   ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
   │  OneLogin   │ │  JumpCloud  │ │   Custom    │ │   Other     │
   │             │ │             │ │   SAML 2.0  │ │             │
   └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘
```

### 9.4 Step 2 — Connect Metadata

```
   Upload your IdP metadata

   You can:
     ○ Paste a metadata URL (recommended for auto-update)
     ○ Upload metadata XML

   [URL field________________________________]  [Fetch]
   or
   [Drop a file or browse]

   When you're done, share Qeet ID's SP metadata with your IdP:
     - Entity ID:      https://acme.qeetify.com/saml/metadata
     - ACS URL:        https://acme.qeetify.com/saml/{conn_id}/acs
     - SLO URL:        https://acme.qeetify.com/saml/{conn_id}/slo
   [Copy all]   [Download Qeet ID SP metadata XML]
```

Behaviour:
- Pasting a URL triggers a live fetch and validation (Phase 2 [SAML Service §4.8](../phase-2/Qeet%20ID%20%E2%80%94%20Microservices%20Decomposition%20%26%20Service%20Boundaries.md)).
- Errors are specific (Daniel's ask). The error voice from [Doc 1 §7.2](Qeet ID%20%E2%80%94%20UX%20Research%20Summary%20%26%20Design%20Principles.md): "Could not parse metadata XML. The metadata at `https://login.acme.example/metadata` returned a 200 OK with `<EntityDescriptor>` but no `<SingleSignOnService>` element. (`saml_metadata_missing_sso_endpoint`)."
- A successful fetch shows the parsed IdP fields in a read-only summary.

### 9.5 Step 3 — Map Attributes

```
   Map IdP attributes to Qeet ID user fields

   Qeet ID field      SAML attribute (from IdP)
   email              [http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress ▾]
   given_name         [http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname ▾]
   family_name        [http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname ▾]
   roles (groups)     [http://schemas.microsoft.com/ws/2008/06/identity/claims/groups ▾]
                     → Map values to Qeet ID roles
                        admin_group       → role "admin"        [×]
                        member_group      → role "member"       [×]
                        [+ Add mapping]

   custom_metadata
     department       [department ▾]
     employee_id      [employeeId ▾]
   [+ Add custom attribute mapping]
```

Behaviour:
- Suggestions from the most common SAML schemas (Microsoft, Okta, Google) auto-populate.
- A "Test mapping" button runs a dry-run of an assertion (from a saved test assertion the IdP previously sent) and shows the resulting Qeet ID user record.

### 9.6 Step 4 — Test Flow

```
   Test the connection end-to-end

   Click "Test sign-in" to be redirected to your IdP, authenticate, and return.
   This won't change anything — it's a dry run.

   [▶ Test sign-in]

   After the test:
   ─ Assertion received: ✓
   ─ Signature valid:    ✓
   ─ Audience matches:   ✓
   ─ Email mapped:       ✓ (alice@acme.com)
   ─ Roles mapped:       ✓ admin, member
```

Behaviour:
- Failed test surfaces the exact failure with the error code (per [P-08](Qeet ID%20%E2%80%94%20UX%20Research%20Summary%20%26%20Design%20Principles.md)).
- A "Retry test" option is always present.
- The wizard does not advance to Step 5 until a successful test (or the admin overrides with an explicit "Skip test — I'll verify later" confirmation, which is logged in the audit).

### 9.7 Step 5 — Activate

```
   Ready to activate

   Connection name        [Entra ID — Acme Corp]
   IdP                    Microsoft Entra ID
   Login URL              https://login.acme.example/saml/sso
   Allow IdP-initiated    ☐  (default off — security recommended)
   Sign AuthnRequest      ☑  (recommended)
   Require signed assertion ☑
   Encrypt assertions     ☐  (recommended for enterprise)

   [Activate connection]
```

On activation, the connection appears in the SSO Connections list. An audit event fires.

### 9.8 Validation Live

Every step's "Next" button is gated on validation. Validation is **live** (not on submit) — Daniel sees errors as he types, not after he advances and waits.

---

### 10. Audit Log Viewer

Route: `/dashboard/{tenant}/security/audit`. The heaviest design in the dashboard — and the screen that determines whether Sandra renews the contract.

### 10.1 Anatomy

```
   ┌──────────────────────────────────────────────────────────────────────────────┐
   │  Audit logs                                                  [Export ⤓] [⋯] │
   ├──────────────────────────────────────────────────────────────────────────────┤
   │  🔍 Search by actor, target, or event type                                    │
   │  [Date: Last 24h ▾] [Event type: All ▾] [Actor: Any ▾] [Result: All ▾]      │
   │  [Source IP: Any ▾]                                       [Save view ▾] [⌘ ⋯]│
   ├──────────────────────────────────────────────────────────────────────────────┤
   │  Time (UTC)    Event              Actor             Target          Result   │
   ├──────────────────────────────────────────────────────────────────────────────┤
   │  14:32:18.231  auth.login.        alice@acme.com    alice@acme.com  ✓        │
   │                  succeeded                                                    │
   │  14:32:14.001  scim.user.          provisioner       new-user@…     ✓        │
   │                  created                                                      │
   │  14:31:55.412  authz.role.        you               carol@acme.com  ✓        │
   │                  assigned                                                     │
   │  14:31:42.901  auth.login.        bob@acme.com      bob@acme.com    ⨯  Denied│
   │                  failed (lockout)                                             │
   │  14:30:18.011  saml.assertion.    saml-conn-entra   alice@acme.com  ✓        │
   │                  accepted                                                     │
   │  14:30:08.412  webhook.delivery   webhook-svc       https://acme…   ✓        │
   │                  succeeded                                                    │
   │  …                                                                            │
   │                                                                              │
   │  Showing 1–50 of ~12,438 events in selected range                            │
   │  ◀ Previous · Next ▶                                                         │
   └──────────────────────────────────────────────────────────────────────────────┘
```

### 10.2 Behaviour

- Density defaults to `compact`. Sandra works through hundreds of rows in a session.
- Search-as-you-type with 300ms debounce. Search hits actor, target, event type, IP, and request_id.
- Date range default: Last 24 h; quick presets (Last 1 h, 24 h, 7 d, 30 d, 90 d, Custom).
- Event-type filter is hierarchical: top-level `auth.*`, `authz.*`, `scim.*`, `saml.*`, `webhook.*`, `admin.*`, `security.*`; each expands to sub-types.

### 10.3 Row Expand

Clicking a row reveals the [Audit Log Row expanded view](Qeet ID%20%E2%80%94%20Component%20Library%20Specification.md) — the full event payload as structured fields + a "Copy JSON" affordance + "View related events" + "View trace" deep-link to Observability ([Phase 2 Observability §6](../phase-2/Qeet%20ID%20%E2%80%94%20Observability%20Architecture.md)).

### 10.4 Saved Views

Saved Views let an admin save a filter combination by name ("Suspicious logins", "SCIM errors this week"). The view shows as a tab strip above the table:

```
   ─ All events ─ Failed logins ─ Suspicious logins ─ My actions ─ + Save view
```

Saved views persist per user.

### 10.5 Export

Per NFR RL-10, audit log export volume is bounded per plan (100 MB/day Free, 10 GB Growth, unlimited Enterprise).

- Inline export: ≤10,000 rows synchronously; CSV or JSON.
- Bulk export: >10,000 rows queued; emailed download link valid for 30 days.

### 10.6 SIEM Export Integration

The `⋯` menu has "Configure SIEM stream..." which opens the SIEM destination wizard (Splunk, Sentinel, Datadog, Sumo Logic — NFR IC-04). The wizard collects credentials and starts streaming.

### 10.7 Hash Chain Indicator

A subtle "✓ Integrity verified" indicator at the table footer (or "⚠ Verifying" while async verification runs). Clicking it opens an integrity-explainer modal describing the cryptographic chain (Phase 2 Database §13.2) — Omar may want to verify this himself.

### 10.8 Performance

- The audit table uses cursor pagination ([Phase 2 API §9](../phase-2/Qeet%20ID%20%E2%80%94%20API%20Design%20Standards.md)) so paging is constant-time even at 50 billion rows (NFR SC-11).
- Server-side rendering for the first page; client-side rendering for subsequent pages.
- Total counts are *approximate* ("~12,438") because exact counts at this scale are expensive.

### 10.9 Accessibility

- The table is keyboard navigable (Up/Down moves rows; Enter expands).
- Row counts are announced via live region on filter changes.
- Compact density preserves contrast and target sizes — `compact` does not mean inaccessible.

---

### 11. Roles & Permissions

### 11.1 Roles Index

Route: `/dashboard/{tenant}/identity/roles`.

A Data Table of roles, each row showing: Role name · Description · Permission count · Assigned users count · Source (Built-in / Custom) · Actions.

### 11.2 Role Editor Screen

Route: `/dashboard/{tenant}/identity/roles/{role_id}`.

```
   ┌─────────────────────────────────────────────────────────────────────────┐
   │  ←  Roles  /  admin                                              [⋯]   │
   ├─────────────────────────────────────────────────────────────────────────┤
   │  Name             admin                                                 │
   │  Description      Full tenant administration                            │
   │  Built-in         Yes (cannot be deleted; permissions are fixed)        │
   │                                                                         │
   │  Permissions                                                            │
   │  ─────────────────                                                      │
   │  All permissions granted (*:*)                                          │
   │                                                                         │
   │  Assigned users   124  [View →]                                         │
   │  Assigned groups  3    [View →]                                         │
   │  ─────────────────                                                      │
   │  Audit trail                                                            │
   │  • Permission "billing:manage" added by you             3 days ago      │
   │  • Role created by SCIM provisioner                     12 days ago     │
   └─────────────────────────────────────────────────────────────────────────┘
```

### 11.3 Permission Picker

A custom role editor exposes a permission picker:

```
   Permissions
   ───────────
   [🔍 Search permissions or paste a permission string]

   ☑ users
       ☑ users:read       Read users
       ☑ users:write      Create and update users
       ☐ users:delete     Delete users
   ☐ roles
       ☐ roles:read
       ☐ roles:write
   ☑ documents (custom)
       ☑ documents:read
       ☑ documents:write
       ☐ documents:delete

   [+ Add custom permission]
```

- Permission strings follow the format from [Phase 2 Authorization Engine §4.1](../phase-2/Qeet%20ID%20%E2%80%94%20Authorization%20Engine%20Design.md).
- Search filters as the user types.
- Wildcards (`*:read`, `documents:*`, `*:*`) are explicit toggles that lower-level entries auto-disable.

---

### 12. Applications

### 12.1 Applications Index

Route: `/dashboard/{tenant}/applications`.

Data Table: App name · `client_id` (with copy button) · Type (`public` / `confidential`) · Created date · Last token issued · Actions.

### 12.2 Application Detail Screen

Route: `/dashboard/{tenant}/applications/{client_id}`.

A tabbed page (General · Credentials · Callbacks · Tokens · Branding · Events).

### 12.3 General Tab

Editable: Name, Description, Logo, Type (public/confidential — confirmation required on change), Allowed grant types (multi-select).

### 12.4 Credentials Tab

For confidential clients:

```
   Client secrets

   ┌──────────────────────────────────────────────────────────────────┐
   │  qf_sec_*** — created Apr 1, last used 2 min ago    [Revoke]    │
   └──────────────────────────────────────────────────────────────────┘
   ┌──────────────────────────────────────────────────────────────────┐
   │  qf_sec_*** — created Jan 15, last used 14 days ago [Revoke]    │
   └──────────────────────────────────────────────────────────────────┘

   [+ Generate new secret]

   Or use private_key_jwt: [Upload public key]
```

Secrets are shown only at creation time (per Phase 2 IdP Core §10 secrets). After creation, only the prefix appears.

### 12.5 Callbacks Tab

Editable list of allowed redirect URIs. Exact match enforced (Protocol OS-03).

```
   Allowed callback URLs

   • https://acme.example.com/auth/callback                  [×]
   • https://acme-staging.example.com/auth/callback          [×]
   • [Add URL_____________________________________]   [+ Add]
```

Validation:
- Must be HTTPS (except `http://localhost:*` allowed for dev).
- Wildcards forbidden (per OS-03).

### 12.6 Tokens Tab

Configurable per application:
- Access token lifetime (5 min – 1 h)
- Refresh token lifetime (1 d – 90 d)
- Refresh rotation: required (locked on; rationale: Phase 2 ADR-019)
- ID token claims to include
- Permissions claim mode (`full` / `summary` / `none`)
- Require PKCE: required for public; configurable for confidential (default on)

### 12.7 Branding Tab

Per-application branding overrides the tenant default if set. Otherwise inherits.

### 12.8 Events Tab

Filtered audit log scoped to this application.

---

### 13. SCIM Configuration

Route: `/dashboard/{tenant}/federation/scim`.

### 13.1 Anatomy

```
   ┌─────────────────────────────────────────────────────────────────────────┐
   │  SCIM provisioning                                                       │
   ├─────────────────────────────────────────────────────────────────────────┤
   │  Status              ✓ Active                                            │
   │  Endpoint            https://acme.qeetify.com/scim/v2/  [Copy]           │
   │  Bearer token        qf_scim_***  [Rotate token]                         │
   │  Last sync           2 min ago                                           │
   │  Users provisioned   1,210                                               │
   │  Sync errors (24h)   3 [View →]                                          │
   ├─────────────────────────────────────────────────────────────────────────┤
   │  Group → Role mapping                                                   │
   │  IdP group               Qeet ID role                                    │
   │  admin_group             admin                                  [×]      │
   │  member_group            member                                 [×]      │
   │  viewer_group            viewer                                 [×]      │
   │  [+ Add mapping]                                                         │
   ├─────────────────────────────────────────────────────────────────────────┤
   │  Recent events                                                          │
   │  • user.created  alice@acme.com  via scim                  2 min ago    │
   │  • user.deprovisioned  bob@acme.com  via scim              5 min ago    │
   │  • scim.provisioning.error  carol@acme.com                  12 min ago   │
   │    (invalid_email)                                                       │
   │  …                                                                       │
   └─────────────────────────────────────────────────────────────────────────┘
```

### 13.2 Sync Status Dashboard

This is Sandra's verbatim pain point (Persona §4.4): *"any identity platform that doesn't provide granular audit logs is immediately disqualified."* SCIM is the most error-prone provisioning surface; the dashboard must surface errors clearly.

Sync errors expand to show the exact failing payload, the error code, and a "Retry" affordance. Bulk-retry is available for transient errors.

### 13.3 Test SCIM

A "Test SCIM endpoint" button performs a full round-trip (`GET /ServiceProviderConfig`, `POST /Users` with a synthetic user, `PATCH active=false`, `DELETE`) and shows the results.

---

### 14. MFA Policy Configuration

Route: `/dashboard/{tenant}/security/mfa`.

```
   ┌─────────────────────────────────────────────────────────────────────────┐
   │  Multi-factor authentication policy                                     │
   ├─────────────────────────────────────────────────────────────────────────┤
   │  Enforcement                                                             │
   │  ○ Optional   — users can enable MFA themselves                          │
   │  ●  Required  — all users must enrol within 14 days                      │
   │  ○ Enforced   — sign-in blocked until MFA is enrolled                    │
   │                                                                         │
   │  Allowed factors                                                         │
   │  ☑ Passkey   — recommended primary                                       │
   │  ☑ TOTP authenticator app                                                │
   │  ☑ SMS OTP   (warn: SMS is less secure than TOTP)                       │
   │  ☐ Email OTP                                                             │
   │  ☑ Backup codes                                                          │
   │                                                                         │
   │  Step-up triggers (require fresh MFA when):                              │
   │  ☑ User accesses admin dashboard                                         │
   │  ☑ User changes password or passkey                                      │
   │  ☐ Configurable per-resource (v1.5)                                      │
   │                                                                         │
   │  Trust this device for 7 days  [On ▾]                                    │
   │                                                                         │
   │  [Save changes]                                                          │
   └─────────────────────────────────────────────────────────────────────────┘
```

---

### 15. Password Policy

Route: `/dashboard/{tenant}/security/password-policy`. Aligns with NIST SP 800-63B guidance and Compliance AS-05.

```
   Password policy

   Minimum length              [8 ▾]   (recommended 8–16)
   Maximum length              ☑ unlimited (recommended)
   Require uppercase           ☐  (NIST: not recommended)
   Require numeric             ☐
   Require symbol              ☐
   Banned words                ☑  (auto: tenant name, "qeetify", common words)
   Compromised-password check  ☑  (HIBP — recommended on)
   Password expiry             ☐  (NIST: not recommended)

   [Save changes]
```

---

### 16. Branding & Customisation

Route: `/dashboard/{tenant}/settings/branding`. Live-preview interface for white-label brand configuration (per [Doc 8](Qeet ID%20%E2%80%94%20Embeddable%20Auth%20UI%20Components%20%28White-Label%29.md)).

### 16.1 Anatomy

```
   ┌──────────────────────────────┬────────────────────────────────────────┐
   │  Branding                    │                                        │
   │  ─────────                   │       (live preview of login page,     │
   │  Logo                        │        updated as user changes form)   │
   │    [Upload light variant]    │                                        │
   │    [Upload dark variant]     │                                        │
   │                              │                                        │
   │  Primary colour              │                                        │
   │    [#2563EB] [colour picker] │                                        │
   │    ⚠ Contrast with white     │                                        │
   │      4.0:1 — too low (AA 4.5)│                                        │
   │                              │                                        │
   │  Accent colour               │                                        │
   │    [#F59E0B]                 │                                        │
   │                              │                                        │
   │  Border radius               │                                        │
   │    [────●────] 8px           │                                        │
   │                              │                                        │
   │  Font family                 │                                        │
   │    [Inter ▾]                 │                                        │
   │                              │                                        │
   │  Background                  │                                        │
   │    ○ Solid colour            │                                        │
   │    ● Image                   │                                        │
   │      [Drop image…]           │                                        │
   │                              │                                        │
   │  Footer attribution          │                                        │
   │    [Powered by Qeet ID ▾]    │  (Enterprise plan: configurable)       │
   │                              │                                        │
   │  [Save changes]              │                                        │
   └──────────────────────────────┴────────────────────────────────────────┘
```

### 16.2 Live Validation

When the admin sets a primary colour with insufficient contrast (Doc 2 §15.3), the warning surfaces inline:

> ⚠ Contrast 4.0:1 with white button text. WCAG AA requires 4.5:1. Pick a darker shade or accept the default white text.

A "Use the closest accessible shade" CTA auto-suggests a darker hex.

### 16.3 Preview

The preview panel renders the live login page in an isolated iframe, updating in real time as the form changes. A device-toggle (desktop / tablet / mobile) lets the admin see the change across breakpoints.

### 16.4 Email Branding

A separate section: email logo (light + dark), email primary colour (defaults to login primary), sender name override (default "Acme via Qeet ID"). Per Doc 8 §11.

---

### 17. Custom Domain Setup Wizard

Route: `/dashboard/{tenant}/settings/branding/domain`. A genuine multi-step wizard (per AP-14 exception — DNS propagation gates the next step).

### 17.1 Stepper

```
   ● ─── ● ─── ○ ─── ○
   Domain  DNS    SSL    Activate
```

### 17.2 Step 1 — Domain

User enters the domain (e.g., `login.acme.com`).

### 17.3 Step 2 — DNS

Shows the required DNS records:

```
   Add these DNS records at your DNS provider

   Type   Host              Value
   CNAME  login.acme.com    custom.qeetify.com
   TXT    _qf.login.acme.com qf-verify-01HX5T0Z9Q…

   [Copy all]   [Refresh status]
   Status: Waiting for DNS propagation… (typically 5–60 minutes)
```

The dashboard polls DNS every 30s. When records are detected, status flips to "✓ DNS verified" and Step 3 unlocks.

### 17.4 Step 3 — SSL Provisioning

Qeet ID auto-provisions the cert via Let's Encrypt:

```
   Provisioning SSL certificate…
   ─ Validating domain ownership: ✓
   ─ Requesting certificate:      ✓
   ─ Installing certificate:      …

   (Typically completes in 1–5 minutes)
```

Failure modes (Let's Encrypt rate limits, CAA records, etc.) surface specific error guidance.

### 17.5 Step 4 — Activate

Final summary; activation flips traffic to the custom domain. Sandra can choose to keep the `acme.qeetify.com` subdomain as a backup or to redirect it.

---

### 18. Email Template Editor

Route: `/dashboard/{tenant}/settings/branding/emails`.

Lists every transactional email template; clicking one opens an editor with a live preview pane.

```
   ┌──────────────────────────────┬──────────────────────────────────────┐
   │  Templates                   │   Edit: Email verification           │
   │  ─────────                   │   ─────────────────                  │
   │  ● Email verification        │                                      │
   │  ○ Magic link                │   Subject                            │
   │  ○ Password reset            │   [Verify your email]                │
   │  ○ MFA SMS code              │                                      │
   │  ○ MFA email code            │   Greeting                           │
   │  ○ New device sign-in        │   [Hi {{ first_name }}]              │
   │  ○ Account deletion          │                                      │
   │  ○ Data export ready         │   Body                               │
   │                              │   [Tap the link to verify…]          │
   │                              │                                      │
   │                              │   ─────────────────                  │
   │                              │   Preview:  [Desktop ▾]              │
   │                              │   [iframe rendering the email]       │
   └──────────────────────────────┴──────────────────────────────────────┘
```

- Variables (`{{first_name}}`, `{{tenant_name}}`, etc.) shown in a sidebar.
- "Send test email" button mails the current draft to the admin.
- Translations per locale managed in the bottom tab (per [Doc 11](Qeet ID%20%E2%80%94%20Internationalization%20%26%20Localization%20Design.md)).

---

### 19. Security Events Dashboard

Route: `/dashboard/{tenant}/security/events`. A filtered view of `audit.security.*` events: anomaly detections, brute-force blocks, impossible-travel signals, refresh-token reuse alerts.

### 19.1 Anatomy

A summary strip + a list:

```
   ┌────────────┬────────────┬────────────┬────────────┐
   │ Anomalies  │ Lockouts   │ Bot blocks │ Token reuse│
   │ 12 (24h)   │ 4 (24h)    │ 142 (24h)  │ 0 (24h)    │
   │ ▲ +3       │ ▼ -2       │ ▼ -18      │ →          │
   └────────────┴────────────┴────────────┴────────────┘

   Recent security events
   (table of events with severity, type, user, detail, time, action)
```

Each event row's action menu offers: Mark as benign · Force step-up next login · Suspend user · Open audit detail.

---

### 20. Webhooks Index & Detail

Route: `/dashboard/{tenant}/applications/webhooks`. List of webhook subscriptions; each shows URL, event types, last delivery time, success rate (rolling 24 h).

### 20.1 Detail Page

Tabs: General (URL, events, signing secret) · Deliveries (history, success/failure) · Settings.

Delivery rows show: timestamp, event ID, HTTP status, response time, retry count. Failed deliveries can be re-sent (manual retry).

---

### 21. API Keys Management

Route: `/dashboard/{tenant}/applications/api-keys`.

```
   API keys

   ┌──────────────────────────────────────────────────────────────────────────────┐
   │  Name              Prefix          Scopes                Created   Last used  │
   ├──────────────────────────────────────────────────────────────────────────────┤
   │  CI pipeline       qf_live_abcd…  users:* roles:read    Apr 1     2 min ago  │
   │  Backend service   qf_live_xyz1…  scim:*                Mar 15    1 hour ago │
   │  Test integration  qf_test_…       users:read            Jan 20    3 days ago │
   └──────────────────────────────────────────────────────────────────────────────┘

   [+ Create API key]
```

### 21.1 Create Flow

Modal:
1. Name + environment (live/test) + scopes.
2. Generate. Key is shown **once** with a copy button and a "Save this somewhere safe — you won't see it again" warning ([Phase 2 IdP Core §10](../phase-2/Qeet%20ID%20%E2%80%94%20Identity%20Provider%20%28IdP%29%20Core%20Engine%20Design.md)).

### 21.2 Rotation

Per-key "Rotate" action: generates a new key, both old and new are valid for the overlap window (configurable, default 7 days), then the old is auto-revoked.

---

### 22. Team & Admin Roles Management (L1 / L2 / L3)

Route: `/dashboard/{tenant}/settings/team`.

Data table of admin team members with: name · email · tier (L1/L2/L3) · last active · actions.

Adding a member: invite by email; pick tier; on accept, member appears in the list.

A separate "Customise tier permissions" section lets L3 admins fine-tune what L2 and L1 can do (within the platform-enforced caps).

---

### 23. Usage Analytics Dashboard

Route: `/dashboard/{tenant}/analytics`.

Charts for: MAUs over time · Login methods distribution · MFA adoption rate · Passkey adoption rate · Geographic distribution of logins · Error rate · API call volume · Top applications by usage.

Filter strip: Date range, Application(s), Method.

Chart colours from the `chart-1..6` palette (Doc 2 §5.2). All charts are accessible (data table view available, colour-blind tested).

---

### 24. Billing Dashboard

Route: `/dashboard/{tenant}/settings/billing`.

```
   ┌─────────────────────────────────────────────────────────────────────────┐
   │  Billing                                                                 │
   ├─────────────────────────────────────────────────────────────────────────┤
   │  Plan: Growth — $99/mo + per-MAU                          [Change plan] │
   │                                                                         │
   │  MAUs this month                                                        │
   │  ────────────────                                                       │
   │  [chart: MAUs trending 12,481]                                          │
   │  12,481 / unlimited                  Includes 10,000 free               │
   │                                       2,481 billable @ $0.02 = $49.62  │
   │                                                                         │
   │  Estimated invoice (May)            $148.62                             │
   │                                                                         │
   ├─────────────────────────────────────────────────────────────────────────┤
   │  Payment method                                                         │
   │  •••• 4242 (Visa)  exp 12/27                          [Update]          │
   ├─────────────────────────────────────────────────────────────────────────┤
   │  Invoice history                                                        │
   │  • Apr 2026  $142.10  Paid    [Download]                                │
   │  • Mar 2026  $128.40  Paid    [Download]                                │
   │  …                                                                       │
   └─────────────────────────────────────────────────────────────────────────┘
```

### 24.1 Plan Upgrade Flow

Route: `/dashboard/{tenant}/settings/billing/upgrade`. A Stepper:
1. Choose plan (Free / Growth / Enterprise — Enterprise opens "Contact sales").
2. Confirm details + add payment method (Stripe Elements embed).
3. Confirm + activate.

---

### 25. Compliance Documents Library

Route: `/dashboard/{tenant}/settings/compliance`. A static-ish page with a card grid:

```
   ┌──────────────────────────────────────────────────────────────────────────┐
   │  Compliance documents                                                    │
   ├──────────────────────────────────────────────────────────────────────────┤
   │  [SOC 2 Type I report]    [DPA template]    [Sub-processor list]         │
   │   Latest: Apr 2026         Latest: Mar 2026   Last updated: 12 days ago  │
   │  [Download]                [Download]         [View →]                   │
   │                                                                          │
   │  [Pen test summary]       [Privacy policy]   [Breach notification        │
   │   Latest: Q1 2026          Latest version    policy]                     │
   │  [Download]                [View →]          [View →]                    │
   └──────────────────────────────────────────────────────────────────────────┘
```

SOC 2 Type I download gates behind an NDA acceptance the first time (the user accepts once per organisation; subsequent downloads are direct).

---

### 26. Settings — Tenant Profile

Route: `/dashboard/{tenant}/settings/profile`.

Editable: Organisation name, slug, data region (read-only with "Contact support to change"), default language for end-user pages, default time zone.

---

### 27. Empty States Per Screen

Every list/table has an empty state per [Component Library §6.11](Qeet ID%20%E2%80%94%20Component%20Library%20Specification.md). Specific copies:

| Screen | Title | Body | Primary CTA | Secondary |
| --- | --- | --- | --- | --- |
| Users | "No users yet" | "Invite your first user, or set up SAML / SCIM to provision automatically." | "Invite user" | "Configure SAML / SCIM" |
| Roles | "Only built-in roles" | "Create custom roles to match your access model." | "Create role" | "Read the RBAC guide" |
| Applications | "No applications yet" | "Create an application to integrate Qeet ID with your codebase." | "Create application" | "Read the Quickstart" |
| SSO Connections | "No SSO connections yet" | "Connect Microsoft Entra ID, Okta, or any SAML / OIDC IdP." | "Add SAML connection" | "Add OIDC connection" |
| SCIM | "SCIM not configured" | "Enable SCIM to provision users automatically from your IdP." | "Enable SCIM" | "Read the SCIM guide" |
| Audit logs | "No events match these filters" | "Try widening the date range or clearing filters." | "Clear filters" | "View all events (Last 24h)" |
| Webhooks | "No webhook subscriptions yet" | "Subscribe to events for your application." | "Create webhook" | "Read webhook docs" |
| API keys | "No API keys yet" | "Create an API key to use the Qeet ID management API." | "Create API key" | "Read the API docs" |
| Team & Admin Roles | "Just you so far" | "Invite teammates to help manage this organisation." | "Invite teammate" | n/a |
| Billing invoices | "No invoices yet" | "Once you have charges, they'll appear here." | n/a | "View plans" |

---

### 28. Error States Per Screen

Generic error template ([Component Library §6.12](Qeet ID%20%E2%80%94%20Component%20Library%20Specification.md)) with error code and Retry. Specific recovery flows:

| Screen | Error scenario | Recovery |
| --- | --- | --- |
| Users | API down | "Try again. If the problem persists, check status.qeetify.com." Status page link. |
| SAML test | Specific protocol error | Specific guidance (see §9.6) |
| SCIM sync failure | Specific error code per failed event | Inline expand of the error with target user + suggested fix |
| Webhook delivery failure | HTTP status code from customer endpoint | Retry button + log of attempts |
| Billing payment failed | Stripe error | Update payment method CTA |

---

### 29. Loading & Skeleton Patterns

- **Initial dashboard load:** skeleton for stat cards + skeleton for recent events + skeleton for alerts banner.
- **Data table:** 8-row skeleton.
- **User detail drawer:** skeleton profile + skeleton tab content.
- **Charts:** dotted-grid placeholder with "Loading…" label.
- **Wizard step transitions:** instant; data fetch happens before navigation, with a button-level spinner.

---

### 30. Dashboard-Specific Keyboard Shortcuts

Per [Doc 4 §13](Qeet ID%20%E2%80%94%20Information%20Architecture%20%26%20Navigation.md). Recap of dashboard-active shortcuts:

| Shortcut | Action |
| --- | --- |
| `cmd+K` | Command palette |
| `cmd+/` | Shortcuts overlay |
| `g u` | Go to Users |
| `g r` | Go to Roles |
| `g a` | Go to Applications |
| `g s` | Go to SSO Connections |
| `g l` | Go to Audit Logs |
| `g b` | Go to Billing |
| `t` | Focus search in any table |
| `f` | Focus filter bar |
| `n` | "New" affordance for the current resource |
| `[` `]` | Previous / next tenant |
| `?` | Shortcuts help |

---

### 31. Bulk Action Patterns

Bulk actions follow a consistent pattern:

1. Selection via header checkbox or shift-click range.
2. Selection persists across pagination (with "Select all matching filters" affordance).
3. A floating bulk-action bar appears at the bottom of the screen.
4. Destructive actions require a confirmation modal with "Type the count to confirm" for very large selections (>100 items).

---

### 32. Data Export Patterns

Every relevant data table has an export affordance (⤓ icon):

| Resource | Formats | Notes |
| --- | --- | --- |
| Users | CSV, JSON | Per-plan row limit |
| Roles | CSV, JSON | |
| Applications | CSV, JSON | |
| Audit logs | CSV, JSON, SIEM stream | Per-plan volume limit (NFR RL-10) |
| Webhook deliveries | CSV, JSON | |
| Sessions | CSV, JSON | |
| Invoices | PDF (individual), CSV (range) | |

For exports >10K rows, the export is async (queued; emailed link).

---

### 33. Dashboard Responsive Behaviour

Per [Phase 3 Doc 10 §3](Qeet ID%20%E2%80%94%20Mobile%20%26%20Responsive%20Design%20Specification.md): desktop primary; tablet adapted; mobile read-only emergency view.

Below 1024px:
- Side nav becomes a drawer.
- Data tables become card-list views.
- Setup wizards (SAML, SCIM, Domain) show "Open on desktop for the best experience" inline banner — they remain functional but visually constrained.
- Audit log viewer is functional but with a simplified filter bar (only date + search).

---

### 34. Open Design Decisions From This Document

| # | Question | Owner | Target |
| --- | --- | --- | --- |
| OD-AD-01 | Default user detail UI — drawer (overlays list) vs full page | UX + Frontend | Phase 3 Week 3 |
| OD-AD-02 | Whether SAML test step (§9.6) is hard-gated or skippable | UX + Federation | Phase 3 Week 3 |
| OD-AD-03 | Audit log default density — compact vs comfortable | UX + Persona testing | Phase 3 Week 4 |
| OD-AD-04 | Per-user dashboard density persistence — at user vs at tenant level | UX + Product | Phase 3 Week 3 |
| OD-AD-05 | Customisable side-nav pinning at MVP vs v1.1 | UX + Frontend | Phase 3 Week 3 |
| OD-AD-06 | Saved views (§10.4) at MVP vs v1.1 | UX + Product | Phase 3 Week 2 |
| OD-AD-07 | Stripe Elements vs Stripe Checkout for plan upgrade flow (§24.1) | Frontend + Billing | Phase 3 Week 4 |
| OD-AD-08 | NDA gate on SOC 2 download — modal accept vs separate signed flow | Compliance + UX | Phase 3 Week 3 |

---

### 35. Cross-References

- Principles applied: [UX Research Summary & Design Principles](Qeet ID%20%E2%80%94%20UX%20Research%20Summary%20%26%20Design%20Principles.md) §6
- Components composed: [Component Library Specification](Qeet ID%20%E2%80%94%20Component%20Library%20Specification.md) — Data Table (§6.4), Audit Log Row (§6.5), Tenant Switcher (§6.3), Stepper (§6.20), Form (§6.14), Drawer (§6.8), Modal (§6.7)
- Tokens consumed: [Design System Foundations & Tokens](Qeet ID%20%E2%80%94%20Design%20System%20Foundations%20%26%20Tokens.md)
- IA structure: [Information Architecture & Navigation](Qeet ID%20%E2%80%94%20Information%20Architecture%20%26%20Navigation.md) §6
- Branding spec: [Embeddable Auth UI Components (White-Label)](Qeet ID%20%E2%80%94%20Embeddable%20Auth%20UI%20Components%20%28White-Label%29.md)
- Accessibility: [Accessibility Compliance Plan (WCAG 2.1 AA)](Qeet ID%20%E2%80%94%20Accessibility%20Compliance%20Plan%20%28WCAG%202.1%20AA%29.md)
- Mobile adaptation: [Mobile & Responsive Design Specification](Qeet ID%20%E2%80%94%20Mobile%20%26%20Responsive%20Design%20Specification.md) §6
- Audit pipeline architecture: [Phase 2 Database Design §13](../phase-2/Qeet%20ID%20%E2%80%94%20Database%20Design%20%26%20Data%20Model.md)
- Authorization model: [Phase 2 Authorization Engine Design](../phase-2/Qeet%20ID%20%E2%80%94%20Authorization%20Engine%20Design.md)
- SCIM provisioning: [Phase 2 Microservices §4.9](../phase-2/Qeet%20ID%20%E2%80%94%20Microservices%20Decomposition%20%26%20Service%20Boundaries.md)
- SAML configuration: [Phase 2 Microservices §4.8](../phase-2/Qeet%20ID%20%E2%80%94%20Microservices%20Decomposition%20%26%20Service%20Boundaries.md)
- Billing service: [Phase 2 Microservices §4.20](../phase-2/Qeet%20ID%20%E2%80%94%20Microservices%20Decomposition%20%26%20Service%20Boundaries.md)

---

### 36. Approvals & Sign-off

| Role | Name | Signature | Date |
| --- | --- | --- | --- |
| UX Designer |  |  |  |
| Product Designer |  |  |  |
| Product Manager |  |  |  |
| Frontend Engineering Lead |  |  |  |
| Team Identity Lead (Users, Roles, Tenant) |  |  |  |
| Team Federation Lead (SAML, SCIM) |  |  |  |
| Team Guard Lead (Audit, Security Events) |  |  |  |
| Team Experience Lead (Dashboard, Billing) |  |  |  |
| Compliance Officer (audit log viewer review) |  |  |  |
| Accessibility Lead |  |  |  |
| QA Lead |  |  |  |

---

*This document is version controlled. Visual updates in Figma do not require re-sign-off; changes to admin role tiers (§4), audit-log viewer behaviour (§10), SCIM sync error UX (§13), SAML wizard validation (§9), or screen-level information architecture (§5–§26) require UX Designer + relevant Team Lead + Product Manager review.*

---

**Qeet ID — Authenticate Everything.** *A Qeet Group Company*
