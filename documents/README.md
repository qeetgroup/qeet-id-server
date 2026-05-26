# Qeetid — Implementation Documents

This folder tracks how this repository ([qeet-identity](../)) implements the requirements published at [qeetgroup/qeetid · qeetid-reqs](https://github.com/qeetgroup/qeetify/tree/main/qeetify-reqs).

## Documents

| Document | Purpose |
|---|---|
| [IMPLEMENTATION-STATUS.md](./IMPLEMENTATION-STATUS.md) | **Start here.** Module-by-module narrative of what's done, partial, and missing across all 12 product categories. Includes summary tables and critical-path list. |
| [FEATURE-MATRIX.md](./FEATURE-MATRIX.md) | Quick-reference table: every v1.0 must-have feature with status (✅ / 🟡 / 🔴 / ⚪) and the file where the work lives. |
| [PROTOCOL-STATUS.md](./PROTOCOL-STATUS.md) | Protocol-by-protocol conformance against the 18 protocols required at MVP (OAuth, OIDC, SAML, SCIM, WebAuthn, TOTP, JWT, PKCE, etc.). |
| [GAP-ANALYSIS.md](./GAP-ANALYSIS.md) | Prioritized punch list (P0 / P1 / P2 / P3) of remaining work, with a suggested 12-week sequencing for v1.0 freeze. |

## Headline numbers

- **140 must-have features** identified in the v1.0 "Foundation" roadmap.
- **~41 (29%) implemented**, **~23 (16%) partial**, **~76 (55%) not started**.
- Biggest gaps: SAML/SCIM (federation), Admin Dashboard screens, Billing, Compliance certifications.
- Strongest areas: core auth (password, magic link, OTP, refresh-token rotation), RBAC, multi-tenancy, API keys, audit logging, marketing & docs sites.

## Source of truth

Requirements: [qeetid-reqs](https://github.com/qeetgroup/qeetify/tree/main/qeetify-reqs) — Phase 1 (Discovery), Phase 2 (System Design), Phase 3 (UI/UX Design).
Implementation: this repository — [backend/](../backend/), [frontend/](../frontend/).

## Last reviewed

2026-05-25.
