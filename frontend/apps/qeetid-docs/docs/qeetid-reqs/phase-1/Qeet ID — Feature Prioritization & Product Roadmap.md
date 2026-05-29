# Qeet ID — Feature Prioritization & Product Roadmap Draft

### 1. Document Information

|  |  |
| --- | --- |
| **Document Name** | Feature Prioritization Matrix & Product Roadmap Draft |
| **Project Name** | Qeet ID |
| **Parent Company** | Qeet Group |
| **Subsidiary** | Qeet ID (Standalone) |
| **Document Version** | v1.0 |
| **Prepared By** | Product Manager |
| **Date** | May 19, 2026 |
| **Status** | Draft — Pending Stakeholder Sign-off |

---

### 2. Purpose & Scope

This document defines the complete feature inventory for Qeet ID, prioritizes every feature using the MoSCoW framework, scores each feature on impact versus effort, and translates the prioritized backlog into a release-by-release product roadmap spanning MVP (v1.0) through v3.0.

This is the authoritative reference for the engineering team during sprint planning, for the design team during interface scoping, for the developer relations team in shaping launch messaging, and for the sales team in setting customer expectations. Once approved, the v1.0 MVP scope is locked. Any change to MVP scope after sign-off requires a formal Change Request submitted to the Product Manager for stakeholder review and re-approval.

Feature prioritization in Qeet ID is driven by five inputs: stakeholder interview findings from Phase 1, competitive intelligence on Auth0 and Okta gaps, the persona pain points documented in the Persona & Customer Journey document, the compliance obligations defined in the Compliance Requirements Matrix, and the protocol requirements specified in the Protocol Requirements Document. No feature has been added to this matrix without justification from at least one of these inputs.

---

### 3. Prioritization Framework

### 3.1 MoSCoW Definitions

| Priority | Definition | Inclusion Rule |
| --- | --- | --- |
| Must Have (M) | Non-negotiable for MVP. Without this feature, Qeet ID cannot launch, cannot pass security review, or cannot be sold. | Included in v1.0 — no exceptions |
| Should Have (S) | High-value features that significantly strengthen the MVP. Excluded only if effort prevents on-time launch. | Targeted for v1.0; descope to v1.1 if at risk |
| Could Have (C) | Valuable features that enhance the product but are not critical for initial launch. | Targeted for v1.1 to v1.5 |
| Won't Have (W) — This Release | Features explicitly deferred. Documented to prevent scope creep. | Deferred to v2.0+ or strategic later release |

---

### 3.2 Scoring Model

Each feature is scored on two dimensions:

**Business Impact (1–10)** — How much does this feature drive activation, retention, revenue, or strategic positioning?

| Score | Definition |
| --- | --- |
| 9–10 | Critical — feature directly determines whether Qeet ID can compete or be adopted |
| 7–8 | High — feature significantly differentiates Qeet ID or unlocks a major customer segment |
| 5–6 | Medium — feature improves the product experience but doesn't move the strategic needle |
| 3–4 | Low — feature is nice-to-have, narrow use case |
| 1–2 | Minimal — feature serves edge cases or is exploratory |

**Engineering Effort (1–10)** — How much engineering, design, and QA effort is required end-to-end?

| Score | Definition |
| --- | --- |
| 9–10 | Massive — multi-quarter effort across multiple teams |
| 7–8 | Large — full quarter of dedicated engineering team |
| 5–6 | Medium — 4–8 weeks of focused engineering work |
| 3–4 | Small — 1–4 weeks of engineering work |
| 1–2 | Trivial — days of engineering work |

**Priority Score** = (Business Impact × 2) − Engineering Effort

Higher priority score means higher recommended priority for inclusion in the next release.

### 4. Complete Feature Inventory & Prioritization Matrix

---

### 4.1 Qeet ID Auth — Authentication Engine

| # | Feature | Description | Impact | Effort | Priority Score | MoSCoW | Release |
| --- | --- | --- | --- | --- | --- | --- | --- |
| QA-01 | Email + password registration & login | Core username/password authentication with secure password hashing (Argon2id) | 10 | 4 | 16 | Must | v1.0 |
| QA-02 | Email verification | Email confirmation flow at signup; required before account activation | 10 | 3 | 17 | Must | v1.0 |
| QA-03 | Password reset (self-service) | Email-based password reset with signed, time-limited reset links | 10 | 3 | 17 | Must | v1.0 |
| QA-04 | Social login — Google | Google Identity Platform OIDC integration | 10 | 4 | 16 | Must | v1.0 |
| QA-05 | Social login — GitHub | GitHub OAuth integration | 9 | 3 | 15 | Must | v1.0 |
| QA-06 | Social login — Microsoft | Microsoft Account OIDC integration | 8 | 3 | 13 | Must | v1.0 |
| QA-07 | Social login — Apple | Apple Sign In integration | 8 | 5 | 11 | Must | v1.0 |
| QA-08 | Magic link login | Email-based passwordless login via signed JWT links | 9 | 4 | 14 | Must | v1.0 |
| QA-09 | Email OTP login | 6-digit email OTP as magic link alternative | 7 | 3 | 11 | Should | v1.0 |
| QA-10 | Passkeys (WebAuthn / FIDO2) | Phishing-resistant passwordless authentication — passkey-first design | 10 | 8 | 12 | Must | v1.0 |
| QA-11 | Cross-device passkey (Hybrid Transport) | QR code flow — phone as authenticator for desktop browser | 9 | 6 | 12 | Must | v1.0 |
| QA-12 | Conditional UI for passkeys | Native browser passkey autofill in email field | 8 | 4 | 12 | Should | v1.0 |
| QA-13 | Hardware security key support | YubiKey, Titan Key — FIDO2 roaming authenticators | 7 | 4 | 10 | Should | v1.0 |
| QA-14 | TOTP MFA | RFC 6238 TOTP — Google Authenticator, Authy, 1Password compatible | 10 | 4 | 16 | Must | v1.0 |
| QA-15 | SMS OTP MFA | SMS-delivered 6-digit OTP via Twilio | 8 | 4 | 12 | Must | v1.0 |
| QA-16 | Email OTP MFA | Email-delivered 6-digit OTP as MFA second factor | 7 | 3 | 11 | Should | v1.0 |
| QA-17 | MFA backup codes | 8 single-use 10-digit recovery codes generated at MFA enrollment | 8 | 2 | 14 | Must | v1.0 |
| QA-18 | Adaptive MFA policy | Risk-based MFA enforcement — IP, device, geolocation triggers | 8 | 7 | 9 | Should | v1.1 |
| QA-19 | Step-up authentication | Re-authentication required for sensitive operations | 8 | 5 | 11 | Should | v1.0 |
| QA-20 | Account lockout & brute force protection | Exponential backoff; CAPTCHA integration after threshold | 9 | 3 | 15 | Must | v1.0 |
| QA-21 | Compromised password detection | Haveibeenpwned API integration at registration and login | 7 | 2 | 12 | Must | v1.0 |
| QA-22 | Session management | Configurable absolute and idle timeouts; concurrent session limits | 9 | 4 | 14 | Must | v1.0 |
| QA-23 | Active sessions view (end user) | User can view and revoke active sessions from account settings | 7 | 3 | 11 | Should | v1.0 |
| QA-24 | Login anomaly detection | Impossible travel; new device alerts; unusual time-of-day alerts | 8 | 6 | 10 | Should | v1.1 |
| QA-25 | Account recovery flow | Multi-step recovery with identity verification | 8 | 5 | 11 | Should | v1.0 |
| QA-26 | Social login — Facebook | Facebook Login integration | 5 | 3 | 7 | Could | v1.2 |
| QA-27 | Social login — LinkedIn | LinkedIn OIDC integration | 5 | 3 | 7 | Could | v1.2 |
| QA-28 | Social login — Twitter / X | Twitter OAuth integration | 4 | 3 | 5 | Could | v1.2 |
| QA-29 | Social login — Discord | Discord OAuth integration | 5 | 2 | 8 | Could | v1.2 |
| QA-30 | Social login — Slack | Slack OAuth integration | 4 | 2 | 6 | Could | v1.2 |
| QA-31 | Custom OIDC provider | Customers configure arbitrary OIDC IdPs as social login source | 7 | 5 | 9 | Should | v1.1 |
| QA-32 | Biometric authentication (mobile SDK) | Touch ID / Face ID native integration in iOS / Android SDKs | 7 | 6 | 8 | Could | v1.2 |
| QA-33 | Push notification authentication | Mobile push approval as MFA second factor | 6 | 8 | 4 | Could | v1.5 |

### 4.2 Qeet ID ID — Identity & Lifecycle Management

| # | Feature | Description | Impact | Effort | Priority Score | MoSCoW | Release |
| --- | --- | --- | --- | --- | --- | --- | --- |
| QI-01 | User profile management | View and edit user profiles — name, email, phone, picture | 10 | 3 | 17 | Must | v1.0 |
| QI-02 | Multi-tenancy (organizations) | Per-organization data isolation; users can belong to multiple orgs | 10 | 8 | 12 | Must | v1.0 |
| QI-03 | Organization management | Create, configure, and manage organizations from admin dashboard | 9 | 5 | 13 | Must | v1.0 |
| QI-04 | User invitation flow | Invite users to organizations via email with role assignment | 9 | 3 | 15 | Must | v1.0 |
| QI-05 | Self-service user signup | Public signup pages with tenant-aware routing | 9 | 4 | 14 | Must | v1.0 |
| QI-06 | User search & filtering | Admin search across users by email, name, organization, status | 8 | 3 | 13 | Must | v1.0 |
| QI-07 | User suspension & reactivation | Admin can suspend or reactivate users without data loss | 9 | 2 | 16 | Must | v1.0 |
| QI-08 | User deletion (GDPR right to erasure) | Hard delete user with full data removal across all systems | 10 | 4 | 16 | Must | v1.0 |
| QI-09 | Data export (GDPR portability) | Self-service JSON/CSV export of all user personal data | 10 | 3 | 17 | Must | v1.0 |
| QI-10 | Consent management | Granular, withdrawable consent records | 9 | 4 | 14 | Must | v1.0 |
| QI-11 | Email verification status tracking | Track and display email_verified status | 9 | 2 | 16 | Must | v1.0 |
| QI-12 | Phone verification status tracking | Track and display phone_number_verified status | 7 | 2 | 12 | Should | v1.0 |
| QI-13 | Profile picture upload & management | User-uploaded avatar; integration with Gravatar fallback | 6 | 3 | 9 | Should | v1.0 |
| QI-14 | Custom user metadata fields | Customers define custom user attributes per tenant | 8 | 5 | 11 | Should | v1.0 |
| QI-15 | Bulk user import (CSV) | Admin can import users via CSV upload | 7 | 4 | 10 | Should | v1.0 |
| QI-16 | Bulk user actions (suspend, delete, role assign) | Admin can act on multiple users at once | 6 | 3 | 9 | Should | v1.1 |
| QI-17 | User lifecycle hooks (webhooks) | Webhook events on user lifecycle changes — created, updated, deleted | 8 | 4 | 12 | Must | v1.0 |
| QI-18 | User merging (identity reconciliation) | Merge duplicate accounts arising from multiple social login providers | 6 | 6 | 6 | Could | v1.2 |
| QI-19 | Progressive profiling | Collect additional user data over time via configurable prompts | 5 | 5 | 5 | Could | v1.2 |
| QI-20 | User impersonation (admin troubleshooting) | Admin can impersonate user for support — fully audited | 7 | 4 | 10 | Should | v1.1 |
| QI-21 | Account merging across tenants | Cross-tenant identity reconciliation | 4 | 8 | 0 | Won't | v2.0 |

---

### 4.3 Qeet ID Access — Authorization (RBAC / ABAC)

| # | Feature | Description | Impact | Effort | Priority Score | MoSCoW | Release |
| --- | --- | --- | --- | --- | --- | --- | --- |
| QC-01 | Role-Based Access Control (RBAC) | Standard role and permission model — users assigned to roles | 10 | 6 | 14 | Must | v1.0 |
| QC-02 | Predefined roles (Admin, Member, Viewer) | Built-in role templates available out of the box | 8 | 2 | 14 | Must | v1.0 |
| QC-03 | Custom role creation | Customers define custom roles with arbitrary permission sets | 9 | 4 | 14 | Must | v1.0 |
| QC-04 | Permission management UI | Admin dashboard for managing permissions and roles | 9 | 4 | 14 | Must | v1.0 |
| QC-05 | Role assignment via SCIM | Roles assigned automatically via SCIM provisioning attributes | 9 | 5 | 13 | Must | v1.0 |
| QC-06 | Role assignment via SAML attributes | Roles mapped from SAML assertion attributes | 9 | 4 | 14 | Must | v1.0 |
| QC-07 | Role assignment via OIDC claims | Roles mapped from OIDC identity provider claims | 8 | 4 | 12 | Must | v1.0 |
| QC-08 | Permissions in access tokens | RBAC roles and permissions embedded in JWT access tokens | 10 | 3 | 17 | Must | v1.0 |
| QC-09 | Permission inheritance (role hierarchy) | Roles can inherit permissions from parent roles | 7 | 5 | 9 | Should | v1.1 |
| QC-10 | Permission audit logging | All permission grants and revocations logged | 9 | 2 | 16 | Must | v1.0 |
| QC-11 | Attribute-Based Access Control (ABAC) | Policy-based authorization — conditions on attributes and context | 9 | 9 | 9 | Should | v1.5 |
| QC-12 | Fine-grained authorization (FGA) | Relationship-based access control — Google Zanzibar style | 8 | 10 | 6 | Could | v2.0 |
| QC-13 | Policy editor UI | Visual policy editor for ABAC rules | 7 | 7 | 7 | Could | v1.5 |
| QC-14 | Policy simulation & testing | Test authorization policies against sample requests before deployment | 7 | 5 | 9 | Should | v1.5 |
| QC-15 | Dynamic permission evaluation API | Authorization API for runtime permission checks | 9 | 5 | 13 | Must | v1.0 |
| QC-16 | Resource-scoped permissions | Permissions scoped to specific resources (documents, projects, etc.) | 7 | 7 | 7 | Could | v1.5 |
| QC-17 | Delegated administration | Customers can delegate admin permissions to specific roles | 7 | 4 | 10 | Should | v1.1 |
| QC-18 | Permission templates marketplace | Shareable RBAC templates for common use cases | 3 | 6 | 0 | Won't | v2.0+ |

### 4.4 Qeet ID Connect — Federation (SAML, OIDC, SCIM)

| # | Feature | Description | Impact | Effort | Priority Score | MoSCoW | Release |
| --- | --- | --- | --- | --- | --- | --- | --- |
| QN-01 | OAuth 2.0 authorization server | Full OAuth 2.0 + PKCE implementation | 10 | 7 | 13 | Must | v1.0 |
| QN-02 | OpenID Connect provider | Full OIDC Core 1.0 + Discovery + Dynamic Registration | 10 | 7 | 13 | Must | v1.0 |
| QN-03 | OIDC Foundation Certification | Certified for Basic OP profile | 9 | 3 | 15 | Must | v1.0 |
| QN-04 | SAML 2.0 Service Provider (SP) | Qeet ID acts as SP — enterprises log in via their IdP | 10 | 8 | 12 | Must | v1.0 |
| QN-05 | SAML 2.0 Identity Provider (IdP) | Qeet ID acts as IdP — apps use Qeet ID as SAML source | 9 | 8 | 10 | Must | v1.0 |
| QN-06 | SAML Single Logout (SLO) | SP-initiated and IdP-initiated logout | 8 | 5 | 11 | Must | v1.0 |
| QN-07 | SAML attribute mapping UI | Visual configuration of SAML attribute → Qeet ID field mapping | 9 | 4 | 14 | Must | v1.0 |
| QN-08 | SAML metadata exchange | Upload and auto-import IdP metadata; publish SP metadata | 9 | 3 | 15 | Must | v1.0 |
| QN-09 | Entra ID integration guide | Pre-tested reference architecture and step-by-step setup | 10 | 2 | 18 | Must | v1.0 |
| QN-10 | Okta integration guide | Pre-tested setup guide for Okta as upstream IdP | 9 | 2 | 16 | Must | v1.0 |
| QN-11 | Google Workspace integration guide | SAML setup with Google Workspace | 8 | 2 | 14 | Must | v1.0 |
| QN-12 | SCIM 2.0 User resource | Full RFC 7643 User schema implementation | 10 | 6 | 14 | Must | v1.0 |
| QN-13 | SCIM 2.0 Group resource | Full Group schema with member management | 9 | 5 | 13 | Must | v1.0 |
| QN-14 | SCIM PATCH operations | Critical for deprovisioning — active=false terminates sessions | 10 | 4 | 16 | Must | v1.0 |
| QN-15 | SCIM filter queries | Filter user lookup for sync operations | 8 | 3 | 13 | Must | v1.0 |
| QN-16 | Real-time SCIM sync dashboard | Visual sync status and error reporting for admins | 8 | 4 | 12 | Should | v1.0 |
| QN-17 | Custom OIDC IdP federation | Customers configure arbitrary OIDC IdPs | 7 | 4 | 10 | Should | v1.1 |
| QN-18 | Multi-IdP per organization | Organization can have multiple federation sources | 7 | 5 | 9 | Should | v1.1 |
| QN-19 | JIT (Just-in-Time) user provisioning via SAML | Auto-create users on first SAML login | 8 | 3 | 13 | Must | v1.0 |
| QN-20 | JIT user provisioning via OIDC | Auto-create users on first OIDC login | 8 | 3 | 13 | Must | v1.0 |
| QN-21 | SCIM Bulk Operations | Batch provisioning for large enterprise sync | 6 | 5 | 7 | Could | v1.2 |
| QN-22 | OIDC Back-Channel Logout | Reliable session termination across federated apps | 7 | 5 | 9 | Should | v1.2 |
| QN-23 | OIDC Front-Channel Logout | Browser-based logout propagation | 6 | 4 | 8 | Could | v1.2 |
| QN-24 | DPoP — Token Binding | High-assurance token binding for sensitive contexts | 7 | 6 | 8 | Could | v1.2 |
| QN-25 | PAR — Pushed Authorization Requests | Pre-registered authorization requests | 6 | 4 | 8 | Could | v1.2 |
| QN-26 | LDAP integration (LDAPv3) | On-premise Active Directory federation | 7 | 9 | 5 | Could | v1.5 |
| QN-27 | Kerberos / SPNEGO | Enterprise legacy integration | 4 | 9 | -1 | Won't | v2.0+ |
| QN-28 | FAPI 2.0 conformance | Financial-grade API for fintech and banking | 6 | 8 | 4 | Could | v2.0 |
| QN-29 | Workday integration | Pre-built Workday HR system connector | 6 | 5 | 7 | Could | v1.2 |
| QN-30 | BambooHR integration | Pre-built BambooHR connector | 5 | 4 | 6 | Could | v1.5 |

### 4.5 Qeet ID Guard — Security & Threat Detection

| # | Feature | Description | Impact | Effort | Priority Score | MoSCoW | Release |
| --- | --- | --- | --- | --- | --- | --- | --- |
| QG-01 | Rate limiting | Per-endpoint and per-client rate limiting with configurable thresholds | 10 | 4 | 16 | Must | v1.0 |
| QG-02 | Brute force detection | Login attempt monitoring with exponential backoff | 10 | 3 | 17 | Must | v1.0 |
| QG-03 | Bot detection (basic) | User-agent analysis, honeypot fields, request signature analysis | 8 | 5 | 11 | Must | v1.0 |
| QG-04 | CAPTCHA integration | hCaptcha and reCAPTCHA integration for high-risk flows | 8 | 3 | 13 | Must | v1.0 |
| QG-05 | Impossible travel detection | Geolocation-based anomaly detection | 7 | 5 | 9 | Should | v1.1 |
| QG-06 | New device alerts | Email notifications on login from unrecognized device | 8 | 3 | 13 | Must | v1.0 |
| QG-07 | Suspicious IP detection | Integration with threat intelligence feeds | 7 | 5 | 9 | Should | v1.1 |
| QG-08 | TOR / proxy detection | Block or flag logins from anonymizing networks | 6 | 4 | 8 | Should | v1.1 |
| QG-09 | Risk scoring engine | Per-login risk score combining multiple signals | 8 | 8 | 8 | Could | v1.2 |
| QG-10 | Advanced bot detection (ML-based) | Machine learning behavioral bot detection | 7 | 9 | 5 | Could | v1.5 |
| QG-11 | DDoS protection | Cloud-native DDoS protection at edge | 9 | 3 | 15 | Must | v1.0 |
| QG-12 | WAF integration | Web Application Firewall with OWASP Top 10 rules | 9 | 3 | 15 | Must | v1.0 |
| QG-13 | Credential stuffing protection | Haveibeenpwned + velocity-based detection | 9 | 3 | 15 | Must | v1.0 |
| QG-14 | Security event webhooks | Real-time webhook notifications for security events | 8 | 3 | 13 | Must | v1.0 |
| QG-15 | Adaptive authentication policies | Configurable policies based on risk signals | 8 | 7 | 9 | Should | v1.2 |
| QG-16 | Breach notification automation | Automated breach notification workflows for affected users | 7 | 5 | 9 | Should | v1.2 |
| QG-17 | Honey accounts (canary tokens) | Detect attacker enumeration of user lists | 5 | 4 | 6 | Could | v1.5 |
| QG-18 | Threat intelligence dashboard | Real-time visualization of attack patterns and signals | 6 | 6 | 6 | Could | v1.5 |
| QG-19 | Account takeover (ATO) response workflow | Automated response — session revocation, password reset, alerts | 8 | 5 | 11 | Should | v1.1 |
| QG-20 | Geo-fencing | Restrict logins to specific countries or regions | 6 | 3 | 9 | Should | v1.1 |

---

### 4.6 Qeet ID Keys — Machine-to-Machine Auth

| # | Feature | Description | Impact | Effort | Priority Score | MoSCoW | Release |
| --- | --- | --- | --- | --- | --- | --- | --- |
| QK-01 | OAuth 2.0 Client Credentials grant | Standards-based M2M authentication | 10 | 3 | 17 | Must | v1.0 |
| QK-02 | API key creation | Generate API keys with scoping and expiry | 10 | 3 | 17 | Must | v1.0 |
| QK-03 | API key revocation | Immediate revocation with under-60-second propagation | 10 | 2 | 18 | Must | v1.0 |
| QK-04 | API key rotation | Rotation flow with overlap window — no downtime | 9 | 3 | 15 | Must | v1.0 |
| QK-05 | API key scoping | Per-key permission and resource scoping | 9 | 3 | 15 | Must | v1.0 |
| QK-06 | API key environment separation | Test vs Live keys; cannot cross environments | 9 | 2 | 16 | Must | v1.0 |
| QK-07 | API key usage logging | Full request log per key | 8 | 2 | 14 | Must | v1.0 |
| QK-08 | API key leak detection | GitHub / GitLab secret scanning; auto-revoke on detection | 8 | 5 | 11 | Should | v1.1 |
| QK-09 | Service account management | First-class service account entity, distinct from human users | 9 | 4 | 14 | Must | v1.0 |
| QK-10 | private_key_jwt client authentication | RFC 7523 — high-security M2M | 7 | 4 | 10 | Should | v1.1 |
| QK-11 | mTLS client authentication | Mutual TLS for high-assurance M2M flows | 7 | 6 | 8 | Could | v1.5 |
| QK-12 | API key expiry warnings | Email alerts before key expires | 6 | 2 | 10 | Should | v1.1 |
| QK-13 | Hierarchical service accounts | Service accounts under organizations with delegation | 6 | 5 | 7 | Could | v1.5 |
| QK-14 | Workload identity (SPIFFE/SPIRE) | Zero-trust workload identity | 5 | 9 | 1 | Won't | v2.0 |

### 4.7 Developer Experience

| # | Feature | Description | Impact | Effort | Priority Score | MoSCoW | Release |
| --- | --- | --- | --- | --- | --- | --- | --- |
| DX-01 | React SDK | First-class React hooks and components | 10 | 5 | 15 | Must | v1.0 |
| DX-02 | Next.js SDK | Native Next.js integration — App Router + Pages Router | 10 | 4 | 16 | Must | v1.0 |
| DX-03 | Node.js SDK | Server-side SDK for Node.js | 10 | 4 | 16 | Must | v1.0 |
| DX-04 | Python SDK | Server-side SDK — Flask, FastAPI, Django support | 10 | 5 | 15 | Must | v1.0 |
| DX-05 | Flutter SDK | Cross-platform mobile SDK | 8 | 6 | 10 | Must | v1.0 |
| DX-06 | Go SDK | Server-side SDK for Go applications | 8 | 4 | 12 | Must | v1.0 |
| DX-07 | Vue SDK | Vue 3 composition API integration | 7 | 4 | 10 | Should | v1.1 |
| DX-08 | Angular SDK | Angular integration | 6 | 5 | 7 | Could | v1.2 |
| DX-09 | Svelte SDK | SvelteKit integration | 5 | 4 | 6 | Could | v1.2 |
| DX-10 | Swift SDK (iOS native) | Native iOS Swift SDK | 7 | 6 | 8 | Should | v1.2 |
| DX-11 | Kotlin SDK (Android native) | Native Android Kotlin SDK | 7 | 6 | 8 | Should | v1.2 |
| DX-12 | React Native SDK | React Native cross-platform mobile SDK | 7 | 5 | 9 | Should | v1.1 |
| DX-13 | Java SDK | Server-side Java / Spring Boot SDK | 7 | 5 | 9 | Should | v1.1 |
| DX-14 | Ruby SDK | Server-side Ruby / Rails SDK | 5 | 4 | 6 | Could | v1.5 |
| DX-15 | PHP SDK | Server-side PHP / Laravel SDK | 5 | 4 | 6 | Could | v1.5 |
| DX-16 | .NET SDK | ASP.NET Core SDK | 6 | 5 | 7 | Could | v1.2 |
| DX-17 | REST API documentation | Comprehensive REST API reference | 10 | 4 | 16 | Must | v1.0 |
| DX-18 | Quickstart guides per SDK | 10-minute setup guides for each SDK | 10 | 4 | 16 | Must | v1.0 |
| DX-19 | Interactive API explorer | Try API endpoints from documentation | 8 | 4 | 12 | Should | v1.0 |
| DX-20 | OpenAPI / Swagger spec | Machine-readable API specification | 9 | 2 | 16 | Must | v1.0 |
| DX-21 | Webhook configuration UI | Configure and test webhooks from dashboard | 8 | 4 | 12 | Must | v1.0 |
| DX-22 | Webhook delivery retry logic | Automatic retry with exponential backoff | 8 | 3 | 13 | Must | v1.0 |
| DX-23 | Webhook signature verification | HMAC signatures for webhook payload integrity | 9 | 2 | 16 | Must | v1.0 |
| DX-24 | Sandbox / test environment | Free isolated environment for development and testing | 9 | 5 | 13 | Must | v1.0 |
| DX-25 | CLI tool | Command-line tool for Qeet ID management | 6 | 6 | 6 | Could | v1.2 |
| DX-26 | Postman collection | Importable Postman collection with all endpoints | 7 | 1 | 13 | Must | v1.0 |
| DX-27 | SDK changelog & migration guides | Versioned changelogs per SDK | 7 | 2 | 12 | Must | v1.0 |
| DX-28 | Code examples in 6+ languages | Documentation code samples in all supported SDK languages | 9 | 3 | 15 | Must | v1.0 |
| DX-29 | Firebase Auth migration guide | Step-by-step Firebase → Qeet ID migration | 9 | 3 | 15 | Must | v1.0 |
| DX-30 | Auth0 migration guide | Step-by-step Auth0 → Qeet ID migration | 9 | 3 | 15 | Must | v1.0 |
| DX-31 | AWS Cognito migration guide | Step-by-step Cognito → Qeet ID migration | 8 | 3 | 13 | Must | v1.0 |
| DX-32 | Migration tooling — user import API | Bulk user import with hashed password preservation | 9 | 5 | 13 | Must | v1.0 |
| DX-33 | Migration tooling — parallel auth mode | Run two auth systems simultaneously during cutover | 7 | 6 | 8 | Should | v1.1 |
| DX-34 | Terraform provider | Manage Qeet ID via Terraform | 7 | 5 | 9 | Should | v1.1 |
| DX-35 | Pulumi provider | Manage Qeet ID via Pulumi | 5 | 4 | 6 | Could | v1.5 |
| DX-36 | Local development tool (Qeet ID CLI dev mode) | Local emulator for offline development | 6 | 7 | 5 | Could | v1.5 |
|  |  |  |  |  |  |  |  |

### 4.8 Admin Dashboard

| # | Feature | Description | Impact | Effort | Priority Score | MoSCoW | Release |
| --- | --- | --- | --- | --- | --- | --- | --- |
| AD-01 | Login & dashboard access | Admin authentication with mandatory MFA | 10 | 3 | 17 | Must | v1.0 |
| AD-02 | Organization overview dashboard | At-a-glance metrics: MAUs, logins, security events | 9 | 4 | 14 | Must | v1.0 |
| AD-03 | User management screens | List, search, filter, view, edit users | 10 | 5 | 15 | Must | v1.0 |
| AD-04 | Role & permission management | Create, edit, assign roles and permissions | 9 | 5 | 13 | Must | v1.0 |
| AD-05 | Application management | Register and configure applications (clients) | 10 | 4 | 16 | Must | v1.0 |
| AD-06 | SSO connection configuration | Set up SAML, OIDC, and social connections | 10 | 6 | 14 | Must | v1.0 |
| AD-07 | SCIM provisioning configuration | Configure SCIM endpoints and monitor sync | 9 | 4 | 14 | Must | v1.0 |
| AD-08 | MFA policy configuration | Configure MFA enforcement rules per tenant | 9 | 4 | 14 | Must | v1.0 |
| AD-09 | Password policy configuration | Define password complexity and rotation rules | 8 | 3 | 13 | Must | v1.0 |
| AD-10 | Branding & customization | Custom logo, colors, and login page URL | 8 | 4 | 12 | Must | v1.0 |
| AD-11 | Custom domain (CNAME) | Customer-branded login domain | 7 | 5 | 9 | Should | v1.1 |
| AD-12 | Email template customization | Customize transactional email templates | 7 | 4 | 10 | Should | v1.0 |
| AD-13 | Audit log viewer | Search, filter, and export audit logs | 10 | 4 | 16 | Must | v1.0 |
| AD-14 | Security events dashboard | Real-time view of security events and anomalies | 8 | 5 | 11 | Should | v1.0 |
| AD-15 | Webhook configuration | Manage webhook endpoints and events | 8 | 3 | 13 | Must | v1.0 |
| AD-16 | API key management | Create, view, rotate, and revoke API keys | 10 | 3 | 17 | Must | v1.0 |
| AD-17 | Team & admin management | Invite team members, assign admin roles | 9 | 3 | 15 | Must | v1.0 |
| AD-18 | Usage & analytics dashboard | MAU trends, login success rates, MFA adoption | 9 | 5 | 13 | Must | v1.0 |
| AD-19 | Billing dashboard | Current plan, usage, invoices, payment method | 10 | 5 | 15 | Must | v1.0 |
| AD-20 | Plan upgrade & downgrade | Self-service plan changes | 9 | 4 | 14 | Must | v1.0 |
| AD-21 | Compliance documents library | Download SOC 2, DPA, security whitepaper | 9 | 2 | 16 | Must | v1.0 |
| AD-22 | Multi-language dashboard | Dashboard UI in 5+ languages | 5 | 7 | 3 | Could | v1.5 |
| AD-23 | Dark mode | Dark theme for admin dashboard | 4 | 2 | 6 | Could | v1.1 |
| AD-24 | Activity feed | Real-time activity feed of admin actions and key events | 6 | 4 | 8 | Could | v1.2 |
| AD-25 | Dashboard mobile optimization | Responsive mobile experience for admin dashboard | 6 | 4 | 8 | Should | v1.1 |
| AD-26 | Granular admin role permissions | L1/L2/L3 admin tiers — restrict dashboard access | 7 | 4 | 10 | Should | v1.1 |
| AD-27 | Bulk user actions | Multi-select users for bulk operations | 6 | 3 | 9 | Should | v1.1 |
| AD-28 | Saved searches & filters | Save common user searches | 5 | 2 | 8 | Could | v1.2 |
| AD-29 | Dashboard export reports | Export usage and audit reports to PDF / CSV | 7 | 3 | 11 | Should | v1.0 |
| AD-30 | Real-time notifications center | In-dashboard notifications for security events | 6 | 4 | 8 | Could | v1.2 |

### 4.9 Developer Portal & Documentation

| # | Feature | Description | Impact | Effort | Priority Score | MoSCoW | Release |
| --- | --- | --- | --- | --- | --- | --- | --- |
| DP-01 | Developer portal homepage | Landing page for developers — quickstart entry points | 10 | 3 | 17 | Must | v1.0 |
| DP-02 | Documentation search | Full-text search across all docs | 9 | 3 | 15 | Must | v1.0 |
| DP-03 | Versioned documentation | Documentation versioned per major release | 8 | 4 | 12 | Must | v1.0 |
| DP-04 | Code playground | In-browser code execution against sandbox environment | 7 | 7 | 7 | Could | v1.2 |
| DP-05 | Community forum / Discord | Public developer community | 8 | 3 | 13 | Must | v1.0 |
| DP-06 | GitHub presence (SDK repos) | Public, well-maintained GitHub repositories per SDK | 9 | 4 | 14 | Must | v1.0 |
| DP-07 | Blog | Technical and product blog | 7 | 3 | 11 | Should | v1.0 |
| DP-08 | Status page | Public uptime and incident status page | 9 | 3 | 15 | Must | v1.0 |
| DP-09 | Roadmap (public) | Public-facing product roadmap | 7 | 2 | 12 | Must | v1.0 |
| DP-10 | Changelog (public) | Public changelog of platform changes | 8 | 2 | 14 | Must | v1.0 |
| DP-11 | Security trust center | One-page security disclosure: SOC 2, pen test, data residency | 10 | 3 | 17 | Must | v1.0 |
| DP-12 | Architecture & reference guides | Deep technical reference content | 8 | 5 | 11 | Must | v1.0 |
| DP-13 | Video tutorials | Short setup and feature videos | 6 | 4 | 8 | Should | v1.1 |
| DP-14 | Documentation feedback | Per-page feedback widget — "Was this helpful?" | 6 | 2 | 10 | Should | v1.0 |
| DP-15 | API status webhook | Subscribe to status changes via webhook | 4 | 3 | 5 | Could | v1.5 |

---

### 4.10 Billing & Subscriptions

| # | Feature | Description | Impact | Effort | Priority Score | MoSCoW | Release |
| --- | --- | --- | --- | --- | --- | --- | --- |
| BL-01 | Free tier (up to 10K MAUs) | Generous free tier with no credit card required | 10 | 3 | 17 | Must | v1.0 |
| BL-02 | Growth plan (per-MAU pricing) | Self-service paid plan with predictable MAU-based pricing | 10 | 5 | 15 | Must | v1.0 |
| BL-03 | Enterprise plan (custom contract) | Annual contracts with custom pricing | 9 | 3 | 15 | Must | v1.0 |
| BL-04 | Stripe billing integration | Payment processing and subscription management | 10 | 4 | 16 | Must | v1.0 |
| BL-05 | Pricing calculator (public) | Public pricing page calculator | 9 | 2 | 16 | Must | v1.0 |
| BL-06 | MAU counter (real-time) | Real-time MAU display in dashboard | 9 | 3 | 15 | Must | v1.0 |
| BL-07 | MAU threshold alerts | Proactive alerts at 80% and 100% of free tier | 8 | 2 | 14 | Must | v1.0 |
| BL-08 | Self-service upgrade | One-click plan upgrade | 9 | 3 | 15 | Must | v1.0 |
| BL-09 | Invoice history | Downloadable invoice PDFs | 8 | 2 | 14 | Must | v1.0 |
| BL-10 | Payment method management | Add, update, remove payment methods | 9 | 2 | 16 | Must | v1.0 |
| BL-11 | Tax handling (VAT, GST) | Automated tax calculation per region via Stripe Tax | 8 | 3 | 13 | Must | v1.0 |
| BL-12 | Annual billing option | Annual billing with discount | 7 | 2 | 12 | Should | v1.0 |
| BL-13 | Multi-currency support | Billing in USD, EUR, GBP at launch | 7 | 4 | 10 | Should | v1.1 |
| BL-14 | Custom invoicing for Enterprise | Manual invoice generation for enterprise contracts | 8 | 3 | 13 | Must | v1.0 |
| BL-15 | Usage forecasting | Predicted MAU growth and cost projection | 6 | 5 | 7 | Could | v1.2 |
| BL-16 | Partner billing | Reseller and partner billing flows | 5 | 7 | 3 | Could | v2.0 |
| BL-17 | Marketplace billing (AWS, GitHub) | Cloud marketplace integration | 7 | 6 | 8 | Could | v1.5 |

---

### 4.11 Infrastructure & Operations

| # | Feature | Description | Impact | Effort | Priority Score | MoSCoW | Release |
| --- | --- | --- | --- | --- | --- | --- | --- |
| IN-01 | 99.9% uptime SLA | Production uptime commitment | 10 | 6 | 14 | Must | v1.0 |
| IN-02 | Multi-AZ deployment | Multi-availability-zone redundancy | 10 | 4 | 16 | Must | v1.0 |
| IN-03 | EU data residency option | EU-resident data hosting available | 9 | 5 | 13 | Must | v1.0 |
| IN-04 | US data residency option | US-resident data hosting available | 9 | 5 | 13 | Must | v1.0 |
| IN-05 | Disaster recovery (DR) | Tested DR plan with under-4-hour RTO | 9 | 5 | 13 | Must | v1.0 |
| IN-06 | Automated backups | Daily backups with 30-day retention | 9 | 3 | 15 | Must | v1.0 |
| IN-07 | Multi-region deployment | Active-active multi-region for enterprise tier | 7 | 9 | 5 | Could | v1.5 |
| IN-08 | APAC data residency | Singapore-based data hosting | 7 | 5 | 9 | Should | v1.2 |
| IN-09 | UK data residency | UK-resident hosting (post-Brexit GDPR alignment) | 6 | 4 | 8 | Could | v1.2 |
| IN-10 | On-premise / self-hosted deployment | Self-hosted enterprise option | 5 | 10 | 0 | Won't | v2.0 |
| IN-11 | Private cloud / VPC peering | Enterprise private cloud deployment | 6 | 8 | 4 | Could | v1.5 |
| IN-12 | 99.99% uptime SLA | Enterprise-tier uptime commitment | 8 | 7 | 9 | Should | v2.0 |
| IN-13 | Auto-scaling | Horizontal autoscaling based on load | 9 | 4 | 14 | Must | v1.0 |
| IN-14 | CDN integration | Global CDN for static assets and login pages | 8 | 3 | 13 | Must | v1.0 |
| IN-15 | Secrets management (Vault/KMS) | Production secrets management | 10 | 4 | 16 | Must | v1.0 |
| IN-16 | Monitoring & alerting (Datadog/Grafana) | Production observability stack | 10 | 4 | 16 | Must | v1.0 |
| IN-17 | Centralized logging (ELK/Loki) | Structured log aggregation | 9 | 3 | 15 | Must | v1.0 |
| IN-18 | SIEM integration (Splunk, Sentinel) | Export logs to enterprise SIEM | 8 | 4 | 12 | Should | v1.1 |
| IN-19 | Incident response runbooks | Documented runbooks for common incidents | 9 | 3 | 15 | Must | v1.0 |
| IN-20 | On-call rotation | 24/7 on-call coverage | 10 | 3 | 17 | Must | v1.0 |

### 4.12 Compliance & Trust

| # | Feature | Description | Impact | Effort | Priority Score | MoSCoW | Release |
| --- | --- | --- | --- | --- | --- | --- | --- |
| CO-01 | SOC 2 Type I certification | Third-party SOC 2 Type I audit and report | 10 | 7 | 13 | Must | v1.0 |
| CO-02 | SOC 2 Type II certification | Twelve-month operating effectiveness audit | 10 | 5 | 15 | Must | v1.2 |
| CO-03 | GDPR compliance | Full GDPR compliance from Day 1 | 10 | 6 | 14 | Must | v1.0 |
| CO-04 | FIDO Alliance FIDO2 certification | Certified FIDO2 server implementation | 9 | 4 | 14 | Must | v1.0 |
| CO-05 | OpenID Foundation certification (Basic OP) | OIDC conformance certification | 9 | 3 | 15 | Must | v1.0 |
| CO-06 | DPA template (publicly available) | Standard DPA for self-service customers | 9 | 3 | 15 | Must | v1.0 |
| CO-07 | Sub-processor list (public) | Published list of all sub-processors | 9 | 2 | 16 | Must | v1.0 |
| CO-08 | CCPA / CPRA compliance | California privacy law compliance | 8 | 4 | 12 | Should | v1.2 |
| CO-09 | PDPA compliance (Singapore) | Singapore privacy law compliance | 6 | 3 | 9 | Should | v1.2 |
| CO-10 | LGPD compliance (Brazil) | Brazil privacy law compliance | 6 | 3 | 9 | Should | v1.2 |
| CO-11 | ISO 27001 certification | International security management standard | 7 | 9 | 5 | Could | v2.0 |
| CO-12 | HIPAA Business Associate Agreement (BAA) | Healthcare-grade compliance | 7 | 7 | 7 | Could | v1.5 |
| CO-13 | PCI DSS compliance (Stripe-handled) | Payment card compliance via Stripe | 7 | 2 | 12 | Must | v1.0 |
| CO-14 | FedRAMP authorization | US federal government compliance | 5 | 10 | 0 | Won't | v3.0 |
| CO-15 | DPDPA compliance (India) | India privacy law compliance | 6 | 4 | 8 | Could | v1.5 |
| CO-16 | Bug bounty program | Public bug bounty via HackerOne or Bugcrowd | 8 | 3 | 13 | Must | v1.0 |
| CO-17 | Vulnerability disclosure policy | Public coordinated disclosure process | 8 | 1 | 15 | Must | v1.0 |
| CO-18 | Annual penetration test | External pen test before launch and annually | 10 | 3 | 17 | Must | v1.0 |
| CO-19 | Security advisory mailing list | Proactive CVE and incident notifications | 7 | 2 | 12 | Should | v1.0 |

---

### 5. Feature Counts Summary

| Category | Must | Should | Could | Won't | Total |
| --- | --- | --- | --- | --- | --- |
| Qeet ID Auth | 14 | 8 | 9 | 0 | 31 |
| Qeet ID ID | 12 | 4 | 4 | 1 | 21 |
| Qeet ID Access | 9 | 2 | 6 | 1 | 18 |
| Qeet ID Connect | 16 | 4 | 8 | 1 | 29 |
| Qeet ID Guard | 8 | 6 | 6 | 0 | 20 |
| Qeet ID Keys | 8 | 2 | 4 | 0 | 14 |
| Developer Experience | 12 | 5 | 18 | 0 | 35 |
| Admin Dashboard | 17 | 6 | 6 | 0 | 29 |
| Developer Portal | 10 | 2 | 3 | 0 | 15 |
| Billing & Subscriptions | 11 | 2 | 4 | 0 | 17 |
| Infrastructure & Ops | 12 | 1 | 5 | 1 | 19 |
| Compliance & Trust | 11 | 4 | 4 | 1 | 19 |
| **TOTAL** | **140** | **46** | **77** | **5** | **268** |

---

### 6. MVP (v1.0) Scope Lock

The MVP scope is the union of all 140 Must Have features plus the Should Have features explicitly slotted to v1.0 in the matrix above. The scope is locked at sign-off. The following statements define what MVP launch includes and does not include:

**What MVP includes:**

- Full authentication suite — email/password, social login (Google, GitHub, Microsoft, Apple), magic links, passkeys, MFA (TOTP, SMS, email OTP)
- Multi-tenancy and organization management
- RBAC with custom roles and permissions
- OAuth 2.0, OpenID Connect, SAML 2.0, SCIM 2.0 protocols
- Six SDKs — React, Next.js, Node.js, Python, Flutter, Go
- Admin dashboard with user management, application management, audit logs, billing
- Developer portal with comprehensive documentation, quickstart guides, code examples, migration guides for Firebase, Auth0, and Cognito
- Stripe billing integration with free, growth, and enterprise tiers
- SOC 2 Type I certification, GDPR compliance, FIDO2 certification, OIDC certification
- 99.9% uptime SLA, EU and US data residency, multi-AZ deployment
- Qeet ID Guard — rate limiting, brute force protection, basic bot detection, WAF, DDoS protection, credential stuffing protection
- Qeet ID Keys — API keys with scoping, rotation, environment separation
- Security Trust Center, public status page, public roadmap, public changelog
- Bug bounty program at launch

**What MVP does not include (deferred):**

- ABAC and fine-grained authorization (deferred to v1.5)
- LDAP federation (deferred to v1.5)
- On-premise or self-hosted deployment (deferred to v2.0)
- ISO 27001 certification (deferred to v2.0)
- HIPAA BAA (deferred to v1.5)
- 99.99% uptime SLA (deferred to v2.0)
- AI-powered ML-based bot detection (deferred to v1.5)
- Multi-region active-active deployment (deferred to v1.5)
- Languages beyond the six core SDKs (Vue, Swift, Kotlin, Java, .NET deferred to v1.1–v1.2)

---

### 7. Product Roadmap Draft

### 7.1 Roadmap Overview

| Release | Codename | Target Date | Theme |
| --- | --- | --- | --- |
| v1.0 | Foundation | Month 15 (Production Launch) | MVP — developer-first, enterprise-ready from Day 1 |
| v1.1 | Polish | Month 18 (3 months post-launch) | Hardening, additional SDKs, adaptive security |
| v1.2 | Expand | Month 21 (6 months post-launch) | More SDKs, more social providers, geographic expansion |
| v1.5 | Depth | Month 27 (12 months post-launch) | ABAC, LDAP, HIPAA, advanced ML threat detection |
| v2.0 | Scale | Month 36 (24 months post-launch) | On-premise option, 99.99% SLA, FGA, FAPI 2.0, ISO 27001 |
| v3.0 | Sovereign | Month 48+ | FedRAMP, sovereign cloud, region expansion, workload identity |

---

### 7.2 v1.0 — Foundation (Production Launch, Month 15)

**Theme:** Launch a market-ready MVP that competes head-on with Auth0 on developer experience and Okta on enterprise readiness, while pricing transparently and undercutting both.

**Key Features:**

- Full authentication suite — passkeys-first, with email/password, social, MFA, magic links
- Multi-tenancy + RBAC + custom roles
- All four core protocols — OAuth 2.0, OIDC, SAML 2.0, SCIM 2.0
- Six SDKs: React, Next.js, Node.js, Python, Flutter, Go
- Admin dashboard with full management UX
- Developer portal with docs, quickstarts, code examples, migration guides
- Free tier (10K MAUs), Growth tier (per-MAU), Enterprise tier (custom)
- SOC 2 Type I, GDPR, FIDO2, OIDC certifications
- 99.9% uptime SLA, EU + US data residency
- Qeet ID Guard baseline — rate limiting, brute force, WAF, DDoS, credential stuffing
- Qeet ID Keys — API key management with rotation and scoping
- Migration guides for Firebase, Auth0, AWS Cognito
- Bug bounty program at launch

**Success Criteria:**

- Production launch on schedule (Month 15)
- 10,000 MAUs within 6 months of launch (Month 21)
- 5 enterprise pilot customers at launch
- Time-to-first-auth under 10 minutes verified via developer beta

---

### 7.3 v1.1 — Polish (Month 18, 3 months post-launch)

**Theme:** Harden the platform, expand SDK reach, deepen security capabilities based on real-world usage data.

**Key Features:**

- New SDKs: Vue, React Native, Java
- Adaptive MFA policy (risk-based MFA triggers)
- Login anomaly detection (impossible travel, new device alerts at scale)
- Suspicious IP and TOR/proxy detection
- ATO response workflow
- Geo-fencing
- Account takeover detection
- Custom domain (CNAME) support
- Multi-currency billing (EUR, GBP added)
- Custom OIDC IdP federation
- Multi-IdP per organization
- Granular admin role permissions (L1/L2/L3)
- Bulk user actions
- API key leak detection (GitHub scanning)
- Migration tooling — parallel auth mode for zero-downtime cutover
- Terraform provider
- Permission inheritance (role hierarchy)
- Delegated administration
- User impersonation (audited)
- Mobile-optimized admin dashboard
- SIEM integration for enterprise (Splunk, Sentinel)

**Success Criteria:**

- 25,000 MAUs across the platform
- 8 SDKs total
- 15 paying enterprise customers
- Time-to-first-auth under 8 minutes

---

### 7.4 v1.2 — Expand (Month 21, 6 months post-launch)

**Theme:** Broaden the addressable market through geographic, language, and protocol expansion.

**Key Features:**

- New SDKs: Angular, Svelte, Swift (iOS native), Kotlin (Android native), .NET
- Additional social providers: Facebook, LinkedIn, Twitter/X, Discord, Slack
- Biometric authentication for native mobile SDKs
- OIDC Back-Channel and Front-Channel Logout
- DPoP token binding
- PAR — Pushed Authorization Requests
- SCIM Bulk Operations
- Risk scoring engine
- Adaptive authentication policies
- Breach notification automation
- CCPA / CPRA compliance
- PDPA (Singapore) compliance
- LGPD (Brazil) compliance
- APAC data residency (Singapore)
- UK data residency
- SOC 2 Type II certification (continuous)
- Workday integration
- Code playground in dev portal
- Real-time notifications center in dashboard
- Saved searches and filters
- Activity feed
- CLI tool
- Usage forecasting in billing
- API status webhook subscription

**Success Criteria:**

- 12 SDKs total
- Active customers in 3 continents
- SOC 2 Type II report published
- 50,000 MAUs platform-wide

---

### 7.5 v1.5 — Depth (Month 27, 12 months post-launch)

**Theme:** Move upmarket into enterprise depth — fine-grained authorization, legacy enterprise federation, regulated industries.

**Key Features:**

- ABAC (Attribute-Based Access Control)
- Policy editor UI with simulation and testing
- Resource-scoped permissions
- LDAP integration (LDAPv3) for legacy Active Directory
- HIPAA Business Associate Agreement (BAA)
- DPDPA (India) compliance
- Advanced bot detection (ML-based)
- Multi-region active-active deployment
- Private cloud / VPC peering for enterprise
- Threat intelligence dashboard
- Honey accounts / canary tokens
- Cloud marketplace billing (AWS, GCP, GitHub Marketplace)
- mTLS client authentication for high-assurance M2M
- Hierarchical service accounts
- Push notification authentication
- Pulumi provider
- Local development tool (Qeet ID dev mode)
- Multi-language dashboard (5+ languages)
- Additional SDKs: Ruby, PHP
- BambooHR connector
- API status webhook

**Success Criteria:**

- 50 paying enterprise customers
- 1 million MAUs platform-wide
- First HIPAA-regulated customer onboarded
- ABAC adoption by 20% of Growth-tier customers

---

### 7.6 v2.0 — Scale (Month 36, 24 months post-launch)

**Theme:** Become enterprise infrastructure at global scale — on-premise option, financial-grade compliance, mission-critical reliability.

**Key Features:**

- On-premise / self-hosted deployment option
- ISO 27001 certification
- 99.99% uptime SLA (enterprise tier)
- Fine-Grained Authorization (FGA) — Google Zanzibar style
- FAPI 2.0 conformance for fintech / banking
- RAR — Rich Authorization Requests
- Account merging across tenants
- Partner / reseller billing
- Permission templates marketplace
- Workload identity (SPIFFE/SPIRE) — pilot

**Success Criteria:**

- $5M ARR
- First on-premise enterprise customer
- ISO 27001 certified
- First Fortune 500 customer signed

---

### 7.7 v3.0 — Sovereign (Month 48+)

**Theme:** Government, sovereign cloud, global reach. Become the auth platform of record for regulated and sovereign deployments.

**Key Features:**

- FedRAMP authorization (US federal government)
- Sovereign cloud deployments (regional compliance: KSA, UAE, India, Brazil)
- Workload identity (SPIFFE/SPIRE) — general availability
- Additional regional data residency (Middle East, India, Australia)
- Kerberos / SPNEGO support (large legacy enterprise integrations)

**Success Criteria:**

- $20M ARR
- FedRAMP certified
- Government customer in at least three sovereign regions

---

### 8. Roadmap Visualization — Release Timeline

`Month:  15      18      21              27                    36                      48+
        │       │       │               │                     │                       │
        ▼       ▼       ▼               ▼                     ▼                       ▼
      ┌────┐ ┌────┐ ┌────────┐    ┌─────────┐         ┌──────────┐            ┌──────────┐
      │v1.0│ │v1.1│ │v1.2    │    │v1.5     │         │v2.0      │            │v3.0      │
      │MVP │ │Pol-│ │Expand  │    │Depth    │         │Scale     │            │Sovereign │
      │    │ │ish │ │        │    │         │         │          │            │          │
      └────┘ └────┘ └────────┘    └─────────┘         └──────────┘            └──────────┘
        │       │       │               │                     │                       │
   Launch    Hard-   Geo +       ABAC, LDAP,         On-prem,              FedRAMP,
   Auth      ening, MFA,        HIPAA, ML            ISO27001,             Sovereign
   suite     more   12 SDKs    detection           99.99% SLA,           cloud,
   + SOC2I,  SDKs   + APAC                          FGA, FAPI             workload
   GDPR,                                                                    identity
   FIDO2`

---

### 9. Roadmap Risk Register

| # | Risk | Likelihood | Impact | Mitigation |
| --- | --- | --- | --- | --- |
| RR-01 | MVP scope creep delays launch | High | High | Strict MoSCoW lock + formal Change Request process |
| RR-02 | SOC 2 Type I delayed | Medium | Critical | Engage audit firm in Phase 5, parallel to development |
| RR-03 | FIDO2 certification delayed | Medium | High | Begin certification process in Phase 6, not after |
| RR-04 | Key SDK quality issues at launch | Medium | High | Dedicated SDK engineer per priority language; beta SDK program with developer feedback before launch |
| RR-05 | Competitor (Auth0 / Okta / Kinde) releases competing feature before MVP | Medium | Medium | Monitor competitor changelogs weekly; accelerate differentiating features (passkeys-first, transparent pricing) |
| RR-06 | Enterprise pilot customers churn before launch | Medium | High | Dedicated customer success lead per pilot; monthly check-ins; clear pilot exit criteria |
| RR-07 | Migration tooling underestimates real-world complexity | High | Medium | Run migrations with 3 beta customers from Firebase, Auth0, Cognito before launch |
| RR-08 | v1.1 features pulled forward into v1.0 under pressure | High | High | Stakeholder agreement on locked MVP scope; visible change request log |
| RR-09 | Cloud infrastructure cost overruns at scale | Medium | Medium | Set billing alerts; optimize architecture early; review unit economics monthly post-launch |
| RR-10 | ABAC complexity delays v1.5 | Medium | Medium | Start ABAC technical design in v1.1, not v1.5; prototype against real customer use cases |

---

### 10. Roadmap Governance

| Activity | Frequency | Owner |
| --- | --- | --- |
| Roadmap review with engineering | Bi-weekly | Product Manager + CTO |
| Roadmap review with stakeholders (CEO, Sales, Marketing) | Monthly | Product Manager |
| Public roadmap update (developer portal) | Quarterly | Product Manager + DevRel |
| Feature prioritization re-scoring | Quarterly | Product Manager |
| Customer feedback intake review | Monthly | Product Manager + Customer Success |
| Competitive intelligence review impacting roadmap | Quarterly | Product Manager + Marketing |
| Change Request handling | Weekly (as needed) | Product Manager |

---

### 11. Change Request Process

After MVP scope sign-off, any addition, removal, or substantial modification of a v1.0 feature requires a formal Change Request submitted via the following process:

1. Requester submits Change Request form (template available in internal documentation) with: feature description, business justification, impact on timeline, impact on dependencies, alternative options considered.
2. Product Manager triages within 3 business days and assigns Impact Level (Low / Medium / High).
3. Low impact: PM approval is sufficient.
4. Medium impact: PM + CTO + affected functional leads review.
5. High impact: full stakeholder steering committee review.
6. Approved changes are added to the roadmap with adjusted timelines and re-baselined.
7. Rejected changes are documented in the Change Request log with rationale.

No engineering effort begins on a non-MVP feature without Change Request approval.

---

### 12. Approvals & Sign-off

| Role | Name | Signature | Date |
| --- | --- | --- | --- |
| Product Manager |  |  |  |
| CTO |  |  |  |
| Solution Architect |  |  |  |
| UX Designer |  |  |  |
| Compliance Officer |  |  |  |
| Sales Lead |  |  |  |
| Marketing Lead |  |  |  |
| CEO / Founder |  |  |  |

---

*This document is version controlled. The MVP scope (v1.0) is locked at sign-off. Post-MVP releases (v1.1 onward) are directional and will be refined quarterly based on customer feedback, market changes, and platform learnings. Any change to v1.0 scope after sign-off requires a formal Change Request reviewed by the Product Manager and approved per the governance process above.*

---

**Qeet ID — Authenticate Everything.** *A Qeet Group Company*