# Qeet ID — Compliance Requirements Matrix

### 1. Document Information

|  |  |
| --- | --- |
| **Document Name** | Compliance Requirements Matrix |
| **Project Name** | Qeet ID |
| **Parent Company** | Qeet Group |
| **Subsidiary** | Qeet ID (Standalone) |
| **Document Version** | v1.0 |
| **Prepared By** | Compliance Officer + Legal Counsel |
| **Date** | May 19, 2026 |
| **Status** | Draft — Pending Stakeholder Sign-off |

---

### 2. Purpose & Scope

This document defines the complete compliance and regulatory requirements that Qeet ID must satisfy across all phases of development, launch, and post-launch operations. It serves as the authoritative reference for the engineering team, security architects, legal counsel, and product leadership when making decisions that carry regulatory, contractual, or legal implications.

Qeet ID operates as an Authentication and Authorization platform — a category of infrastructure that sits at the intersection of identity, data privacy, and security law globally. Every feature built, every data element stored, and every integration shipped carries compliance obligations. This matrix ensures those obligations are understood, assigned, tracked, and met before the platform reaches production.

This document covers mandatory compliance requirements at MVP launch, deferred compliance targets for v1.5 and v2.0, protocol-level compliance standards, data handling obligations, contractual compliance requirements from enterprise customers, and the ongoing compliance monitoring program.

---

### 3. Compliance Framework Overview

### 3.1 Compliance Tiers

| Tier | Classification | Description | Timeline |
| --- | --- | --- | --- |
| Tier 1 — Non-Negotiable | Mandatory at Launch | Requirements that must be fully satisfied before production deployment. Any gap is a launch blocker. | MVP Launch (Month 15) |
| Tier 2 — Committed | Pre-Committed Post-Launch | Requirements publicly committed to enterprise customers. Failure creates contractual liability. | Within 12 months post-launch |
| Tier 3 — Targeted | Strategic Growth | Requirements that unlock regulated industry markets (healthcare, finance, government). | v1.5 / v2.0 |
| Tier 4 — Monitored | Emerging Obligations | Requirements that are emerging, jurisdiction-specific, or applicable only at significant scale. | Ongoing monitoring |

---

### 3.2 Compliance Frameworks in Scope

| # | Framework / Regulation | Tier | Primary Jurisdiction | Applicability to Qeet ID |
| --- | --- | --- | --- | --- |
| 1 | GDPR — General Data Protection Regulation | Tier 1 | European Union | Processes personal data of EU residents — full applicability |
| 2 | SOC 2 Type I | Tier 1 | United States (AICPA) | Enterprise customer prerequisite — Trust Services Criteria |
| 3 | SOC 2 Type II | Tier 2 | United States (AICPA) | Enterprise customer requirement — 12 months post-launch |
| 4 | CCPA / CPRA — California Consumer Privacy Act | Tier 2 | California, USA | Applicable when processing personal data of California residents |
| 5 | PDPA — Personal Data Protection Act | Tier 2 | Singapore | Applicable when processing personal data of Singapore residents |
| 6 | LGPD — Lei Geral de Proteção de Dados | Tier 2 | Brazil | Applicable when processing personal data of Brazilian residents |
| 7 | ISO 27001 | Tier 3 | International | Enterprise and government market requirement |
| 8 | HIPAA — Health Insurance Portability and Accountability Act | Tier 3 | United States | Required when Qeet ID serves healthcare customers |
| 9 | PCI DSS — Payment Card Industry Data Security Standard | Tier 3 | International | Required if Qeet ID stores or processes payment card data |
| 10 | FedRAMP | Tier 3 | United States Federal | Required for US federal government customer access |
| 11 | DPDPA — Digital Personal Data Protection Act | Tier 4 | India | Applicable when processing personal data of Indian residents |
| 12 | NIS2 Directive | Tier 4 | European Union | Emerging critical infrastructure regulation — monitoring required |
| 13 | NIST Cybersecurity Framework | Tier 2 | United States | Enterprise security baseline reference — aligned with SOC 2 |
| 14 | FIDO2 / WebAuthn W3C Standard | Tier 1 | International | Mandatory for passkey implementation |
| 15 | OAuth 2.0 RFC 6749 / RFC 9700 | Tier 1 | International | Core protocol standard — full conformance required |
| 16 | OpenID Connect Core 1.0 | Tier 1 | International | Core protocol standard — full conformance required |
| 17 | SAML 2.0 OASIS Standard | Tier 1 | International | Enterprise SSO protocol — full conformance required |
| 18 | SCIM 2.0 RFC 7642 / RFC 7643 / RFC 7644 | Tier 1 | International | Enterprise provisioning protocol — full conformance required |

### 4. GDPR — General Data Protection Regulation

### 4.1 Applicability Assessment

Qeet ID processes personal data on behalf of its customers (controllers) and is therefore classified as a **Data Processor** under GDPR Article 28. Qeet ID also acts as a **Data Controller** for personal data it processes independently — including customer account data, billing information, and platform usage analytics. Both classifications carry distinct obligations. Dual-role compliance must be explicitly addressed in all contracts and privacy documentation.

---

### 4.2 GDPR Requirements Matrix

| # | Requirement | GDPR Article | Obligation Type | Owner | Status at MVP |
| --- | --- | --- | --- | --- | --- |
| G-01 | Lawful basis for processing personal data documented for every processing activity | Art. 6 | Mandatory | Legal Counsel | Required |
| G-02 | Privacy Notice published — clear, plain language, fully GDPR-compliant | Art. 13 / 14 | Mandatory | Legal Counsel + Marketing | Required |
| G-03 | Data Processing Agreements (DPAs) in place with all customers | Art. 28 | Mandatory | Legal Counsel | Required |
| G-04 | Sub-processor list published and maintained — all sub-processors compliant | Art. 28(2) | Mandatory | Legal Counsel + Compliance | Required |
| G-05 | Data Subject Rights portal — access, rectification, erasure, portability, restriction, objection | Art. 15–21 | Mandatory | Product + Engineering | Required |
| G-06 | Right to Erasure (Right to Be Forgotten) — technical capability to delete all personal data per user | Art. 17 | Mandatory | Engineering | Required |
| G-07 | Data Portability — machine-readable export of user data on request | Art. 20 | Mandatory | Engineering | Required |
| G-08 | Consent management — explicit, granular, withdrawable consent records | Art. 7 | Mandatory | Engineering + Legal | Required |
| G-09 | Records of Processing Activities (ROPA) maintained and current | Art. 30 | Mandatory | Compliance Officer | Required |
| G-10 | Data Protection Impact Assessment (DPIA) completed for high-risk processing | Art. 35 | Mandatory | Compliance + Legal | Required before launch |
| G-11 | Data Protection Officer (DPO) appointed or documented exemption rationale recorded | Art. 37 | Mandatory | Legal Counsel | Required |
| G-12 | Breach notification procedure — 72-hour notification to supervisory authority | Art. 33 | Mandatory | Compliance + Security | Required |
| G-13 | Breach notification to affected data subjects — without undue delay for high-risk breaches | Art. 34 | Mandatory | Compliance + Legal | Required |
| G-14 | Data minimisation — only personal data strictly necessary for the purpose collected | Art. 5(1)(c) | Mandatory | Product + Engineering | Required |
| G-15 | Purpose limitation — personal data not processed beyond original stated purpose | Art. 5(1)(b) | Mandatory | Legal + Product | Required |
| G-16 | Storage limitation — personal data retention periods defined and technically enforced | Art. 5(1)(e) | Mandatory | Engineering + Compliance | Required |
| G-17 | Encryption at rest and in transit for all personal data | Art. 5(1)(f) / Art. 32 | Mandatory | Security Engineering | Required |
| G-18 | Pseudonymisation applied where technically feasible | Art. 25 / Art. 32 | Mandatory | Engineering | Required |
| G-19 | Privacy by Design and by Default documented and implemented | Art. 25 | Mandatory | Product + Engineering | Required |
| G-20 | International data transfer mechanisms — Standard Contractual Clauses (SCCs) or adequacy decision | Art. 44–49 | Mandatory | Legal Counsel | Required |
| G-21 | Cookie consent management — PECR / ePrivacy compliant cookie banner | ePrivacy Directive | Mandatory | Engineering + Legal | Required |
| G-22 | Age verification — no processing of personal data of children under 16 without parental consent | Art. 8 | Mandatory | Engineering + Legal | Required |
| G-23 | Supervisory Authority registration — register with lead supervisory authority in EU establishment | Art. 30(4) | Mandatory | Legal Counsel | Required |

---

### 4.3 GDPR — Data Subject Rights Technical Requirements

| Right | Technical Implementation Required | Priority |
| --- | --- | --- |
| Right of Access (Art. 15) | Self-service data export from user account panel; API endpoint for programmatic access | P1 — MVP |
| Right to Rectification (Art. 16) | User profile editing capability in account panel; admin override in dashboard | P1 — MVP |
| Right to Erasure (Art. 17) | Hard delete capability — removes all personal data from primary storage, backups within retention window, and downstream systems | P1 — MVP |
| Right to Data Portability (Art. 20) | Machine-readable JSON / CSV export of all personal data on user request | P1 — MVP |
| Right to Restriction of Processing (Art. 18) | Account suspension without deletion; processing flag in user record | P1 — MVP |
| Right to Object (Art. 21) | Opt-out mechanism for analytics and non-essential processing | P1 — MVP |
| Right Not to be Subject to Automated Decision-Making (Art. 22) | No fully automated decisions with legal effect — human review path documented | P2 — Post-Launch |

### 4.4 GDPR — Data Retention Schedule

| Data Category | Retention Period | Basis | Deletion Mechanism |
| --- | --- | --- | --- |
| User authentication records (active) | Duration of account + 30 days post-deletion | Contract | Automated deletion on account closure |
| User authentication logs (audit) | 12 months | Legitimate interest / Legal obligation | Automated rolling deletion |
| Session tokens | Duration of session + 24 hours | Contract | Automated expiry |
| Refresh tokens | 30 days from issuance or last use | Contract | Automated expiry |
| Billing records | 7 years | Legal obligation (tax / financial regulations) | Manual archival after 7 years |
| Support ticket records | 3 years from ticket closure | Legitimate interest | Automated deletion |
| Marketing contact data | Until withdrawal of consent | Consent | Automated deletion on opt-out |
| Security incident logs | 3 years | Legal obligation / Legitimate interest | Archived and encrypted |
| API access logs | 12 months | Legitimate interest | Automated rolling deletion |

---

### 5. SOC 2 — System and Organisation Controls

### 5.1 Applicability Assessment

SOC 2 is a non-negotiable requirement for Qeet ID. Enterprise customers in the technology, financial services, and healthcare sectors will not sign contracts without a current SOC 2 report. SOC 2 Type I — which attests to the design of controls at a point in time — must be obtained **before production launch**. SOC 2 Type II — which attests to the operating effectiveness of controls over a period of at least six months — must be obtained **within 12 months of production launch**.

The audit will be conducted against the **Trust Services Criteria (TSC)** defined by the AICPA. Qeet ID must meet all five TSC categories.

---

### 5.2 SOC 2 Trust Services Criteria Requirements Matrix

### TSC 1 — Security (Common Criteria) — Mandatory for all SOC 2 reports

| # | Control Requirement | Description | Owner | MVP Status |
| --- | --- | --- | --- | --- |
| CC1.1 | Control environment documentation | COSO principles — documented organizational structure, code of conduct, board oversight | Compliance + Legal | Required |
| CC2.1 | Internal communication of policies | Security policies communicated to all staff; training records maintained | Compliance + HR | Required |
| CC3.1 | Risk assessment process | Formal risk assessment process documented and executed at least annually | Compliance + Security | Required |
| CC4.1 | Monitoring of controls | Ongoing monitoring activities defined — internal audit, automated control monitoring | Compliance | Required |
| CC5.1 | Control activities — policies and procedures | Written policies and procedures covering all security domains | Compliance | Required |
| CC6.1 | Logical and physical access controls | Role-based access controls on all systems; MFA enforced for all admin access | Security Engineering | Required |
| CC6.2 | Prior to issuing credentials | Identity verification before account activation; credential issuance procedures documented | Engineering + Security | Required |
| CC6.3 | Role-based access — need to know | Access provisioned on least-privilege principle; access reviews conducted quarterly | Security + DevOps | Required |
| CC6.6 | Security threats from outside the boundary | WAF, DDoS protection, intrusion detection deployed; threat monitoring operational | DevOps + Security | Required |
| CC6.7 | Transmission of data | All data in transit encrypted via TLS 1.2 minimum; TLS 1.3 preferred | Engineering | Required |
| CC6.8 | Prevention of unauthorized access | Endpoint detection, network segmentation, vulnerability management program | Security Engineering | Required |
| CC7.1 | Detection and monitoring | SIEM operational; security event monitoring with defined alert thresholds | DevOps + Security | Required |
| CC7.2 | Anomalies and security events | Incident detection procedures; Qeet ID Guard anomaly detection operational | Security Engineering | Required |
| CC7.3 | Evaluation of security events | Incident classification, triage, and escalation procedures documented | Security + Compliance | Required |
| CC7.4 | Response to identified security incidents | Incident response plan documented, tested, and maintained | Security + Compliance | Required |
| CC7.5 | Recovery from identified security incidents | Disaster recovery and business continuity plan documented and tested | DevOps + SRE | Required |
| CC8.1 | Change management | Formal change management process — code review, approval, deployment controls | Engineering + DevOps | Required |
| CC9.1 | Risk mitigation | Vendor risk management program; sub-processor due diligence documented | Compliance + Legal | Required |

### TSC 2 — Availability

| # | Control Requirement | Description | Owner | MVP Status |
| --- | --- | --- | --- | --- |
| A1.1 | Performance monitoring | System performance monitored against defined uptime SLA (99.9% at launch) | SRE + DevOps | Required |
| A1.2 | Environmental protections | Infrastructure redundancy — multi-AZ deployment; no single point of failure | DevOps + Cloud Architect | Required |
| A1.3 | Recovery testing | Disaster recovery testing conducted at least annually; results documented | SRE | Required |

### TSC 3 — Processing Integrity

| # | Control Requirement | Description | Owner | MVP Status |
| --- | --- | --- | --- | --- |
| PI1.1 | System processing is complete | Input validation, output verification, error handling documented and tested | Engineering + QA | Required |
| PI1.2 | System processing is accurate | Data integrity controls — checksums, validation, reconciliation procedures | Engineering | Required |
| PI1.3 | Processing errors are identified and addressed | Error monitoring, alerting, and resolution procedures defined | Engineering + SRE | Required |

### TSC 4 — Confidentiality

| # | Control Requirement | Description | Owner | MVP Status |
| --- | --- | --- | --- | --- |
| C1.1 | Confidential information identified | Data classification policy — identifies and labels confidential data | Compliance + Engineering | Required |
| C1.2 | Confidential information protected | Encryption at rest for all confidential data; access controls enforced | Engineering + Security | Required |

### TSC 5 — Privacy

| # | Control Requirement | Description | Owner | MVP Status |
| --- | --- | --- | --- | --- |
| P1.0 | Privacy notice | Privacy notice published — consistent with GDPR and AICPA privacy criteria | Legal + Marketing | Required |
| P2.0 | Choice and consent | Consent mechanisms implemented; preferences stored and honoured | Engineering + Legal | Required |
| P3.0 | Collection | Only data necessary for disclosed purposes collected | Product + Engineering | Required |
| P4.0 | Use, retention, and disposal | Retention schedules defined, technically enforced, and documented | Engineering + Compliance | Required |
| P5.0 | Access | Data subject access rights technically supported | Engineering | Required |
| P6.0 | Disclosure and notification | Data breach notification procedures documented and tested | Compliance + Legal | Required |
| P7.0 | Quality | Data accuracy and completeness maintained; correction mechanisms available | Engineering | Required |
| P8.0 | Monitoring and enforcement | Privacy compliance monitoring program operational; DPO or equivalent assigned | Compliance | Required |

---

### 5.3 SOC 2 Audit Timeline

| Milestone | Target Date | Owner |
| --- | --- | --- |
| Engage SOC 2 audit firm | Phase 7 — Month 11 | Compliance Officer |
| Readiness assessment completed | Month 11 | Compliance + Security |
| Gap remediation completed | Month 12 | Engineering + Security |
| SOC 2 Type I audit window | Month 12 | Third-Party Auditor |
| SOC 2 Type I report issued | Month 13 — before launch | Third-Party Auditor |
| SOC 2 Type II observation period begins | Production launch | Compliance Officer |
| SOC 2 Type II report issued | Month 27 (12 months post-launch) | Third-Party Auditor |

---

### 6. CCPA / CPRA — California Consumer Privacy Act

### 6.1 Applicability Assessment

CCPA / CPRA applies to Qeet ID when it processes personal information of California residents and meets applicable revenue or data processing thresholds. Given Qeet ID's target of 50,000+ MAUs within 12 months, CCPA applicability is highly likely. Compliance must be achieved before or concurrent with US market growth.

---

### 6.2 CCPA / CPRA Requirements Matrix

| # | Requirement | Description | Owner | Timeline |
| --- | --- | --- | --- | --- |
| CA-01 | Privacy Policy update — CCPA disclosures | Categories of personal information collected, sold, shared, and disclosed must be explicitly listed | Legal Counsel | Tier 2 — within 6 months post-launch |
| CA-02 | Right to Know | Consumers can request disclosure of personal information collected about them in the last 12 months | Engineering + Legal | Tier 2 |
| CA-03 | Right to Delete | Consumers can request deletion of personal information; exceptions documented | Engineering + Legal | Tier 2 |
| CA-04 | Right to Correct | Consumers can request correction of inaccurate personal information | Engineering | Tier 2 |
| CA-05 | Right to Opt-Out of Sale or Sharing | "Do Not Sell or Share My Personal Information" mechanism required if data is sold or shared for cross-context advertising | Legal + Engineering | Tier 2 |
| CA-06 | Right to Limit Use of Sensitive Personal Information | Mechanism to limit use of sensitive personal information to disclosed purposes | Engineering + Legal | Tier 2 |
| CA-07 | Non-Discrimination | No discrimination against consumers exercising CCPA rights | Legal + Product | Tier 2 |
| CA-08 | Data Broker Registration | If Qeet ID is classified as a data broker under CPRA, registration with the California Privacy Protection Agency required | Legal Counsel | Tier 2 |
| CA-09 | Opt-out signals — Global Privacy Control (GPC) | Technical implementation to honour GPC browser signals automatically | Engineering | Tier 2 |
| CA-10 | Contractor agreements | CCPA-compliant contractual terms with all contractors and service providers who process California resident data | Legal Counsel | Tier 2 |

---

### 7. Protocol Compliance Standards

### 7.1 OAuth 2.0 — RFC 6749 / RFC 9700 (OAuth 2.1)

| # | Requirement | Description | Owner | MVP Status |
| --- | --- | --- | --- | --- |
| OA-01 | Authorization Code Flow with PKCE | Mandatory for all public clients — no implicit flow permitted | Engineering | Required |
| OA-02 | Client Credentials Flow | Supported for M2M authentication — Qeet ID Keys | Engineering | Required |
| OA-03 | Token Endpoint security | HTTPS enforced; client authentication required; rate limiting applied | Engineering + Security | Required |
| OA-04 | Refresh Token rotation | Refresh tokens must be rotated on use; previous token invalidated | Engineering | Required |
| OA-05 | Token binding and sender-constrained tokens | DPoP (Demonstrating Proof of Possession) support for high-security flows | Engineering | Post-Launch |
| OA-06 | Scope enforcement | Token scopes strictly enforced — no privilege escalation via scope manipulation | Engineering | Required |
| OA-07 | Redirect URI validation | Exact match validation for all redirect URIs — no open redirector vulnerabilities | Engineering + Security | Required |
| OA-08 | State parameter enforcement | CSRF protection via state parameter mandatory for authorization code flow | Engineering | Required |
| OA-09 | Token introspection (RFC 7662) | Resource servers can validate tokens via introspection endpoint | Engineering | Required |
| OA-10 | Token revocation (RFC 7009) | Access and refresh token revocation endpoint implemented | Engineering | Required |

### 7.2 OpenID Connect Core 1.0

| # | Requirement | Description | Owner | MVP Status |
| --- | --- | --- | --- | --- |
| OI-01 | ID Token — JWT signed with RS256 or ES256 | All ID tokens signed with asymmetric keys; key rotation supported | Engineering | Required |
| OI-02 | UserInfo endpoint | OIDC-compliant UserInfo endpoint returning standard claims | Engineering | Required |
| OI-03 | Discovery document (/.well-known/openid-configuration) | Published and maintained — enables dynamic client registration | Engineering | Required |
| OI-04 | JWKS endpoint (/.well-known/jwks.json) | Public key set published for ID token verification | Engineering | Required |
| OI-05 | Nonce validation | Nonce parameter enforced to prevent replay attacks | Engineering | Required |
| OI-06 | Standard claims support | sub, iss, aud, exp, iat, nonce, email, name, picture claims implemented | Engineering | Required |
| OI-07 | ACR (Authentication Context Class Reference) | Authentication strength signalling — MFA vs password-only | Engineering | Required |
| OI-08 | AMR (Authentication Methods References) | Authentication method signalling — password, otp, webauthn, etc. | Engineering | Required |
| OI-09 | PKCE enforcement for all flows | PKCE mandatory for all authorization code flows | Engineering | Required |
| OI-10 | OIDC Conformance testing | OpenID Foundation conformance test suite passed before launch | QA + Engineering | Required |

---

### 7.3 SAML 2.0 — OASIS Standard

| # | Requirement | Description | Owner | MVP Status |
| --- | --- | --- | --- | --- |
| SA-01 | SAML 2.0 Web Browser SSO Profile | Full implementation of SP-initiated and IdP-initiated SSO flows | Engineering | Required |
| SA-02 | XML Signature validation | All SAML assertions and responses must be signed and signature validated | Engineering + Security | Required |
| SA-03 | XML Encryption | SAML assertions must support encryption (AES-256 minimum) | Engineering | Required |
| SA-04 | Assertion validity window | Maximum assertion validity of 5 minutes — clock skew tolerance of 2 minutes | Engineering | Required |
| SA-05 | Replay attack prevention | AssertionID tracking to prevent assertion replay | Engineering + Security | Required |
| SA-06 | Metadata exchange | SP and IdP metadata exchange supported — dynamic and static | Engineering | Required |
| SA-07 | Single Logout (SLO) | SP-initiated and IdP-initiated single logout supported | Engineering | Required |
| SA-08 | NameID formats | Persistent, transient, and email NameID formats supported | Engineering | Required |
| SA-09 | Attribute statements | Custom attribute mapping from SAML assertions to Qeet ID user profiles | Engineering | Required |
| SA-10 | XXE and XML injection prevention | All XML parsing hardened against XML External Entity (XXE) injection | Engineering + Security | Required |

---

### 7.4 SCIM 2.0 — RFC 7642 / RFC 7643 / RFC 7644

| # | Requirement | Description | Owner | MVP Status |
| --- | --- | --- | --- | --- |
| SC-01 | SCIM 2.0 User resource | Full User schema implementation per RFC 7643 | Engineering | Required |
| SC-02 | SCIM 2.0 Group resource | Full Group schema implementation — group membership provisioning | Engineering | Required |
| SC-03 | CRUD operations | Create, Read, Update, Delete operations for Users and Groups | Engineering | Required |
| SC-04 | Patch operations | SCIM PATCH (RFC 7396) for partial updates — enable, disable, attribute changes | Engineering | Required |
| SC-05 | Filter operations | SCIM filter queries for user lookup and sync operations | Engineering | Required |
| SC-06 | Bulk operations | SCIM bulk endpoint for high-volume provisioning events | Engineering | Post-Launch |
| SC-07 | Authentication | SCIM endpoint protected by OAuth 2.0 bearer token | Engineering + Security | Required |
| SC-08 | Schema discovery | ServiceProviderConfig and Schemas endpoints published | Engineering | Required |
| SC-09 | Soft delete / deprovisioning | User deprovisioning disables access immediately — hard delete on request | Engineering | Required |
| SC-10 | Sync conflict handling | Documented conflict resolution strategy for concurrent provisioning updates | Engineering | Required |

---

### 7.5 WebAuthn / FIDO2 — W3C Recommendation + FIDO Alliance

| # | Requirement | Description | Owner | MVP Status |
| --- | --- | --- | --- | --- |
| WA-01 | WebAuthn Level 2 compliance | Full implementation of W3C WebAuthn Level 2 specification | Engineering | Required |
| WA-02 | FIDO2 authenticator attestation | Support for platform and roaming authenticators; attestation verification | Engineering + Security | Required |
| WA-03 | Resident key (discoverable credential) support | Passkeys stored on device — no username entry required | Engineering | Required |
| WA-04 | Cross-device authentication | Cross-device passkey flows (phone as authenticator for desktop) | Engineering | Required |
| WA-05 | Relying Party ID validation | RP ID strictly bound to origin — prevents cross-origin credential theft | Engineering + Security | Required |
| WA-06 | Challenge freshness | Challenge generated per ceremony — minimum 128 bits entropy; single-use | Engineering | Required |
| WA-07 | Authenticator data validation | All authenticator data fields validated per specification — no partial validation | Engineering | Required |
| WA-08 | FIDO Metadata Service (MDS3) integration | Authenticator metadata validation against FIDO MDS3 for attestation trust | Engineering | Required |
| WA-09 | Backup eligibility and backup state flags | BS/BE flags honoured in synced passkey scenarios | Engineering | Required |
| WA-10 | FIDO2 Certification | Qeet ID passkey implementation certified through FIDO Alliance | QA + Compliance | Required before launch |

### 8. Security Controls Compliance Requirements

### 8.1 Encryption Standards

| # | Requirement | Standard | Minimum Requirement | Owner | MVP Status |
| --- | --- | --- | --- | --- | --- |
| EN-01 | Data in transit | TLS | TLS 1.2 minimum; TLS 1.3 preferred; TLS 1.0 and 1.1 disabled | Engineering | Required |
| EN-02 | Data at rest — user passwords | Hashing | Argon2id (primary); bcrypt (fallback) — no MD5, SHA-1, or unsalted hashing | Engineering | Required |
| EN-03 | Data at rest — PII fields | Symmetric encryption | AES-256-GCM — field-level encryption for PII | Engineering | Required |
| EN-04 | Data at rest — database volumes | Disk encryption | AES-256 disk-level encryption on all database storage | DevOps | Required |
| EN-05 | Backup encryption | Symmetric encryption | AES-256 on all backup files; encryption keys stored separately | DevOps | Required |
| EN-06 | JWT signing | Asymmetric signing | RS256 (RSA-2048 minimum) or ES256 (ECDSA P-256) — no HS256 for public-facing tokens | Engineering | Required |
| EN-07 | API key storage | Hashing | HMAC-SHA256 of API keys stored — raw keys never persisted | Engineering | Required |
| EN-08 | Secrets management | KMS | All secrets stored in managed KMS (AWS KMS / GCP KMS / HashiCorp Vault) — no plaintext secrets in code or config | DevOps + Security | Required |
| EN-09 | Certificate management | PKI | TLS certificates from trusted CA; automated renewal via cert-manager; expiry monitoring | DevOps | Required |
| EN-10 | Key rotation | Policy | Encryption keys rotated annually minimum; JWT signing keys rotated every 90 days | Security Engineering | Required |

---

### 8.2 Authentication Security Controls

| # | Requirement | Description | Owner | MVP Status |
| --- | --- | --- | --- | --- |
| AS-01 | MFA enforcement for admin accounts | All Qeet ID staff accessing production systems must use MFA — hardware key or TOTP minimum | Security + IT | Required |
| AS-02 | MFA enforcement for customer admin dashboard | Customers can enforce MFA for all admin users in their organisation | Engineering | Required |
| AS-03 | Brute force protection | Account lockout after 5 failed attempts; exponential backoff; CAPTCHA integration | Engineering + Security | Required |
| AS-04 | Credential stuffing protection | Haveibeenpwned API integration — flag compromised passwords at registration and login | Engineering | Required |
| AS-05 | Password complexity policy | Minimum 8 characters; no maximum below 64; complexity rules configurable per tenant | Engineering | Required |
| AS-06 | Passkey as default | New accounts encouraged to register passkey at signup; password treated as fallback | Engineering + UX | Required |
| AS-07 | Session management | Absolute session timeout: 24 hours; idle timeout: 30 minutes (configurable); secure HttpOnly cookies | Engineering | Required |
| AS-08 | Concurrent session control | Configurable concurrent session limits per tenant; session list visible to user | Engineering | Required |
| AS-09 | Login anomaly detection | Impossible travel detection; new device alerts; unusual time-of-day alerts | Engineering + Security | Required |
| AS-10 | Token binding | Tokens bound to client IP and user-agent fingerprint; violations flagged | Engineering | Post-Launch |

---

### 8.3 Infrastructure Security Controls

| # | Requirement | Description | Owner | MVP Status |
| --- | --- | --- | --- | --- |
| IN-01 | Network segmentation | Production, staging, and development environments fully isolated; no shared credentials | DevOps | Required |
| IN-02 | Principle of least privilege — infrastructure | Every service account, IAM role, and cloud permission scoped to minimum required access | DevOps + Security | Required |
| IN-03 | Web Application Firewall (WAF) | WAF deployed at edge — OWASP Top 10 rule set active; custom rules for auth-specific threats | DevOps + Security | Required |
| IN-04 | DDoS protection | Cloud-native DDoS protection active on all public-facing endpoints (AWS Shield / GCP Cloud Armor) | DevOps | Required |
| IN-05 | Vulnerability management | Dependency scanning in CI/CD pipeline (Dependabot / Snyk); critical CVEs patched within 72 hours | DevOps + Security | Required |
| IN-06 | Container security | Container images scanned for vulnerabilities; no root containers in production; immutable image tags | DevOps + Security | Required |
| IN-07 | Secrets scanning | Pre-commit hooks and CI/CD pipeline scanning for accidentally committed secrets | DevOps + Engineering | Required |
| IN-08 | Penetration testing | External penetration test conducted before launch; annual thereafter | Security + Third-Party | Required |
| IN-09 | Bug bounty program | Public bug bounty program launched at or within 3 months of production launch | Security + Legal | Required |
| IN-10 | Security patching SLA | Critical: 72 hours; High: 7 days; Medium: 30 days; Low: 90 days | Security + DevOps | Required |

### 9. Audit Logging & Monitoring Requirements

### 9.1 Audit Log Requirements Matrix

| # | Event Category | Events to Log | Retention | Owner | MVP Status |
| --- | --- | --- | --- | --- | --- |
| AL-01 | Authentication events | Login success, login failure, MFA success, MFA failure, logout, session expiry | 12 months | Engineering | Required |
| AL-02 | Registration events | Account creation, email verification, identity verification | 12 months | Engineering | Required |
| AL-03 | Credential events | Password change, password reset, passkey registration, passkey deletion, API key creation/revocation | 12 months | Engineering | Required |
| AL-04 | Authorization events | Permission grant, permission revocation, role assignment, role removal, policy evaluation | 12 months | Engineering | Required |
| AL-05 | Administrative events | Admin login, user suspension, user deletion, tenant configuration changes | 3 years | Engineering | Required |
| AL-06 | Data access events | Personal data export requests, data deletion requests, data subject rights actions | 3 years | Engineering | Required |
| AL-07 | Security events | Brute force detection, anomalous login alert, impossible travel detection, bot detection trigger | 3 years | Engineering + Security | Required |
| AL-08 | Token lifecycle events | Token issuance, token refresh, token revocation, token introspection | 12 months | Engineering | Required |
| AL-09 | SCIM provisioning events | User provision, user deprovision, group changes, attribute updates | 12 months | Engineering | Required |
| AL-10 | API access events | API key usage, rate limit hits, API errors | 12 months | Engineering | Required |
| AL-11 | Billing events | Plan changes, payment events, MAU threshold alerts | 7 years | Engineering + Finance | Required |
| AL-12 | Compliance events | DPA execution, consent changes, data subject rights fulfilment | 3 years | Compliance + Engineering | Required |

---

### 9.2 Audit Log Technical Requirements

| # | Requirement | Description | Owner | MVP Status |
| --- | --- | --- | --- | --- |
| ALT-01 | Tamper-evident logs | Audit logs must be write-once; no deletion or modification by application layer | Engineering + Security | Required |
| ALT-02 | Structured log format | All audit logs in structured JSON format with standard fields: timestamp (ISO 8601 UTC), event_type, actor_id, target_id, ip_address, user_agent, result | Engineering | Required |
| ALT-03 | Log integrity | Cryptographic hash chaining or append-only log storage to detect tampering | Engineering + Security | Required |
| ALT-04 | Log export API | Audit logs exportable via API for SIEM integration (Splunk, Microsoft Sentinel, Datadog) | Engineering | Required |
| ALT-05 | Real-time streaming | Security events streamed in near-real-time to monitoring platform; maximum 60-second lag | Engineering + DevOps | Required |
| ALT-06 | Log search and filtering | Admin dashboard provides searchable audit log with filter by event type, user, date range, IP address | Engineering | Required |
| ALT-07 | Log access controls | Audit logs accessible only to authorised admin roles; log access itself logged | Engineering + Security | Required |
| ALT-08 | Cross-tenant isolation | Tenant A's audit logs are never accessible to Tenant B; strict tenant boundary enforcement | Engineering | Required |

---

### 10. Data Classification & Handling Policy

### 10.1 Data Classification Levels

| Level | Classification | Description | Examples |
| --- | --- | --- | --- |
| Level 1 | Public | Information approved for public release | Marketing content, public documentation, open-source code |
| Level 2 | Internal | Information for internal use only — not for external distribution | Internal processes, non-sensitive configuration, general product metrics |
| Level 3 | Confidential | Sensitive business or personal information — restricted access | Customer lists, API keys, non-PII user data, internal financials |
| Level 4 | Restricted | Highest sensitivity — personal data, credentials, compliance-sensitive data | Passwords (hashed), PII, authentication tokens, audit logs, SOC 2 evidence |

---

### 10.2 Personal Data Inventory — Qeet ID Platform

| # | Data Element | Classification | Processing Purpose | Lawful Basis (GDPR) | Stored | Encrypted |
| --- | --- | --- | --- | --- | --- | --- |
| PD-01 | User email address | Restricted | Authentication, account management, notifications | Contract | Yes | Yes (field-level) |
| PD-02 | User display name | Confidential | User profile, OIDC claims | Contract | Yes | No |
| PD-03 | User phone number | Restricted | MFA (SMS), account recovery | Contract | Yes | Yes (field-level) |
| PD-04 | IP address | Restricted | Security, fraud prevention, anomaly detection | Legitimate interest | Yes (logs) | Yes |
| PD-05 | User agent / device fingerprint | Confidential | Security, session management | Legitimate interest | Yes (logs) | No |
| PD-06 | Passkey public credential | Confidential | Passwordless authentication | Contract | Yes | Yes |
| PD-07 | TOTP seed (MFA) | Restricted | Multi-factor authentication | Contract | Yes | Yes (AES-256) |
| PD-08 | Hashed password | Restricted | Authentication fallback | Contract | Yes | Yes (Argon2id) |
| PD-09 | OAuth access tokens | Restricted | Authorization | Contract | No (ephemeral) | In transit (TLS) |
| PD-10 | Refresh tokens | Restricted | Session continuity | Contract | Yes (hashed) | Yes |
| PD-11 | Social provider ID (Google, GitHub, etc.) | Confidential | Social login linkage | Contract | Yes | No |
| PD-12 | Profile photo URL | Confidential | OIDC picture claim | Contract | Yes (reference) | No |
| PD-13 | Organisation membership | Confidential | Multi-tenancy, RBAC | Contract | Yes | No |
| PD-14 | Role and permission assignments | Confidential | Authorization | Contract | Yes | No |
| PD-15 | Billing name and address | Restricted | Billing and invoicing | Contract / Legal obligation | Yes | Yes (field-level) |
| PD-16 | Payment method token | Restricted | Subscription billing | Contract | Yes (tokenized via Stripe) | Yes |
| PD-17 | Login history | Restricted | Security, audit | Legitimate interest | Yes (12 months) | Yes |
| PD-18 | Consent records | Restricted | GDPR compliance evidence | Legal obligation | Yes | Yes |
| PD-19 | API key (hashed) | Restricted | M2M authentication | Contract | Yes (HMAC-SHA256) | Yes |
| PD-20 | SAML assertion attributes | Restricted | Enterprise SSO | Contract | No (transient) | In transit (TLS) |

### 11. Third-Party & Sub-Processor Compliance

### 11.1 Sub-Processor Requirements

All sub-processors engaged by Qeet ID must satisfy the following minimum requirements before engagement:

- Signed Data Processing Agreement (DPA) conforming to GDPR Article 28
- SOC 2 Type II report or equivalent — issued within the last 12 months
- EU Standard Contractual Clauses (SCCs) where data is transferred outside the EU/EEA
- ISO 27001 certification preferred for Tier 1 sub-processors
- Annual due diligence review documented by the Compliance Officer

---

### 11.2 Sub-Processor Register

| # | Sub-Processor | Category | Data Processed | GDPR Basis | Compliance Status |
| --- | --- | --- | --- | --- | --- |
| SP-01 | AWS / GCP (Cloud Provider) | Infrastructure | All platform data — stored and processed in region | SCCs + DPA | To be confirmed in Phase 2 |
| SP-02 | Stripe | Payment Processing | Billing name, payment method token | SCCs + DPA | SOC 2 Type II — confirmed |
| SP-03 | Datadog / Grafana Cloud | Monitoring & Observability | System logs, performance metrics, sanitised event data | DPA | SOC 2 Type II — to be confirmed |
| SP-04 | SendGrid / AWS SES | Transactional Email | Email address, email content | DPA | SOC 2 Type II — to be confirmed |
| SP-05 | Twilio | SMS (MFA) | Phone number, OTP message content | DPA + SCCs | SOC 2 Type II — to be confirmed |
| SP-06 | GitHub | Source Code Management | Source code (no PII in repos) | DPA | SOC 2 Type II — confirmed |
| SP-07 | Intercom / Zendesk | Customer Support | Support ticket content, email, name | DPA + SCCs | To be evaluated in Phase 1 |
| SP-08 | HubSpot / Salesforce | CRM (Enterprise Sales) | Enterprise contact names, emails, company data | DPA + SCCs | To be evaluated in Phase 1 |
| SP-09 | HashiCorp Vault / AWS KMS | Secrets Management | Encryption keys, secrets metadata | DPA | SOC 2 Type II — to be confirmed |
| SP-10 | Third-Party Pen Test Firm | Security Testing | Controlled access to test environment only | DPA + NDA | Engaged in Phase 6 |

---

### 12. Contractual Compliance Requirements

### 12.1 Customer Contract Obligations

All Qeet ID customer contracts must include the following compliance provisions:

| # | Provision | Applicable Tier | Owner |
| --- | --- | --- | --- |
| CC-01 | Data Processing Agreement (DPA) executed before activation | All tiers | Legal Counsel |
| CC-02 | Acceptable Use Policy (AUP) accepted at signup | All tiers | Legal Counsel |
| CC-03 | Service Level Agreement (SLA) — 99.9% uptime commitment at launch | Growth + Enterprise | Legal + SRE |
| CC-04 | Security addendum available on request | Enterprise | Legal + Security |
| CC-05 | Sub-processor list disclosed and maintained; customer notified of changes with 30-day notice | All tiers | Legal + Compliance |
| CC-06 | Breach notification to customer — within 72 hours of Qeet ID becoming aware | All tiers | Legal + Security |
| CC-07 | Data residency commitment documented for enterprise customers | Enterprise | Legal + DevOps |
| CC-08 | Termination and data deletion clause — customer data deleted within 30 days of contract termination | All tiers | Legal + Engineering |
| CC-09 | Audit rights — enterprise customers may request audit evidence annually | Enterprise | Legal + Compliance |
| CC-10 | Intellectual property ownership — customer owns their user data | All tiers | Legal Counsel |

---

### 12.2 Key Legal Documents Required at Launch

| # | Document | Description | Owner | Status |
| --- | --- | --- | --- | --- |
| LD-01 | Terms of Service (ToS) | Governing terms for all Qeet ID customers | Legal Counsel | Draft required |
| LD-02 | Privacy Policy | GDPR + CCPA compliant privacy disclosure | Legal Counsel | Draft required |
| LD-03 | Data Processing Agreement (DPA) | GDPR Art. 28 compliant standard DPA | Legal Counsel | Draft required |
| LD-04 | Acceptable Use Policy (AUP) | Prohibited uses of the Qeet ID platform | Legal Counsel | Draft required |
| LD-05 | Cookie Policy | PECR / ePrivacy compliant cookie disclosure | Legal Counsel + Engineering | Draft required |
| LD-06 | Service Level Agreement (SLA) | Uptime commitment, support response times, credit terms | Legal + SRE | Draft required |
| LD-07 | Enterprise Security Addendum | Additional security commitments for enterprise customers | Legal + Security | Draft required |
| LD-08 | Bug Bounty Policy | Scope, reward structure, responsible disclosure terms | Legal + Security | Draft required |
| LD-09 | Vulnerability Disclosure Policy (VDP) | Public coordinated disclosure process | Legal + Security | Draft required |
| LD-10 | Sub-Processor List | Publicly published list of all sub-processors | Legal + Compliance | Draft required |

---

### 13. Compliance Roadmap

### 13.1 Phase-by-Phase Compliance Obligations

| Phase | Compliance Activity | Owner | Deadline |
| --- | --- | --- | --- |
| Phase 1 — Discovery | DPIA initiated; ROPA started; compliance framework documented; sub-processor evaluation initiated | Compliance Officer | Week 6 |
| Phase 2 — System Design | Privacy by Design review of architecture; data flow diagrams for GDPR mapping; encryption standards confirmed | Compliance + Security Architect | Week 14 |
| Phase 3 — UI/UX Design | Cookie consent UI designed; data subject rights flows designed; privacy notice and AUP screens designed | UX Designer + Legal | Week 20 |
| Phase 4 — Development | GDPR technical controls implemented; audit logging built; data subject rights API built; SCIM provisioning | Engineering + Security | Month 9 |
| Phase 5 — Infrastructure | Data residency configuration; encryption at rest deployed; secrets management operational; DDoS and WAF live | DevOps + Security | Month 9 |
| Phase 6 — Testing | Privacy compliance testing; security penetration testing; GDPR data flow validation; OIDC conformance testing | QA + Security + Compliance | Month 11 |
| Phase 7 — Audit | SOC 2 Type I audit; GDPR readiness review; FIDO2 certification; legal documents finalised | Compliance + Legal + Third-Party Auditor | Month 12–13 |
| Phase 8 — Beta | Beta customer DPAs executed; consent collection live; audit logs reviewed for completeness | Legal + Compliance + Engineering | Month 13 |
| Phase 9 — Launch | All Tier 1 requirements satisfied; legal documents published; security trust center live; sub-processor list published | All | Month 15 |
| Post-Launch Month 6 | CCPA compliance; PDPA compliance; LGPD compliance; NIST CSF mapping completed | Compliance + Legal | Month 21 |
| Post-Launch Month 12 | SOC 2 Type II observation period complete; ISO 27001 gap analysis initiated | Compliance + Third-Party Auditor | Month 27 |

### 13.2 Compliance Gaps Register

| # | Gap | Tier | Risk Level | Owner | Target Resolution |
| --- | --- | --- | --- | --- | --- |
| CG-01 | DPO appointment decision not yet formalised | Tier 1 | High | Legal Counsel | Phase 1 close |
| CG-02 | Sub-processor DPA status unconfirmed for 6 of 10 identified sub-processors | Tier 1 | High | Legal + Compliance | Phase 3 |
| CG-03 | FIDO2 certification process not yet initiated with FIDO Alliance | Tier 1 | High | Engineering + QA | Phase 6 |
| CG-04 | OIDC conformance test suite run not yet scheduled | Tier 1 | Medium | QA + Engineering | Phase 6 |
| CG-05 | SOC 2 audit firm not yet engaged | Tier 1 | Medium | Compliance Officer | Phase 5 |
| CG-06 | Data residency region selection pending cloud provider decision | Tier 1 | High | CTO + DevOps + Legal | Phase 2 |
| CG-07 | CCPA applicability threshold analysis not yet conducted | Tier 2 | Medium | Legal Counsel | Phase 4 |
| CG-08 | Bug bounty program scope and platform not yet defined | Tier 1 | Medium | Security + Legal | Phase 8 |
| CG-09 | ISO 27001 gap analysis not yet initiated | Tier 3 | Low | Compliance Officer | Post-Launch Year 1 |
| CG-10 | HIPAA applicability framework for healthcare customer segment not yet documented | Tier 3 | Low | Legal + Compliance | v1.5 planning |

---

### 14. Compliance Monitoring & Governance

### 14.1 Ongoing Compliance Calendar

| Activity | Frequency | Owner |
| --- | --- | --- |
| Sub-processor due diligence review | Annual | Compliance Officer |
| ROPA review and update | Quarterly | Compliance Officer |
| Data subject rights request handling SLA review | Monthly | Compliance + Engineering |
| Security control testing (internal) | Quarterly | Security Engineering |
| External penetration test | Annual | Third-Party Security Firm |
| SOC 2 audit (Type II ongoing) | Annual | Third-Party Auditor |
| Privacy policy and ToS review | Annual or on regulatory change | Legal Counsel |
| GDPR training — all staff | Annual | Compliance + HR |
| Incident response tabletop exercise | Bi-annual | Security + Compliance |
| Risk register review | Quarterly | Compliance + Product Manager |
| Regulatory change monitoring (GDPR, CCPA, NIS2, DPDPA) | Monthly | Legal + Compliance |

---

### 14.2 Compliance Escalation Path

| Trigger | Response | Escalation Path |
| --- | --- | --- |
| Personal data breach suspected | Immediate investigation; clock starts on 72-hour GDPR notification window | Security Lead → Compliance Officer → Legal Counsel → CEO → Supervisory Authority |
| Data subject rights request received | Acknowledge within 72 hours; respond within 30 days (GDPR); track via compliance ticket | Engineering → Compliance Officer → Legal Counsel |
| SOC 2 control failure identified | Log in risk register; assess impact; determine remediation timeline | Compliance Officer → CISO → CTO → Product Manager |
| Regulatory change with material impact | Impact assessment within 30 days; implementation plan drafted | Legal Counsel → Compliance Officer → Product Manager → CTO |
| Sub-processor security incident | Notify affected customers per DPA terms; assess impact | Compliance Officer → Legal Counsel → Customer Success → Affected Customers |
| Regulator inquiry or audit request | Engage Legal Counsel immediately; do not respond without legal review | Legal Counsel → CEO → Compliance Officer |

---

### 15. Approvals & Sign-off

| Role | Name | Signature | Date |
| --- | --- | --- | --- |
| Compliance Officer |  |  |  |
| Legal Counsel |  |  |  |
| CISO |  |  |  |
| CTO |  |  |  |
| Security Architect |  |  |  |
| Product Manager |  |  |  |
| CEO / Founder |  |  |  |

---

*This document is version controlled. Compliance requirements are a living obligation — this matrix must be reviewed when new markets are entered, new customer segments are served, new regulations come into force, or significant product features are added. Any material change requires formal review by the Compliance Officer and Legal Counsel and re-approval by the sign-off parties above.*

---

**Qeet ID — Authenticate Everything.** *A Qeet Group Company*