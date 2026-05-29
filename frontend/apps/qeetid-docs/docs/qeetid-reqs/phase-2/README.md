# Phase 2 — System Design & Architecture

Welcome to the Qeet ID Phase 2 baseline. This directory contains the twelve architectural Markdown documents that define how Qeet ID is built, along with the supporting Open Decisions Register and the Phase 2 Exit Checklist.

Phase 2 refines the Phase 1 Discovery & Requirements baseline into a buildable architecture. Every document here cross-references the Phase 1 NFR, Protocol Requirements, Compliance Matrix, Persona, and Feature Prioritization documents in [/phase-1/](../phase-1/). Read Phase 1 first; this directory presumes that context.

The documents are designed to be read in order — each one builds on its predecessors. The High-Level System Architecture is the anchor; everything else refines a piece of it.

---

## 1. Document Index

| # | Document | Owner | Purpose |
| --- | --- | --- | --- |
| 1 | [Qeet ID — High-Level System Architecture](Qeet ID%20%E2%80%94%20High-Level%20System%20Architecture.md) | Solution Architect | Anchors Phase 2 — system context, container view, layered architecture, principles, constraints, open questions, and dependencies on every later document. |
| 2 | [Qeet ID — Microservices Decomposition & Service Boundaries](Qeet ID%20%E2%80%94%20Microservices%20Decomposition%20%26%20Service%20Boundaries.md) | Solution Architect + Backend Lead | Enumerates the 20+ services that make up the platform; defines responsibilities, data ownership, APIs, SLO tier, and team ownership. |
| 3 | [Qeet ID — Identity Provider (IdP) Core Engine Design](Qeet ID%20%E2%80%94%20Identity%20Provider%20%28IdP%29%20Core%20Engine%20Design.md) | Backend Lead + Security Architect | The cryptographic, credential, token-lifecycle, and session-management core. Includes the Keycloak-vs-Ory-vs-Build analysis and the recommendation (ADR-011 Proposed). |
| 4 | [Qeet ID — Authentication Flow Designs](Qeet ID%20%E2%80%94%20Authentication%20Flow%20Designs.md) | Solution Architect | Step-by-step ASCII sequence diagrams for the 18 MVP authentication and federation flows — OAuth, OIDC, SAML, SCIM, WebAuthn, MFA, magic links, recovery. |
| 5 | [Qeet ID — Authorization Engine Design](Qeet ID%20%E2%80%94%20Authorization%20Engine%20Design.md) | Solution Architect | RBAC at MVP, ABAC at v1.5, FGA at v2.0. Includes the role/permission model, JWT claim composition, sync permission-check API, and forward-compatibility hooks. |
| 6 | [Qeet ID — Multi-Tenancy Architecture](Qeet ID%20%E2%80%94%20Multi-Tenancy%20Architecture.md) | Solution Architect + Backend Lead | The architecturally enforced isolation model — RLS, sharding, dedicated tier, propagation, lifecycle, GDPR erasure, and the five-layer cross-tenant prevention guarantee. |
| 7 | [Qeet ID — Database Design & Data Model](Qeet ID%20%E2%80%94%20Database%20Design%20%26%20Data%20Model.md) | Database Architect + Backend Lead | The PostgreSQL data model, indexing, partitioning, sharding, migrations, retention, backup, caching, and the event-sourced audit pipeline. |
| 8 | [Qeet ID — API Design Standards](Qeet ID%20%E2%80%94%20API%20Design%20Standards.md) | Backend Lead + API Designer | The contract for every public and internal API — URL conventions, headers, pagination, errors, versioning, webhook signing, and OpenAPI requirements. |
| 9 | [Qeet ID — Security Architecture (Zero Trust)](Qeet ID%20%E2%80%94%20Security%20Architecture%20%28Zero%20Trust%29.md) | Security Architect | Zero Trust principles, trust boundaries, identity propagation, encryption, secrets, key management, WAF / DDoS, audit pipeline, vulnerability management, STRIDE, OWASP API Top 10, incident response, and SOC 2 control mapping. |
| 10 | [Qeet ID — Infrastructure & Deployment Architecture](Qeet ID%20%E2%80%94%20Infrastructure%20%26%20Deployment%20Architecture.md) | DevOps / Cloud Architect | AWS region topology, EKS layout, ingress, CDN, database hosting, CI/CD, environments, IaC, networking, cost optimisation, DR, and residency enforcement. |
| 11 | [Qeet ID — Observability Architecture](Qeet ID%20%E2%80%94%20Observability%20Architecture.md) | SRE Lead | Logs, metrics, traces, SLOs, alerting, dashboards, synthetic monitoring, RUM, audit pipeline retention, correlation, on-call tooling, and customer-facing observability. |
| 12 | [Qeet ID — Architecture Decision Records (ADRs)](Qeet ID%20%E2%80%94%20Architecture%20Decision%20Records%20%28ADRs%29.md) | Solution Architect (running log) | The running register of major architectural decisions — context, decision, consequences, alternatives. Seeded with 20 ADRs (ADR-001 to ADR-020). |

---

## 2. Supporting Files

| File | Purpose |
| --- | --- |
| [Open-Decisions-Register.md](Open-Decisions-Register.md) | All open architectural decisions surfaced during Phase 2 — Phase 1 carry-forwards plus per-document opens. Owner and target resolution date for each. |
| [Phase-2-Exit-Checklist.md](Phase-2-Exit-Checklist.md) | The Solution Architect's gate for declaring Phase 2 complete and ready for Phase 3 / Phase 4. |

---

## 3. How to Use This Phase 2 Baseline

### For Architects and Engineering Leads

Read documents 1, 2, 9, and 12 first. They give you the shape of the platform and the decisions that bind future work. Then read your service's relevant detail document (3, 4, 5, 7, or 8 depending on team).

### For DevOps / SRE

Read documents 1, 10, and 11 in that order, then 9 for the security envelope.

### For Compliance and Auditors

Read documents 1 and 9 first. Document 9 §19 maps Qeet ID's architecture to the SOC 2 Common Criteria; the Compliance Matrix in Phase 1 lists the controls. Documents 6 and 7 describe data-residency and retention mechanisms.

### For Product Management

Read documents 1, 2, and 4. They tell you what the platform does, who owns it, and what the user-visible flows look like.

### For Developer Relations / SDK Engineers

Read documents 4 and 8. The SDKs are generated against the OpenAPI specs that conform to Document 8; the flows in Document 4 are what each SDK must enable customers to do.

---

## 4. Cross-Document Reading Map

```
                     ┌──────────────────────────────────────┐
                     │  1. High-Level System Architecture   │
                     └──────────────────┬───────────────────┘
                                        │
   ┌────────────────────────────────────┴────────────────────────────────────┐
   │                                                                          │
   ▼                                                                          ▼
┌────────────────────────────┐                              ┌────────────────────────────┐
│  2. Microservices          │ ─────────────────────────────│  9. Security Architecture  │
│     Decomposition          │                              │     (Zero Trust)            │
└──────┬───────────────────┬─┘                              └────────────────────────────┘
       │                   │
       │                   │
       ▼                   ▼
┌──────────────┐    ┌──────────────────────────┐
│ 3. IdP Core  │ ──▶│ 4. Authentication Flows  │
└──────┬───────┘    └──────────────────────────┘
       │
       ▼
┌──────────────────────────┐    ┌──────────────────────────┐    ┌──────────────────────────┐
│ 5. Authorization Engine  │    │ 6. Multi-Tenancy         │    │ 8. API Design Standards  │
└──────────┬───────────────┘    └──────────┬───────────────┘    └──────────────────────────┘
           │                                │
           │                                │
           └─────────────┬──────────────────┘
                         │
                         ▼
              ┌──────────────────────────┐
              │ 7. Database Design       │
              └──────────────┬───────────┘
                             │
                             ▼
                ┌──────────────────────────────┐
                │ 10. Infrastructure & Deploy  │
                └──────────────┬───────────────┘
                               │
                               ▼
                  ┌──────────────────────────┐
                  │ 11. Observability         │
                  └──────────────┬────────────┘
                                 │
                                 ▼
                    ┌──────────────────────────┐
                    │ 12. Architecture Decision│
                    │     Records (ADRs)       │
                    └──────────────────────────┘
```

Every arrow above represents a cross-document dependency that is explicitly linked in the text.

---

## 5. Phase 2 Standards

All documents in this Phase 2 baseline:

- Open with a standard Document Information table (project, parent, subsidiary, version, prepared-by, date, status).
- Close with the standard footer:
  > *This document is version controlled. [version control statement].*
  >
  > **Qeet ID — Authenticate Everything.** *A Qeet Group Company*
- Use numbered sections matching Phase 1 style.
- Use tables for matrices, decisions, comparisons, and lists.
- Use ASCII diagrams for architecture, flows, and topologies — no external image links.
- Reference Phase 1 documents explicitly when a decision flows from them.
- Reference other Phase 2 documents when there are cross-dependencies.
- Surface open decisions rather than invent resolutions.

---

## 6. Phase 2 Status

| Item | Status |
| --- | --- |
| All 12 architecture documents produced | ✅ |
| Open Decisions Register established | ✅ |
| Phase 2 Exit Checklist established | ✅ |
| ADR-001 to ADR-020 seeded | ✅ |
| ADR-011 (Open-source base layer) | Proposed — Legal license audit prerequisite |
| Cross-references verified bi-directionally | ✅ (initial pass — re-verified at Phase 2 close) |
| Stakeholder sign-off | Pending |

---

## 7. What Phase 2 Does NOT Cover

This baseline is **Phase 2 only**. The following are explicitly out of scope and live in their own phase deliverables:

- **Phase 3** — UI/UX Design (developer portal, admin dashboard, end-user flows, design system).
- **Phase 4** — Development (code, SDKs, the actual MVP build).
- **Phase 5** — Infrastructure & DevOps execution (this document defines the *architecture*; the *runbooks* and *deployment artifacts* come in Phase 5).
- **Phase 6** — Testing & QA execution.
- **Phase 7** — Security audit and certification.
- **Phase 8** — Beta launch.
- **Phase 9** — Production deployment.
- **Phase 10** — Post-launch & growth.

---

## 8. Contact

Questions about a document → contact the document's owner from the table in §1.
Questions about an architectural decision → consult the relevant ADR; if absent, open a discussion with the Solution Architect.
Open decision needing resolution → see [Open-Decisions-Register.md](Open-Decisions-Register.md) for owner and target date.

---

**Qeet ID — Authenticate Everything.** *A Qeet Group Company*
