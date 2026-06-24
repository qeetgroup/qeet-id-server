# ADR-0001: Modular Monolith over Microservices

**Status:** Accepted  
**Date:** 2025-Q1  
**Deciders:** Qeet ID core team

---

## Context

Qeet ID is being built as a pre-1.0 product with a small team. The feature surface is wide (auth, RBAC, OIDC, SAML, SCIM, billing, audit) and requires rapid iteration. The team considered three architectural styles:

1. **Microservices** — each bounded context as an independently deployable service
2. **Monolith (unstructured)** — everything in one flat codebase
3. **Modular monolith** — single deployable with enforced internal domain boundaries

Microservices were attractive for long-term scalability but would introduce significant operational overhead (service mesh, inter-service auth, distributed tracing, contract testing) before the product had proven product-market fit. An unstructured monolith would move fast initially but accrue coupling debt that would make extraction painful later.

## Decision

Build Qeet ID as a **modular monolith**:

- **Single Go module** rooted at the repository root (`github.com/qeetgroup/qeet-id`)
- **Single PostgreSQL instance** with one schema per bounded context
- **Five bounded contexts** as enforced package boundaries (see ADR-0002)
- **One deployable binary** (`cmd/server/main.go`)
- **Per-context outbox** topic so each context can be peeled off later without rewriting business logic

Cross-domain calls go through interfaces declared by the consumer (not direct package imports of concrete types), preserving the extraction seam.

## Consequences

**Positive:**
- One deployment unit — no service mesh, no inter-service auth, no distributed transaction coordination
- Fast development: a feature touching auth + billing + audit is a single PR with no service boundary to cross
- Simple local development: `make dev` starts everything
- Architecture tests enforce the modular discipline without paying microservice costs

**Negative / watch-outs:**
- All contexts scale together — a high-throughput SCIM provisioning job cannot be independently scaled without splitting off the context first
- A bug in any context can affect the whole process; mitigation is thorough integration testing
- Extraction to a separate service when the time comes will require additional operational work (add service-to-service auth, split DB, deploy separately)

**Future path:** When a context needs independent scaling or deployment (SCIM or billing are candidates), the combination of a separate schema, interface-mediated dependencies, and a per-context outbox makes extraction a defined refactor rather than a rewrite.
