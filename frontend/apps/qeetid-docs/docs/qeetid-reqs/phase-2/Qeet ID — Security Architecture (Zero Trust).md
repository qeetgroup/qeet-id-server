# Qeet ID — Security Architecture (Zero Trust)

### 1. Document Information

|  |  |
| --- | --- |
| **Document Name** | Security Architecture (Zero Trust) |
| **Project Name** | Qeet ID |
| **Parent Company** | Qeet Group |
| **Subsidiary** | Qeet ID (Standalone) |
| **Document Version** | v1.0 |
| **Prepared By** | Security Architect |
| **Date** | May 19, 2026 |
| **Status** | Draft — Pending Stakeholder Sign-off |

---

### 2. Purpose & Scope

This document defines the security architecture of Qeet ID. Security in an Authentication & Authorization platform is not a layer — it is the product. A Qeet ID outage is bad; a Qeet ID breach is existential.

The document covers: the Zero Trust operating model, trust boundaries, identity propagation across services, network segmentation, encryption at rest and in transit, secrets management, key management lifecycle, WAF and DDoS protection, rate limiting, bot detection, audit logging, vulnerability management, the Security Development Lifecycle (SDL), the STRIDE threat model per service, the top ten threats and their mitigations, incident response architecture, and the mapping of design decisions to SOC 2 Common Criteria.

The audience is the Security Architect, CISO, Compliance Officer, Solution Architect, every Backend Engineering Lead, DevOps Lead, SRE Lead, and CTO.

This document depends on every other Phase 2 architecture document. It is the audit-evidence anchor for SOC 2 Type I.

---

### 3. Zero Trust Principles Applied to Qeet ID

**ZT-01 — Never trust, always verify.** No request is trusted because it came from inside the VPC, from a known IP, or with a credential that worked yesterday. Every request — including service-to-service — is authenticated, authorised, and audited.

**ZT-02 — Assume breach.** Architecture decisions presume that one component will eventually be compromised. A compromised pod must not become a compromised cluster. A compromised cluster must not become a compromised tenant. A compromised tenant must not become a compromised platform.

**ZT-03 — Least privilege.** Every workload identity, every IAM role, every database grant, every secret access scope is the minimum necessary. Standing admin privileges do not exist; access is just-in-time (NFR AC-03).

**ZT-04 — Defence in depth.** Multiple independent controls guard each asset (Multi-Tenancy §11.1 enumerates five layers for tenant isolation; analogous layering applies to credentials, tokens, keys, audit trails).

**ZT-05 — Explicit identity for every actor.** Users, services, machines — each has a verifiable identity. Identity is propagated end-to-end across service boundaries.

**ZT-06 — Encryption everywhere.** In transit (TLS 1.2+; mTLS internal). At rest (AES-256-GCM at field, disk, and backup levels). Keys in a hardware-backed KMS, never on disk or in environment variables in plaintext.

**ZT-07 — Comprehensive audit.** Every security-relevant action is logged with immutable, hash-chained evidence (Database §13).

**ZT-08 — Secure defaults.** New tenants get MFA-recommended, passkey-prompted, refresh-token-rotation, PKCE-required, modern-TLS-only configurations. Insecure options are not configurable.

**ZT-09 — Automated enforcement.** Policies are enforced by code, not by checklists. SAST/DAST run on every commit. Container images are signed and verified. IaC scans block insecure infrastructure changes.

**ZT-10 — Continuous improvement.** Threat models refresh with the architecture. Pen-tests annually. Bug bounty always-on. Post-incident reviews feed back into design.

---

### 4. Trust Boundaries

```
   ┌─────────────────────────────────────────────────────────────────────────────────┐
   │  ZONE 0 — INTERNET (untrusted)                                                  │
   │  - End users, customer applications, attackers, bots                            │
   └─────────────────────────────────────────────────────────────────────────────────┘
                                       │ TLS 1.2+/1.3
                                       ▼
   ┌─────────────────────────────────────────────────────────────────────────────────┐
   │  ZONE 1 — EDGE (limited trust)                                                  │
   │  - Cloudflare WAF, Bot Management, DDoS L7                                      │
   │  - AWS Shield Advanced L3/L4                                                    │
   │  - CloudFront                                                                   │
   │  Trust posture: drop obviously malicious; rate-limit; bot-score; pass through   │
   └─────────────────────────────────────────────────────────────────────────────────┘
                                       │ HTTPS (re-terminated at ALB)
                                       ▼
   ┌─────────────────────────────────────────────────────────────────────────────────┐
   │  ZONE 2 — INGRESS (gateway boundary)                                            │
   │  - AWS ALB                                                                      │
   │  - Istio ingress gateway: validates JWT, applies per-tenant rate limit,         │
   │    extracts tenant identity, attaches request_id                                │
   │  Trust posture: trust the bearer-token assertion if signature verifies          │
   └─────────────────────────────────────────────────────────────────────────────────┘
                                       │ mTLS (mesh internal)
                                       ▼
   ┌─────────────────────────────────────────────────────────────────────────────────┐
   │  ZONE 3 — APPLICATION SERVICES (workload trust)                                 │
   │  - Stateless services in Kubernetes namespaces                                  │
   │  - Each pod has a workload identity (Istio-issued)                              │
   │  Trust posture: trust workload identity proven by mTLS + service token         │
   └─────────────────────────────────────────────────────────────────────────────────┘
                                       │ mTLS to data tier
                                       ▼
   ┌─────────────────────────────────────────────────────────────────────────────────┐
   │  ZONE 4 — DATA TIER (constrained access)                                        │
   │  - Aurora PostgreSQL, ElastiCache Redis, MSK Kafka, S3                          │
   │  - Reachable only from application namespaces; private subnets                  │
   │  Trust posture: trust authenticated workload with least-privilege grants        │
   └─────────────────────────────────────────────────────────────────────────────────┘

   ┌─────────────────────────────────────────────────────────────────────────────────┐
   │  ZONE 5 — KEY & SECRETS PLANE (highest trust required to access)                │
   │  - AWS KMS, HashiCorp Vault                                                     │
   │  - Audited just-in-time access; HSM-backed root keys                            │
   └─────────────────────────────────────────────────────────────────────────────────┘

   ┌─────────────────────────────────────────────────────────────────────────────────┐
   │  ZONE 6 — OPERATIONS (privileged human)                                         │
   │  - Engineer access to production: hardware-MFA, time-bound, fully logged        │
   └─────────────────────────────────────────────────────────────────────────────────┘
```

Each transition between zones requires a credential and a policy decision. Even the trusted-internal Zone 3 → Zone 4 transition requires Vault-mediated database credentials with bounded lifetime.

---

### 5. Identity Propagation Across Services

### 5.1 The Three-Layer Identity

Every internal request carries three identities:

| Layer | Identity | Verification |
| --- | --- | --- |
| Transport | Workload identity from mTLS cert | Istio mesh CA |
| Application | Service-token-signed identity claim | ES256-signed by internal CA |
| Business | End-user / tenant identity | Public JWT claims propagated as headers |

```
   ─── HTTP request internal ─────────────────────────────────────────
   :method GET
   :path /internal/permissions/check
   :authority svc-rbac.identity.svc.cluster.local

   Authorization: Bearer <user-access-token>     ← original customer token if needed
   X-Qeetify-Service-Token: <internal-ES256>     ← caller workload identity claim
   X-Qeetify-Tenant-Id: org_acme                 ← propagated tenant
   X-Qeetify-User-Id: user_8f3                   ← propagated subject
   X-Qeetify-Request-Id: req_01HX...             ← W3C trace-id
   ─── mTLS encapsulation ────────────────────────────────────────────
   Cert: SPIFFE-style URI SAN
         spiffe://qeetify.svc/ns/auth/sa/auth-service
```

### 5.2 The Service Token

Issued by an internal token authority every 5 minutes:

```
   {
     "iss": "internal.qeetify.svc",
     "sub": "spiffe://qeetify.svc/ns/auth/sa/auth-service",
     "aud": "spiffe://qeetify.svc/ns/identity/sa/rbac-service",
     "tenant_id": "org_acme",
     "request_id": "req_01HX...",
     "iat": 1747900800,
     "exp": 1747901100
   }
```

The receiving service verifies the token signature, checks the `aud` matches itself, and confirms `tenant_id` matches the inbound application-layer claim. A mismatch is a P1 audit event.

### 5.3 SPIFFE / SPIRE Roadmap

At MVP, workload identities are bound to Istio-issued certs with the SAN URI form. SPIFFE/SPIRE formalisation is targeted for v2.0 (NFR NS-05) — it adds machine-rotation and cross-cluster identity federation we will need at scale.

---

### 6. Network Segmentation

### 6.1 VPC Layout

```
   VPC: qeetify-prod
     Region: us-east-1
     CIDR: 10.0.0.0/16
     │
     ├── Public subnets (10.0.0.0/24, 10.0.1.0/24, 10.0.2.0/24)
     │     - 3 AZs
     │     - Holds: ALB, NAT Gateways
     │     - No EC2 / compute pods here
     │
     ├── Application subnets (10.0.10.0/22, three /22 spreads across AZs)
     │     - EKS worker nodes
     │     - No direct internet ingress; outbound via NAT
     │
     └── Data subnets (10.0.30.0/24 per AZ)
           - Aurora, ElastiCache, MSK, OpenSearch
           - No internet routing; isolated from Application via subnet ACL
```

Each environment (dev, staging, prod) is a separate VPC. No VPC peering between them; bastion is not a thing (NFR NS-02).

### 6.2 Kubernetes NetworkPolicies

Every namespace has default-deny ingress and egress NetworkPolicies. Explicit allows are declared per service pair.

```
   apiVersion: networking.k8s.io/v1
   kind: NetworkPolicy
   metadata:
     name: rbac-allow-from-auth-token
     namespace: identity
   spec:
     podSelector:
       matchLabels:
         app: rbac
     policyTypes: [Ingress]
     ingress:
       - from:
           - namespaceSelector: { matchLabels: { name: auth } }
             podSelector: { matchLabels: { app: auth } }
           - namespaceSelector: { matchLabels: { name: auth } }
             podSelector: { matchLabels: { app: token } }
         ports:
           - port: 8443
             protocol: TCP
```

The default-deny posture combined with Istio mesh authorisation policies enforces "explicit allow only" service-to-service traffic.

### 6.3 Istio AuthorizationPolicies

In addition to network-layer NetworkPolicies, Istio AuthorizationPolicies enforce identity-aware allow lists at the L7 layer — combining mTLS principal, request path, and HTTP method.

### 6.4 Egress Restrictions

Outbound traffic from production is routed through a NAT Gateway with **egress proxy filtering** (Cloudflare or AWS-native): only approved destinations are allowed. The destination list includes Stripe, Twilio, SendGrid, AWS SES, AWS SNS, HIBP, FIDO MDS3, GitHub Container Registry, OpenTelemetry collectors, PagerDuty — and nothing else. Any service attempting to reach an unknown host fails and triggers an alert.

### 6.5 DNS Security

- Authoritative DNS for `qeetify.com` and `*.qeetify.com` runs on two providers (NFR RD-07).
- DNSSEC enabled.
- CAA records published restricting which CAs may issue Qeet ID certificates.

---

### 7. Encryption Architecture

### 7.1 In Transit

| Path | Encryption | Configuration |
| --- | --- | --- |
| Client ↔ Edge | TLS 1.2 minimum; 1.3 preferred | AEAD ciphers only (NFR SE-02); HSTS + preload |
| Edge ↔ Origin | TLS 1.2+ | Cloudflare → ALB; certificate-pinned for highest-tier paths |
| ALB ↔ Pod | mTLS (mesh) | Istio-injected sidecar |
| Pod ↔ Pod | mTLS (mesh) | Istio sidecar |
| Pod ↔ Aurora | TLS (RDS-required) | AWS-managed cert |
| Pod ↔ ElastiCache | TLS | AWS in-transit encryption |
| Pod ↔ MSK | TLS + SASL/SCRAM | AWS in-transit encryption |
| Pod ↔ S3 | HTTPS | AWS endpoint TLS |
| Pod ↔ KMS / Vault | HTTPS / TLS 1.2+ | — |

### 7.2 At Rest

| Tier | Algorithm | Key custody |
| --- | --- | --- |
| Disk (EBS) | AES-256-XTS via EBS encryption | KMS CMK per environment |
| Database (Aurora cluster) | AES-256 via Aurora encryption | KMS CMK |
| Cache (ElastiCache) | AES-256 | KMS CMK |
| Kafka (MSK) | AES-256 | KMS CMK |
| Object storage (S3) | AES-256-GCM | SSE-KMS with per-bucket CMK |
| Backup snapshots | AES-256-GCM | Separate KMS CMK (NFR SE-08) |
| Field-level PII (email, phone, TOTP seed, etc.) | AES-256-GCM envelope (per-tenant DEK) | KEK in KMS; DEK wrapped, cached in-process |
| Password hashes | Argon2id with KMS-pepper | Argon2id parameters declared in [IdP Core §7.1] |

### 7.3 Envelope Encryption Pattern

```
   Plaintext PII (e.g. user email)
        │
        ▼
   AES-256-GCM(plaintext, DEK_tenant) → ciphertext + nonce + tag
        │
        ▼
   stored {ciphertext, nonce, tag, dek_id, enc_version}

   DEK_tenant lifecycle:
     - Generated by KMS GenerateDataKey (returns plaintext DEK + wrapped DEK)
     - Plaintext DEK held in process memory for ≤15 min
     - Wrapped DEK stored in tenant_dek table
     - Rotation: new DEK generated; new writes use new DEK; old data retains its dek_id reference
```

### 7.4 Why Argon2id, Not bcrypt

Argon2id (PHC 2015 winner) provides memory-hard hashing — resistant to GPU and ASIC brute-force. bcrypt remains acceptable but Argon2id is the platform choice (Compliance EN-02). Parameters revisited annually as hardware evolves.

### 7.5 Certificate Management

- Public TLS certs (Cloudflare → user; ALB → Cloudflare) issued via Let's Encrypt or AWS Certificate Manager.
- Internal mesh certs issued by Istio CA, rotated every 24 h automatically.
- Cert expiry monitoring with 30-day alert (NFR SE-03).
- `cert-manager` automates renewals.

---

### 8. Secrets Management

### 8.1 Architecture

```
   ┌──────────────────────────────────────────────────────────┐
   │                       AWS KMS                            │
   │  - Root KEKs (HSM-backed; FIPS 140-2 Level 3)            │
   │  - Used for wrapping DEKs and Vault root                 │
   └─────────────────────┬────────────────────────────────────┘
                         │
                         ▼
   ┌──────────────────────────────────────────────────────────┐
   │                  HashiCorp Vault                         │
   │  - KV secrets (3rd-party API keys: Stripe, Twilio, ...)  │
   │  - Database dynamic credentials (per-pod, time-bound)    │
   │  - Transit engine (envelope-encrypt API for services)    │
   │  - Auth methods: Kubernetes service-account-token        │
   └─────────────────────┬────────────────────────────────────┘
                         │
                         ▼
                  Application pods
                  (Vault Agent sidecar injects secrets;
                   no plaintext in env vars in containers)
```

### 8.2 Secret Classes & Custody

| Class | Stored In | Rotation | Notes |
| --- | --- | --- | --- |
| TLS certs | ACM / cert-manager | Automatic | Public-facing only |
| Database credentials | Vault (dynamic) | Per-pod issuance; 24-hour leases | No static DB passwords in env |
| Third-party API keys (Stripe, Twilio, SendGrid) | Vault KV | Manual / per-incident | Audited access |
| JWT signing keys | KMS-wrapped in Postgres `signing_keys` | 90 days (Protocol JW-05) | See [IdP Core §5] |
| HMAC peppers (refresh tokens, API keys) | KMS-stored, never extracted in plaintext | On-incident | Vault Transit |
| Service-account credentials | Vault | 30 days | OAuth client_credentials for internal jobs |
| Webhook signing secrets (per-tenant per-subscription) | Field-encrypted in Postgres | Customer-rotatable | Customer-managed |

### 8.3 Forbidden Practices

- No secret in source code (pre-commit hooks + CI secret scanning; NFR VM-08).
- No plaintext secret in environment variables baked into container images.
- No secret in CI/CD logs (masking enforced).
- No secret in cloud-provider tags.
- No `--debug` or `--verbose` flag that prints secrets.

### 8.4 Secret Access Audit

Every Vault read is audited: who, what, when. Vault audit logs ship to the central audit pipeline. Quarterly Compliance review against access patterns.

---

### 9. Key Management Lifecycle

(Complements [IdP Core §5].)

### 9.1 Key Inventory & Cadence

| Key class | Created by | Rotation | Retired-key retention |
| --- | --- | --- | --- |
| Root KEK (KMS CMK) | Operator (manual; annual review) | Annual | Indefinite (KMS handles internally) |
| Field encryption DEK (envelope) | Auto, per-tenant | Annual | All historical retained for read |
| JWT signing key (public) | Auto every 90 d | 90 d | 24 h post-rotation |
| Internal service-token signing | Auto every 30 d | 30 d | 1 h post-rotation |
| Magic-link signing | Auto every 90 d | 90 d | 15 min (link TTL) |
| Webhook signing secret | Customer | Customer-rotated | Dual-active window during rotation |
| TLS server cert | cert-manager | Automatic (≤90 d Let's Encrypt) | n/a |
| Mesh mTLS cert | Istio CA | 24 h | n/a (auto-renewed) |

### 9.2 Compromise Response

If a key is suspected compromised:

1. Operator initiates emergency rotation (runbook).
2. Customer Security Advisory issued if customer-visible (Protocol PV-04).
3. Affected tokens or data invalidated; users forced to re-authenticate where applicable.
4. Post-incident review within 5 business days (NFR IR-06).

---

### 10. WAF & DDoS Protection

### 10.1 Edge Stack

```
   Internet
       │
       ▼
   ┌──────────────────────────────────────────────────┐
   │     Cloudflare                                   │
   │     - WAF: OWASP Top 10 ruleset (NFR NS-06)      │
   │     - WAF: Qeet ID-specific rules (next §10.2)   │
   │     - Bot Management (NFR NS-08)                 │
   │     - L7 DDoS rate-limit + challenge             │
   │     - Edge rate limiting (NFR NS-09)             │
   │     - TLS termination optional                   │
   └──────────────────────┬───────────────────────────┘
                          │
                          ▼
   ┌──────────────────────────────────────────────────┐
   │     AWS Shield Advanced                          │
   │     - L3 / L4 volumetric DDoS                    │
   │     - 24/7 DRT engagement on attack              │
   │     - Cost-protection clause for attack-driven   │
   │       autoscaling                                │
   └──────────────────────────────────────────────────┘
                          │
                          ▼
                     ALB → Mesh
```

### 10.2 Qeet ID-Specific WAF Rules

Beyond the OWASP ruleset, Qeet ID deploys auth-specific rules:

- Reject `Authorization: none` headers.
- Reject `alg: none` JWT detection on token-bearing requests.
- Anomalous OAuth request shapes (e.g., `response_type=token` reaches a non-existent flow surface) → block with metrics.
- SAML XML containing suspicious patterns (XSW signatures, DTD declarations) → block at edge.
- High-rate `/oauth/token` from a single source on rotating client_ids → bot-management challenge.

### 10.3 Attack Mode

A toggled "Attack Mode" deploys stricter Cloudflare rules: managed challenge for all anonymous traffic, IP reputation gating, geo-fencing. Activated on detection of sustained attack (PagerDuty + on-call decision).

---

### 11. Rate Limiting

### 11.1 Layered Rate Limiting

| Layer | Scope | Rationale |
| --- | --- | --- |
| Cloudflare | Per-IP global | First-line crude shedding |
| API Gateway | Per-IP per-endpoint-class | Pre-application defence |
| Guard Service | Per-tenant + per-client_id + per-endpoint | Plan-aware policy |
| Database | Per-tenant connection pool limits | Prevents one tenant exhausting connections |

Limits are documented in NFR RL-01..RL-10 and surfaced via the standard rate-limit headers ([API Design Standards §12](Qeet ID%20%E2%80%94%20API%20Design%20Standards.md)).

### 11.2 Spike Detection

A sudden order-of-magnitude RPS increase from a single source triggers automatic challenge insertion (CAPTCHA) and an SRE pager event for confirmation.

---

### 12. Bot Detection & Anomaly Detection

### 12.1 Bot Detection (Cloudflare)

- Behavioural analysis: TLS fingerprints, header patterns, request cadence.
- Cloudflare Bot Score forwarded as `Cf-Bot-Score` header → Guard Service.
- Above-threshold scores trigger CAPTCHA challenges or outright block, depending on endpoint sensitivity.

### 12.2 Anomaly Detection at Application Layer

Anomaly Service (Microservices §4.13) consumes authentication events from Kafka and detects:

- **Impossible travel** (NFR AS-09): two successful logins for the same user in geographies that imply >800km/h travel.
- **New-device login**: device fingerprint not previously seen → step-up triggered.
- **Unusual time-of-day**: outside the user's typical pattern (90-day rolling window).
- **High failure rate**: > 30% login failures across a tenant in 5 min → tenant security flag.

At MVP these are rule-based heuristics. ML-based detection moves to v1.5.

---

### 13. Audit Logging Architecture

### 13.1 Architecture

```
   Application Services
        │  (audit.{plane}.{verb} on Kafka, partitioned by tenant_id)
        ▼
   Kafka topics audit.*
        │
        ├──▶ Audit Ingestion Service
        │       │
        │       ├──▶ PostgreSQL audit_log_hot (12-month hot tier)
        │       │       - Partitioned by (tenant_id, month)
        │       │       - Hash-chained per tenant per day
        │       │
        │       └──▶ S3 audit-cold-{region} (12–84-month cold tier)
        │               - Glacier transition at 12 months
        │               - Object Lock + bucket versioning
        │
        └──▶ OpenSearch (search index for dashboard)
                - Per-tenant index; field-level ACL
                - 90-day retention in OpenSearch; long queries
                  fall back to Postgres
```

### 13.2 Tamper Evidence

- Hash chain (Database §13.2). Tampering with event N invalidates every hash from N forward.
- Chain heads exported daily to a separate immutable store (S3 Object Lock).
- Operators with database write access cannot rewrite history without producing a hash chain inconsistency caught by daily verification.

### 13.3 Customer-Side Audit Access

- Dashboard audit log viewer with full-text search.
- Audit log export API for SIEM ingestion (Splunk, Sentinel, Datadog, Sumo Logic — NFR IC-04).
- Per-tenant audit access; cross-tenant access blocked by OpenSearch index permissions.

---

### 14. Vulnerability Management & Patching

(Aligned to NFR §8.4 and Compliance §8.3 IN-05/IN-10.)

| Severity | Patch SLA | Source NFR |
| --- | --- | --- |
| Critical (CVSS 9.0–10.0) | 72 h | VM-01 |
| High (7.0–8.9) | 7 d | VM-02 |
| Medium (4.0–6.9) | 30 d | VM-03 |
| Low (< 4.0) | 90 d | VM-04 |

### 14.1 Scanning Pipeline

- **Dependency scan** (Snyk / Dependabot) on every PR + nightly on default branch — fails build on critical (NFR VM-05).
- **Container image scan** (Trivy / Grype) on every build + nightly re-scan of running images (NFR VM-06).
- **IaC scan** (tfsec / Checkov) on every Terraform PR (NFR VM-07).
- **Secret scan** (gitleaks) on every commit + nightly repo-wide (NFR VM-08).
- **SAST** (Semgrep, CodeQL) on every PR.
- **DAST** in staging after every deploy.

### 14.2 Bug Bounty & VDP

- Public bug bounty at launch (Compliance IN-09; NFR VM-10).
- Vulnerability Disclosure Policy with 90-day coordinated disclosure default (NFR VM-11).

### 14.3 Penetration Testing

- External pen-test before MVP launch (Compliance IN-08).
- Annual external pen-test thereafter.
- Internal continuous red-team in v1.5+.

---

### 15. Security Development Lifecycle (SDL)

The SDL is the engineering process that bakes security into Phase 4 onward.

### 15.1 SDL Activities by Phase

| Phase | Activity | Owner |
| --- | --- | --- |
| Design | Threat model per service (STRIDE; §17) | Service author + Security Architect |
| Design | Security review of design docs | Security Architect |
| Implementation | Secure coding standards | Engineering Lead |
| Implementation | Pair-review of security-sensitive code (auth, crypto, multi-tenancy guards) | Engineering Lead + Security |
| CI | SAST, dependency scan, secret scan, IaC scan | Platform Team |
| CI | Unit + integration security tests | Service author |
| Pre-merge | Security review for: new endpoints, new data flows, new third-party dependencies, changes to crypto code | Security Architect or designate |
| Pre-deploy | DAST in staging | QA Lead |
| Post-deploy | Continuous monitoring; anomaly alerts | SRE + Security |
| Quarterly | Threat model refresh | Security Architect |
| Annually | External pen-test; bug bounty review; SOC 2 evidence audit | CISO + Compliance |

### 15.2 Security-Sensitive Code Designation

Files and packages designated security-sensitive (auth, token, crypto, RLS policies, mesh authorization policies, IaC modules creating IAM) require two reviewers including one Security-Engineering-trained reviewer (NFR MN-03).

---

### 16. Threat Model — STRIDE per Service

STRIDE applied to each service's principal assets:

### 16.1 Auth Service

| STRIDE | Threat | Mitigation |
| --- | --- | --- |
| S | Attacker impersonates user via stolen password | Argon2id; MFA; HIBP check; anti-enumeration; account lockout |
| T | Auth assertion tampering between Auth and Token | ES256-signed internal assertion; signature verified |
| R | User denies authentication that succeeded | Audit log with hash chain |
| I | Attacker discovers valid emails via login response timing | Constant-time verification path |
| D | Brute-force lockout used to deny legitimate user | Rate limit per IP separate from per-user |
| E | Attacker bypasses MFA via skipped challenge step | Server is source of truth for MFA requirements; never accepted from client |

### 16.2 Token Service

| STRIDE | Threat | Mitigation |
| --- | --- | --- |
| S | Token forging via algorithm confusion (RS256 → HS256) | Library config rejects `alg=HS256` on public-facing tokens; key-type-specific verify (Protocol JT-04) |
| T | Refresh token tampering | Opaque tokens; only HMAC reference stored; rotation+reuse detection |
| R | Repudiation of issued token | Audit; introspection trail |
| I | Token leakage via URL | Tokens forbidden in URLs (Protocol OS-14) |
| D | JWKS endpoint overload | Aggressive caching; CDN-edge serving |
| E | Privilege escalation via scope manipulation | Scope minimisation; scope ⊂ allowed_scopes for client (Protocol OS-10) |

### 16.3 SAML Service

| STRIDE | Threat | Mitigation |
| --- | --- | --- |
| S | Forged SAML assertion | Signature validation on full DOM; trust anchors from metadata |
| T | XML Signature Wrapping (XSW) attack | Full-DOM signature verification before extraction (RA-12) |
| R | Replay of valid assertion | AssertionID dedup window (RA-07); NotBefore/NotOnOrAfter |
| I | XXE / XML external entity disclosure | XML parser hardened — entities disabled (RA-13) |
| D | XML bomb (billion-laughs) | Parser entity limits |
| E | Privilege grant via attribute injection | Attribute mapping is explicit per connection; no auto-admin |

### 16.4 SCIM Service

| STRIDE | Threat | Mitigation |
| --- | --- | --- |
| S | Forged SCIM client | OAuth bearer with `qeetify:scim` scope; mTLS optional |
| T | Tampered PATCH payload | TLS in transit; signed bearer |
| R | Denial of provisioning action | Audit log |
| I | Cross-tenant user enumeration via filter queries | Tenant-scoped query; RLS |
| D | Bulk operation overload | Rate limit; quotas (NFR RL-04) |
| E | Cross-tenant write via crafted endpoint | Tenant-scoped middleware; RLS |

### 16.5 RBAC Service

| STRIDE | Threat | Mitigation |
| --- | --- | --- |
| S | Forged permission check from a service | Service token verification |
| T | Permission cache poisoning | Tenant-prefixed cache keys; bound TTL; signed cache events |
| R | Repudiation of permission grant | Audit log of role-assignment changes |
| I | Permission disclosure via timing | Constant-time policy evaluation where exposed |
| D | Permission-check overload | Cache + autoscale; per-tenant rate limit |
| E | Privilege escalation via direct DB write | DB write access restricted to RBAC Service identity |

### 16.6 Other Services

Token, Keys, Session, Webhook, MFA, User, Tenant, Guard, Notification, Billing, Admin BFF — each owns a similar STRIDE table maintained in its repository security doc. The platform-level Security Architecture document maintains the index; the repository docs maintain the detail.

---

### 17. Top 10 Threats & Mitigations (OWASP API Security Top 10 aligned)

| # | Threat | Mitigation |
| --- | --- | --- |
| T-01 | Broken Object-Level Authorization (BOLA) | Tenant-scoped queries with RLS; application-layer assertions; `/permissions/check` API |
| T-02 | Broken Authentication | Argon2id passwords; MFA; passkey-first; PKCE-required; refresh-token rotation; reuse detection |
| T-03 | Broken Object Property-Level Authorization | Sparse fieldsets controlled at API; per-field encryption for restricted fields |
| T-04 | Unrestricted Resource Consumption | Per-tenant rate limits; quotas; pagination caps; query timeout enforcement |
| T-05 | Broken Function-Level Authorization | RBAC; scoped tokens; admin endpoints behind elevated MFA |
| T-06 | Unrestricted Access to Sensitive Business Flows | Bot detection; CAPTCHA; rate limiting; anomaly detection |
| T-07 | Server-Side Request Forgery (SSRF) | Egress allow-list; outbound proxy filter; no user-controlled URLs in fetch |
| T-08 | Security Misconfiguration | IaC scanning; baselines enforced; quarterly config audit |
| T-09 | Improper Inventory Management | Service catalog (Microservices §5); OpenAPI spec required; sunset/deprecation headers |
| T-10 | Unsafe Consumption of APIs | Customer integrations consume Qeet ID via signed-and-versioned endpoints; SDK retries on 5xx only; webhook HMAC verification mandatory |

---

### 18. Incident Response Architecture

### 18.1 Classification

P1 / P2 / P3 / P4 (NFR IR-01). Triggers:

- P1: data breach, tenant isolation breach, complete auth outage, KMS unavailable, signing key compromise.
- P2: partial outage, > 1% error rate, MFA service failure for a region, single-AZ degradation.
- P3: dashboard slow, non-critical dependency degradation.
- P4: capacity warnings, certificate expiry approaching.

### 18.2 Roles in Incident

- **Incident Commander** — assigned within 10 min on P1/P2 (NFR IR-03).
- **Communications Lead** — status page updates within 15 min for P1 (NFR IR-04).
- **Technical Lead(s)** — service experts.
- **Scribe** — timeline capture.
- **Security Lead** — for security incidents.
- **Customer Success Lead** — for customer-visible impact.

### 18.3 Tooling

- PagerDuty for paging and rotation.
- Dedicated Slack channel auto-created per incident.
- Public status page (`status.qeetify.com`) — independently hosted, NFR AV-10.
- Internal incident commander runbook in the SRE wiki.

### 18.4 Post-Incident

- Blameless post-mortem within 5 business days for P1/P2 (NFR IR-06).
- Public incident summary on status page within 7 days (NFR IR-07).
- Root cause traceable to design / process / monitoring; corrective actions filed.

### 18.5 Security-Specific Procedures

For security incidents:

- 72-hour GDPR breach notification clock starts on awareness (NFR CN-02).
- Customer DPA-driven notification within 72 h of awareness (Compliance CC-06).
- Coordinated disclosure with affected sub-processors as applicable.
- Forensics preserves audit evidence: chain-of-custody documented.

---

### 19. Compliance Control Mapping

This section maps key Qeet ID Phase 2 design choices to the SOC 2 Common Criteria (Compliance §5.2) and the relevant GDPR Articles. The full mapping table is maintained by the Compliance Officer; selected entries:

| Design / Control | SOC 2 CC | GDPR Article |
| --- | --- | --- |
| Role-based access to production with hardware MFA, just-in-time elevation | CC6.1, CC6.3 | Art. 32 |
| TLS 1.2+ in transit; AES-256 at rest; field-level encryption for PII | CC6.7, CC6.8 | Art. 32 (security of processing) |
| Audit logs with hash chaining and tamper evidence | CC4.1, CC7.1 | Art. 30 (records) |
| Tenant isolation via RLS + application guards (architectural) | CC6.1, CC6.3 | Art. 5 (integrity & confidentiality) |
| Refresh token rotation with reuse detection | CC6.1, CC7.2 | — |
| Multi-AZ redundancy; failover < 60 s | A1.1, A1.2 | — |
| Online schema migrations only | CC8.1 | — |
| DR runbook + quarterly tabletop | A1.3, CC7.4, CC7.5 | — |
| Sub-processor register + DPAs | CC9.1 | Art. 28 |
| Data subject rights APIs (export, erasure) | P5.0, P7.0 | Art. 15–21 |
| 30-day end-to-end erasure | P4.0 | Art. 17 |
| Bug bounty + VDP | CC4.1, CC9.1 | — |
| Annual pen-test | CC4.1 | Art. 32 |
| Vendor risk management | CC9.1 | Art. 28 |
| Customer data residency enforcement | CC6.1 | Art. 5 (storage limitation/locality) |
| Backup encryption with separate key + cross-region | A1.2, A1.3 | Art. 32 |

This mapping is the spine of the SOC 2 evidence collection plan (Compliance §5.3).

---

### 20. Open Decisions Carried From This Document

| # | Question | Owner | Target |
| --- | --- | --- | --- |
| OQ-SEC-01 | SPIFFE/SPIRE adoption — v2.0 vs sooner | Security Architect | v2.0 design |
| OQ-SEC-02 | Egress proxy choice (Cloudflare vs AWS Network Firewall vs PoC custom) | DevOps + Security | Phase 2 close |
| OQ-SEC-03 | Bug bounty platform (HackerOne vs Bugcrowd vs Intigriti) | CISO + Legal | Phase 6 |
| OQ-SEC-04 | DAST tool selection for staging post-deploy | QA Lead + Security | Phase 2 close |
| OQ-SEC-05 | Customer-managed encryption keys (BYOK) for Enterprise tier — v1.5 target | Security + Product | v1.5 planning |

---

### 21. Approvals & Sign-off

| Role | Name | Signature | Date |
| --- | --- | --- | --- |
| Security Architect |  |  |  |
| CISO |  |  |  |
| Solution Architect |  |  |  |
| Compliance Officer |  |  |  |
| CTO |  |  |  |
| DevOps / SRE Lead |  |  |  |
| Backend Engineering Lead |  |  |  |
| Legal Counsel |  |  |  |

---

*This document is version controlled. The Security Architecture must be reviewed when a new threat emerges (CVE in a dependency, post-incident finding, new regulatory expectation), when a new service is added, when a new third-party sub-processor is engaged, and at minimum quarterly. Any deviation from the Zero Trust principles in §3 requires CISO sign-off.*

---

**Qeet ID — Authenticate Everything.** *A Qeet Group Company*
