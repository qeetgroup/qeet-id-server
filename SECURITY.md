# Security Policy

Qeet ID is identity infrastructure. We take security reports seriously and triage them ahead of feature work.

## Supported versions

| Version | Supported |
|---|---|
| `main` (development) | ✅ |
| Released versions | ✅ latest minor only |
| Pre-release / forks | ❌ |

The platform is pre-1.0; until v1.0 ships we support only the `main` branch.

## Reporting a vulnerability

**Please do not open a public GitHub Issue or PR for security vulnerabilities.**

Report privately via one of:

1. **GitHub Security Advisory** (preferred) — [Open a private advisory](https://github.com/qeetgroup/qeet-identity/security/advisories/new). GitHub will notify the maintainers and keep the conversation private.
2. **Email** — `security@qeetid.com` with subject `[SECURITY] <short summary>`. PGP key available on request.

Please include:

- A description of the issue and the impact you've observed
- Reproduction steps (or a proof-of-concept) — minimal is best
- The affected commit SHA or version
- Your name / handle if you'd like credit in the advisory

## Response SLAs

| Severity | Acknowledgement | Initial assessment | Fix target |
|---|---|---|---|
| **Critical** — remote auth bypass, full account takeover, key compromise, data exfil | < 24 hours | < 72 hours | 7 days |
| **High** — privilege escalation, MFA bypass, tenant-isolation break | < 48 hours | < 5 business days | 14 days |
| **Medium** — info disclosure (non-PII), CSRF, persistent XSS in admin | < 5 business days | < 10 business days | 30 days |
| **Low** — best-practice deviations, hardening suggestions | < 10 business days | < 20 business days | next release |

We will keep you informed throughout triage and remediation, and credit you (if you wish) in the released advisory.

## Scope

**In scope:**
- This repository (`qeet-identity`) — backend, frontend, and infrastructure code
- Anything that ships from `main` to production
- Authentication, authorization, session management, token issuance / validation, MFA, passkeys, SAML/OIDC handlers, SCIM, audit logging

**Out of scope:**
- Vulnerabilities requiring physical access to a user's device
- Social engineering of Qeet ID staff or customers
- Denial-of-service via volumetric traffic against production hosts
- Self-XSS, missing security headers without demonstrated impact, automated-scanner output without proof of exploit
- Issues in third-party dependencies that have already been disclosed upstream (please file with the upstream maintainer instead)

## Safe harbor

We will not pursue legal action against researchers who:
- Make a good-faith effort to follow this policy
- Avoid privacy violations, destruction of data, or service degradation
- Do not exploit the issue beyond what is necessary to demonstrate it
- Give us a reasonable time to remediate before any public disclosure (we target 90 days; longer is OK by agreement)

## Public disclosure

Once a fix is released, we publish a security advisory on this repository describing the issue, impact, affected versions, and credit. We aim for coordinated disclosure within 90 days of the initial report.

## Bug bounty

A formal bug bounty program will launch alongside v1.0. Until then, we handle reports through this policy and offer thanks + advisory credit.

## Hardening expectations for self-hosters

If you are deploying Qeet ID yourself, please also:
- Run TLS 1.2+ on every public endpoint
- Rotate the JWT signing key set every 90 days
- Keep dependencies current — `go.mod` and `pnpm-lock.yaml` are version-pinned for reproducibility, not because they should stay stale
- Enable WAF / DDoS protection at the edge (Cloudflare, AWS Shield)
- Review the [GAP-ANALYSIS](./documents/GAP-ANALYSIS.md) before going to production — several v1.0 hardening items are still outstanding

---

Thank you for helping keep Qeet ID and its users safe.
