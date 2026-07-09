# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Pre-1.0 minor versions may include breaking changes — they will be called out explicitly under a **Breaking** subsection.

---

## 1.0.0 (2026-06-22)


### Features

* **deploy:** add deploy/release layer (Compose, Helm, migrate image, AWS KMS, CI→CD) ([3e176c5](https://github.com/qeetgroup/qeet-id/commit/3e176c59a8fca6bbf1bf614a4c97b0bdab5a8dfb))
* **frontend:** adopt @qeetrix/ui across admin, web, and docs ([c32b8b9](https://github.com/qeetgroup/qeet-id/commit/c32b8b9b7d152b1aeb94d8424ac3d7ef9d7667dd))


### Bug Fixes

* **api:** align Postman baseUrl to port 4000 (matches standardized backend port) ([202aa84](https://github.com/qeetgroup/qeet-id/commit/202aa845ad0d527367d32c0e1a454b9cfd2b12f3))
* **deploy:** assemble DB_URL via interpolation; drop distroless-incompatible healthcheck ([94da569](https://github.com/qeetgroup/qeet-id/commit/94da5697a3c1f8f0fc48a3418965d8b2c7c5b9b9))
* **oidc:** derive issuer/discovery scheme from X-Forwarded-Proto ([f03b6dd](https://github.com/qeetgroup/qeet-id/commit/f03b6dd193fd94b1e162e0f8364575385d6937bd))
* **repo:** correct doc drift, dead docs targets, eslint login wiring, image license ([c250c60](https://github.com/qeetgroup/qeet-id/commit/c250c603d4fdf9dc8af5ddb91b6a381992436e4a))


### Refactoring

* **backend:** unify SAML error envelope, bound SMTP, log encode errors ([2fed216](https://github.com/qeetgroup/qeet-id/commit/2fed21639b4318adafb729fda113d5de026f080f))
* rename qeet-identity → qeet-id across module path, URLs, names ([9c438ef](https://github.com/qeetgroup/qeet-id/commit/9c438ef523875ecd5a9ee2692ac67b762d5f3b99))

## [Unreleased]

This section tracked a pre-implementation snapshot (WebAuthn/SAML/SCIM/billing as 501s, HS256, bcrypt) that no longer matches the codebase — all of those shipped as part of or before `1.0.0` below. **[ROADMAP.md](./ROADMAP.md) is the single source of truth for current shipped-vs-planned status**; this file only records what actually landed in each release going forward.
