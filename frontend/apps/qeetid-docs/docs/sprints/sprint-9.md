# Sprint 9 — Import-path E2E + 🚀 Zero-Downtime Universal Importer (D9)

| | |
|---|---|
| **Window** | 2026-09-21 → 2026-10-02 (2 weeks) |
| **Theme** | Verify password login under foreign hashes, then kill the #1 reason teams stay locked into Auth0/Cognito/etc. — migration pain |
| **Depends on** | Sprints 1–2 (users/auth verified), roadmap **#5 (Argon2id + multi-hash verify)** is the foundation |
| **Closes** | New differentiator **D9**; builds on roadmap **#5** |
| **Status** | ⬜ Not started |

**Why:** The biggest moat competitors have isn't features — it's **switching cost**. Migrating off Auth0/Cognito/Firebase usually means either forcing every user to reset their password (churn-inducing) or running a fragile lazy-migration bridge. If Qeet ID can import users **with their existing password hashes intact** and zero forced resets, adoption friction collapses.

---

## Part A — 🧪 Test existing features (E2E)

### 🧪 SCENARIO 9.1 — Password login still rock-solid (regression)
- **Steps:** re-run Sprint 1.2/1.3/1.4 (login, rotation, theft detection) to confirm nothing regressed before we touch the hashing layer.
- **Pass:** [ ] all green.

### 🧪 SCENARIO 9.2 — Multi-hash verification + lazy rehash (roadmap #5)
- **Pre:** seed a user whose stored credential is a **bcrypt** hash and another with a **PBKDF2/scrypt/argon2** hash (simulating imports).
- **Steps:** log in as each; check the stored hash after a successful login.
- **Expect:** login succeeds verifying the original algorithm; on success the platform **transparently rehashes to Argon2id** (lazy upgrade) without the user noticing.
- **Pass:** [ ] each legacy hash verifies [ ] hash upgraded to Argon2id after first login [ ] wrong password still fails.

### 🧪 SCENARIO 9.3 — Bulk user creation (existing `users/import`)
- **Steps:** use the admin CSV import (or `POST /v1/users` in a loop) to load 1k users; verify pagination + uniqueness.
- **Pass:** [ ] bulk load completes [ ] duplicates rejected [ ] list/search scale.

**Part A exit:** green + in Newman (`FOLDER=Auth`, `FOLDER=Users`).

---

## Part B — 🚀 D9: Zero-Downtime Universal Importer

### The problem nobody solves well
Every vendor's "import" assumes either plaintext passwords (impossible) or their own export format, and most force a password reset because they can't verify a foreign hash. Auth0→X, Cognito→X, Firebase→X migrations are notorious multi-month projects. There's no clean, **vendor-aware, hash-preserving** importer with a safe dry-run.

### Our solution
1. **Vendor-aware adapters**: importers that understand the export formats of **Auth0, AWS Cognito, Firebase Auth, Clerk, Keycloak, and generic CSV/JSON** — mapping users, emails, verified flags, MFA enrollments where exportable, orgs/tenants, roles, and identities.
2. **Hash-preserving credentials**: a pluggable **multi-algorithm verifier** (bcrypt, scrypt, PBKDF2-HMAC-SHA1/256, Argon2i/id, Firebase's modified-scrypt, Django-style) so imported users log in with their **existing password**, then get **lazily rehashed** to Argon2id on first successful login (built on #5). **Zero forced resets.**
3. **Dry-run + reconciliation**: `POST /v1/import/dryrun` validates the file, reports counts, conflicts (email collisions), unsupported hash schemes, and a diff — **before** writing anything. `POST /v1/import/commit` runs it (idempotent, resumable, chunked) and produces a **reconciliation report** (imported / skipped / errored with reasons).
4. **Identity & org mapping**: bring over social identities (so users keep "Sign in with Google") and map source tenants/orgs/roles to Qeet ID's model.
5. **Cutover playbook**: optional **co-existence mode** — proxy-verify against the old provider for any user not yet migrated (catch-all), so you can flip traffic gradually with zero downtime, then disable once drained.

### Design / changes
**Backend**
- New module `internal/importer/`: adapter interface + per-vendor adapters; dry-run/commit endpoints; job runner (chunked, resumable) reusing the outbox for progress events.
- `internal/platform/password/`: extend the verifier to a **scheme registry** (`$bcrypt$…`, `$argon2id$…`, `firebase-scrypt`, `pbkdf2_sha256$…`, etc.) with lazy rehash on login (this is #5, generalized).
- Migration `0034_import_jobs.up.sql`: `import.jobs`, `import.records`, credential `scheme` column on stored credentials.
- Co-existence: optional `LegacyProvider` verifier interface (HTTP call to old IdP) used only as fallback for un-migrated users.

**Frontend (admin)**
- **Migrate** wizard: pick source vendor → upload export / connect API → **dry-run report** → commit → live progress → reconciliation report + downloadable error CSV.

**Docs**
- `content/docs/migrate/index.mdx` + per-vendor guides (`auth0.mdx`, `cognito.mdx`, `firebase.mdx`, `clerk.mdx`, `keycloak.mdx`, `csv.mdx`). These double as **marketing** ("switch in a weekend").

### Acceptance criteria
- [ ] A user imported from each supported vendor can log in with their **original** password (no reset).
- [ ] On first login the credential is upgraded to Argon2id, verified by inspecting the stored scheme.
- [ ] Dry-run reports conflicts/unsupported hashes and writes nothing.
- [ ] Commit is idempotent and resumable; re-running doesn't duplicate.
- [ ] Social identities survive (imported users can use the linked social login).
- [ ] (Optional) Co-existence fallback verifies an un-migrated user against the legacy provider once, then imports them.

### 🧪 How you test D9
1. Export a small fixture set in Auth0 format (or use provided sample fixtures); dry-run → review report (intentionally include 1 email collision + 1 unsupported hash and confirm they're flagged).
2. Commit; log in as an imported bcrypt user with the original password → success; check stored scheme flipped to Argon2id.
3. Repeat with a Firebase-scrypt fixture and a Cognito fixture.
4. Re-run commit on the same file → no duplicates (idempotent).

---

## Definition of Done
- [ ] Part A: scenarios pass + in Newman.
- [ ] Part B: importer module + vendor adapters + multi-scheme verifier (#5) + dry-run/commit + reconciliation, migrations, tests green.
- [ ] Admin Migrate wizard live with dry-run + progress + error export.
- [ ] `migrate/*` docs published (incl. per-vendor guides).
- [ ] Roadmap: #5 checked; D9 noted; status ✅; changelog filled.

## Changelog
| Date | Change |
|---|---|
| 2026-05-29 | Sprint defined. |
