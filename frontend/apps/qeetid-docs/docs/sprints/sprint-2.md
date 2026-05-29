# Sprint 2 — Identity & Access E2E + 🚀 Explainable Authorization (D2)

| | |
|---|---|
| **Window** | 2026-06-15 → 2026-06-26 (2 weeks) |
| **Theme** | Verify the RBAC core, then make authorization decisions *explainable* and *group-aware* |
| **Depends on** | Sprint 1 (use Test Mode for setup) |
| **Closes** | New differentiator **D2**; roadmap **#15** (group-level RBAC) |
| **Status** | ⬜ Not started |

**Why:** RBAC is the backbone of every B2B deal. First prove it's correct; then solve the universal pain — *"why was this user allowed/denied?"* — which no platform answers well.

---

## Part A — 🧪 Test existing features (E2E)

### 🧪 SCENARIO 2.1 — Users CRUD + soft delete
- **Steps:** create user (`POST /v1/users`), get, list (cursor pagination), patch (display_name/status), delete; list again.
- **Expect:** create `201`; list paginates; patch reflects; delete is **soft** (row retained, excluded from default list).
- **Pass:** [ ] cursor pagination works [ ] soft delete hides user [ ] global email uniqueness enforced (duplicate email → `409`).

### 🧪 SCENARIO 2.2 — Tenants CRUD + isolation
- **Steps:** create two tenants T1/T2; create a user in each; list users of T1.
- **Expect:** T1's list never shows T2's users.
- **Pass:** [ ] cross-tenant isolation holds [ ] soft-delete tenant works.

### 🧪 SCENARIO 2.3 — Groups (nested)
- **Steps:** create group "Engineering"; create child "Backend" with `parent_id`; list; patch; delete child.
- **Expect:** hierarchy reflected; tenant-scoped.
- **Pass:** [ ] nesting via parent_id [ ] delete child doesn't orphan parent.

### 🧪 SCENARIO 2.4 — Invites end-to-end
- **Steps:** `POST /v1/invites` for bob@test.dev; read invite token from **Dev Inbox**; `POST /v1/invites/accept`; confirm bob is a member; revoke a second pending invite.
- **Expect:** accept creates user + session + membership; revoked/expired invites can't be accepted.
- **Pass:** [ ] accept works [ ] reused/expired/revoked invite rejected.

### 🧪 SCENARIO 2.5 — RBAC: roles, permissions, assignment, effective perms
- **Steps:**
  1. `GET /v1/permissions` (platform permission list).
  2. `POST /v1/tenants/{t}/roles` create role "editor".
  3. Grant a permission: `POST /v1/roles/{role}/permissions/{perm}`.
  4. Assign role to user: `POST /v1/users/{u}/tenants/{t}/roles/{role}`.
  5. `GET /v1/users/{u}/tenants/{t}/permissions` (effective perms).
- **Expect:** effective perms reflect the granted permission via the role.
- **Pass:** [ ] grant/assign work [ ] effective perms computed correctly [ ] revoke removes it.

### 🧪 SCENARIO 2.6 — The `check` API
- **Steps:** `GET /v1/check?user=&tenant=&permission=` for a granted and a non-granted permission.
- **Expect:** granted → allow; non-granted → deny.
- **Pass:** [ ] allow/deny correct [ ] unknown permission → deny (fail-closed).

**Part A exit:** scenarios green + in Newman (`FOLDER=RBAC`, `FOLDER=Users`).

---

## Part B — 🚀 D2: Explainable Authorization (+ group-level RBAC)

### The problem nobody solves well
In Auth0, Clerk, WorkOS, Keycloak — when a `check` returns **deny**, you get a boolean. No platform tells you **why**: which role granted it, which permission was missing, which policy denied, whether a group membership mattered. Debugging "user can't access X" is a support-ticket black hole. ReBAC engines (OpenFGA/Keto) have `expand`, but it's low-level and not exposed as a human-readable decision trace in mainstream CIAM.

### Our solution
1. **`GET /v1/authz/explain`** — same inputs as `check`, but returns a **decision trace**:
   ```jsonc
   {
     "decision": "deny",
     "permission": "billing:write",
     "trace": [
       {"step":"role:editor","grants":["billing:read"],"matched":false},
       {"step":"group:Finance → role:billing-admin","grants":["billing:write"],"matched":false,"reason":"user not in group Finance"},
       {"step":"policy:mfa-required","effect":"deny","reason":"permission requires MFA; session amr lacks 'mfa'"}
     ],
     "to_allow": ["add user to group 'Finance'", "or grant 'billing:write' to a role the user holds", "and satisfy policy 'mfa-required'"]
   }
   ```
2. **Group-level RBAC** (roadmap #15): a user's effective permissions now include permissions from roles attached to their **groups** (transitive through nested groups). This is needed for the trace to be meaningful and closes a real gap.
3. **Admin "Why?" inspector**: paste user + permission, see the trace visualized as a tree with the exact missing link highlighted and a one-click "fix" suggestion.

### Design / changes

**Backend**
- `internal/rbac/`: extend effective-permission resolution to walk **group → role → permission** (recursive CTE over nested groups), unioned with direct user→role grants. Add `Explain(ctx, user, tenant, permission) Trace`.
- New endpoint `GET /v1/authz/explain` (auth-scoped; requires permission to inspect within the tenant).
- Migration `0027_group_roles.up.sql`: `rbac.group_roles (group_id, role_id, tenant_id)`.
- Keep `check` fast (existing path); `explain` is the verbose sibling.

**Frontend (admin)**
- Extend **Access → Roles/Permissions** with an **"Authorization Inspector"** tab: inputs (user, permission), renders the trace tree, highlights the failing node, shows `to_allow` remediation. Add a "group → roles" assignment UI on the group detail page.

**Docs**
- `content/docs/rbac.mdx`: add "Explaining decisions" section. New `content/docs/authorization/explain.mdx`.

### Acceptance criteria
- [ ] `explain` returns a correct, ordered trace for allow and deny.
- [ ] Group-attached roles contribute to effective permissions (incl. nested groups).
- [ ] `to_allow` suggestions are actionable and correct for the deny case.
- [ ] Admin inspector renders the trace and highlights the missing link.
- [ ] `check` and `explain` always agree on the decision.

### 🧪 How you test D2
1. Give a permission only via a group role; confirm `check` now allows (group RBAC working).
2. Remove the user from the group; `explain` shows the group step as `matched:false` with the right reason and a "add to group" suggestion.
3. Diff `check` vs `explain.decision` across 10 random cases — must always match.

---

## Definition of Done
- [ ] Part A: scenarios pass + in Newman.
- [ ] Part B: group_roles migration, recursive resolution, `explain` endpoint, tests green.
- [ ] Admin Authorization Inspector + group-roles UI live.
- [ ] `rbac.mdx` updated + `authorization/explain.mdx` added.
- [ ] Roadmap: #15 checked; D2 noted; status ✅; changelog row filled.

## Changelog
| Date | Change |
|---|---|
| 2026-05-29 | Sprint defined. |
