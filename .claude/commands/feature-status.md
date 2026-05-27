---
description: Look up the implementation status of a feature, citing the authoritative docs.
---

Report on the implementation status of the feature named in `$ARGUMENTS` (e.g. `passkeys`, `device flow`, `SCIM`).

Steps:

1. Search [documents/IMPLEMENTATION-STATUS.md](../../documents/IMPLEMENTATION-STATUS.md), [documents/FEATURE-MATRIX.md](../../documents/FEATURE-MATRIX.md), [documents/PROTOCOL-STATUS.md](../../documents/PROTOCOL-STATUS.md), and [documents/GAP-ANALYSIS.md](../../documents/GAP-ANALYSIS.md) for the feature.
2. Cross-check by grepping `backend/internal/` for related code (use the feature name and obvious aliases — e.g. `passkey` → also try `webauthn`).
3. Output a short report:
   - **Status:** done / partial / not started.
   - **Where it lives:** module path(s), if implemented.
   - **What's missing:** items still on the gap list.
   - **Sources:** which doc lines and which code files you based the conclusion on (link them).
4. If the docs and the code disagree (a feature is in the code but the docs still mark it not-started, or vice versa), call out the discrepancy explicitly. Do not silently trust the docs.

Read-only command. Don't edit anything.
