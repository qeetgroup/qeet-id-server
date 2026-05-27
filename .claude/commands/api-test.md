---
description: Run the Postman/Newman API collection against the local backend (or a folder of it).
---

Run the API test suite.

1. Confirm the backend is up by checking `lsof -nP -iTCP:4000 -sTCP:LISTEN -t`. If nothing is listening on `:4000`, tell the user to start it with `make dev-backend` first — don't try to start it yourself, that's a long-running process.
2. Decide scope from `$ARGUMENTS`:
   - Empty → run everything: `make test-api`.
   - Looks like a folder name (e.g. `Auth`, `Users`, `Tenants`) → `make test-api FOLDER="<arg>"`.
   - Has `--ci` → `make test-api-ci` (produces JUnit + HTML reports in `backend/api/postman/reports/`).
3. Stream the Newman output. If anything fails, summarize: which request, which assertion, the HTTP status returned vs expected. Don't paste the full body unless asked.
4. After the run, if reports were produced, point the user at `backend/api/postman/reports/`.

Do not edit the Postman collection from this command — only run it.
