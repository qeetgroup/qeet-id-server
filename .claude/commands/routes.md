---
description: List every HTTP route mounted by the backend, grouped by module.
---

Print the full backend route table.

1. Read `backend/internal/http/router.go` to see how modules are mounted (the `r.Mount(...)` / `r.Route(...)` calls and the prefix each module gets).
2. For every module mounted there, grep the module's `http.go` (or `<module>.go` for collapsed modules) for `r.Get(`, `r.Post(`, `r.Patch(`, `r.Put(`, `r.Delete(` and collect the verb + path + handler name.
3. Print a markdown table grouped by module, with columns: `Method | Full path (including mount prefix) | Handler`. Sort each group by path.
4. If `$ARGUMENTS` is non-empty, filter to routes whose path or handler contains that substring (case-insensitive).

Do not modify any files. Pure reporting.
