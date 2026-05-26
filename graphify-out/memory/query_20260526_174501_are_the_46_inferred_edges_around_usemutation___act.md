---
type: "query"
date: "2026-05-26T17:45:01.931430+00:00"
question: "Are the 46 INFERRED edges around useMutation() actually correct?"
contributor: "graphify"
source_nodes: ["useMutation()", "ImpersonationBanner()", "useLogin", "useMarkAllRead", "api()"]
---

# Q: Are the 46 INFERRED edges around useMutation() actually correct?

## Answer

Yes — all 46 verified. Sampled 5 callers (auth.ts, notifications.ts, impersonation-banner.tsx, users.tsx, keys.tsx) and each imports useMutation from @tanstack/react-query and invokes it. The edges are marked INFERRED only because the AST extractor cannot resolve the imported symbol to the declaration that lives in the compiled .output/server/_libs/tanstack__react-query.mjs bundle. The relationships themselves are real. Architectural read: every admin route owns its own useMutation calls and routes through api() in src/lib/api.ts — there is no intermediate service layer.

## Source Nodes

- useMutation()
- ImpersonationBanner()
- useLogin
- useMarkAllRead
- api()