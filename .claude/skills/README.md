# .claude/skills/ — project-local skills

Skills here extend the global skills (graphify, verify, simplify, …) with repo-specific procedures. A skill is heavier than a slash command:

- A **command** in [../commands/](../commands/) is one prompt that runs once.
- A **skill** here is a multi-phase procedure, possibly with helper templates, that Claude auto-triggers when its description matches the user's intent — or you can invoke it explicitly.

## When to write a new skill (vs. a command)

Use a skill if **any** of these are true:

- The workflow has three or more phases that each need judgment.
- It benefits from auto-triggering on natural-language phrases ("add an endpoint", "ready to ship"), not just an explicit `/name`.
- It carries reusable assets — templates, checklists, scripts — alongside the prompt.

Otherwise write a command.

## Index

| Skill | Triggers on | What it does |
|---|---|---|
| [add-endpoint](./add-endpoint/SKILL.md) | "add endpoint", "new route", "new handler", new HTTP surface | End-to-end new endpoint: handler → OpenAPI → Postman → test → audit/outbox → docs. |
| [release-readiness](./release-readiness/SKILL.md) | "release check", "ready to ship", "v1.0 readiness", "cut a release" | Comprehensive pre-release audit against [documents/GAP-ANALYSIS.md](../../documents/GAP-ANALYSIS.md) + protocol status. |
| [gap-fill](./gap-fill/SKILL.md) | "next gap", "pick from gap analysis", "what should I work on" | Picks the next-best item off `GAP-ANALYSIS.md`, scopes it, and starts an implementation plan. |

## SKILL.md format

```markdown
---
name: kebab-case-name
description: One line. Used to auto-trigger; be specific about WHEN this skill applies.
---

# Skill body

Phase 1: …
Phase 2: …
```

Keep the description tight — Claude matches user intent against it, so vague descriptions cause false triggers.

Skills can reference [../rules/](../rules/) for the binding policy instead of duplicating it.
