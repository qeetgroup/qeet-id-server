# Git workflow rules

## Branches

- `main` — protected. Direct pushes forbidden; everything goes via PR.
- `develop` — current integration branch.
- Feature branches: `<initials>/<short-topic>` or `feature/<topic>`. Keep them short-lived.

## Commits

- Imperative subject: "Add MFA enrolment endpoint", not "Added" or "Adding".
- Subject ≤ 70 characters. Body wrapped at 72.
- Body explains **why**, not what. The diff shows what.
- One logical change per commit. If you can split it into reviewable pieces, do.

## What to keep out

- ❌ `.env` files, anything matching `*.pem`, `*.key`, `*.p12`, `*.pfx`. Already in [.gitignore](../../.gitignore) — verify before staging.
- ❌ `node_modules/`, build artifacts (`bin/`, `dist/`, `.next/`, `.turbo/`). Already ignored.
- ❌ Generated files unless the project policy says check them in (it doesn't, currently).
- ❌ Editor cruft (`.idea/`, `.vscode/*` except the two allowed files).
- ❌ Anything under `graphify-out/` (now gitignored — regenerated on demand).

When in doubt, stage by file name with `git add path/to/file` rather than `git add -A`.

## Pull requests

- Title under 70 chars, imperative ("Add passkey enrolment").
- Body has **Summary** (1–3 bullets) and **Test plan** (checklist of what was verified). The PR template at [.github/PULL_REQUEST_TEMPLATE.md](../../.github/PULL_REQUEST_TEMPLATE.md) is the template.
- Link the issue or upstream requirement.
- Security-relevant work: prefix title with `[security]` and mention in body which protocol-status entries are affected.
- A behaviour change PR includes a regression test (see [testing.md](./testing.md)).

## Reviews

- Use the [qeetid-reviewer agent](../agents/qeetid-reviewer.md) before opening the PR — catches the project-specific stuff (audit, outbox, tenancy, migration safety) that generic linters miss.
- Block on: missing tests for behaviour change, missing OpenAPI/Postman updates, edits to a merged migration, missing audit/outbox calls, comments restating code.

## Don't

- ❌ Force-push to `main`. Force-push to your own branch is fine before review.
- ❌ Amend a commit someone has already reviewed — stack a new commit instead.
- ❌ `git reset --hard` someone else's branch. Use `git revert` for shared history.
- ❌ Run `git config` to change repo-level config. Personal config goes in your global `~/.gitconfig`.
- ❌ Skip `pre-commit` hooks (`--no-verify`) or signing (`--no-gpg-sign`) unless explicitly told to. If a hook fails, fix the cause.

## Useful commands

```bash
git status
git diff                            # unstaged
git diff --staged                   # staged
git diff main...HEAD                # full branch diff vs main
git log --oneline -20
git log --follow -- path/to/file    # history of one file across renames
git ls-files | xargs wc -l          # repo size by line count
```
