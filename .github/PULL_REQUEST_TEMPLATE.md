<!--
  Thanks for the PR! Please fill in the sections below.
  Delete sections that don't apply.
-->

## Summary

<!-- Describe what this PR changes and WHY. Link the issue if there is one. -->

Fixes #<issue-number>

## Type of change

- [ ] feat — new feature
- [ ] fix — bug fix
- [ ] refactor — code restructure with no behaviour change
- [ ] docs — documentation only
- [ ] chore — tooling / dependencies
- [ ] test — adding or fixing tests
- [ ] perf — performance improvement
- [ ] BREAKING CHANGE — incompatible API change

## Affected areas

- [ ] Backend — `backend/internal/<module>`
- [ ] Frontend — admin dashboard
- [ ] Frontend — marketing site
- [ ] Frontend — docs site
- [ ] Shared UI library (`@qeetid/ui`)
- [ ] Database migrations
- [ ] CI / build / tooling
- [ ] Documentation only

## Testing

<!-- How did you verify this works? Include commands and what you observed. -->

```bash
# e.g.
cd backend && make test
cd frontend && pnpm typecheck && pnpm lint
```

## Screenshots / recordings (frontend changes only)

<!-- Drag-and-drop screenshots or short clips here. -->

## Documentation updates

- [ ] Updated [documents/IMPLEMENTATION-STATUS.md](../documents/IMPLEMENTATION-STATUS.md) / [documents/FEATURE-MATRIX.md](../documents/FEATURE-MATRIX.md) if a feature status changed
- [ ] Updated [documents/PROTOCOL-STATUS.md](../documents/PROTOCOL-STATUS.md) if a protocol implementation changed
- [ ] Updated [backend/api/openapi.yaml](../backend/api/openapi.yaml) for new/changed endpoints
- [ ] Updated [CHANGELOG.md](../CHANGELOG.md) under "Unreleased"
- [ ] Updated end-user docs in [frontend/apps/qeetid-docs/](../frontend/apps/qeetid-docs/) if user-facing

## Checklist

- [ ] My code follows the project's [contribution guidelines](../CONTRIBUTING.md)
- [ ] I have run `make test` and `make lint` locally — both pass
- [ ] I have added tests covering my change (or explained why none are needed)
- [ ] I have updated documentation where applicable
- [ ] No secrets, credentials, or PII are committed
- [ ] If this is a breaking change, I have explicitly called it out above
