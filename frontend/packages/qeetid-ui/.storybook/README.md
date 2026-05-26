# Storybook for @qeetid/ui

Scaffold only — install the deps to bring it live:

```bash
pnpm --filter @qeetid/ui add -D \
  storybook \
  @storybook/react-vite \
  @storybook/addon-essentials \
  @storybook/addon-themes \
  @storybook/addon-a11y \
  @storybook/test
```

Then:

```bash
pnpm --filter @qeetid/ui storybook         # dev server on :6006
pnpm --filter @qeetid/ui build-storybook   # static build to storybook-static/
```

## Adding stories

Copy `../src/stories/button.stories.tsx` and adapt it. One `.stories.tsx`
per primitive; group with `title: "Primitives/<Name>"` so the sidebar
matches the export name.

## Visual regression (later)

When we wire Chromatic (IMPROVEMENTS §13.7) the `build-storybook` step
runs in CI and the static bundle uploads via `npx chromatic`.
