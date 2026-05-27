# Frontend rules — `frontend/`

pnpm 9 + Turborepo workspace. React 19. Three apps + a shared UI package.

## Apps

| App | Path | Stack | Port |
|---|---|---|---|
| Admin dashboard | [frontend/apps/qeetid-admin](../../frontend/apps/qeetid-admin/) | Vite + TanStack Router (file-based at `src/routes/`) | `:3002` |
| Marketing site | [frontend/apps/qeetid-web](../../frontend/apps/qeetid-web/) | Next.js App Router (`src/app/`) | `:3001` |
| Docs | [frontend/apps/qeetid-docs](../../frontend/apps/qeetid-docs/) | Next.js + fumadocs, MDX under `content/docs/` | `:3003` |

## Shared package

- [frontend/packages/qeetid-ui](../../frontend/packages/qeetid-ui/) — shadcn-style primitives. Anything used in **two or more apps** moves here and exports from `src/index.ts`.
- Single-app components stay in the app — don't pre-promote.
- The eslint + tsconfig packages ([packages/qeetid-eslint](../../frontend/packages/qeetid-eslint/), [packages/qeetid-tsconfig](../../frontend/packages/qeetid-tsconfig/)) are the shared config. Don't duplicate config files in apps.

## Routing

- **qeetid-admin** — TanStack Router. New route = new file under `src/routes/`. After adding, regenerate the route tree (`pnpm dev:admin` does it on save).
- **qeetid-web / qeetid-docs** — Next.js App Router. Folder = route; `page.tsx` is the entry; `layout.tsx` wraps children.

## Admin navigation

- New top-level admin route needs an entry in [frontend/apps/qeetid-admin/src/config/navigation.tsx](../../frontend/apps/qeetid-admin/src/config/navigation.tsx). A route without a nav entry is invisible.

## Styling

- Tailwind. `prettier-plugin-tailwindcss` (already configured) sorts classes — run `make format` before committing.
- Don't write raw CSS files for component-specific styling. Use Tailwind utilities + the UI primitives.

## API calls

- Admin app calls the backend at `:4000` (dev) or whatever `VITE_API_BASE` points to. Don't hardcode `http://localhost:4000` in components — read from the config helper / env.
- Auth is cookie-based by default. Don't store tokens in `localStorage`.

## Type checks and lint

- `make typecheck` runs `tsc --noEmit` across the workspace via Turbo.
- `make lint` runs eslint via Turbo.
- Both must pass before merge.

## Comments

Same rule as backend: default to none. JSDoc is overkill for components that are small and named clearly.

## Don't

- Don't add a new external UI library when shadcn primitives already cover the need.
- Don't add a Redux/Zustand/etc. store for state that lives in three components — prop drilling or context is fine at this scale.
- Don't add a server action that proxies a backend call when the client can hit the backend directly — extra hop, extra surface.
