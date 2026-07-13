# Frontend Development

Qeet ID has three frontend apps in Bun workspaces. All are TypeScript + React 19.

## Apps

| App | Package | Framework | Port | Purpose |
|---|---|---|---|---|
| Admin console | `@qeetid/admin` | Vite + TanStack Router | 3002 | Tenant management, user admin, developer tools |
| Hosted login | `@qeetid/login` | Next.js | 3004 | Login, signup, MFA, recovery, consent flows |
| Website | `@qeetid/web` | Next.js | 3001 | Marketing pages, changelog, customers |

## Setup

```bash
make install       # installs all workspace deps (bun install at root)
```

## Starting apps

```bash
make dev              # all three apps + backend simultaneously
bun run dev:console   # admin console only (:3002)
bun run dev:login     # login app only (:3004)
bun run dev:website   # website only (:3001)
```

## Admin console (`@qeetid/admin`)

**Directory:** `apps/console/`  
**Routing:** TanStack Router with **file-based routing**  
**API client:** `apps/console/src/lib/` — 30+ modules, one per domain (e.g., `users.ts`, `audit.ts`, `agents.ts`)

### File-based routing

Routes are defined by file structure under `apps/console/src/routes/`:

```
src/routes/
  index.tsx              → /
  users/
    index.tsx            → /users
    $userId.tsx          → /users/:userId
  developer/
    api-keys/
      index.tsx          → /developer/api-keys
      new.tsx            → /developer/api-keys/new
```

**Important:** TanStack Router uses `routeTree.gen.ts` (auto-generated, do not edit). When adding a new route file, regenerate it:

```bash
bun --filter @qeetid/admin exec vite dev
# Wait for: "Generated routeTree.gen.ts", then Ctrl+C
```

There is no `tsr` CLI — the tree regenerates automatically when `vite dev` starts.

### Adding an admin page

1. Create a route file: `apps/console/src/routes/my-feature/index.tsx`
2. Start Vite dev server briefly to regenerate `routeTree.gen.ts`
3. Add navigation entry in `apps/console/src/config/navigation.tsx` if it should appear in the sidebar
4. Add API client function in `apps/console/src/lib/my-feature.ts`

### API client pattern

API client modules in `src/lib/` follow this pattern:

```typescript
// src/lib/widgets.ts
const API_BASE = import.meta.env.VITE_API_URL;

export async function listWidgets(): Promise<Widget[]> {
    const res = await fetch(`${API_BASE}/v1/widgets`, {
        headers: { Authorization: `Bearer ${getToken()}` }
    });
    if (!res.ok) throw await parseError(res);
    return res.json().then(d => d.items);
}
```

## Login app (`@qeetid/login`)

**Directory:** `apps/login/`  
**Routing:** Next.js App Router  
**i18n:** `apps/login/src/i18n/` (JSON locale files; currently English only)

### Flow pages

Each authentication flow has its own directory:

```
src/app/
  (login)/page.tsx         → /  (login form)
  signup/page.tsx          → /signup
  forgot-password/page.tsx → /forgot-password
  reset/page.tsx           → /reset
  consent/page.tsx         → /consent (OAuth consent)
  device/page.tsx          → /device (OAuth device flow)
  logged-out/page.tsx      → /logged-out
```

Each page typically has a `*-form.tsx` file with the actual form component.

### Adding a new login flow step

1. Create a new directory + `page.tsx` in `apps/login/src/app/`
2. Add i18n strings in `apps/login/src/i18n/en/*.json`
3. Add social provider buttons (if relevant) by updating `src/components/social-providers.tsx`

### i18n

Add new translation keys in the appropriate JSON file under `src/i18n/en/`:

```json
// src/i18n/en/login.json
{
  "submit": "Sign in",
  "email_placeholder": "name@company.com",
  "my_new_key": "My new text"
}
```

## Website (`@qeetid/web`)

**Directory:** `apps/website/`  
**Routing:** Next.js App Router  
**Note:** This Next.js version has breaking changes from training data. Read `apps/website/CLAUDE.md` (which points to `@AGENTS.md`) before writing any Next.js code here, and check `node_modules/next/dist/docs/` for accurate API references.

Marketing components live in `src/components/marketing/`:
- `header.tsx`, `footer.tsx` — layout
- `hero.tsx`, `cta.tsx` — homepage sections
- `pricing.tsx`, `faq.tsx` — product sections
- `customers/` — customer logos and quotes

## Design system (`@qeetrix/*`)

All three apps use the `@qeetrix/ui` design system as a live dependency. **Do not duplicate components** from `@qeetrix/ui` in the app codebases.

Check available components:
```bash
ls ../../qeetrix/packages/ui/src/components/
```

To use a Qeetrix component:
```tsx
import { Button, Input, Badge } from '@qeetrix/ui';
```

The design system is in `../../qeetrix/` (a sibling repo). It's referenced via the Bun workspace protocol. If you need a component that doesn't exist, add it to Qeetrix first (see Qeetrix's own CLAUDE.md for guidance).

## Shared config packages

- `packages/qeetid-tsconfig/` — shared `tsconfig.json` base

This is a workspace package referenced as `"@qeet-id/tsconfig": "workspace:*"` in each app's `package.json`. Linting and formatting are handled by Biome from the repo root (`biome.json`).

## Building for production

```bash
make build            # builds Go binary + all frontend apps
bun run build         # frontend apps only (Bun runs all three in parallel via `bun run --filter`)
bun run --filter @qeetid/admin build   # one app only
```

## TypeScript and linting

```bash
make typecheck        # tsc --noEmit across all apps
make lint             # Biome lint across all apps + Go golangci-lint
```

Fix TypeScript errors before opening a PR — the CI pipeline runs `typecheck` and will fail on errors.
