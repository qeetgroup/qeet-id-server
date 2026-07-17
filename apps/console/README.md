# Qeet ID Console

The operator control plane for Qeet ID. It serves identity administrators, security teams, and platform engineers managing tenants, users, authentication, authorization, audit, compliance, and developer integrations.

## Product direction

The console uses an institutional enterprise language rather than stock shadcn styling:

- high information density with clear operational hierarchy;
- cool neutral surfaces with Qeet orange reserved for primary intent;
- a persistent dark control rail in both themes;
- data-first panels, metric rails, and dividers instead of grids of identical cards;
- visible loading, empty, error, focus, hover, active, and reduced-motion states;
- WCAG 2.2 AA contrast targets and semantic status colours;
- desktop operator efficiency without sacrificing touch and mobile access.

The shared `@qeetrix/ui` package remains the component foundation. Console-specific product character lives in `src/styles.css`; do not fork Qeetrix primitives or add local shadcn copies.

## Stack

- TanStack Start and TanStack Router file-based routes
- React 19 with React Compiler
- TanStack Query for server state
- Tailwind CSS 4 through the Vite plugin
- Qeetrix UI for accessible primitives and design tokens
- Recharts through Qeetrix chart wrappers
- i18next for localization
- Vitest for unit tests
- Bun workspaces from the repository root

## Architecture

```text
src/
├── components/                 Shared cross-domain console composition
│   ├── data-table/             Search, filters, density, sorting, bulk actions
│   ├── page-header.tsx         Standard route heading and action boundary
│   └── ...
├── config/
│   ├── navigation.tsx          Operator information architecture and labels
│   └── navigation-state.ts     Pure active-route matching
├── features/
│   ├── dashboard/
│   │   ├── components/         Shell, metrics, panels, charts, activity, notices
│   │   ├── dashboard-model.ts  Pure dashboard transformations and formatting
│   │   └── use-dashboard-activity.ts
│   ├── authorization/          Complex policy and graph experiences
│   ├── compliance/             Shared evidence surfaces
│   └── auth/                   Console authentication screens
├── integrations/               Query provider and development integrations
├── i18n/                       Namespaced locale resources
├── lib/                        Typed endpoint clients, query hooks, auth, exports
├── routes/                     Thin file-route boundaries and domain screens
├── router.tsx                  Router and query integration
└── styles.css                  Console semantic theme and product-level patterns
```

### Boundaries

1. **Routes own URL concerns.** Route files validate search parameters, declare route boundaries, and compose feature modules. Large reusable experiences do not live in a route file.
2. **Features own product composition.** The dashboard shell and command-center modules live under `features/dashboard`; authorization graph tooling stays under `features/authorization`.
3. **`lib` owns remote contracts.** API calls, query keys, token handling, and reusable domain hooks stay out of presentational components.
4. **`config` owns information architecture.** Sidebar, breadcrumbs, and command-palette navigation derive from one navigation model.
5. **Qeetrix owns primitives.** Buttons, fields, dialogs, sheets, tables, charts, and accessibility behavior come from `@qeetrix/ui`.
6. **Console CSS owns application identity.** Semantic token overrides and named product patterns are centralized in `styles.css`; raw colours should not be introduced in route components.

## Enterprise shell

`routes/_app.tsx` is the authenticated shell boundary. It composes:

- `AppSidebar` for workspace context and domain navigation;
- `ConsoleHeader` for breadcrumbs, command search, notifications, preferences, and account access;
- one semantic `main` content landmark with a skip link;
- command-palette and shortcut dialogs at shell scope.

The sidebar account menu was intentionally removed. Account actions live in one predictable location in the top bar. The navigation rail uses real route state rather than a static active flag and keeps parent branches active on detail routes.

## Dashboard command center

The overview route is deliberately thin. `features/dashboard/components/dashboard-overview.tsx` coordinates data and composes dedicated modules:

- `dashboard-metrics.tsx` — primary metric rail and secondary directory indicators;
- `dashboard-charts.tsx` — authentication, method-mix, MFA, and failed-login telemetry;
- `dashboard-activity.tsx` — recent audit events and operator actions;
- `dashboard-panel.tsx` — a shared, accessible data-surface boundary;
- `dashboard-model.ts` — testable formatting and transformation logic;
- `use-dashboard-activity.ts` — the independently refreshed audit stream.

The analytics overview remains one backend round trip. Recent activity refreshes independently every 15 seconds. Charts include text labels and hidden table alternatives so colour and pointer interaction are not the only ways to read data.

## Styling rules

- Use semantic tokens such as `bg-card`, `text-muted-foreground`, `text-success`, and `border-border`.
- Reserve `primary` for the current navigation indicator and primary actions.
- Use red, amber, green, and blue only for destructive, warning, success, and informational meaning.
- Use `enterprise-panel`, `dashboard-metric-rail`, and the other named application patterns before inventing one-off surface classes.
- Keep numbers tabular and use the bundled Fira Code only for identifiers and compact telemetry.
- Motion must explain state or hierarchy, use transform/opacity where possible, and honor `prefers-reduced-motion`.
- Do not restore a wall of equal elevated cards. Prefer rails, grouped rows, dividers, or asymmetric data panels.

## Responsive behavior

- Mobile: one-column content, 44-pixel shell targets, off-canvas navigation, and horizontally safe tables.
- Tablet: two-column metric rails and selectively stacked data panels.
- Desktop: persistent 280-pixel navigation and a bounded 1680-pixel workspace canvas.
- Wide desktop: 12-column dashboard composition for primary telemetry and supporting controls.

Validate at 375, 768, 1024, 1440, and 1600 pixels in both themes.

## Development

Run commands from the repository root:

```bash
bun install
bun run dev:console
bun run --filter '@qeet-id/console' typecheck
bun run --filter '@qeet-id/console' test
bun run --filter '@qeet-id/console' build
bun run lint
```

The local TanStack devtools launcher is hidden by default so it never competes with operator UI. Opt in only when debugging:

```bash
VITE_ENABLE_DEVTOOLS=true bun run dev:console
```

The API defaults to `http://localhost:4001`; override it with `VITE_API_URL`.
