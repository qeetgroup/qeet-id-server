# Spec — Enterprise AI Copilot (Qeet ID admin console)

- **Feature id:** FP-QEETID-COPILOT · **Priority:** 🟠 P1 · **Bounded context:** `operations` (new pkg `domains/operations/copilot`) + `apps/console`
- **Author:** Tech Lead · **Date:** 2026-07-18 · **Status:** spec (ready to build)
- **Provenance:** Direct feature ask. There is no active `FEATURE-PROPOSALS.md` in-repo (only
  `qeet-files/qeet-id/archive/FEATURE-PROPOSALS.OLD-20260708.md`), so no proposal row is added — this
  spec is the build contract. Supersedes the `ComingSoon` stub at
  `apps/console/src/routes/_app/authorization/assistant.tsx`.

This spec is the **shared contract** for parallel engineer agents. File ownership is disjoint per track
(§E) so no two agents edit the same file. Two artifacts are the single source of truth that both the
Go backend and the React frontend build from independently: **§B tool catalog** and the SSE event
union in **§A.4**. Both are also committed as `api/copilot/tools.manifest.json` (§C).

---

## 1. Summary & acceptance criteria

A native AI workspace docked inside the console shell (not a bolted-on chatbot). Streaming chat that can
**read and act** on the tenant's identity estate through the *existing* authenticated console endpoints,
so RBAC + Postgres RLS + audit are inherited, never re-implemented.

Done =

- [ ] `⌘J` / `Ctrl-J` toggles the copilot from anywhere in `_app`; the shortcut is listed in the
      `ShortcutsDialog`. No collision with `⌘K` (palette), `⌘B` (sidebar), `d` (theme), `?` (shortcuts).
- [ ] Panel supports **docked** (reflows content as a flex sibling of `.console-workspace`, does not
      overlay), **floating** (draggable/resizable via `FloatingWindow`), **fullscreen**, **collapsed**,
      **closed**; mode + size persist across reloads; the active conversation survives route changes.
- [ ] Streaming assistant replies with markdown + syntax-highlighted code; per-message copy / regenerate /
      stop / edit-and-resend.
- [ ] Conversation list: create / rename / pin / search / delete, persisted server-side (tenant + user
      scoped) and mirrored client-side.
- [ ] Automatic context-awareness: the copilot knows the current route, tenant, the selected
      user/role/policy/client, and the caller's capabilities — used for **grounding only, never authz**.
- [ ] Every action runs as a **typed tool** (§B): Zod-validated input → capability gate (`can()`) →
      confirmation for destructive ops → execution through the real authenticated hook/endpoint →
      audited. Execution timeline UI (`queued → validating → awaiting_confirmation → authorizing →
      executing → succeeded|failed`) with cancel + retry/timeout.
- [ ] Destructive tools (delete/disable user, reset MFA, rotate keys/secrets) show an affected-resource
      summary and require explicit confirmation before execution.
- [ ] Secrets (client secrets, rotated private keys) are **never** rendered in chat or sent to the model;
      they surface out-of-band via the existing `CopyableSecret` pattern.
- [ ] Route-aware proactive suggestions (e.g. on `/security/audit-logs`, offer "summarize anomalies").
- [ ] Graceful degradation: when no provider key is configured server-side, the copilot renders an
      "unconfigured" setup state (mirrors the existing `ComingSoon` pattern) — the console still builds
      and runs.
- [ ] WCAG 2.2 AA: full keyboard nav, focus trap in floating/fullscreen, `usePrefersReducedMotion`
      honored, dark mode via existing semantic tokens.
- [ ] New backend routes documented in `api/openapi/operations.yaml` (the `chi.Walk` coverage test in
      `platform/api/rest/openapi_coverage_test.go` fails otherwise).
- [ ] Backend inference key held server-side only; the browser never sees the provider key.

Out of scope (v1): multi-model routing, voice, file uploads/attachments, cross-user session search,
server-side tool execution, autonomous multi-step plans without per-tool confirmation.

---

## 2. Bounded context & packages

**Backend context: `operations`.** New package `domains/operations/copilot`. Justification vs the domain
map (`CLAUDE.md`): the copilot is an internal admin productivity surface that *orchestrates* actions
across every context (identity/access/federation/developer) and persists conversation history — a
cross-cutting operations concern, alongside `operations/audit`, `operations/analytics`,
`operations/notifications`. It is **not** `developer/*`: that context is external, developer-facing
machine identity (api-keys, service-accounts, agents, webhooks). The copilot is neither an external API
product nor a machine identity.

- New domain: `domains/operations/copilot/` — conversation/message persistence + Anthropic
  tool-orchestration loop + SSE HTTP handler.
- New platform infra: `platform/ai/anthropic/` — a thin Anthropic Messages API streaming client
  (holds base URL/model, streams deltas). **Infra only, imports nothing from `domains/*`** — satisfies
  arch rule R1 in `tests/architecture/arch_test.go` (`platform/*` must not import `domains/*`). The
  copilot domain imports `platform/ai/anthropic`; the reverse is forbidden.
- Reused platform: `platform/api/rest/httpx` (`RequireAuth`, `EnforceTenantScope`, `RequireTenant`,
  `RequireUser`, `PrincipalFromCtx`, `WriteJSON`/`WriteError`), `platform/database/postgres` (pool
  stamps `app.tenant_id` for RLS), `platform/events/outbox` + `EventEmitter`, `operations/audit`
  (`audit.Record`), `platform/config`.

**Frontend:** all in `apps/console` (admin). No changes to `apps/login` or `apps/website`.

---

## 3. Data model & migration plan

Latest migration pair is `0082_rls_tenant_isolation`. **Next migration = `0083`.** Add the pair
`platform/database/migrations/0083_copilot_conversations.{up,down}.sql`.

`0082`'s trailing note is binding: *tables added by future migrations that carry a `tenant_id` must
enable RLS + the `tenant_isolation` policy themselves*. So `0083` must (a) create the schema, (b) grant
`qid_app`, (c) create tables, (d) enable RLS + re-declare the policy per table (copy the `USING`/
`WITH CHECK` block verbatim from `0082`).

New schema `copilot` with two tables — both carry `tenant_id` (multi-tenant, not global):

`copilot.conversations`
| column | type | notes |
|---|---|---|
| `id` | uuid pk | |
| `tenant_id` | uuid not null | RLS key |
| `user_id` | uuid not null | owner (author); conversations are per-user |
| `title` | text not null default `'New conversation'` | |
| `pinned` | boolean not null default false | |
| `created_at` | timestamptz not null default now() | |
| `updated_at` | timestamptz not null default now() | bumped on new message |
- index `(tenant_id, user_id, pinned desc, updated_at desc)` for the list view.

`copilot.messages`
| column | type | notes |
|---|---|---|
| `id` | uuid pk | |
| `tenant_id` | uuid not null | RLS key |
| `conversation_id` | uuid not null | FK → `copilot.conversations(id)` on delete cascade |
| `role` | text not null | check in (`'user'`,`'assistant'`,`'tool'`) |
| `content` | jsonb not null | Anthropic content-block array (`text` / `tool_use` / `tool_result`) so tool turns round-trip losslessly. **Redacted**: no secret artifacts persisted. |
| `created_at` | timestamptz not null default now() | |
- index `(conversation_id, created_at)`.

Required migration content (spec, not applied here):
1. `CREATE SCHEMA IF NOT EXISTS copilot;`
2. `GRANT USAGE ON SCHEMA copilot TO qid_app;` + `ALTER DEFAULT PRIVILEGES IN SCHEMA copilot GRANT
   SELECT,INSERT,UPDATE,DELETE ON TABLES TO qid_app;` (+ sequences) — mirrors `0082` grants so the
   least-privilege app role can DML the new tables.
3. `CREATE TABLE copilot.conversations …` / `copilot.messages …` as above.
4. Per table: `ALTER TABLE … ENABLE ROW LEVEL SECURITY;` + `CREATE POLICY tenant_isolation …` copying
   the `current_setting('app.bypass_rls'…) OR tenant_id = …app.tenant_id…` predicate from `0082`.

`down`: drop both tables then `DROP SCHEMA copilot`.

> Retention: copilot history is user content — wire it into the existing `operations/retention`
> auto-purge in a follow-up (noted in §8, not v1-blocking).

---

## 4. API surface

New routes under the authenticated `/v1` group in `platform/api/rest/router.go` (added via
`d.Copilot.Mount(r)`, mounted alongside the other `operations` handlers). All inherit the standard chain:
APIKey → `RequireAuth` → `EnforceTenantScope` (RLS stamp) → rate limiters → `rbac.Enforce`. Handlers take
tenant/user from the JWT principal (`RequireTenant`/`PrincipalFromCtx`), never from body/URL.

| Method | Path | Purpose |
|---|---|---|
| GET | `/v1/copilot/status` | `{ configured, provider, model }` — drives unconfigured state |
| POST | `/v1/copilot/conversations` | create; body `{ title? }` → `Conversation` |
| GET | `/v1/copilot/conversations` | list (tenant+user scoped) → `{ items: Conversation[] }` |
| GET | `/v1/copilot/conversations/{conversationID}` | get with messages |
| PATCH | `/v1/copilot/conversations/{conversationID}` | rename/pin; body `{ title?, pinned? }` |
| DELETE | `/v1/copilot/conversations/{conversationID}` | delete |
| POST | `/v1/copilot/conversations/{conversationID}/messages` | **SSE stream** — see below |

`POST …/messages` request body (one turn):
```jsonc
{
  "message": "disable the user bob@acme.com",          // turn-opening user text, OR:
  "tool_results": [                                     // continuation after client executed tools
    { "tool_call_id": "toolu_…", "name": "disable_user",
      "output": { "summary": "Suspended bob@acme.com" } }   // or "error": { code, message }
  ],
  "context": { "route": {"pathname":"/users","title":"Users"}, "selection": {"kind":"user","id":"…"} }
}
```
Response: `200 text/event-stream`. Frames are `event: <type>\ndata: <json>\n\n`. **Event union (canonical
— frontend `StreamEvent` and backend emitter must match):**

| `event:` | `data` shape | direction |
|---|---|---|
| `thinking` | `{ text? }` | server → client (status/reasoning ping) |
| `token` | `{ text }` | server → client (assistant text delta) |
| `tool_call` | `{ id, name, input }` | server → client (model requests a tool; turn then ends with `done.reason="tool_use"`) |
| `tool_result` | `{ id, name, status, summary }` | server → client (on **history reload**, echoes an already-executed tool) |
| `error` | `{ code, message }` | server → client |
| `done` | `{ reason: "end_turn"\|"tool_use"\|"stopped"\|"error", messageId? }` | server → client (stream terminator) |

Turn model is **stateless/turn-based** (chosen over one long-lived socket): the stream ends after
`tool_use`; the client executes tools and POSTs `tool_results` to the same endpoint, which persists the
tool_result blocks and reopens a fresh stream that continues generation from DB-reconstructed history.
This is resilient to reconnects and keeps each SSE call a clean request/response — easier to test and
parallelize than a blocking socket that waits mid-stream.

> **Streaming client note:** `EventSource` cannot send a POST body or an `Authorization` header, so the
> frontend `streaming-client.ts` uses `fetch()` (bearer + `qeetid.tenant_id` from `tokenStore`) and
> parses `text/event-stream` off `response.body.getReader()`. It cannot reuse `lib/api.ts`'s `api()`
> (that buffers the whole body). It must reuse `tokenStore` and perform the same single-flight 401→
> refresh on stream open.

**OpenAPI:** add all seven paths to `api/openapi/operations.yaml` (operations context). The SSE endpoint
is documented as a `post` with `responses.200.content."text/event-stream"`. The coverage test only
asserts method+path presence, so documenting each path/method is sufficient (and required).

**permissionMap (`platform/api/rest/permissions.go`): no entries added — intentionally ungated.** Any
authenticated principal may chat; each *tool* self-authorizes through the endpoint it calls. Gating the
chat itself would wrongly block members whose individual tools are already capability-gated client-side
and RBAC-enforced server-side.

---

## 5. Security & tenant isolation

The core invariant: **the copilot can never exceed the acting user's authorization, and never touches a
resource outside the user's tenant.** How each requirement is met:

- **Tools = existing authenticated endpoints (client-side execution).** Chosen over server-side
  execution. When the model requests a tool, the backend emits a `tool_call` event and *stops*; the
  browser's `execution-engine.ts` runs the tool through the *same* `lib/*` hook a human uses. That hook
  goes through `lib/api.ts` → bearer token → server `RequireAuth` → `EnforceTenantScope` (RLS) →
  `rbac.Enforce` → domain handler → `audit.Record`. So RBAC, RLS tenant isolation, audit, and the
  mutation toasts are **inherited unchanged**. The copilot backend never holds the user's permissions
  and never calls a domain service directly — there is no new authz path to get wrong. Server-side
  execution was rejected because it would require re-minting the user's token or bypassing HTTP RBAC.
- **Capability gate (defense in depth).** Every `ToolDefinition` declares a `requiredCapability`
  (`Capability` union, `capability-model.ts`). The registry disables a tool when `can()` is false and
  the execution engine refuses to run it; the backend still enforces regardless (client gate is UX, not
  security).
- **Tenant isolation.** Conversation/message rows carry `tenant_id` under the `0083` RLS policy; the
  handler derives tenant from the JWT via `RequireTenant`. Tool executions are tenant-scoped by the
  endpoints they hit. The model receives `context.selection` for grounding but authorization is always
  the server's, never the context's.
- **Destructive-op confirmation.** `destructive: true` tools (`delete_user`, `disable_user`,
  `reset_user_mfa`, `rotate_signing_keys`, `rotate_oauth_client_secret`) route through an `AlertDialog`
  (`confirm()` in `ToolContext`) showing the affected-resource summary; execution proceeds only on
  explicit confirm. The engine transitions `awaiting_confirmation → authorizing → executing`.
- **Secrets never exposed.** Provider (Anthropic) key lives only in `COPILOT_API_KEY` server-side; it is
  never returned by `/v1/copilot/status` and never sent to the browser. Tool results that contain
  secrets (`create_oauth_client` → `client_secret`, `rotate_signing_keys` → `private_key_pem`,
  `rotate_oauth_client_secret`) put the value in `ToolResult.sensitiveArtifact`, which is surfaced
  out-of-band via `CopyableSecret` and is **stripped from both the chat transcript and the `tool_result`
  posted back to the model.** Only the redacted `summary` reaches the model / DB.
- **Every tool execution audited.** Twice: (1) the domain endpoint records its own `audit.Event`
  (inherited); (2) the copilot backend records `copilot.message.sent` and `copilot.tool.requested`
  (tool name + redacted input) via `audit.Record`, giving a distinct "AI intent" trail alongside the
  "actual action" trail.
- **Prompt-injection posture.** The model can only ever emit a `tool_call` whose `name` is in the
  manifest; an unknown name is rejected by the registry before any HTTP call. Inputs are Zod-validated
  client-side and JSON-Schema-constrained in the Anthropic request. The model cannot invent an endpoint,
  cannot widen scope, cannot skip the capability gate or the destructive confirmation, and cannot read a
  secret it wasn't already entitled to. `context.*` from the page is treated as untrusted grounding text.

**security-reviewer must check:** `0083` RLS policy present on both tables; `/status` never leaks the
key; `sensitiveArtifact` redaction in the tool-result post-back + transcript; capability gate wired on
every destructive tool; SSE handler enforces `RequireTenant`; no domain-service call path that skips HTTP
RBAC; audit records emitted per message + per tool request.

---

## 6. Frontend surfaces

App: `apps/console` only. New feature module `apps/console/src/features/copilot/` (full tree in §A). Built
entirely on `@qeetrix/ui@0.4.0` primitives (`Sheet`, `FloatingWindow`/`useFloatingWindow`,
`ResizablePanelGroup`, `ScrollArea`, `Collapsible`, `AlertDialog`, `Tabs`, `Command…`, `Button`,
`Textarea`, `Skeleton`, `Progress`, `Kbd`, `StatusPill`, `EmptyState`, `DataState`, `cn`, `useIsMobile`,
`usePrefersReducedMotion`, semantic tokens). Toasts reuse the app's existing `sonner` mutation-cache
toasts (`integrations/tanstack-query/root-provider.tsx`) — tools go through existing hooks which already
toast; do **not** mount a second `Toaster`.

Screens/components:
- **Docked/floating/fullscreen workspace** mounted in the app shell (§A wiring), reflowing content in
  docked mode.
- **Conversation view** (message list, markdown + code, streaming cursor, per-message actions).
- **Execution timeline** (per-tool status stepper + cancel/retry) and **confirmation dialog**.
- **History panel** (list, search, pin, rename, delete).
- **Trigger** button in `console-header.tsx` + `⌘J`, and the repointed
  `/authorization/assistant` landing that opens the copilot seeded with authz example prompts.
- **Suggestions** strip (route-aware).

**New console dependencies (isolated in `components/markdown-message/` only):** `react-markdown`,
`remark-gfm`, and `shiki` (preferred highlighter; lazy-load a single theme + the languages we emit:
`json,hcl,bash,typescript,go,python,sql`). `@qeetrix/ui` ships no markdown renderer and only a JSON-only
`CodeBlock`, so this gap is real. `@monaco-editor/react` is already a dep and is the read-only fallback
if `shiki` bundle size is a concern.

---

## A. Frontend module — `apps/console/src/features/copilot/`

One responsibility per module. Interfaces below are the **frozen contracts** (Phase 0, §E) that tracks 2
and 3 import.

```
features/copilot/
  copilot-provider.tsx              # context: wires stores + active AIProvider + ⌘J target + confirm() portal
  store/
    workspace-store.ts              # TanStack Store: panel mode, size, open state, persistence (localStorage)
    conversation-store.ts           # TanStack Store: working set (streaming buffer, draft, search, pin filter)
  context/
    use-console-context.ts          # builds ConsoleContext from route + capabilities + registry snapshot
    context-registry.ts             # pub/sub store; route pages publish { selection, filters }
  ai/
    ai-provider.ts                  # AIProvider seam interface + StreamEvent/SendInput/ProviderStatus types
    backend-provider.ts             # AIProvider over the SSE backend (uses streaming-client)
    streaming-client.ts             # fetch() + text/event-stream reader → StreamEvent async iterable
    prompt-builder.ts               # serializes ConsoleContext + user input → SendInput
    unconfigured-provider.ts        # AIProvider stub when /status.configured === false
  tools/
    tool-types.ts                   # ToolDefinition, ToolContext, ToolResult, ConfirmRequest (Phase 0)
    tool-registry.ts                # name → ToolDefinition; can()-based enable/disable
    execution-engine.ts             # ToolExecution state machine, validation, confirm, retry/timeout, cancel
    definitions/                    # one file per tool group (§B)
      user.tools.ts  role.tools.ts  org.tools.ts  credentials.tools.ts
      authz.tools.ts  audit.tools.ts  codegen.tools.ts
    index.ts                        # assembles the registry from all definitions/*
  suggestions/
    suggestion-engine.ts            # ranks suggestions for the current ConsoleContext
    route-suggestions.ts            # static route → suggestion map
  components/
    copilot-workspace.tsx           # mode switch: docked | FloatingWindow | fullscreen | collapsed
    copilot-trigger.tsx             # header button (console-header)
    copilot-launcher.tsx            # portal host mounted in _app
    conversation/                   # message-list, message-item, composer, streaming-cursor, message-actions
    execution/                      # execution-timeline, execution-step, confirm-dialog
    suggestions/                    # suggestion-strip, suggestion-chip
    history/                        # history-panel, conversation-row, history-search
    markdown-message/               # markdown-message.tsx (react-markdown + remark-gfm + shiki) — deps isolated here
  __tests__/                        # vitest (registry, engine, context, stores, streaming parser)
```

Companion (thin REST hooks over `api()`, house convention): **`apps/console/src/lib/copilot.ts`** —
`useCopilotStatus`, `useConversations`, `useConversation`, `useCreateConversation`,
`useRenameConversation`, `usePinConversation`, `useDeleteConversation`. Conversation CRUD lives here;
message streaming lives in `ai/streaming-client.ts`.

### Frozen interface contracts (Phase 0)

```ts
// ai/ai-provider.ts
export type StreamEvent =
  | { type: "thinking"; text?: string }
  | { type: "token"; text: string }
  | { type: "tool_call"; id: string; name: string; input: unknown }
  | { type: "tool_result"; id: string; name: string; status: "succeeded" | "failed"; summary: string }
  | { type: "error"; code: string; message: string }
  | { type: "done"; reason: "end_turn" | "tool_use" | "stopped" | "error"; messageId?: string };

export interface SendInput {
  conversationId: string;
  message?: string;
  toolResults?: { toolCallId: string; name: string; output?: unknown; error?: { code: string; message: string } }[];
  context: ConsoleContext;
}
export interface ProviderStatus { configured: boolean; provider?: string; model?: string }
export interface AIProvider {
  readonly id: string;
  status(signal?: AbortSignal): Promise<ProviderStatus>;
  send(input: SendInput, opts: { signal: AbortSignal }): AsyncIterable<StreamEvent>;
}

// context/use-console-context.ts
import type { Capability } from "@/features/access-control/capability-model";
export interface ConsoleContext {
  route: { pathname: string; title: string; group?: string };
  tenantId: string | null;
  userId: string | null;
  capabilities: Capability[];                        // grounding/UI hint only — NOT authz
  selection?: { kind: "user" | "role" | "policy" | "oidc_client" | "agent" | "audit_event" | string; id: string; label?: string };
  filters?: Record<string, string>;
}

// tools/tool-types.ts
import type { z } from "zod";
import type { QueryClient } from "@tanstack/react-query";
export type ToolCategory = "directory" | "authz" | "credentials" | "audit" | "codegen";
export interface ConfirmRequest {
  title: string; body: string;
  affected: { label: string; value: string }[];
  confirmText: string; tone: "default" | "destructive";
}
export interface ToolResult {
  ok: boolean;
  summary: string;                                   // redacted, model-safe; fed back + rendered
  data?: Record<string, unknown>;                    // redacted structured payload for rich render
  sensitiveArtifact?: { kind: "secret" | "private_key"; label: string; value: string }; // client-only, never to model
  error?: { code: string; message: string };
}
export interface ToolContext {
  tenantId: string; userId: string;
  console: ConsoleContext;
  can: (c?: Capability) => boolean;
  queryClient: QueryClient;                          // imperative hook execution
  signal: AbortSignal;
  confirm: (req: ConfirmRequest) => Promise<boolean>;
}
export interface ToolDefinition<I = unknown> {
  name: string;                                      // snake_case; must equal manifest + backend name
  category: ToolCategory;
  title: string;
  description: string;                               // model-facing
  input: z.ZodType<I>;
  requiredCapability?: Capability;
  destructive: boolean;
  confirm?: (input: I, ctx: ToolContext) => ConfirmRequest;
  auditLabel: string;
  run: (ctx: ToolContext, input: I) => Promise<ToolResult>;
}

// tools/execution-engine.ts
export type ExecutionStatus =
  | "queued" | "validating" | "awaiting_confirmation"
  | "authorizing" | "executing" | "succeeded" | "failed" | "cancelled" | "timed_out";
export interface ToolExecution {
  id: string;                                        // == tool_call_id
  toolName: string; input: unknown;
  status: ExecutionStatus;
  startedAt: number; endedAt?: number;
  result?: ToolResult; error?: { code: string; message: string };
  attempts: number;
}
```

State machine: `queued → validating → (awaiting_confirmation if destructive) → authorizing → executing →
succeeded | failed | timed_out`. `cancelled` reachable from any non-terminal state via `signal`. `failed`
and `timed_out` are retryable (`attempts++`); a capability denial in `authorizing` is terminal
(non-retryable).

### Wiring edits (exact files)

- `apps/console/src/routes/_app.tsx` — wrap `ConsoleFrame` return so `<CopilotProvider>` is inside
  `CapabilityProvider` (copilot needs `useCapabilities`). Mount `<CopilotWorkspace/>` as a **flex sibling
  of `.console-workspace`** inside `SidebarProvider` (docked reflow, not overlay). Mount
  `<CopilotLauncher/>` next to the existing `CommandPaletteLauncher`. Add `onToggleCopilot` to the
  `useGlobalShortcuts` call, wired to `workspaceStore.toggle()`.
- `apps/console/src/lib/shortcuts.ts` — add `onToggleCopilot?: () => void` to `Options`; handle `⌘J`/
  `Ctrl-J` **before** the `if (e.metaKey || e.ctrlKey …) return` guard (with `preventDefault`, fires even
  inside inputs). Add `{ keys: ["⌘","J"], description: "Toggle AI Copilot" }` to the "General"
  `SHORTCUT_GROUPS` so it appears in `ShortcutsDialog`.
- `apps/console/src/features/dashboard/components/console-header.tsx` — add `<CopilotTrigger/>` beside the
  existing search/shortcuts buttons.
- `apps/console/src/config/navigation.tsx` — the "Authorization → AI assistant" item
  (`/authorization/assistant`, `SparklesIcon`, `policy.read`) stays but is renamed "AI Copilot"; the
  route now opens the copilot (below) instead of `ComingSoon`.
- `apps/console/src/routes/_app/authorization/assistant.tsx` — replace `ComingSoon` body with a thin
  landing that on mount calls `workspaceStore.open("docked")`, publishes an authz `selection` intent to
  the `context-registry`, and renders the existing `EXAMPLE_PROMPTS` as clickable seed chips.
- `apps/console/src/env.ts` — add `VITE_COPILOT_ENABLED` (client, `z.enum(["true","false"]).optional()`,
  default on) as a build-time kill switch. The real gate is backend `/status`.
- `apps/console/src/i18n/index.ts` — import + register a `copilot` namespace.
- `apps/console/src/i18n/locales/en/copilot.json` — new shell/UI strings. (Tool titles/descriptions/audit
  labels are code constants in the `ToolDefinition`, not i18n, to keep §B a single source and avoid a
  cross-track collision on this file.)

---

## B. Tool catalog (canonical — also committed as `api/copilot/tools.manifest.json`)

Each tool maps to a **real** existing endpoint/hook unless flagged 🚩. Capability is the `Capability`
union value. "Destructive" ⇒ confirmation dialog with affected-resource summary. Backend uses the same
`name` + a JSON-Schema form of `input` for the Anthropic `tools` param; the frontend attaches `run()`.

> 🚩 **`lib/users.ts` does not exist.** User CRUD is inlined in `routes/_app/users/index.tsx` /
> `$userId.tsx` (`POST/PATCH/DELETE /v1/users…`). **Extract thin hooks** `useCreateUser`, `useUpdateUser`,
> `useDeleteUser`, `useSetUserStatus`, `useResetUserMfa`, `useAssignRole` into a new `lib/users.ts`
> (endpoints already exist and are in `permissions.go`), so the route pages *and* the copilot tools share
> one authenticated hook. Assigned to track 3.

### Directory (`definitions/user.tools.ts`, `org.tools.ts`, `role.tools.ts`)
| name | input (Zod) | capability | destr. | endpoint / hook |
|---|---|---|---|---|
| `search_users` | `{ q?, status?, limit? }` | `user.read` | no | `GET /v1/users` |
| `create_user` | `{ email, name?, password?, tenant_id, role_id? }` | `user.write` | no | `POST /v1/users` (+ optional `POST /v1/users/{id}/tenants/{tenant_id}/roles/{role_id}`) → new `useCreateUser` |
| `update_user` | `{ user_id, name? }` | `user.write` | no | `PATCH /v1/users/{id}` |
| `disable_user` | `{ user_id }` | `user.write` | **yes** | `PATCH /v1/users/{id}` `{status:"suspended"}` |
| `enable_user` | `{ user_id }` | `user.write` | no | `PATCH /v1/users/{id}` `{status:"active"}` |
| `delete_user` | `{ user_id }` | `user.write` | **yes** | `DELETE /v1/users/{id}` |
| `reset_user_mfa` | `{ user_id }` | `user.write` | **yes** | `DELETE /v1/users/{id}/mfa` (admin MFA reset — forces re-enrollment). 🚩 See "Enable MFA" note below. |
| `create_organization` | `{ name, slug? }` | `tenant.write` | no | `POST /v1/tenants` |
| `create_role` | `{ name, description? }` | `role.write` | no | `POST /v1/tenants/{tenantID}/roles` → `useCreateRole` (`lib/authz-rbac.ts`) |
| `assign_role` | `{ user_id, role_id }` | `role.write` | no | `POST /v1/users/{userID}/tenants/{tenantID}/roles/{roleID}` |
| `grant_permission` | `{ role_id, permission_id }` | `role.write` | no | `POST /v1/roles/{roleID}/permissions/{permID}` → `useGrantPermission` |

🚩 **"Enable MFA"** from the product list has **no admin endpoint** to *enable* a factor for another user —
MFA enrollment is a self-scoped multi-step ceremony (`/v1/mfa/*`, user derived from JWT). Verified: the
tenant `AuthPolicy` (`lib/auth-policy.ts` / `domains/access/authorization/authpolicy/authpolicy.go`) has
**no `mfa_required` field** — per the backend comment "MFA stays always-on unless a tenant opts in" to
`remember_device_enabled` (adaptive skip), so "enable MFA org-wide" is not an existing lever. v1 ships two
real substitutes: `reset_user_mfa` (above; forces per-user re-enrollment) and `set_strict_mfa`
(`{ enabled }` → `PATCH …/auth-policy` toggling `remember_device_enabled` off = no adaptive skip;
`policy.write`, non-destructive, `useUpdateAuthPolicy`). A true per-user "enable MFA" tool is deferred
until an admin enrollment endpoint exists (backend follow-up).

### Credentials (`definitions/credentials.tools.ts`) — secret-bearing, redact
| name | input | capability | destr. | endpoint / hook |
|---|---|---|---|---|
| `create_oauth_client` | `{ name, type:"public"\|"confidential", redirect_uris?, grant_types?, scopes? }` | `connection.write` | no | `POST /v1/oidc/clients` → `useCreateOidcClient`. Returns `client_secret` once → `sensitiveArtifact`, **redact from chat + model**. |
| `rotate_oauth_client_secret` | `{ client_id }` | `connection.write` | **yes** | `POST /v1/tenants/{tenantID}/oidc/clients/{id}/rotate-secret`. Secret → `sensitiveArtifact`. |
| `rotate_signing_keys` | `{}` | `connection.write` | **yes** | `POST /v1/oidc/signing-keys/rotate` → `useRotateKey`. Returns `private_key_pem` → `sensitiveArtifact`, **redact**. Confirm copy: "rotating invalidates the current signing key after the grace window." |

### Audit & sessions (`definitions/audit.tools.ts`)
| name | input | capability | destr. | endpoint / hook |
|---|---|---|---|---|
| `search_audit_logs` | `{ q?, action?, resource_type?, actor_user_id?, limit? }` | `audit.read` | no | `GET /v1/tenants/{tenantID}/audit` |
| `search_sessions` | `{}` | `user.read` | no | `GET /v1/auth/sessions`. 🚩 **Self-scoped only** (current principal's sessions); there is no admin cross-user session-search endpoint — tool documents that limitation. |

### Authorization (`definitions/authz.tools.ts`)
| name | input | capability | destr. | endpoint / hook |
|---|---|---|---|---|
| `simulate_authorization` | `{ engine:"authzen"\|"abac"\|"rbac"\|"rebac", subject, resource, action, context? }` | `role.read` (rbac/rebac/authzen) / `policy.read` (abac) | no | `lib/authz-simulate.ts` (`callAuthzen`/`callAbac`/`callRbac`/`callRebac`) → real `/access/v1/evaluation`, `/abac/evaluate`, `/check`, `/relation-tuples/check` |

### Codegen (`definitions/codegen.tools.ts`) — 🚩 client-side templating, **no backend endpoint**
| name | input | capability | destr. | source |
|---|---|---|---|---|
| `generate_terraform` | `{ resource_type:"oidc_client"\|"tenant"\|"role", resource_id? }` | read cap for the type (e.g. `connection.read`) | no | reads live config via existing GET hooks (`useOidcClients`, tenants, roles) and emits HCL. Pure client-side. |
| `generate_sdk_snippet` | `{ endpoint, language:"curl"\|"typescript"\|"go"\|"python" }` | none (informational) | no | templated snippet for a known endpoint. Client-side. |
| `generate_api_example` | `{ endpoint, method }` | none | no | example request/response derived from the OpenAPI shape. Client-side. |

Total: **21 tools** (covers all ~18 from the product spec + `search_users`, `enable_user`,
`rotate_oauth_client_secret` siblings). `generate_*` and `simulate_authorization` reuse `authz-codegen.ts`
patterns where applicable.

---

## C. Backend copilot inference service (Go)

Package `domains/operations/copilot/`:
```
copilot.go        # Service: conversation/message CRUD (pgx like operations/notifications) + domain types
orchestrator.go   # Anthropic tool-loop: build Messages request, stream deltas → StreamEvent SSE frames
http.go           # Handler + Mount + SSE writer + tool_result intake + /status
tools.go          # //go:embed ../../../api/copilot/tools.manifest.json → []anthropic tool defs (NO run())
sse.go            # SSE frame writer (event:/data:, flush, keep-alive)
```
Plus `platform/ai/anthropic/client.go` — Messages API streaming client (infra; no `domains/*` imports).

**Provider key:** `COPILOT_API_KEY` read via envconfig into the Anthropic client at construction in
`cmd/server/main.go`; never serialized to any response. `GET /v1/copilot/status` returns
`{ configured: key!="", provider, model }` — no key material.

**Orchestration loop (client-side tool execution, turn-based):**
1. Client `POST …/messages` with `message` (+ `context`). Handler `RequireTenant`/`PrincipalFromCtx`,
   persists the user message, records `audit` `copilot.message.sent`.
2. `orchestrator` calls Anthropic Messages (streaming) with: system prompt (grounded by `context`, which
   is untrusted), full conversation history from DB, and `tools` = the embedded manifest defs.
3. Stream `text` deltas as `token` frames / `thinking` pings. If `stop_reason=end_turn`, persist the
   assistant message, emit `done{end_turn}`, close.
4. If `stop_reason=tool_use`: for each `tool_use` block emit `tool_call{id,name,input}`, persist the
   assistant message (with tool_use blocks), record `copilot.tool.requested` (redacted input), emit
   `done{tool_use}`, close the stream.
5. Client executes tools (§B) via the authenticated hooks (RBAC/RLS/audit inherited), then
   `POST …/messages` with `tool_results`. Handler persists a `tool`-role message (redacted), re-invokes
   from step 2 with the appended results, streaming the continuation.

This model is chosen precisely so the copilot **cannot exceed the acting user's authorization** (§5): the
server never executes a domain mutation; the browser does, under the user's own token.

**Config (`platform/config/config.go`) additions:**
```go
CopilotProvider string `envconfig:"COPILOT_PROVIDER" default:""`      // "" = disabled/unconfigured
CopilotAPIKey   string `envconfig:"COPILOT_API_KEY" default:""`       // server-side only
CopilotModel    string `envconfig:"COPILOT_MODEL" default:"claude-…"` // pick current Anthropic model id
CopilotMaxTokens int   `envconfig:"COPILOT_MAX_TOKENS" default:"4096"`
CopilotBaseURL  string `envconfig:"COPILOT_BASE_URL" default:"https://api.anthropic.com"`
```
`Validate()` cross-field (outside dev): if `CopilotProvider != ""` then `CopilotAPIKey` required. Provider
unset ⇒ feature simply disabled; no hard requirement (optional feature). Also add the vars to
`.env.example`.

**Graceful degradation:** provider unset/empty key ⇒ `/status.configured=false`; the frontend
`unconfigured-provider` renders a setup CTA (mirrors `ComingSoon`). Conversation CRUD endpoints still work
(history is viewable); only `…/messages` returns `409 copilot_unconfigured` when not configured.

**Shared backend files to edit (backend-engineer only — flagged to prevent collisions):**
`platform/api/rest/router.go` (add `Copilot *copilot.Handler` to `Deps` + `d.Copilot.Mount(r)`),
`platform/api/rest/openapi_coverage_test.go` (`testDeps()` must set `Copilot: &copilot.Handler{}` or the
walk-router test nil-mounts), `platform/config/config.go`, `cmd/server/main.go` (construct
anthropic.Client + copilot.Service/Handler), `api/openapi/operations.yaml` (document the 7 paths),
`platform/database/migrations/0083_*`. `permissions.go` — no change (intentionally ungated, §4).

**Migration:** `0083_copilot_conversations.{up,down}.sql` per §3.

---

## D. Security model — see §5 (kept in one place to avoid drift)

§5 is the authoritative security section (AI never bypasses authz; tenant isolation; destructive
confirmation; secrets server-side + never in chat; dual-layer audit; prompt-injection posture). This
subsection is intentionally a pointer.

---

## E. Task breakdown for parallel agents

Legend: 🔵 backend-engineer · 🟢 frontend-engineer · 🟣 qa-test-engineer · then security-reviewer, then
docs-writer. Concurrency noted per phase.

**Phase 0 — shared contracts (must land first; blocks tracks 2 & 3).** Owner: 🟢 frontend track-1 lead.
- Author the frozen interfaces (§A): `ai/ai-provider.ts`, `context/use-console-context.ts` (types),
  `tools/tool-types.ts`, `tools/execution-engine.ts` (types only). Commit
  `api/copilot/tools.manifest.json` transcribed from §B (name, description, JSON schema, destructive,
  capability). Add `lib/copilot.ts` REST hook signatures.
- 🔵 backend can start **immediately in parallel** — it builds from §A.4 (SSE union) + §B in this spec,
  not from track-1's files; the manifest file is the reconciliation point (qa parity test).

**🔵 Backend (fully concurrent from t0; disjoint file set).**
1. `platform/ai/anthropic/client.go` (streaming Messages client).
2. `domains/operations/copilot/{copilot,orchestrator,http,tools,sse}.go`.
3. `0083_copilot_conversations.{up,down}.sql` (§3).
4. Wire-up in the shared backend files listed in §C (router `Deps`+mount, coverage-test `testDeps`,
   `config.go`, `cmd/server/main.go`, `api/openapi/operations.yaml`, `.env.example`).

**🟢 Frontend track 1 — shell, stores, provider, wiring (after Phase 0).**
`copilot-provider.tsx`, `store/workspace-store.ts`, `store/conversation-store.ts`,
`components/copilot-workspace.tsx`, `copilot-trigger.tsx`, `copilot-launcher.tsx`, `lib/copilot.ts`
(impl). Wiring edits: `_app.tsx`, `lib/shortcuts.ts`, `console-header.tsx`, `config/navigation.tsx`,
`env.ts`, `i18n/index.ts`, `i18n/locales/en/copilot.json`.

**🟢 Frontend track 2 — conversation UI, streaming, execution, history (after Phase 0; concurrent with 1
& 3).** `ai/backend-provider.ts`, `ai/streaming-client.ts`, `ai/prompt-builder.ts`,
`ai/unconfigured-provider.ts`, `components/conversation/*`, `components/execution/*`,
`components/history/*`, `components/markdown-message/*` (+ add `react-markdown`, `remark-gfm`, `shiki`
deps), and the repointed `routes/_app/authorization/assistant.tsx` landing.

**🟢 Frontend track 3 — tools, context, suggestions (after Phase 0; concurrent).**
`tools/tool-registry.ts`, `tools/execution-engine.ts` (impl), `tools/definitions/*.tools.ts` (all §B),
`tools/index.ts`, `context/use-console-context.ts` (impl), `context/context-registry.ts`,
`suggestions/*`. Also extract **`lib/users.ts`** hooks (§B 🚩) and publish `context-registry` selection
from a couple of anchor pages (`users/$userId.tsx`, an authz page) — coordinate those two page edits with
track 1/2 (small, additive `registerContext()` calls).

**🟣 qa-test-engineer (after each track's units land).**
- vitest: `tool-registry` (name↔manifest parity, capability gating), `execution-engine` (state-machine
  transitions, confirm/cancel/retry/timeout, redaction of `sensitiveArtifact`), `use-console-context`,
  `workspace-store`/`conversation-store` persistence, `streaming-client` SSE parser.
- Go: `copilot` service (conversation/message CRUD under RLS), `orchestrator` tool-loop (tool_use →
  tool_call frames → resume), `/status` never leaks key, SSE framing.
- **OpenAPI coverage:** ensure `TestOpenAPICoversAllMountedRoutes` passes (all 7 copilot paths in
  `operations.yaml`).
- **Manifest parity test:** frontend registry tool names == `api/copilot/tools.manifest.json` ==
  backend embedded defs.

**Concurrency summary:** Phase 0 first. Then 🔵 backend + 🟢 tracks 1/2/3 all run concurrently (disjoint
files; the SSE union + manifest are the only cross-boundary contracts, both pinned here). qa trails each.
security-reviewer runs against §5 once backend + track 2/3 land. docs-writer updates `ROADMAP.md` /
`docs/` and any operator note for `COPILOT_*` env once green.

---

## Risks / open questions

1. **"Enable MFA" has no admin endpoint** (🚩 §B, verified). `AuthPolicy` has no `mfa_required` field
   (MFA is always-on modulo `remember_device_enabled` adaptive skip). v1 ships `reset_user_mfa` +
   `set_strict_mfa` (toggles `remember_device_enabled`); a true per-user admin MFA-enable endpoint is a
   backend follow-up.
2. **Cross-user session search** (🚩 §B): `/v1/auth/sessions` is self-scoped. `search_sessions` returns
   the caller's sessions only; a real admin session-search endpoint is a follow-up.
3. **Anthropic model id / API version** — `CopilotModel` default must be set to the current supported
   model at build time; confirm the Messages API `anthropic-version` header in `platform/ai/anthropic`.
4. **SSE behind the deploy** — Caddy/EC2 (`deploy/README.md`) must not buffer `text/event-stream`; verify
   proxy flush + `X-Accel-Buffering: no` where relevant, and the 30s `HTTP_WRITE_TIMEOUT` default
   (`config.go`) is too short for a streamed turn — copilot SSE responses need an extended/again-reset
   write deadline on that handler.
5. **shiki bundle size** — lazy-load a single theme + the 7 languages; fall back to read-only Monaco
   (already a dep) if the budget is exceeded.
6. **Toaster** — reuse the app's existing `sonner` mutation-cache toasts; do not mount a second
   `Toaster`. (House-style note: `@qeetrix/ui` also exports its own `Toaster`/`toast`; the console
   currently standardizes on `sonner` — leave that migration out of this feature.)
7. **Retention** — copilot history is user content; wire into `operations/retention` auto-purge in a
   follow-up (not v1-blocking).
8. **Manifest drift** — `api/copilot/tools.manifest.json` is the single source both sides load; the qa
   parity test is the guard. Adding a tool = edit §B + manifest + a frontend `run()` only.
