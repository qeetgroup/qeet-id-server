import {
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  Combobox,
  CopyableSecret,
  DataState,
  Field,
  FieldLabel,
  Input,
} from "@qeetrix/ui";
import { useQuery } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";
import {
  ArrowRightLeftIcon,
  Loader2Icon,
  PauseIcon,
  PlayIcon,
  ShieldAlertIcon,
  SkullIcon,
  SparklesIcon,
  Trash2Icon,
} from "lucide-react";
import { useState } from "react";

import { useConfirmDialog } from "@/components/confirm-dialog";
import { PageHeader } from "@/components/page-header";
import { api, ApiError } from "@/lib/api";
import { useMe, useTenantId } from "@/lib/auth";
import {
  useAgents,
  useAgentsSponsoredBy,
  useCreateAgent,
  useDeleteAgent,
  useKillAllAgents,
  useSetAgentDisabled,
  useTransferSponsor,
  type Agent,
} from "@/lib/agents";
import { useReviewShadowAIClient, useShadowAICandidates } from "@/lib/oidc-clients";

export const Route = createFileRoute("/_app/developer/agents")({ component: AgentsPage });

function AgentsPage() {
  const [confirmDialog, openConfirm] = useConfirmDialog();
  const meQ = useMe();
  const agentsQ = useAgents();
  const createM = useCreateAgent();
  const deleteM = useDeleteAgent();
  const disableM = useSetAgentDisabled();
  const killAllM = useKillAllAgents();

  const [name, setName] = useState("");
  const [scopes, setScopes] = useState("");
  const [ttl, setTtl] = useState(600);
  const [created, setCreated] = useState<Agent | null>(null);

  const items = agentsQ.data?.items ?? [];
  const activeCount = items.filter((a) => !a.disabled).length;
  const sponsorId = meQ.data?.id;

  return (
    <div className="flex min-w-0 flex-col gap-4">
      {confirmDialog}
      <PageHeader
        title="Agent Governance"
        description="First-class identities for AI agents / MCP clients, and the primitives that keep them accountable to a human: sponsorship, Shadow-AI discovery, ephemeral tokens, and a tenant-wide kill-switch. An agent authenticates with its secret at POST /v1/agents/token and gets a short-lived, scoped token marked actor_type=&ldquo;agent&rdquo; — ephemeral by design (re-mint, no refresh). Token Vault (3rd-party OAuth on an agent's behalf) and CIBA (backchannel auth) are part of the same governance surface but are API-only today — see the docs."
      />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Create an agent</CardTitle>
          <CardDescription>
            The secret is shown once. Scopes are space-separated; token lifetime is clamped to
            60&ndash;3600s. You&rsquo;re recorded as the agent&rsquo;s sponsor — its accountable
            human owner — and can transfer that later if it changes hands.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form
            className="flex flex-col gap-3"
            onSubmit={(e) => {
              e.preventDefault();
              if (name.trim() && sponsorId) {
                createM.mutate(
                  {
                    name: name.trim(),
                    scopes: scopes.trim() ? scopes.trim().split(/\s+/) : [],
                    token_ttl_seconds: ttl,
                    sponsor_user_id: sponsorId,
                  },
                  {
                    onSuccess: (a) => {
                      setCreated(a);
                      setName("");
                      setScopes("");
                    },
                  },
                );
              }
            }}
          >
            <div className="flex flex-col gap-3 sm:flex-row sm:items-end">
              <Field className="flex-1">
                <FieldLabel htmlFor="name">Name</FieldLabel>
                <Input
                  id="name"
                  placeholder="support-copilot"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                />
              </Field>
              <Field className="flex-1">
                <FieldLabel htmlFor="scopes">Scopes</FieldLabel>
                <Input
                  id="scopes"
                  placeholder="tickets:read kb:read"
                  value={scopes}
                  onChange={(e) => setScopes(e.target.value)}
                />
              </Field>
              <Field className="sm:w-32">
                <FieldLabel htmlFor="ttl">Token TTL (s)</FieldLabel>
                <Input
                  id="ttl"
                  type="number"
                  min={60}
                  max={3600}
                  value={ttl}
                  onChange={(e) => setTtl(Number(e.target.value) || 600)}
                />
              </Field>
              <Button type="submit" disabled={createM.isPending || !name.trim() || !sponsorId}>
                {createM.isPending && <Loader2Icon className="animate-spin" />}
                Create
              </Button>
            </div>
            {createM.error && (
              <p className="text-destructive text-sm">{(createM.error as ApiError).message}</p>
            )}
          </form>

          {created?.secret && (
            <div className="mt-4 rounded-lg border border-amber-500/40 bg-amber-50/40 p-4 dark:bg-amber-950/20">
              <p className="mb-2 text-sm font-medium">
                Agent <span className="font-mono">{created.name}</span> created — copy its
                credentials now (the secret won&apos;t be shown again):
              </p>
              <div className="grid gap-2 sm:grid-cols-[auto_1fr]">
                <span className="text-sm text-muted-foreground">agent_id</span>
                <CopyableSecret value={created.id} size="sm" />
                <span className="text-sm text-muted-foreground">secret</span>
                <CopyableSecret value={created.secret} size="sm" />
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between gap-4">
          <div>
            <CardTitle className="text-base">Agents</CardTitle>
            <CardDescription>AI-agent identities in this tenant.</CardDescription>
          </div>
          {activeCount > 0 && (
            <Button
              variant="destructive"
              size="sm"
              disabled={killAllM.isPending}
              onClick={() =>
                openConfirm({
                  title: `Suspend all ${activeCount} active agent(s)?`,
                  description: "Their tokens will stop working immediately.",
                  variant: "destructive",
                  confirmLabel: "Suspend All",
                  onConfirm: () => killAllM.mutate(),
                })
              }
            >
              {killAllM.isPending ? (
                <Loader2Icon className="animate-spin" />
              ) : (
                <SkullIcon />
              )}
              Suspend All
            </Button>
          )}
        </CardHeader>
        <CardContent className="p-0">
          <DataState
            isLoading={agentsQ.isLoading}
            isError={agentsQ.isError}
            error={agentsQ.error}
            isEmpty={items.length === 0}
            emptyIcon={SparklesIcon}
            emptyTitle="No agents yet."
            emptyDescription="Create an agent above to issue it ephemeral, scoped tokens."
            skeletonRows={2}
          >
            <ul className="divide-y">
              {items.map((a) => (
                <AgentRow
                  key={a.id}
                  agent={a}
                  onToggle={() => disableM.mutate({ id: a.id, disabled: !a.disabled })}
                  onDelete={() =>
                    openConfirm({
                      title: `Delete agent "${a.name}"?`,
                      variant: "destructive",
                      confirmLabel: "Delete",
                      onConfirm: () => deleteM.mutate(a.id),
                    })
                  }
                  busy={disableM.isPending || deleteM.isPending}
                />
              ))}
            </ul>
          </DataState>
        </CardContent>
      </Card>

      <SponsorTransferCard />
      <ShadowAICard />
    </div>
  );
}

interface TenantUserOption {
  id: string;
  email: string;
  display_name?: string | null;
}

function useTenantUserOptions() {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: ["agent-governance-users", tenantId],
    queryFn: () =>
      api<{ items: TenantUserOption[] }>("/v1/users", { query: { limit: "200" } }),
    enabled: !!tenantId,
    select: (data) =>
      data.items.map((u) => ({
        label: u.display_name ? `${u.display_name} · ${u.email}` : u.email,
        value: u.id,
      })),
  });
}

function SponsorTransferCard() {
  const [confirmDialog, openConfirm] = useConfirmDialog();
  const usersQ = useTenantUserOptions();
  const [fromUserId, setFromUserId] = useState<string | null>(null);
  const [toUserId, setToUserId] = useState<string | null>(null);
  const sponsoredQ = useAgentsSponsoredBy(fromUserId);
  const transferM = useTransferSponsor();

  const sponsoredCount = sponsoredQ.data?.items.length ?? 0;

  return (
    <>
      {confirmDialog}
      <Card>
      <CardHeader>
        <CardTitle className="text-base">Sponsor transfer</CardTitle>
        <CardDescription>
          Every agent has a named human sponsor. When a sponsor is offboarded, reassign
          everything they own to a new sponsor in one call — no agent is left ownerless.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="flex flex-col gap-3 sm:flex-row sm:items-end">
          <Field className="flex-1">
            <FieldLabel htmlFor="sponsor-from">From (departing sponsor)</FieldLabel>
            <Combobox
              id="sponsor-from"
              items={usersQ.data ?? []}
              value={fromUserId}
              onValueChange={setFromUserId}
              placeholder="Search users…"
              emptyMessage="No users found."
            />
          </Field>
          <Field className="flex-1">
            <FieldLabel htmlFor="sponsor-to">To (new sponsor)</FieldLabel>
            <Combobox
              id="sponsor-to"
              items={usersQ.data ?? []}
              value={toUserId}
              onValueChange={setToUserId}
              placeholder="Search users…"
              emptyMessage="No users found."
            />
          </Field>
          <Button
            disabled={
              !fromUserId ||
              !toUserId ||
              fromUserId === toUserId ||
              sponsoredCount === 0 ||
              transferM.isPending
            }
            onClick={() => {
              if (!fromUserId || !toUserId) return;
              openConfirm({
                title: `Transfer ${sponsoredCount} agent(s) to the new sponsor?`,
                description: "This can't be undone.",
                variant: "destructive",
                confirmLabel: "Transfer",
                onConfirm: () =>
                  transferM.mutate(
                    { fromUserId, toUserId },
                    { onSuccess: () => { setFromUserId(null); setToUserId(null); } },
                  ),
              });
            }}
          >
            {transferM.isPending && <Loader2Icon className="animate-spin" />}
            <ArrowRightLeftIcon />
            Transfer
          </Button>
        </div>
        {fromUserId && (
          <p className="mt-2 text-sm text-muted-foreground">
            {sponsoredQ.isLoading
              ? "Checking…"
              : `${sponsoredCount} agent(s) sponsored by this user will move.`}
          </p>
        )}
        {transferM.error && (
          <p className="mt-2 text-destructive text-sm">
            {(transferM.error as ApiError).message}
          </p>
        )}
      </CardContent>
    </Card>
    </>
  );
}

function ShadowAICard() {
  const candidatesQ = useShadowAICandidates();
  const reviewM = useReviewShadowAIClient();
  const items = candidatesQ.data?.items ?? [];

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Shadow AI discovery</CardTitle>
        <CardDescription>
          OAuth clients that picked up a machine grant type (client_credentials /
          token-exchange) without ever going through the agents/service-accounts registry —
          unmanaged automation acting under this tenant, ranked by live grants.
        </CardDescription>
      </CardHeader>
      <CardContent className="p-0">
        <DataState
          isLoading={candidatesQ.isLoading}
          isError={candidatesQ.isError}
          error={candidatesQ.error}
          isEmpty={items.length === 0}
          emptyIcon={ShieldAlertIcon}
          emptyTitle="No unreviewed candidates."
          emptyDescription="Every machine-grant OIDC client has been acknowledged."
          skeletonRows={2}
        >
          <ul className="divide-y">
            {items.map((c) => (
              <li key={c.id} className="flex items-center justify-between gap-4 px-6 py-3">
                <div className="min-w-0">
                  <p className="text-sm font-medium">{c.name}</p>
                  <p className="truncate text-xs text-muted-foreground">
                    <span className="font-mono">{c.client_id}</span> · {c.grant_types.join(", ")}{" "}
                    · {c.live_grants} live grant{c.live_grants === 1 ? "" : "s"}
                  </p>
                </div>
                <Button
                  variant="ghost"
                  size="sm"
                  disabled={reviewM.isPending}
                  onClick={() => reviewM.mutate(c.id)}
                >
                  Acknowledge
                </Button>
              </li>
            ))}
          </ul>
        </DataState>
      </CardContent>
    </Card>
  );
}

function AgentRow({
  agent: a,
  onToggle,
  onDelete,
  busy,
}: {
  agent: Agent;
  onToggle: () => void;
  onDelete: () => void;
  busy: boolean;
}) {
  return (
    <li className="flex items-center justify-between gap-4 px-6 py-3">
      <div className="min-w-0">
        <p className="flex items-center gap-2 text-sm font-medium">
          {a.name}
          {a.disabled ? (
            <Badge variant="outline" className="text-amber-600 border-amber-400">
              Suspended
            </Badge>
          ) : (
            <Badge variant="outline" className="text-green-600 border-green-400">
              Active
            </Badge>
          )}
        </p>
        <p className="truncate text-xs text-muted-foreground">
          <span className="font-mono">{a.id}</span> · {a.token_ttl_seconds}s ·{" "}
          {a.scopes.length ? a.scopes.join(" ") : "no scopes"}
        </p>
      </div>
      <div className="flex items-center gap-1">
        <Button
          variant="ghost"
          size="sm"
          disabled={busy}
          onClick={onToggle}
          title={a.disabled ? "Resume agent" : "Suspend agent"}
        >
          {a.disabled ? <PlayIcon /> : <PauseIcon />}
          {a.disabled ? "Resume" : "Suspend"}
        </Button>
        <Button
          variant="ghost"
          size="sm"
          disabled={busy}
          onClick={onDelete}
        >
          <Trash2Icon /> Delete
        </Button>
      </div>
    </li>
  );
}
