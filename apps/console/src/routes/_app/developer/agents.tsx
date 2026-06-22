import {
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  CopyableSecret,
  DataState,
  Field,
  FieldLabel,
  Input,
} from "@qeetrix/ui";
import { createFileRoute } from "@tanstack/react-router";
import { Loader2Icon, SparklesIcon, Trash2Icon } from "lucide-react";
import { useState } from "react";

import { PageHeader } from "@/components/page-header";
import { ApiError } from "@/lib/api";
import { useAgents, useCreateAgent, useDeleteAgent, type Agent } from "@/lib/agents";

export const Route = createFileRoute("/_app/developer/agents")({ component: AgentsPage });

function AgentsPage() {
  const agentsQ = useAgents();
  const createM = useCreateAgent();
  const deleteM = useDeleteAgent();

  const [name, setName] = useState("");
  const [scopes, setScopes] = useState("");
  const [ttl, setTtl] = useState(600);
  const [created, setCreated] = useState<Agent | null>(null);

  const items = agentsQ.data?.items ?? [];

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <PageHeader description="First-class identities for AI agents / MCP clients. An agent authenticates with its secret at POST /v1/agents/token and gets a short-lived, scoped token marked actor_type=&ldquo;agent&rdquo; — ephemeral by design (re-mint, no refresh)." />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Create an agent</CardTitle>
          <CardDescription>
            The secret is shown once. Scopes are space-separated; token lifetime is clamped to
            60&ndash;3600s.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form
            className="flex flex-col gap-3"
            onSubmit={(e) => {
              e.preventDefault();
              if (name.trim()) {
                createM.mutate(
                  {
                    name: name.trim(),
                    scopes: scopes.trim() ? scopes.trim().split(/\s+/) : [],
                    token_ttl_seconds: ttl,
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
              <Button type="submit" disabled={createM.isPending || !name.trim()}>
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
        <CardHeader>
          <CardTitle className="text-base">Agents</CardTitle>
          <CardDescription>Active AI-agent identities in this tenant.</CardDescription>
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
                <li key={a.id} className="flex items-center justify-between gap-4 px-6 py-3">
                  <div className="min-w-0">
                    <p className="flex items-center gap-2 text-sm font-medium">
                      {a.name}
                      {a.disabled && <Badge variant="outline">disabled</Badge>}
                    </p>
                    <p className="truncate text-xs text-muted-foreground">
                      <span className="font-mono">{a.id}</span> · {a.token_ttl_seconds}s ·{" "}
                      {a.scopes.length ? a.scopes.join(" ") : "no scopes"}
                    </p>
                  </div>
                  <Button
                    variant="ghost"
                    size="sm"
                    disabled={deleteM.isPending}
                    onClick={() => {
                      if (confirm(`Delete agent "${a.name}"?`)) deleteM.mutate(a.id);
                    }}
                  >
                    <Trash2Icon /> Delete
                  </Button>
                </li>
              ))}
            </ul>
          </DataState>
        </CardContent>
      </Card>
    </div>
  );
}
