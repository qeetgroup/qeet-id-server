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
import { useTranslation } from "react-i18next";

import { useConfirmDialog } from "@/components/confirm-dialog";
import { PageHeader } from "@/components/page-header";
import {
  type Agent,
  useAgents,
  useAgentsSponsoredBy,
  useCreateAgent,
  useDeleteAgent,
  useKillAllAgents,
  useSetAgentDisabled,
  useTransferSponsor,
} from "@/lib/agents";
import { type ApiError, api } from "@/lib/api";
import { useMe, useTenantId } from "@/lib/auth";
import { useReviewShadowAIClient, useShadowAICandidates } from "@/lib/oidc-clients";

export const Route = createFileRoute("/_app/developer/agents")({
  component: AgentsPage,
});

function AgentsPage() {
  const { t } = useTranslation("developer");
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
      <PageHeader title="Agent Governance" description={t("agents.description")} />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">{t("agents.create.title")}</CardTitle>
          <CardDescription>{t("agents.create.description")}</CardDescription>
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
                <FieldLabel htmlFor="agent-name">{t("agents.create.name")}</FieldLabel>
                <Input
                  id="agent-name"
                  placeholder={t("agents.create.namePlaceholder")}
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                />
              </Field>
              <Field className="flex-1">
                <FieldLabel htmlFor="agent-scopes">{t("agents.create.scopes")}</FieldLabel>
                <Input
                  id="agent-scopes"
                  placeholder={t("agents.create.scopesPlaceholder")}
                  value={scopes}
                  onChange={(e) => setScopes(e.target.value)}
                />
              </Field>
              <Field className="sm:w-32">
                <FieldLabel htmlFor="agent-ttl">{t("agents.create.ttl")}</FieldLabel>
                <Input
                  id="agent-ttl"
                  type="number"
                  min={60}
                  max={3600}
                  value={ttl}
                  onChange={(e) => setTtl(Number(e.target.value) || 600)}
                />
              </Field>
              <Button type="submit" disabled={createM.isPending || !name.trim() || !sponsorId}>
                {createM.isPending && <Loader2Icon className="animate-spin" />}
                {t("agents.create.submit")}
              </Button>
            </div>
            {createM.error && (
              <p className="text-destructive text-sm">{(createM.error as ApiError).message}</p>
            )}
          </form>

          {created?.secret && (
            <div className="mt-4 rounded-lg border border-amber-500/40 bg-amber-50/40 p-4 dark:bg-amber-950/20">
              <p className="mb-2 text-sm font-medium">
                {t("agents.create.secretNotice", { name: created.name })}
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
            <CardTitle className="text-base">{t("agents.list.title")}</CardTitle>
            <CardDescription>{t("agents.list.description")}</CardDescription>
          </div>
          {activeCount > 0 && (
            <Button
              variant="destructive"
              size="sm"
              disabled={killAllM.isPending}
              onClick={() =>
                openConfirm({
                  title: t("agents.confirm.suspendAll", { count: activeCount }),
                  description: t("agents.confirm.suspendAllDescription"),
                  variant: "destructive",
                  confirmLabel: t("agents.confirm.suspendAllLabel"),
                  onConfirm: () => killAllM.mutate(),
                })
              }
            >
              {killAllM.isPending ? <Loader2Icon className="animate-spin" /> : <SkullIcon />}
              {t("agents.list.suspendAll")}
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
            emptyTitle={t("agents.list.empty")}
            emptyDescription={t("agents.list.emptyDescription")}
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
                      title: t("agents.confirm.delete", { name: a.name }),
                      variant: "destructive",
                      confirmLabel: t("agents.confirm.deleteLabel"),
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
      api<{ items: TenantUserOption[] }>("/v1/users", {
        query: { limit: "200" },
      }),
    enabled: !!tenantId,
    select: (data) =>
      data.items.map((u) => ({
        label: u.display_name ? `${u.display_name} · ${u.email}` : u.email,
        value: u.id,
      })),
  });
}

function SponsorTransferCard() {
  const { t } = useTranslation("developer");
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
          <CardTitle className="text-base">{t("agents.sponsor.title")}</CardTitle>
          <CardDescription>{t("agents.sponsor.description")}</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex flex-col gap-3 sm:flex-row sm:items-end">
            <Field className="flex-1">
              <FieldLabel htmlFor="sponsor-from">{t("agents.sponsor.from")}</FieldLabel>
              <Combobox
                id="sponsor-from"
                items={usersQ.data ?? []}
                value={fromUserId}
                onValueChange={setFromUserId}
                placeholder={t("agents.sponsor.search")}
                emptyMessage={t("agents.sponsor.noUsers")}
              />
            </Field>
            <Field className="flex-1">
              <FieldLabel htmlFor="sponsor-to">{t("agents.sponsor.to")}</FieldLabel>
              <Combobox
                id="sponsor-to"
                items={usersQ.data ?? []}
                value={toUserId}
                onValueChange={setToUserId}
                placeholder={t("agents.sponsor.search")}
                emptyMessage={t("agents.sponsor.noUsers")}
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
                  title: t("agents.sponsor.confirm.title", {
                    count: sponsoredCount,
                  }),
                  description: t("agents.sponsor.confirm.description"),
                  variant: "destructive",
                  confirmLabel: t("agents.sponsor.confirm.label"),
                  onConfirm: () =>
                    transferM.mutate(
                      { fromUserId, toUserId },
                      {
                        onSuccess: () => {
                          setFromUserId(null);
                          setToUserId(null);
                        },
                      },
                    ),
                });
              }}
            >
              {transferM.isPending && <Loader2Icon className="animate-spin" />}
              <ArrowRightLeftIcon />
              {t("agents.sponsor.transfer")}
            </Button>
          </div>
          {fromUserId && (
            <p className="mt-2 text-sm text-muted-foreground">
              {sponsoredQ.isLoading
                ? t("agents.sponsor.checking")
                : t("agents.sponsor.count", { count: sponsoredCount })}
            </p>
          )}
          {transferM.error && (
            <p className="mt-2 text-destructive text-sm">{(transferM.error as ApiError).message}</p>
          )}
        </CardContent>
      </Card>
    </>
  );
}

function ShadowAICard() {
  const { t } = useTranslation("developer");
  const candidatesQ = useShadowAICandidates();
  const reviewM = useReviewShadowAIClient();
  const items = candidatesQ.data?.items ?? [];

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">{t("agents.shadow.title")}</CardTitle>
        <CardDescription>{t("agents.shadow.description")}</CardDescription>
      </CardHeader>
      <CardContent className="p-0">
        <DataState
          isLoading={candidatesQ.isLoading}
          isError={candidatesQ.isError}
          error={candidatesQ.error}
          isEmpty={items.length === 0}
          emptyIcon={ShieldAlertIcon}
          emptyTitle={t("agents.shadow.empty")}
          emptyDescription={t("agents.shadow.emptyDescription")}
          skeletonRows={2}
        >
          <ul className="divide-y">
            {items.map((c) => (
              <li key={c.id} className="flex items-center justify-between gap-4 px-6 py-3">
                <div className="min-w-0">
                  <p className="text-sm font-medium">{c.name}</p>
                  <p className="truncate text-xs text-muted-foreground">
                    <span className="font-mono">{c.client_id}</span> · {c.grant_types.join(", ")} ·{" "}
                    {t("agents.shadow.grants", { count: c.live_grants })}
                  </p>
                </div>
                <Button
                  variant="ghost"
                  size="sm"
                  disabled={reviewM.isPending}
                  onClick={() => reviewM.mutate(c.id)}
                >
                  {t("agents.shadow.acknowledge")}
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
  const { t } = useTranslation("developer");
  return (
    <li className="flex items-center justify-between gap-4 px-6 py-3">
      <div className="min-w-0">
        <p className="flex items-center gap-2 text-sm font-medium">
          {a.name}
          {a.disabled ? (
            <Badge variant="outline" className="text-amber-600 border-amber-400">
              {t("agents.row.suspended")}
            </Badge>
          ) : (
            <Badge variant="outline" className="text-green-600 border-green-400">
              {t("agents.row.active")}
            </Badge>
          )}
        </p>
        <p className="truncate text-xs text-muted-foreground">
          <span className="font-mono">{a.id}</span> · {a.token_ttl_seconds}s ·{" "}
          {a.scopes.length ? a.scopes.join(" ") : t("agents.row.noScopes")}
        </p>
      </div>
      <div className="flex items-center gap-1">
        <Button
          variant="ghost"
          size="sm"
          disabled={busy}
          onClick={onToggle}
          title={a.disabled ? t("agents.row.resumeTitle") : t("agents.row.suspendTitle")}
        >
          {a.disabled ? <PlayIcon /> : <PauseIcon />}
          {a.disabled ? t("agents.row.resume") : t("agents.row.suspend")}
        </Button>
        <Button variant="ghost" size="sm" disabled={busy} onClick={onDelete}>
          <Trash2Icon /> {t("agents.row.delete")}
        </Button>
      </div>
    </li>
  );
}
