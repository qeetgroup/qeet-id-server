import {
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  DataState,
  Field,
  FieldDescription,
  FieldLabel,
  Input,
  StatusPill,
  Switch,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  TimeSince,
} from "@qeetrix/ui";
import { createFileRoute } from "@tanstack/react-router";
import { CheckIcon, CopyIcon, KeyRoundIcon, RefreshCwIcon, UsersIcon } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { useConfirmDialog } from "@/components/confirm-dialog";
import { PageHeader } from "@/components/page-header";
import {
  SCIM_BASE_URL,
  useRevokeScimToken,
  useRotateScimToken,
  useScimConfig,
  useScimProvisionedUsers,
} from "@/lib/scim";

export const Route = createFileRoute("/_app/auth/connections/scim")({ component: ScimPage });

function ScimPage() {
  const { t } = useTranslation("auth");
  const [confirmDialog, openConfirm] = useConfirmDialog();
  const cfgQ = useScimConfig();
  const usersQ = useScimProvisionedUsers();
  const rotateM = useRotateScimToken();
  const revokeM = useRevokeScimToken();

  const config = cfgQ.data;
  const enabled = config?.token_set ?? false;
  const busy = rotateM.isPending || revokeM.isPending || cfgQ.isLoading;

  const [copied, setCopied] = useState<string | null>(null);
  const copy = (label: string, value: string) => {
    void navigator.clipboard?.writeText(value);
    setCopied(label);
    window.setTimeout(() => setCopied((c) => (c === label ? null : c)), 1500);
  };

  const toggle = (next: boolean) => {
    if (next) {
      if (!enabled) rotateM.mutate();
      return;
    }
    openConfirm({
      title: t("scim.disable.title"),
      description: t("scim.disable.description"),
      variant: "destructive",
      confirmLabel: t("scim.disable.label"),
      onConfirm: () => revokeM.mutate(),
    });
  };

  const users = usersQ.data?.items ?? [];
  const freshToken = rotateM.data?.token;

  return (
    <div className="flex min-w-0 flex-col gap-6">
      {confirmDialog}
      <PageHeader
        description={t("scim.description")}
        actions={
          <div className="flex items-center gap-2">
            <span className="text-sm text-muted-foreground">{t("scim.endpointEnabled")}</span>
            <Switch checked={enabled} onCheckedChange={toggle} disabled={busy} />
          </div>
        }
      />

      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardDescription>{t("scim.stats.provisioned")}</CardDescription>
            <UsersIcon className="size-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold tracking-tight">
              {config?.provisioned_count ?? "—"}
            </div>
            <p className="text-xs text-muted-foreground">{t("scim.stats.provisionedHelp")}</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardDescription>{t("scim.stats.status")}</CardDescription>
            <KeyRoundIcon className="size-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <StatusPill status={enabled ? "active" : "disabled"} />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardDescription>{t("scim.stats.lastSync")}</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold tracking-tight">
              {config?.last_used_at ? <TimeSince value={config.last_used_at} /> : t("scim.stats.never")}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* One-time token reveal, shown only immediately after rotation. */}
      {freshToken && (
        <Card className="border-primary">
          <CardHeader>
            <CardTitle className="text-base">{t("scim.token.title")}</CardTitle>
            <CardDescription>
              {t("scim.token.description")}
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-3">
            <div className="flex gap-2">
              <Input value={freshToken} readOnly className="font-mono text-xs" />
              <Button variant="outline" size="icon" onClick={() => copy("new", freshToken)}>
                {copied === "new" ? <CheckIcon className="size-4" /> : <CopyIcon className="size-4" />}
              </Button>
            </div>
            <div>
              <Button variant="outline" size="sm" onClick={() => rotateM.reset()}>
                {t("scim.token.saved")}
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle>{t("scim.endpoint.title")}</CardTitle>
          <CardDescription>
            {t("scim.endpoint.description")}
          </CardDescription>
        </CardHeader>
        <CardContent className="grid gap-4">
          <Field>
            <FieldLabel>{t("scim.endpoint.baseUrlLabel")}</FieldLabel>
            <div className="flex gap-2">
              <Input value={SCIM_BASE_URL} readOnly className="font-mono text-xs" />
              <Button variant="outline" size="icon" onClick={() => copy("url", SCIM_BASE_URL)}>
                {copied === "url" ? <CheckIcon className="size-4" /> : <CopyIcon className="size-4" />}
              </Button>
            </div>
            <FieldDescription>
              Append <code>/Users</code> for the resource endpoint. The IdP authenticates with the
              bearer token below.
            </FieldDescription>
          </Field>

          <Field>
            <FieldLabel>{t("scim.endpoint.bearerLabel")}</FieldLabel>
            <div className="flex gap-2">
              <Input
                value={
                  enabled
                    ? `${config?.token_prefix ?? "qf_scim_"}••••••••••••••••••••••••`
                    : t("scim.endpoint.noToken")
                }
                readOnly
                className="font-mono text-xs"
              />
              <Button variant="outline" onClick={() => rotateM.mutate()} disabled={busy}>
                <RefreshCwIcon className={rotateM.isPending ? "mr-2 size-4 animate-spin" : "mr-2 size-4"} />
                {enabled ? t("scim.endpoint.rotate") : t("scim.endpoint.generate")}
              </Button>
            </div>
            <FieldDescription>
              {enabled
                ? t("scim.endpoint.rotateHelp")
                : t("scim.endpoint.generateHelp")}
            </FieldDescription>
          </Field>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>{t("scim.users.title")}</CardTitle>
          <CardDescription>
            Users created or deprovisioned over SCIM. Deactivations (<code>active=false</code>) move a
            user to suspended and terminate their sessions.
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <DataState
            isLoading={usersQ.isLoading}
            isError={usersQ.isError}
            error={usersQ.error}
            isEmpty={users.length === 0}
            emptyIcon={UsersIcon}
            emptyTitle={t("scim.users.empty")}
            skeletonRows={3}
          >
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t("scim.columns.user")}</TableHead>
                  <TableHead>{t("scim.columns.externalId")}</TableHead>
                  <TableHead>{t("scim.columns.status")}</TableHead>
                  <TableHead>{t("scim.columns.created")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {users.map((u) => (
                  <TableRow key={u.id}>
                    <TableCell>
                      <div className="font-medium">{u.display_name || u.email}</div>
                      {u.display_name && (
                        <div className="text-xs text-muted-foreground">{u.email}</div>
                      )}
                    </TableCell>
                    <TableCell className="max-w-55 truncate font-mono text-xs text-muted-foreground">
                      {u.external_id || "—"}
                    </TableCell>
                    <TableCell>
                      <StatusPill status={u.status} />
                    </TableCell>
                    <TableCell>
                      <TimeSince value={u.created_at} />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </DataState>
        </CardContent>
      </Card>
    </div>
  );
}
