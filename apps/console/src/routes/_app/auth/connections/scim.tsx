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
    if (
      window.confirm(
        "Disable SCIM provisioning? The current token is revoked and your IdP will stop syncing.",
      )
    ) {
      revokeM.mutate();
    }
  };

  const users = usersQ.data?.items ?? [];
  const freshToken = rotateM.data?.token;

  return (
    <div className="flex min-w-0 flex-col gap-6">
      <PageHeader
        description="SCIM 2.0 endpoint for automated provisioning and deprovisioning from your IdP."
        actions={
          <div className="flex items-center gap-2">
            <span className="text-sm text-muted-foreground">Endpoint enabled</span>
            <Switch checked={enabled} onCheckedChange={toggle} disabled={busy} />
          </div>
        }
      />

      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardDescription>Provisioned users</CardDescription>
            <UsersIcon className="size-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold tracking-tight">
              {config?.provisioned_count ?? "—"}
            </div>
            <p className="text-xs text-muted-foreground">Created or managed over SCIM</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardDescription>Status</CardDescription>
            <KeyRoundIcon className="size-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <StatusPill status={enabled ? "active" : "disabled"} />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardDescription>Last sync</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold tracking-tight">
              {config?.last_used_at ? <TimeSince value={config.last_used_at} /> : "Never"}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* One-time token reveal, shown only immediately after rotation. */}
      {freshToken && (
        <Card className="border-primary">
          <CardHeader>
            <CardTitle className="text-base">Your new SCIM bearer token</CardTitle>
            <CardDescription>
              Copy it now — for security it is shown once and cannot be retrieved again.
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
                I&apos;ve saved it
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle>Endpoint &amp; token</CardTitle>
          <CardDescription>
            Paste these into Okta / Entra ID / Google when configuring the SCIM app.
          </CardDescription>
        </CardHeader>
        <CardContent className="grid gap-4">
          <Field>
            <FieldLabel>SCIM base URL</FieldLabel>
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
            <FieldLabel>Bearer token</FieldLabel>
            <div className="flex gap-2">
              <Input
                value={
                  enabled
                    ? `${config?.token_prefix ?? "qf_scim_"}••••••••••••••••••••••••`
                    : "No token — provisioning disabled"
                }
                readOnly
                className="font-mono text-xs"
              />
              <Button variant="outline" onClick={() => rotateM.mutate()} disabled={busy}>
                <RefreshCwIcon className={rotateM.isPending ? "mr-2 size-4 animate-spin" : "mr-2 size-4"} />
                {enabled ? "Rotate" : "Generate"}
              </Button>
            </div>
            <FieldDescription>
              {enabled
                ? "Rotating immediately invalidates the previous token; update your IdP afterwards."
                : "Generate a token to enable the SCIM endpoint."}
            </FieldDescription>
          </Field>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Provisioned users</CardTitle>
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
            emptyTitle="No users provisioned over SCIM yet."
            skeletonRows={3}
          >
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>User</TableHead>
                  <TableHead>External ID</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Created</TableHead>
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
                    <TableCell className="max-w-[220px] truncate font-mono text-xs text-muted-foreground">
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
