import {
  AlertDialog,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  DataState,
  StatusPill,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  TimeSince,
} from "@qeetrix/ui";
import { createFileRoute } from "@tanstack/react-router";
import { Loader2Icon, MonitorSmartphoneIcon, RefreshCwIcon, Trash2Icon } from "lucide-react";
import { useState } from "react";
import { Trans, useTranslation } from "react-i18next";

import { PageHeader } from "@/components/page-header";
import { type DeviceAuth, useDeviceAuthorizations, useRevokeDeviceAuth } from "@/lib/device-auth";

export const Route = createFileRoute("/_app/security/device-authorizations")({
  component: DeviceAuthorizationsPage,
});

function DeviceAuthorizationsPage() {
  const { t } = useTranslation("device");
  const listQ = useDeviceAuthorizations();
  const revokeM = useRevokeDeviceAuth();
  const [confirming, setConfirming] = useState<DeviceAuth | null>(null);

  const items = listQ.data?.items ?? [];

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <PageHeader
        title={t("page.title")}
        description={t("page.description")}
        actions={
          <Button
            variant="outline"
            size="sm"
            onClick={() => listQ.refetch()}
            disabled={listQ.isFetching}
          >
            <RefreshCwIcon className={listQ.isFetching ? "animate-spin" : ""} />
            {t("common:actions.refresh")}
          </Button>
        }
      />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">{t("list.title")}</CardTitle>
          <CardDescription>{t("list.count", { count: items.length })}</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <DataState
            isLoading={listQ.isLoading}
            isError={listQ.isError}
            error={listQ.error}
            isEmpty={items.length === 0}
            emptyIcon={MonitorSmartphoneIcon}
            emptyTitle={t("list.emptyTitle")}
            emptyDescription={t("list.emptyDescription")}
            skeletonRows={3}
          >
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t("table.clientId")}</TableHead>
                  <TableHead>{t("table.userCode")}</TableHead>
                  <TableHead>{t("table.status")}</TableHead>
                  <TableHead>{t("table.user")}</TableHead>
                  <TableHead>{t("table.scopes")}</TableHead>
                  <TableHead>{t("table.created")}</TableHead>
                  <TableHead>{t("table.expires")}</TableHead>
                  <TableHead className="text-right">{t("table.actions")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((d) => (
                  <TableRow key={d.id}>
                    <TableCell className="font-mono text-xs text-muted-foreground">
                      {d.client_id.slice(0, 16)}…
                    </TableCell>
                    <TableCell className="font-mono text-sm font-medium tracking-wider">
                      {d.user_code}
                    </TableCell>
                    <TableCell>
                      <StatusPill status={d.status} />
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {d.user_email || "—"}
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        {d.scopes.map((s) => (
                          <Badge key={s} variant="muted">
                            {s}
                          </Badge>
                        ))}
                      </div>
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      <TimeSince value={d.created_at} />
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      <TimeSince value={d.expires_at} />
                    </TableCell>
                    <TableCell className="text-right">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => setConfirming(d)}
                        disabled={revokeM.isPending}
                      >
                        <Trash2Icon /> {t("common:actions.revoke")}
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </DataState>
        </CardContent>
      </Card>

      <AlertDialog
        open={!!confirming}
        onOpenChange={(o) => {
          if (!o && !revokeM.isPending) setConfirming(null);
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t("revoke.title")}</AlertDialogTitle>
            <AlertDialogDescription>
              {confirming ? (
                <Trans
                  t={t}
                  i18nKey="revoke.descriptionNamed"
                  values={{ code: confirming.user_code }}
                  components={{
                    code: <span className="font-mono font-medium text-foreground" />,
                  }}
                />
              ) : (
                t("revoke.descriptionFallback")
              )}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={revokeM.isPending}>
              {t("common:actions.cancel")}
            </AlertDialogCancel>
            <Button
              variant="destructive"
              disabled={revokeM.isPending}
              onClick={() =>
                confirming &&
                revokeM.mutate(confirming.id, {
                  onSuccess: () => setConfirming(null),
                })
              }
            >
              {revokeM.isPending && <Loader2Icon className="animate-spin" />}
              {revokeM.isPending ? t("common:actions.revoking") : t("common:actions.revoke")}
            </Button>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
