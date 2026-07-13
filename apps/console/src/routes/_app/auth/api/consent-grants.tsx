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
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  TimeSince,
} from "@qeetrix/ui";
import { createFileRoute } from "@tanstack/react-router";
import { KeyRoundIcon, Loader2Icon, RefreshCwIcon, Trash2Icon } from "lucide-react";
import { useState } from "react";
import { Trans, useTranslation } from "react-i18next";

import { PageHeader } from "@/components/page-header";
import { type OAuthGrant, useOAuthGrants, useRevokeOAuthGrant } from "@/lib/oauth-grants";

export const Route = createFileRoute("/_app/auth/api/consent-grants")({
  component: ConsentGrantsPage,
});

function ConsentGrantsPage() {
  const { t } = useTranslation("consent");
  const listQ = useOAuthGrants();
  const revokeM = useRevokeOAuthGrant();
  const [confirming, setConfirming] = useState<OAuthGrant | null>(null);

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
            emptyIcon={KeyRoundIcon}
            emptyTitle={t("list.emptyTitle")}
            emptyDescription={t("list.emptyDescription")}
            skeletonRows={3}
          >
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t("table.application")}</TableHead>
                  <TableHead>{t("table.user")}</TableHead>
                  <TableHead>{t("table.scopes")}</TableHead>
                  <TableHead>{t("table.issued")}</TableHead>
                  <TableHead>{t("table.expires")}</TableHead>
                  <TableHead className="text-right">{t("table.actions")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((g) => (
                  <TableRow key={g.id}>
                    <TableCell className="font-mono text-xs text-muted-foreground">
                      {g.client_id.slice(0, 16)}…
                    </TableCell>
                    <TableCell className="font-medium">{g.user_email}</TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        {g.scopes.map((s) => (
                          <Badge key={s} variant="muted">
                            {s}
                          </Badge>
                        ))}
                      </div>
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      <TimeSince value={g.issued_at} />
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      <TimeSince value={g.expires_at} />
                    </TableCell>
                    <TableCell className="text-right">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => setConfirming(g)}
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
                  values={{ email: confirming.user_email }}
                  components={{
                    strong: <span className="font-medium text-foreground" />,
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
