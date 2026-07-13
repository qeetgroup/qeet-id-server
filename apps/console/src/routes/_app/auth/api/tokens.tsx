import {
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
import { KeyRoundIcon, Trash2Icon } from "lucide-react";
import { useTranslation } from "react-i18next";

import { useConfirmDialog } from "@/components/confirm-dialog";
import { PageHeader } from "@/components/page-header";
import { useOAuthGrants, useRevokeOAuthGrant } from "@/lib/oauth-grants";

export const Route = createFileRoute("/_app/auth/api/tokens")({
  component: TokensPage,
});

function TokensPage() {
  const { t } = useTranslation("auth");
  const [confirmDialog, openConfirm] = useConfirmDialog();
  const listQ = useOAuthGrants();
  const revokeM = useRevokeOAuthGrant();
  const items = listQ.data?.items ?? [];

  return (
    <div className="flex min-w-0 flex-col gap-6">
      {confirmDialog}
      <PageHeader description={t("tokens.description")} />

      <Card>
        <CardHeader>
          <CardTitle>{t("tokens.list.title")}</CardTitle>
          <CardDescription>{t("tokens.list.count", { count: items.length })}</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <DataState
            isLoading={listQ.isLoading}
            isError={listQ.isError}
            error={listQ.error}
            isEmpty={items.length === 0}
            emptyIcon={KeyRoundIcon}
            emptyTitle={t("tokens.list.empty")}
            skeletonRows={3}
          >
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t("tokens.columns.client")}</TableHead>
                  <TableHead>{t("tokens.columns.user")}</TableHead>
                  <TableHead>{t("tokens.columns.scopes")}</TableHead>
                  <TableHead>{t("tokens.columns.issued")}</TableHead>
                  <TableHead>{t("tokens.columns.expires")}</TableHead>
                  <TableHead className="text-right">{t("tokens.columns.actions")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((g) => (
                  <TableRow key={g.id}>
                    <TableCell className="max-w-50 truncate font-mono text-xs">
                      {g.client_id}
                    </TableCell>
                    <TableCell>{g.user_email || g.user_id}</TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        {g.scopes.map((s) => (
                          <Badge key={s} variant="muted" className="text-xs">
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
                        onClick={() =>
                          openConfirm({
                            title: t("tokens.confirm.title", {
                              user: g.user_email || t("tokens.confirm.thisUser"),
                              client: g.client_id,
                            }),
                            variant: "destructive",
                            confirmLabel: t("tokens.confirm.label"),
                            onConfirm: () => revokeM.mutate(g.id),
                          })
                        }
                        disabled={revokeM.isPending}
                      >
                        <Trash2Icon /> {t("tokens.revoke")}
                      </Button>
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
