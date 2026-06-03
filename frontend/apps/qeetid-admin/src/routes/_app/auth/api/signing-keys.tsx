import {
  Badge,
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
} from "@qeetrix/ui";
import { createFileRoute } from "@tanstack/react-router";
import { InfoIcon, KeyRoundIcon } from "lucide-react";
import { Trans, useTranslation } from "react-i18next";

import { PageHeader } from "@/components/page-header";
import { useSigningKeys } from "@/lib/signing-keys";

export const Route = createFileRoute("/_app/auth/api/signing-keys")({ component: SigningKeysPage });

function SigningKeysPage() {
  const { t } = useTranslation("signingKeys");
  const keysQ = useSigningKeys();
  const keys = keysQ.data?.keys ?? [];

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <PageHeader title={t("page.title")} description={t("page.description")} />

      <Card className="border-blue-500/30 bg-blue-50/40 dark:bg-blue-950/20">
        <CardContent className="flex items-start gap-3 py-4">
          <InfoIcon className="mt-0.5 size-4 shrink-0 text-blue-600 dark:text-blue-400" />
          <p className="text-sm text-muted-foreground">
            <Trans
              t={t}
              i18nKey="notice"
              components={{
                activeState: <span className="font-medium text-foreground" />,
                retiredState: <span className="font-medium text-foreground" />,
              }}
            />
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">{t("list.title")}</CardTitle>
          <CardDescription>{t("list.count", { count: keys.length })}</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <DataState
            isLoading={keysQ.isLoading}
            isError={keysQ.isError}
            error={keysQ.error}
            isEmpty={keys.length === 0}
            emptyIcon={KeyRoundIcon}
            emptyTitle={t("list.emptyTitle")}
            skeletonRows={2}
          >
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t("table.kid")}</TableHead>
                  <TableHead>{t("table.algorithm")}</TableHead>
                  <TableHead>{t("table.use")}</TableHead>
                  <TableHead>{t("table.status")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {keys.map((k) => (
                  <TableRow key={k.kid}>
                    <TableCell className="font-mono text-xs">{k.kid}</TableCell>
                    <TableCell>
                      <Badge variant="secondary">{k.alg}</Badge>
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">{k.use}</TableCell>
                    <TableCell>
                      <StatusPill
                        status={k.status}
                        kind={k.status === "active" ? "success" : "muted"}
                      />
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
