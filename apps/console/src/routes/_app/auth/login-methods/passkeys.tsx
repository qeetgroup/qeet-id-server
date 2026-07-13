import {
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  Skeleton,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@qeetrix/ui";
import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { startRegistration } from "@simplewebauthn/browser";
import { FingerprintIcon, PlusIcon, RefreshCwIcon, Trash2Icon } from "lucide-react";
import { useTranslation } from "react-i18next";

import { useConfirmDialog } from "@/components/confirm-dialog";
import { PageHeader } from "@/components/page-header";
import { api } from "@/lib/api";

export const Route = createFileRoute("/_app/auth/login-methods/passkeys")({ component: PasskeysPage });

type Passkey = {
  id: string;
  user_id: string;
  name: string;
  transports?: string[] | null;
  last_used_at?: string | null;
  created_at: string;
};

function PasskeysPage() {
  const { t } = useTranslation("auth");
  const [confirmDialog, openConfirm] = useConfirmDialog();
  const qc = useQueryClient();

  const listQ = useQuery({
    queryKey: ["passkeys"],
    queryFn: () => api<{ items: Passkey[] }>("/v1/passkeys"),
  });

  const deleteM = useMutation({
    mutationFn: (id: string) => api<void>(`/v1/passkeys/${id}`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["passkeys"] }),
  });

  // Registration ceremony: ask the backend for creation options, drive the
  // browser WebAuthn API, then post the attestation back to finish.
  const registerM = useMutation({
    mutationFn: async () => {
      const begin = await api<{
        session_id: string;
        publicKey: Parameters<typeof startRegistration>[0]["optionsJSON"];
      }>("/v1/passkeys/register/begin", { method: "POST" });
      const credential = await startRegistration({ optionsJSON: begin.publicKey });
      const name = window.prompt(t("loginMethods.passkeys.promptName"), t("loginMethods.passkeys.promptDefault"))?.trim() || undefined;
      await api<void>("/v1/passkeys/register/finish", {
        method: "POST",
        body: { session_id: begin.session_id, credential, name },
      });
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ["passkeys"] }),
    onError: (e) => window.alert((e as Error).message),
  });

  return (
    <div className="flex min-w-0 flex-col gap-4">
      {confirmDialog}
      <PageHeader
        description={t("loginMethods.passkeys.description")}
        actions={
          <>
            <Button variant="outline" size="sm" onClick={() => listQ.refetch()} disabled={listQ.isFetching}>
              <RefreshCwIcon className={listQ.isFetching ? "animate-spin" : ""} />
              {t("loginMethods.passkeys.refreshBtn")}
            </Button>
            <Button size="sm" onClick={() => registerM.mutate()} disabled={registerM.isPending}>
              <PlusIcon /> {registerM.isPending ? t("loginMethods.passkeys.registeringBtn") : t("loginMethods.passkeys.registerBtn")}
            </Button>
          </>
        }
      />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">{t("loginMethods.passkeys.list.title")}</CardTitle>
          <CardDescription>
            {t("loginMethods.passkeys.list.count", { count: listQ.data?.items?.length ?? 0 })}
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {listQ.isLoading ? (
            <div className="space-y-3 p-4">{[...Array(3)].map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}</div>
          ) : listQ.isError ? (
            <div className="p-6 text-sm text-destructive">{(listQ.error as Error).message}</div>
          ) : !listQ.data?.items?.length ? (
            <div className="flex flex-col items-center gap-2 p-10 text-center">
              <FingerprintIcon className="size-8 text-muted-foreground" />
              <p className="text-sm text-muted-foreground">{t("loginMethods.passkeys.list.empty")}</p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t("loginMethods.passkeys.columns.name")}</TableHead>
                  <TableHead>{t("loginMethods.passkeys.columns.transports")}</TableHead>
                  <TableHead>{t("loginMethods.passkeys.columns.lastUsed")}</TableHead>
                  <TableHead>{t("loginMethods.passkeys.columns.created")}</TableHead>
                  <TableHead className="text-right">{t("loginMethods.passkeys.columns.actions")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {listQ.data.items.map((p) => (
                  <TableRow key={p.id}>
                    <TableCell className="font-medium">{p.name}</TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        {(p.transports ?? []).map((transport) => <Badge key={transport} variant="muted">{transport}</Badge>)}
                      </div>
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      {p.last_used_at ? new Date(p.last_used_at).toLocaleString() : t("loginMethods.passkeys.lastUsedNever")}
                    </TableCell>
                    <TableCell className="text-muted-foreground">{new Date(p.created_at).toLocaleDateString()}</TableCell>
                    <TableCell className="text-right">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() =>
                          openConfirm({
                            title: t("loginMethods.passkeys.confirm.title", { name: p.name }),
                            variant: "destructive",
                            confirmLabel: t("loginMethods.passkeys.confirm.label"),
                            onConfirm: () => deleteM.mutate(p.id),
                          })
                        }
                        disabled={deleteM.isPending}
                      >
                        <Trash2Icon /> {t("loginMethods.passkeys.removeBtn")}
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
