import {
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  Field,
  FieldDescription,
  FieldError,
  FieldGroup,
  FieldLabel,
  Input,
  Sheet,
  SheetClose,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
  Skeleton,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  Textarea,
} from "@qeetrix/ui";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";
import {
  Loader2Icon,
  PlusIcon,
  RefreshCwIcon,
  ScrollTextIcon,
  ShieldCheckIcon,
} from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { useConfirmDialog } from "@/components/confirm-dialog";
import { PageHeader } from "@/components/page-header";
import { type ApiError, api } from "@/lib/api";
import { useTenantId } from "@/lib/auth";

export const Route = createFileRoute("/_app/security/compliance/gdpr")({
  component: GdprPage,
});

type PurgeRequest = {
  id: string;
  tenant_id: string;
  user_id: string;
  requested_by?: string | null;
  reason?: string | null;
  status: "pending" | "completed" | "cancelled";
  grace_until: string;
  completed_at?: string | null;
  created_at: string;
};

function GdprPage() {
  const { t } = useTranslation("compliance");
  const [confirmDialog, openConfirm] = useConfirmDialog();
  const tenantId = useTenantId();
  const qc = useQueryClient();
  const [creating, setCreating] = useState(false);

  const listQ = useQuery({
    queryKey: ["gdpr-purges", tenantId],
    queryFn: () => api<{ items: PurgeRequest[] }>(`/v1/tenants/${tenantId}/gdpr/purge`),
    enabled: !!tenantId,
  });

  const cancelM = useMutation({
    mutationFn: (id: string) => api<void>(`/v1/gdpr/purge/${id}`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["gdpr-purges"] }),
  });

  const itemCount = listQ.data?.items?.length ?? 0;

  return (
    <div className="flex min-w-0 flex-col gap-4">
      {confirmDialog}
      <PageHeader
        description={t("gdpr.description")}
        actions={
          <>
            <Button
              variant="outline"
              size="sm"
              onClick={() => listQ.refetch()}
              disabled={listQ.isFetching}
            >
              <RefreshCwIcon className={listQ.isFetching ? "animate-spin" : ""} />
              {t("gdpr.refresh")}
            </Button>
            <Button size="sm" onClick={() => setCreating(true)}>
              <PlusIcon /> {t("gdpr.fileRequest")}
            </Button>
          </>
        }
      />

      <Card className="border-amber-500/40 bg-amber-50/30 dark:bg-amber-950/20">
        <CardContent className="flex items-start gap-3 p-4">
          <ShieldCheckIcon className="size-5 text-emerald-700 dark:text-emerald-500" />
          <div className="text-sm">
            <p className="font-medium">{t("gdpr.infoBanner.title")}</p>
            <p className="text-muted-foreground">{t("gdpr.infoBanner.description")}</p>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">{t("gdpr.list.title")}</CardTitle>
          <CardDescription>{t("gdpr.list.count", { count: itemCount })}</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {listQ.isLoading ? (
            <div className="space-y-3 p-4">
              {[...Array(3)].map((_, i) => (
                <Skeleton key={i} className="h-10 w-full" />
              ))}
            </div>
          ) : listQ.isError ? (
            <div className="p-6 text-sm text-destructive">{(listQ.error as Error).message}</div>
          ) : !listQ.data?.items?.length ? (
            <div className="flex flex-col items-center gap-2 p-10 text-center">
              <ScrollTextIcon className="size-8 text-muted-foreground" />
              <p className="text-sm text-muted-foreground">{t("gdpr.list.empty")}</p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t("gdpr.list.columns.user")}</TableHead>
                  <TableHead>{t("gdpr.list.columns.reason")}</TableHead>
                  <TableHead>{t("gdpr.list.columns.status")}</TableHead>
                  <TableHead>{t("gdpr.list.columns.graceUntil")}</TableHead>
                  <TableHead>{t("gdpr.list.columns.filed")}</TableHead>
                  <TableHead className="text-right">{t("gdpr.list.columns.actions")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {listQ.data.items.map((r) => {
                  const variant =
                    r.status === "completed"
                      ? "destructive"
                      : r.status === "cancelled"
                        ? "muted"
                        : "warning";
                  return (
                    <TableRow key={r.id}>
                      <TableCell className="font-mono text-xs text-muted-foreground">
                        {r.user_id.slice(0, 16)}…
                      </TableCell>
                      <TableCell
                        className="max-w-md truncate text-muted-foreground"
                        title={r.reason ?? ""}
                      >
                        {r.reason ?? "—"}
                      </TableCell>
                      <TableCell>
                        <Badge variant={variant}>{r.status}</Badge>
                      </TableCell>
                      <TableCell className="text-muted-foreground">
                        {new Date(r.grace_until).toLocaleDateString()}
                      </TableCell>
                      <TableCell className="text-muted-foreground">
                        {new Date(r.created_at).toLocaleDateString()}
                      </TableCell>
                      <TableCell className="text-right">
                        <Button
                          variant="ghost"
                          size="sm"
                          disabled={r.status !== "pending" || cancelM.isPending}
                          onClick={() =>
                            openConfirm({
                              title: t("gdpr.confirm.cancelTitle"),
                              variant: "default",
                              confirmLabel: t("gdpr.confirm.cancelLabel"),
                              onConfirm: () => cancelM.mutate(r.id),
                            })
                          }
                        >
                          {t("gdpr.list.cancelRequest")}
                        </Button>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <CreatePurgeSheet
        open={creating}
        onOpenChange={setCreating}
        tenantId={tenantId}
        onCreated={() => qc.invalidateQueries({ queryKey: ["gdpr-purges"] })}
      />
    </div>
  );
}

type CreatePurgeSheetProps = {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  tenantId: string | null;
  onCreated: () => void;
};

function CreatePurgeSheet({ open, onOpenChange, tenantId, onCreated }: CreatePurgeSheetProps) {
  const { t } = useTranslation("compliance");
  const createM = useMutation({
    mutationFn: (body: { tenant_id: string; user_id: string; reason: string }) =>
      api<PurgeRequest>("/v1/gdpr/purge", { method: "POST", body }),
    onSuccess: () => {
      onCreated();
      onOpenChange(false);
    },
  });

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="w-full sm:max-w-md">
        <form
          className="flex h-full flex-col"
          onSubmit={(e) => {
            e.preventDefault();
            if (!tenantId) return;
            const data = new FormData(e.currentTarget);
            createM.mutate({
              tenant_id: tenantId,
              user_id: String(data.get("user_id") ?? "").trim(),
              reason: String(data.get("reason") ?? "").trim(),
            });
          }}
        >
          <SheetHeader>
            <SheetTitle>{t("gdpr.create.title")}</SheetTitle>
            <SheetDescription>{t("gdpr.create.description")}</SheetDescription>
          </SheetHeader>
          <div className="flex-1 overflow-y-auto p-4">
            <FieldGroup>
              <Field>
                <FieldLabel htmlFor="user_id">{t("gdpr.create.userId")}</FieldLabel>
                <Input
                  id="user_id"
                  name="user_id"
                  pattern="[0-9a-fA-F-]{36}"
                  placeholder="00000000-0000-0000-0000-000000000000"
                  required
                />
                <FieldDescription>{t("gdpr.create.userIdHelp")}</FieldDescription>
              </Field>
              <Field>
                <FieldLabel htmlFor="reason">{t("gdpr.create.reason")}</FieldLabel>
                <Textarea
                  id="reason"
                  name="reason"
                  rows={4}
                  placeholder="User requested account deletion via support ticket #1234"
                />
                <FieldDescription>{t("gdpr.create.reasonHelp")}</FieldDescription>
              </Field>
              {createM.error && (
                <Field>
                  <FieldError>{(createM.error as ApiError).message}</FieldError>
                </Field>
              )}
            </FieldGroup>
          </div>
          <SheetFooter className="flex-row justify-end gap-2 border-t">
            <SheetClose render={<Button type="button" variant="outline" />}>
              {t("gdpr.create.cancel")}
            </SheetClose>
            <Button type="submit" disabled={createM.isPending}>
              {createM.isPending && <Loader2Icon className="animate-spin" />}
              {createM.isPending ? t("gdpr.create.submitting") : t("gdpr.create.submit")}
            </Button>
          </SheetFooter>
        </form>
      </SheetContent>
    </Sheet>
  );
}
