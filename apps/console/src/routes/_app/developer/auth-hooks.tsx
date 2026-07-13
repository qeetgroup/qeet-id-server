import {
  Badge,
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
  Switch,
  TimeSince,
} from "@qeetrix/ui";
import { createFileRoute } from "@tanstack/react-router";
import { Loader2Icon, Trash2Icon, ZapIcon } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { useConfirmDialog } from "@/components/confirm-dialog";
import { PageHeader } from "@/components/page-header";
import type { ApiError } from "@/lib/api";
import {
  useAuthHooks,
  useCreateAuthHook,
  useDeleteAuthHook,
  useUpdateAuthHook,
} from "@/lib/auth-hooks";

export const Route = createFileRoute("/_app/developer/auth-hooks")({
  component: AuthHooksPage,
});

function AuthHooksPage() {
  const { t } = useTranslation("developer");
  const [confirmDialog, openConfirm] = useConfirmDialog();
  const hooksQ = useAuthHooks();
  const createM = useCreateAuthHook();
  const updateM = useUpdateAuthHook();
  const deleteM = useDeleteAuthHook();

  const [url, setUrl] = useState("");
  const [secret, setSecret] = useState("");
  const [failOpen, setFailOpen] = useState(true);

  const items = hooksQ.data?.items ?? [];

  return (
    <div className="flex min-w-0 flex-col gap-4">
      {confirmDialog}
      <PageHeader description={t("authHooks.description")} />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">{t("authHooks.add.title")}</CardTitle>
          <CardDescription>{t("authHooks.add.description")}</CardDescription>
        </CardHeader>
        <CardContent>
          <form
            className="flex flex-col gap-3"
            onSubmit={(e) => {
              e.preventDefault();
              if (url.trim()) {
                createM.mutate(
                  {
                    url: url.trim(),
                    secret: secret.trim(),
                    fail_open: failOpen,
                  },
                  {
                    onSuccess: () => {
                      setUrl("");
                      setSecret("");
                    },
                  },
                );
              }
            }}
          >
            <div className="flex flex-col gap-3 sm:flex-row sm:items-end">
              <Field className="flex-1">
                <FieldLabel htmlFor="hook-url">{t("authHooks.add.url")}</FieldLabel>
                <Input
                  id="hook-url"
                  placeholder={t("authHooks.add.urlPlaceholder")}
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                />
              </Field>
              <Field className="sm:w-56">
                <FieldLabel htmlFor="hook-secret">{t("authHooks.add.secret")}</FieldLabel>
                <Input
                  id="hook-secret"
                  type="password"
                  placeholder={t("authHooks.add.secretPlaceholder")}
                  value={secret}
                  onChange={(e) => setSecret(e.target.value)}
                />
              </Field>
              <Button type="submit" disabled={createM.isPending || !url.trim()}>
                {createM.isPending && <Loader2Icon className="animate-spin" />}
                {t("authHooks.add.submit")}
              </Button>
            </div>
            <Field>
              <div className="flex items-center justify-between gap-4">
                <div>
                  <FieldLabel>{t("authHooks.add.failOpen")}</FieldLabel>
                  <FieldDescription>{t("authHooks.add.failOpenDescription")}</FieldDescription>
                </div>
                <Switch
                  checked={failOpen}
                  aria-label={t("authHooks.add.failOpenAriaLabel")}
                  onCheckedChange={setFailOpen}
                />
              </div>
            </Field>
          </form>
          {createM.error && (
            <p className="mt-2 text-destructive text-sm">{(createM.error as ApiError).message}</p>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">{t("authHooks.list.title")}</CardTitle>
          <CardDescription>{t("authHooks.list.description")}</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <DataState
            isLoading={hooksQ.isLoading}
            isError={hooksQ.isError}
            error={hooksQ.error}
            isEmpty={items.length === 0}
            emptyIcon={ZapIcon}
            emptyTitle={t("authHooks.list.empty")}
            emptyDescription={t("authHooks.list.emptyDescription")}
            skeletonRows={2}
          >
            <ul className="divide-y">
              {items.map((h) => (
                <li key={h.id} className="flex items-center justify-between gap-4 px-6 py-3">
                  <div className="min-w-0">
                    <p className="flex items-center gap-2 text-sm font-medium">
                      <span className="truncate font-mono">{h.url}</span>
                      <Badge variant={h.fail_open ? "outline" : "destructive"}>
                        {h.fail_open
                          ? t("authHooks.list.failOpen")
                          : t("authHooks.list.failClosed")}
                      </Badge>
                    </p>
                    <p className="text-xs text-muted-foreground">
                      {h.trigger} · added <TimeSince value={h.created_at} />
                    </p>
                  </div>
                  <div className="flex items-center gap-3">
                    <Switch
                      checked={h.enabled}
                      aria-label={t("authHooks.list.enabledAriaLabel")}
                      disabled={updateM.isPending}
                      onCheckedChange={(v) =>
                        updateM.mutate({
                          id: h.id,
                          enabled: v,
                          fail_open: h.fail_open,
                        })
                      }
                    />
                    <Button
                      variant="ghost"
                      size="sm"
                      disabled={deleteM.isPending}
                      onClick={() =>
                        openConfirm({
                          title: t("authHooks.confirm.removeTitle"),
                          variant: "destructive",
                          confirmLabel: t("authHooks.confirm.removeLabel"),
                          onConfirm: () => deleteM.mutate(h.id),
                        })
                      }
                    >
                      <Trash2Icon /> {t("authHooks.list.remove")}
                    </Button>
                  </div>
                </li>
              ))}
            </ul>
          </DataState>
        </CardContent>
      </Card>
    </div>
  );
}
