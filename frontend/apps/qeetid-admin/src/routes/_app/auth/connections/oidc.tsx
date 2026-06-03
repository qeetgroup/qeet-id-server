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
  CopyableSecret,
  DataState,
  Field,
  FieldDescription,
  FieldError,
  FieldGroup,
  FieldLabel,
  Input,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Sheet,
  SheetClose,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  Textarea,
} from "@qeetrix/ui";
import { Link, createFileRoute } from "@tanstack/react-router";
import { Loader2Icon, PlusIcon, RefreshCwIcon, Trash2Icon, WorkflowIcon } from "lucide-react";
import { useState } from "react";
import { Trans, useTranslation } from "react-i18next";

import { PageHeader } from "@/components/page-header";
import { ApiError } from "@/lib/api";
import {
  type OidcClient,
  useCreateOidcClient,
  useDeleteOidcClient,
  useOidcClients,
} from "@/lib/oidc-clients";

export const Route = createFileRoute("/_app/auth/connections/oidc")({ component: OidcPage });

function OidcPage() {
  const { t } = useTranslation("oidc");
  const listQ = useOidcClients();
  const deleteM = useDeleteOidcClient();
  const [creating, setCreating] = useState(false);
  const [confirmingDelete, setConfirmingDelete] = useState<OidcClient | null>(null);
  const [revealed, setRevealed] = useState<{ client: OidcClient; secret: string } | null>(null);

  const items = listQ.data?.items ?? [];

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <PageHeader
        description={t("list.description")}
        actions={
          <>
            <Button
              variant="outline"
              size="sm"
              onClick={() => listQ.refetch()}
              disabled={listQ.isFetching}
            >
              <RefreshCwIcon className={listQ.isFetching ? "animate-spin" : ""} />
              {t("common:actions.refresh")}
            </Button>
            <Button size="sm" onClick={() => setCreating(true)}>
              <PlusIcon /> {t("list.register")}
            </Button>
          </>
        }
      />

      {revealed && (
        <Card className="border-emerald-500/40 bg-emerald-50/50 dark:bg-emerald-950/20">
          <CardHeader>
            <CardTitle className="text-base">
              {t("credentials.title", { name: revealed.client.name })}
            </CardTitle>
            <CardDescription>{t("credentials.description")}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-2">
            <CopyableSecret value={revealed.client.client_id} label="client_id=" size="sm" />
            <CopyableSecret value={revealed.secret} label="client_secret=" size="sm" />
            <Button variant="ghost" size="sm" onClick={() => setRevealed(null)}>
              {t("common:actions.dismiss")}
            </Button>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle className="text-base">{t("list.registeredTitle")}</CardTitle>
          <CardDescription>{t("list.appCount", { count: items.length })}</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <DataState
            isLoading={listQ.isLoading}
            isError={listQ.isError}
            error={listQ.error}
            isEmpty={items.length === 0}
            emptyIcon={WorkflowIcon}
            emptyTitle={t("list.emptyTitle")}
            emptyDescription={t("list.emptyDescription")}
            skeletonRows={3}
          >
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t("table.name")}</TableHead>
                  <TableHead>{t("table.clientId")}</TableHead>
                  <TableHead>{t("table.type")}</TableHead>
                  <TableHead>{t("table.redirectUris")}</TableHead>
                  <TableHead>{t("table.scopes")}</TableHead>
                  <TableHead className="text-right">{t("table.actions")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((c) => (
                  <TableRow key={c.id}>
                    <TableCell className="font-medium">
                      <Link
                        to="/auth/connections/oidc/$clientId"
                        params={{ clientId: c.client_id }}
                        className="hover:underline"
                      >
                        {c.name}
                      </Link>
                    </TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">
                      {c.client_id.slice(0, 16)}…
                    </TableCell>
                    <TableCell>
                      <Badge variant={c.type === "confidential" ? "default" : "muted"}>
                        {c.type}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {c.redirect_uris.slice(0, 2).join(", ")}
                      {c.redirect_uris.length > 2 && ` +${c.redirect_uris.length - 2}`}
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        {c.scopes.slice(0, 3).map((s) => (
                          <Badge key={s} variant="muted">
                            {s}
                          </Badge>
                        ))}
                        {c.scopes.length > 3 && <Badge variant="muted">+{c.scopes.length - 3}</Badge>}
                      </div>
                    </TableCell>
                    <TableCell className="text-right whitespace-nowrap">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => setConfirmingDelete(c)}
                        disabled={deleteM.isPending}
                      >
                        <Trash2Icon /> {t("common:actions.delete")}
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </DataState>
        </CardContent>
      </Card>

      <CreateOidcSheet
        open={creating}
        onOpenChange={setCreating}
        onCreated={(client, secret) => {
          if (secret) setRevealed({ client, secret });
        }}
      />

      <AlertDialog
        open={!!confirmingDelete}
        onOpenChange={(o) => {
          if (!o && !deleteM.isPending) setConfirmingDelete(null);
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t("delete.title")}</AlertDialogTitle>
            <AlertDialogDescription>
              {confirmingDelete ? (
                <Trans
                  t={t}
                  i18nKey="delete.descriptionNamed"
                  values={{ name: confirmingDelete.name }}
                  components={{ strong: <span className="font-medium text-foreground" /> }}
                />
              ) : (
                t("delete.descriptionFallback")
              )}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleteM.isPending}>
              {t("common:actions.cancel")}
            </AlertDialogCancel>
            <Button
              variant="destructive"
              disabled={deleteM.isPending}
              onClick={() =>
                confirmingDelete &&
                deleteM.mutate(confirmingDelete.id, {
                  onSuccess: () => setConfirmingDelete(null),
                })
              }
            >
              {deleteM.isPending && <Loader2Icon className="animate-spin" />}
              {deleteM.isPending ? t("common:actions.deleting") : t("common:actions.delete")}
            </Button>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

type CreateOidcSheetProps = {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  onCreated: (c: OidcClient, secret: string) => void;
};

function CreateOidcSheet({ open, onOpenChange, onCreated }: CreateOidcSheetProps) {
  const { t } = useTranslation("oidc");
  const [type, setType] = useState<"public" | "confidential">("public");
  const createM = useCreateOidcClient();

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="w-full sm:max-w-lg">
        <form
          className="flex h-full flex-col"
          onSubmit={(e) => {
            e.preventDefault();
            const data = new FormData(e.currentTarget);
            const lines = (k: string) =>
              String(data.get(k) ?? "")
                .split(/\n+/)
                .map((s) => s.trim())
                .filter(Boolean);
            const scopesRaw = String(data.get("scopes") ?? "openid profile email").trim();
            createM.mutate(
              {
                name: String(data.get("name") ?? "").trim(),
                type,
                redirect_uris: lines("redirect_uris"),
                post_logout_uris: lines("post_logout_uris"),
                grant_types: ["authorization_code", "refresh_token"],
                scopes: scopesRaw.split(/\s+/).filter(Boolean),
              },
              {
                onSuccess: (res) => {
                  onCreated(res.client, res.client_secret ?? "");
                  onOpenChange(false);
                },
              },
            );
          }}
        >
          <SheetHeader>
            <SheetTitle>{t("create.title")}</SheetTitle>
            <SheetDescription>{t("create.description")}</SheetDescription>
          </SheetHeader>
          <div className="flex-1 overflow-y-auto p-4">
            <FieldGroup>
              <Field>
                <FieldLabel htmlFor="name">{t("create.name")}</FieldLabel>
                <Input id="name" name="name" placeholder="My SPA" required />
              </Field>
              <Field>
                <FieldLabel id="oidc-type-label">{t("create.type")}</FieldLabel>
                <Select value={type} onValueChange={(v) => v && setType(v as typeof type)}>
                  <SelectTrigger aria-labelledby="oidc-type-label">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="public">{t("create.typePublic")}</SelectItem>
                    <SelectItem value="confidential">{t("create.typeConfidential")}</SelectItem>
                  </SelectContent>
                </Select>
              </Field>
              <Field>
                <FieldLabel htmlFor="redirect_uris">{t("create.redirectUris")}</FieldLabel>
                <Textarea
                  id="redirect_uris"
                  name="redirect_uris"
                  rows={3}
                  placeholder={"http://localhost:3000/callback\nhttps://app.acme.com/callback"}
                  required
                />
                <FieldDescription>{t("create.redirectUrisHelp")}</FieldDescription>
              </Field>
              <Field>
                <FieldLabel htmlFor="post_logout_uris">{t("create.postLogoutUris")}</FieldLabel>
                <Textarea
                  id="post_logout_uris"
                  name="post_logout_uris"
                  rows={2}
                  placeholder="https://app.acme.com/"
                />
                <FieldDescription>{t("create.postLogoutUrisHelp")}</FieldDescription>
              </Field>
              <Field>
                <FieldLabel htmlFor="scopes">{t("create.scopes")}</FieldLabel>
                <Input id="scopes" name="scopes" defaultValue="openid profile email" />
                <FieldDescription>{t("create.scopesHelp")}</FieldDescription>
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
              {t("common:actions.cancel")}
            </SheetClose>
            <Button type="submit" disabled={createM.isPending}>
              {createM.isPending && <Loader2Icon className="animate-spin" />}
              {createM.isPending ? t("create.submitting") : t("create.submit")}
            </Button>
          </SheetFooter>
        </form>
      </SheetContent>
    </Sheet>
  );
}
