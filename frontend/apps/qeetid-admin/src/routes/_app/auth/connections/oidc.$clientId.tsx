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
  StatusPill,
  Textarea,
  TimeSince,
} from "@qeetrix/ui";
import { Link, createFileRoute, useNavigate } from "@tanstack/react-router";
import { ArrowLeftIcon, KeySquareIcon, Loader2Icon, RefreshCwIcon, Trash2Icon } from "lucide-react";
import { useState } from "react";
import { Trans, useTranslation } from "react-i18next";

import { ApiError } from "@/lib/api";
import {
  type OidcClient,
  useDeleteOidcClient,
  useOidcClients,
  useRotateClientSecret,
  useUpdateOidcClient,
} from "@/lib/oidc-clients";

export const Route = createFileRoute("/_app/auth/connections/oidc/$clientId")({
  component: OidcClientDetailPage,
});

/** Split a comma / whitespace / newline separated textarea into a clean list. */
function splitList(raw: string): string[] {
  return raw
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

function OidcClientDetailPage() {
  const { t } = useTranslation("oidc");
  const { clientId } = Route.useParams();
  const listQ = useOidcClients();
  const client = listQ.data?.items?.find((c) => c.client_id === clientId || c.id === clientId);

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <div>
        <Link
          to="/auth/connections/oidc"
          className="inline-flex items-center gap-1 text-sm text-muted-foreground transition-colors hover:text-foreground"
        >
          <ArrowLeftIcon className="size-3.5" /> {t("detail.backToList")}
        </Link>
      </div>

      <DataState
        isLoading={listQ.isLoading}
        isError={listQ.isError}
        error={listQ.error}
        isEmpty={listQ.isSuccess && !client}
        emptyIcon={KeySquareIcon}
        emptyTitle={t("detail.notFoundTitle", { clientId })}
        emptyDescription={t("detail.notFoundDescription")}
      >
        {client && <OidcClientDetail client={client} />}
      </DataState>
    </div>
  );
}

function OidcClientDetail({ client }: { client: OidcClient }) {
  const { t } = useTranslation("oidc");
  const navigate = useNavigate();
  const updateM = useUpdateOidcClient(client.id);
  const rotateM = useRotateClientSecret(client.id);
  const deleteM = useDeleteOidcClient();
  const [confirmingDelete, setConfirmingDelete] = useState(false);
  const [rotatedSecret, setRotatedSecret] = useState<string | null>(null);

  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
      <Card className="lg:col-span-2">
        <CardHeader className="flex flex-row items-start justify-between gap-3">
          <div>
            <CardTitle className="text-xl">{client.name}</CardTitle>
            <CardDescription className="font-mono">{client.client_id}</CardDescription>
          </div>
          <StatusPill kind={client.type === "confidential" ? "info" : "muted"}>
            {client.type}
          </StatusPill>
        </CardHeader>
        <CardContent>
          <form
            className="flex flex-col gap-5"
            onSubmit={(e) => {
              e.preventDefault();
              const data = new FormData(e.currentTarget);
              updateM.mutate({
                name: String(data.get("name") ?? "").trim(),
                redirect_uris: splitList(String(data.get("redirect_uris") ?? "")),
                post_logout_uris: splitList(String(data.get("post_logout_uris") ?? "")),
                grant_types: splitList(String(data.get("grant_types") ?? "")),
                scopes: splitList(String(data.get("scopes") ?? "")),
              });
            }}
          >
            <FieldGroup>
              <Field>
                <FieldLabel htmlFor="name">{t("detail.name")}</FieldLabel>
                <Input id="name" name="name" defaultValue={client.name} required />
              </Field>
              <Field>
                <FieldLabel htmlFor="redirect_uris">{t("detail.redirectUris")}</FieldLabel>
                <Textarea
                  id="redirect_uris"
                  name="redirect_uris"
                  rows={3}
                  className="font-mono text-xs"
                  defaultValue={client.redirect_uris.join("\n")}
                />
                <FieldDescription>{t("detail.redirectUrisHelp")}</FieldDescription>
              </Field>
              <Field>
                <FieldLabel htmlFor="post_logout_uris">{t("detail.postLogoutUris")}</FieldLabel>
                <Textarea
                  id="post_logout_uris"
                  name="post_logout_uris"
                  rows={2}
                  className="font-mono text-xs"
                  defaultValue={(client.post_logout_uris ?? []).join("\n")}
                />
              </Field>
              <Field>
                <FieldLabel htmlFor="grant_types">{t("detail.grantTypes")}</FieldLabel>
                <Input
                  id="grant_types"
                  name="grant_types"
                  defaultValue={client.grant_types.join(" ")}
                />
                <FieldDescription>{t("detail.grantTypesHelp")}</FieldDescription>
              </Field>
              <Field>
                <FieldLabel htmlFor="scopes">{t("detail.scopes")}</FieldLabel>
                <Input id="scopes" name="scopes" defaultValue={client.scopes.join(" ")} />
                <FieldDescription>{t("detail.scopesHelp")}</FieldDescription>
              </Field>
              {updateM.error && (
                <Field>
                  <FieldError>{(updateM.error as ApiError).message}</FieldError>
                </Field>
              )}
            </FieldGroup>
            <div className="flex justify-end">
              <Button type="submit" disabled={updateM.isPending}>
                {updateM.isPending && <Loader2Icon className="animate-spin" />}
                {updateM.isPending ? t("common:actions.saving") : t("common:actions.saveChanges")}
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>

      <div className="flex flex-col gap-4">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">{t("detail.metadataTitle")}</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col gap-4 text-sm">
            <div>
              <p className="text-xs text-muted-foreground">{t("detail.createdLabel")}</p>
              <TimeSince value={client.created_at} className="font-mono text-xs" />
            </div>
            <div>
              <p className="text-xs text-muted-foreground">{t("detail.rowIdLabel")}</p>
              <p className="font-mono text-xs break-all">{client.id}</p>
            </div>
            <div>
              <p className="text-xs text-muted-foreground">{t("detail.tenantLabel")}</p>
              <p className="font-mono text-xs break-all">{client.tenant_id}</p>
            </div>
            <div>
              <p className="text-xs text-muted-foreground">{t("detail.grantTypesLabel")}</p>
              <div className="mt-1 flex flex-wrap gap-1.5">
                {client.grant_types.map((g) => (
                  <Badge key={g} variant="secondary">
                    {g}
                  </Badge>
                ))}
              </div>
            </div>
          </CardContent>
        </Card>

        {client.type === "confidential" && (
          <Card>
            <CardHeader>
              <CardTitle className="text-base">{t("detail.secretTitle")}</CardTitle>
              <CardDescription>{t("detail.secretDescription")}</CardDescription>
            </CardHeader>
            <CardContent className="flex flex-col gap-3">
              {rotatedSecret ? (
                <>
                  <CopyableSecret value={rotatedSecret} label="client_secret=" size="sm" />
                  <p className="text-xs text-muted-foreground">{t("detail.secretCopyHint")}</p>
                  <Button variant="ghost" size="sm" onClick={() => setRotatedSecret(null)}>
                    {t("common:actions.dismiss")}
                  </Button>
                </>
              ) : (
                <Button
                  variant="outline"
                  size="sm"
                  disabled={rotateM.isPending}
                  onClick={() =>
                    rotateM.mutate(undefined, {
                      onSuccess: (res) => setRotatedSecret(res.client_secret),
                    })
                  }
                >
                  {rotateM.isPending ? (
                    <Loader2Icon className="animate-spin" />
                  ) : (
                    <RefreshCwIcon />
                  )}
                  {t("detail.rotateSecret")}
                </Button>
              )}
            </CardContent>
          </Card>
        )}

        <Card className="border-destructive/30">
          <CardHeader>
            <CardTitle className="text-base">{t("detail.dangerZoneTitle")}</CardTitle>
            <CardDescription>{t("detail.dangerZoneDescription")}</CardDescription>
          </CardHeader>
          <CardContent>
            <Button
              variant="destructive"
              size="sm"
              onClick={() => setConfirmingDelete(true)}
              disabled={deleteM.isPending}
            >
              <Trash2Icon /> {t("detail.deleteApplication")}
            </Button>
          </CardContent>
        </Card>
      </div>

      <AlertDialog
        open={confirmingDelete}
        onOpenChange={(o) => {
          if (!o && !deleteM.isPending) setConfirmingDelete(false);
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t("detail.deleteTitle")}</AlertDialogTitle>
            <AlertDialogDescription>
              <Trans
                t={t}
                i18nKey="detail.deleteDescription"
                values={{ name: client.name }}
                components={{ strong: <span className="font-medium text-foreground" /> }}
              />
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
                deleteM.mutate(client.id, {
                  onSuccess: () => navigate({ to: "/auth/connections/oidc" }),
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
