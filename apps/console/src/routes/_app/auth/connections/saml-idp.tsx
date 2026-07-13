import {
  AlertDialog,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
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
  Sheet,
  SheetClose,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
  StatusPill,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  Textarea,
  TimeSince,
} from "@qeetrix/ui";
import { createFileRoute } from "@tanstack/react-router";
import { Loader2Icon, PencilIcon, PlusIcon, ServerIcon, Trash2Icon } from "lucide-react";
import { useState } from "react";
import { Trans, useTranslation } from "react-i18next";

import { PageHeader } from "@/components/page-header";
import type { ApiError } from "@/lib/api";
import {
  idpMetadataUrl,
  type SamlProvider,
  useCreateSamlProvider,
  useDeleteSamlProvider,
  useSamlProviders,
  useUpdateSamlProvider,
} from "@/lib/saml-idp";

export const Route = createFileRoute("/_app/auth/connections/saml-idp")({
  component: SamlIdpPage,
});

function SamlIdpPage() {
  const { t } = useTranslation("saml");
  const listQ = useSamlProviders();
  const deleteM = useDeleteSamlProvider();
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<SamlProvider | null>(null);
  const [confirmingDelete, setConfirmingDelete] = useState<SamlProvider | null>(null);

  const items = listQ.data?.items ?? [];

  return (
    <div className="flex min-w-0 flex-col gap-6">
      <PageHeader
        title={t("page.title")}
        description={t("page.description")}
        actions={
          <Button size="sm" onClick={() => setCreating(true)}>
            <PlusIcon /> {t("page.addProvider")}
          </Button>
        }
      />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">{t("metadata.title")}</CardTitle>
          <CardDescription>{t("metadata.description")}</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          <CopyableSecret value={idpMetadataUrl()} oneLine />
          <FieldDescription>{t("metadata.hint")}</FieldDescription>
        </CardContent>
      </Card>

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
            emptyIcon={ServerIcon}
            emptyTitle={t("list.emptyTitle")}
            emptyDescription={t("list.emptyDescription")}
            skeletonRows={3}
          >
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t("table.name")}</TableHead>
                  <TableHead>{t("table.entityId")}</TableHead>
                  <TableHead>{t("table.acsUrl")}</TableHead>
                  <TableHead>{t("table.status")}</TableHead>
                  <TableHead>{t("table.lastLogin")}</TableHead>
                  <TableHead className="text-right">{t("table.actions")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((p) => (
                  <TableRow key={p.id}>
                    <TableCell className="font-medium">{p.name}</TableCell>
                    <TableCell className="max-w-[220px] truncate font-mono text-xs text-muted-foreground">
                      {p.entity_id}
                    </TableCell>
                    <TableCell className="max-w-[220px] truncate font-mono text-xs text-muted-foreground">
                      {p.acs_url}
                    </TableCell>
                    <TableCell>
                      <StatusPill status={p.status} />
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {p.last_login_at ? <TimeSince value={p.last_login_at} /> : "—"}
                    </TableCell>
                    <TableCell className="text-right whitespace-nowrap">
                      <Button variant="ghost" size="sm" onClick={() => setEditing(p)}>
                        <PencilIcon /> {t("common:actions.edit")}
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => setConfirmingDelete(p)}
                        disabled={deleteM.isPending}
                      >
                        <Trash2Icon /> {t("common:actions.remove")}
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </DataState>
        </CardContent>
      </Card>

      <SamlProviderSheet open={creating} onOpenChange={setCreating} />
      <SamlProviderSheet
        provider={editing ?? undefined}
        open={!!editing}
        onOpenChange={(o) => !o && setEditing(null)}
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
                  components={{
                    strong: <span className="font-medium text-foreground" />,
                  }}
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
              {deleteM.isPending ? t("common:actions.removing") : t("common:actions.remove")}
            </Button>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

function SamlProviderSheet({
  provider,
  open,
  onOpenChange,
}: {
  provider?: SamlProvider;
  open: boolean;
  onOpenChange: (o: boolean) => void;
}) {
  const { t } = useTranslation("saml");
  const createM = useCreateSamlProvider();
  const updateM = useUpdateSamlProvider();
  const isEdit = !!provider;
  const pending = createM.isPending || updateM.isPending;
  const error = (createM.error ?? updateM.error) as ApiError | null;

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="w-full sm:max-w-lg">
        <form
          className="flex h-full flex-col"
          onSubmit={(e) => {
            e.preventDefault();
            const data = new FormData(e.currentTarget);
            const body = {
              name: String(data.get("name") ?? "").trim(),
              entity_id: String(data.get("entity_id") ?? "").trim(),
              acs_url: String(data.get("acs_url") ?? "").trim(),
              name_id_format: String(data.get("name_id_format") ?? "").trim() || undefined,
              name_id_attribute: String(data.get("name_id_attribute") ?? "").trim() || undefined,
              certificate: String(data.get("certificate") ?? "").trim() || undefined,
            };
            const onSuccess = () => onOpenChange(false);
            if (isEdit) updateM.mutate({ id: provider.id, ...body }, { onSuccess });
            else createM.mutate(body, { onSuccess });
          }}
        >
          <SheetHeader>
            <SheetTitle>{isEdit ? t("form.editTitle") : t("form.addTitle")}</SheetTitle>
            <SheetDescription>{t("form.description")}</SheetDescription>
          </SheetHeader>
          <div className="flex-1 overflow-y-auto p-4">
            <FieldGroup>
              <Field>
                <FieldLabel htmlFor="sp-name">{t("form.name")}</FieldLabel>
                <Input
                  id="sp-name"
                  name="name"
                  placeholder="Acme Analytics"
                  defaultValue={provider?.name}
                  required
                />
              </Field>
              <Field>
                <FieldLabel htmlFor="sp-entity-id">{t("form.entityId")}</FieldLabel>
                <Input
                  id="sp-entity-id"
                  name="entity_id"
                  placeholder="https://analytics.acme.com/saml/metadata"
                  defaultValue={provider?.entity_id}
                  required
                />
              </Field>
              <Field>
                <FieldLabel htmlFor="sp-acs-url">{t("form.acsUrl")}</FieldLabel>
                <Input
                  id="sp-acs-url"
                  name="acs_url"
                  type="url"
                  placeholder="https://analytics.acme.com/saml/acs"
                  defaultValue={provider?.acs_url}
                  required
                />
                <FieldDescription>{t("form.acsUrlHelp")}</FieldDescription>
              </Field>
              <Field>
                <FieldLabel htmlFor="sp-name-id-format">{t("form.nameIdFormat")}</FieldLabel>
                <Input
                  id="sp-name-id-format"
                  name="name_id_format"
                  placeholder="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
                  defaultValue={provider?.name_id_format}
                />
                <FieldDescription>{t("form.nameIdFormatHelp")}</FieldDescription>
              </Field>
              <Field>
                <FieldLabel htmlFor="sp-name-id-attribute">{t("form.nameIdAttribute")}</FieldLabel>
                <Input
                  id="sp-name-id-attribute"
                  name="name_id_attribute"
                  placeholder="email"
                  defaultValue={provider?.name_id_attribute}
                />
                <FieldDescription>{t("form.nameIdAttributeHelp")}</FieldDescription>
              </Field>
              <Field>
                <FieldLabel htmlFor="sp-certificate">{t("form.certificate")}</FieldLabel>
                <Textarea
                  id="sp-certificate"
                  name="certificate"
                  rows={5}
                  className="font-mono text-xs"
                  placeholder="-----BEGIN CERTIFICATE----- … (optional, for encrypted/signed SP requests)"
                  defaultValue={provider?.certificate}
                />
                <FieldDescription>{t("form.certificateHelp")}</FieldDescription>
              </Field>
              {error && (
                <Field>
                  <FieldError>{error.message}</FieldError>
                </Field>
              )}
            </FieldGroup>
          </div>
          <SheetFooter className="flex-row justify-end gap-2 border-t">
            <SheetClose render={<Button type="button" variant="outline" />}>
              {t("common:actions.cancel")}
            </SheetClose>
            <Button type="submit" disabled={pending}>
              {pending && <Loader2Icon className="animate-spin" />}
              {isEdit
                ? pending
                  ? t("common:actions.saving")
                  : t("common:actions.saveChanges")
                : pending
                  ? t("form.addSubmitting")
                  : t("form.addSubmit")}
            </Button>
          </SheetFooter>
        </form>
      </SheetContent>
    </Sheet>
  );
}
