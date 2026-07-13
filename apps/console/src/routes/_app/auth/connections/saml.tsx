import {
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
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
import {
  CheckCircle2Icon,
  DownloadIcon,
  ExternalLinkIcon,
  Loader2Icon,
  PlusIcon,
  ShieldCheckIcon,
  Trash2Icon,
  WorkflowIcon,
  XCircleIcon,
} from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { useConfirmDialog } from "@/components/confirm-dialog";
import { PageHeader } from "@/components/page-header";
import type { ApiError } from "@/lib/api";
import {
  type SamlConnection,
  samlLoginUrl,
  samlMetadataUrl,
  useCreateSamlConnection,
  useDeleteSamlConnection,
  useSamlConnections,
  useTestSamlConnection,
  useUpdateSamlConnection,
} from "@/lib/saml";

export const Route = createFileRoute("/_app/auth/connections/saml")({
  component: SamlPage,
});

function SamlPage() {
  const { t } = useTranslation("auth");
  const [confirmDialog, openConfirm] = useConfirmDialog();
  const listQ = useSamlConnections();
  const updateM = useUpdateSamlConnection();
  const deleteM = useDeleteSamlConnection();
  const [creating, setCreating] = useState(false);

  const items = listQ.data?.items ?? [];
  const active = items.filter((c) => c.status === "active").length;
  const lastLogin = items
    .map((c) => c.last_login_at)
    .filter(Boolean)
    .sort()
    .at(-1);

  return (
    <div className="flex min-w-0 flex-col gap-6">
      {confirmDialog}
      <PageHeader
        description={t("samlSp.description")}
        actions={
          <Button size="sm" onClick={() => setCreating(true)}>
            <PlusIcon className="mr-2 size-4" />
            {t("samlSp.newButton")}
          </Button>
        }
      />

      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardDescription>{t("samlSp.stats.active")}</CardDescription>
            <WorkflowIcon className="size-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold tracking-tight">{active}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardDescription>{t("samlSp.stats.total")}</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold tracking-tight">{items.length}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardDescription>{t("samlSp.stats.lastLogin")}</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold tracking-tight">
              {lastLogin ? <TimeSince value={lastLogin} /> : t("samlSp.stats.never")}
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>{t("samlSp.list.title")}</CardTitle>
          <CardDescription>{t("samlSp.list.description")}</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <DataState
            isLoading={listQ.isLoading}
            isError={listQ.isError}
            error={listQ.error}
            isEmpty={items.length === 0}
            emptyIcon={WorkflowIcon}
            emptyTitle={t("samlSp.list.empty")}
            skeletonRows={3}
          >
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t("samlSp.columns.name")}</TableHead>
                  <TableHead>{t("samlSp.columns.idpEntityId")}</TableHead>
                  <TableHead>{t("samlSp.columns.status")}</TableHead>
                  <TableHead>{t("samlSp.columns.lastLogin")}</TableHead>
                  <TableHead className="text-right">{t("samlSp.columns.actions")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((c) => (
                  <TableRow key={c.id}>
                    <TableCell className="font-medium">{c.name}</TableCell>
                    <TableCell className="max-w-65 truncate font-mono text-xs text-muted-foreground">
                      {c.idp_entity_id}
                    </TableCell>
                    <TableCell>
                      <StatusPill status={c.status} />
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {c.last_login_at ? <TimeSince value={c.last_login_at} /> : "—"}
                    </TableCell>
                    <TableCell className="text-right whitespace-nowrap">
                      <ValidateConnection id={c.id} />
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => window.open(samlLoginUrl(c.id), "_blank", "noopener")}
                        disabled={c.status === "disabled"}
                        title={t("samlSp.testSsoTitle")}
                      >
                        <ExternalLinkIcon /> {t("samlSp.testSso")}
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => window.open(samlMetadataUrl(c.id), "_blank", "noopener")}
                        title={t("samlSp.metadataTitle")}
                      >
                        <DownloadIcon /> {t("samlSp.metadata")}
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() =>
                          updateM.mutate({
                            id: c.id,
                            status: c.status === "active" ? "disabled" : "active",
                          })
                        }
                        disabled={updateM.isPending}
                      >
                        {c.status === "active" ? t("samlSp.disable") : t("samlSp.enable")}
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() =>
                          openConfirm({
                            title: t("samlSp.confirm.title", { name: c.name }),
                            variant: "destructive",
                            confirmLabel: t("samlSp.confirm.label"),
                            onConfirm: () => deleteM.mutate(c.id),
                          })
                        }
                        disabled={deleteM.isPending}
                      >
                        <Trash2Icon /> {t("samlSp.deleteBtn")}
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </DataState>
        </CardContent>
      </Card>

      <CreateConnectionSheet open={creating} onOpenChange={setCreating} />
    </div>
  );
}

// ValidateConnection runs an offline config preflight (POST .../saml/{id}/test)
// and shows the per-check results in a side panel — complementary to "Test SSO"
// (a live IdP round-trip), this catches config errors before any login.
function ValidateConnection({ id }: { id: string }) {
  const { t } = useTranslation("auth");
  const testM = useTestSamlConnection();
  const [open, setOpen] = useState(false);

  return (
    <>
      <Button
        variant="ghost"
        size="sm"
        disabled={testM.isPending}
        onClick={() => {
          setOpen(true);
          testM.mutate(id);
        }}
        title={t("samlSp.validate.buttonTitle")}
      >
        {testM.isPending ? <Loader2Icon className="animate-spin" /> : <ShieldCheckIcon />}{" "}
        {t("samlSp.validate.button")}
      </Button>
      <Sheet open={open} onOpenChange={setOpen}>
        <SheetContent side="right" className="w-full sm:max-w-md">
          <div className="flex h-full flex-col">
            <SheetHeader>
              <SheetTitle>{t("samlSp.validate.sheetTitle")}</SheetTitle>
              <SheetDescription>{t("samlSp.validate.sheetDescription")}</SheetDescription>
            </SheetHeader>
            <div className="flex-1 overflow-y-auto p-4">
              {testM.isPending && (
                <p className="text-sm text-muted-foreground">{t("samlSp.validate.running")}</p>
              )}
              {testM.error && (
                <p className="text-destructive text-sm">{(testM.error as ApiError).message}</p>
              )}
              {testM.data && (
                <ul className="flex flex-col gap-3">
                  {testM.data.checks.map((c) => (
                    <li key={c.name} className="flex items-start gap-2">
                      {c.ok ? (
                        <CheckCircle2Icon className="mt-0.5 size-4 shrink-0 text-emerald-600 dark:text-emerald-400" />
                      ) : (
                        <XCircleIcon className="text-destructive mt-0.5 size-4 shrink-0" />
                      )}
                      <div className="min-w-0">
                        <p className="text-sm font-medium">{c.name}</p>
                        {c.detail && <p className="text-xs text-muted-foreground">{c.detail}</p>}
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        </SheetContent>
      </Sheet>
    </>
  );
}

function CreateConnectionSheet({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
}) {
  const { t } = useTranslation("auth");
  const createM = useCreateSamlConnection();
  const [status, setStatus] = useState<SamlConnection["status"]>("draft");

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="w-full sm:max-w-lg">
        <form
          className="flex h-full flex-col"
          onSubmit={(e) => {
            e.preventDefault();
            const data = new FormData(e.currentTarget);
            createM.mutate(
              {
                name: String(data.get("name") ?? "").trim(),
                idp_entity_id: String(data.get("idp_entity_id") ?? "").trim(),
                idp_sso_url: String(data.get("idp_sso_url") ?? "").trim(),
                idp_certificate: String(data.get("idp_certificate") ?? "").trim(),
                email_attribute: String(data.get("email_attribute") ?? "").trim(),
                name_attribute: String(data.get("name_attribute") ?? "").trim(),
                status,
              },
              { onSuccess: () => onOpenChange(false) },
            );
          }}
        >
          <SheetHeader>
            <SheetTitle>{t("samlSp.create.title")}</SheetTitle>
            <SheetDescription>{t("samlSp.create.description")}</SheetDescription>
          </SheetHeader>
          <div className="flex-1 overflow-y-auto p-4">
            <FieldGroup>
              <Field>
                <FieldLabel htmlFor="saml-name">{t("samlSp.create.nameLabel")}</FieldLabel>
                <Input id="saml-name" name="name" placeholder="Acme — Okta" required />
              </Field>
              <Field>
                <FieldLabel htmlFor="saml-idp_entity_id">
                  {t("samlSp.create.idpEntityIdLabel")}
                </FieldLabel>
                <Input
                  id="saml-idp_entity_id"
                  name="idp_entity_id"
                  placeholder="http://www.okta.com/exk1abc"
                  required
                />
              </Field>
              <Field>
                <FieldLabel htmlFor="saml-idp_sso_url">
                  {t("samlSp.create.idpSsoUrlLabel")}
                </FieldLabel>
                <Input
                  id="saml-idp_sso_url"
                  name="idp_sso_url"
                  type="url"
                  placeholder="https://acme.okta.com/app/.../sso/saml"
                  required
                />
              </Field>
              <Field>
                <FieldLabel htmlFor="saml-idp_certificate">
                  {t("samlSp.create.idpCertLabel")}
                </FieldLabel>
                <Textarea
                  id="saml-idp_certificate"
                  name="idp_certificate"
                  rows={6}
                  className="font-mono text-xs"
                  placeholder="-----BEGIN CERTIFICATE----- … or bare base64 from IdP metadata"
                  required
                />
                <FieldDescription>
                  PEM or the bare base64 from the IdP metadata&apos;s X509Certificate.
                </FieldDescription>
              </Field>
              <Field>
                <FieldLabel htmlFor="saml-email_attribute">
                  {t("samlSp.create.emailAttrLabel")}
                </FieldLabel>
                <Input
                  id="saml-email_attribute"
                  name="email_attribute"
                  placeholder="email (blank = use NameID)"
                />
              </Field>
              <Field>
                <FieldLabel htmlFor="saml-name_attribute">
                  {t("samlSp.create.nameAttrLabel")}
                </FieldLabel>
                <Input
                  id="saml-name_attribute"
                  name="name_attribute"
                  placeholder="displayName (optional)"
                />
              </Field>
              <Field>
                <FieldLabel>{t("samlSp.create.statusLabel")}</FieldLabel>
                <Select
                  value={status}
                  onValueChange={(v) => setStatus(v as SamlConnection["status"])}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="draft">{t("samlSp.create.statusDraft")}</SelectItem>
                    <SelectItem value="active">{t("samlSp.create.statusActive")}</SelectItem>
                  </SelectContent>
                </Select>
                <FieldDescription>{t("samlSp.create.statusHelp")}</FieldDescription>
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
              {t("samlSp.create.cancelBtn")}
            </SheetClose>
            <Button type="submit" disabled={createM.isPending}>
              {createM.isPending && <Loader2Icon className="animate-spin" />}
              {createM.isPending ? t("samlSp.create.creatingBtn") : t("samlSp.create.createBtn")}
            </Button>
          </SheetFooter>
        </form>
      </SheetContent>
    </Sheet>
  );
}
