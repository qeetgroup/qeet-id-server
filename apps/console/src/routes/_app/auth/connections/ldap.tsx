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
  Switch,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  TimeSince,
} from "@qeetrix/ui";
import { createFileRoute } from "@tanstack/react-router";
import { Loader2Icon, PlugIcon, PlusIcon, ServerIcon, Trash2Icon } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { useConfirmDialog } from "@/components/confirm-dialog";
import { PageHeader } from "@/components/page-header";
import { ApiError } from "@/lib/api";
import {
  type LdapConnection,
  useCreateLdapConnection,
  useDeleteLdapConnection,
  useLdapConnections,
  useTestLdapConnection,
  useUpdateLdapConnection,
} from "@/lib/ldap";

export const Route = createFileRoute("/_app/auth/connections/ldap")({ component: LdapPage });

function LdapPage() {
  const { t } = useTranslation("auth");
  const [confirmDialog, openConfirm] = useConfirmDialog();
  const listQ = useLdapConnections();
  const updateM = useUpdateLdapConnection();
  const deleteM = useDeleteLdapConnection();
  const testM = useTestLdapConnection();
  const [creating, setCreating] = useState(false);

  const items = listQ.data?.items ?? [];

  return (
    <div className="flex min-w-0 flex-col gap-6">
      {confirmDialog}
      <PageHeader
        description={t("ldap.description")}
        actions={
          <Button size="sm" onClick={() => setCreating(true)}>
            <PlusIcon className="mr-2 size-4" />
            {t("ldap.newButton")}
          </Button>
        }
      />

      <Card>
        <CardHeader>
          <CardTitle>{t("ldap.list.title")}</CardTitle>
          <CardDescription>
            {t("ldap.list.description")}
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <DataState
            isLoading={listQ.isLoading}
            isError={listQ.isError}
            error={listQ.error}
            isEmpty={items.length === 0}
            emptyIcon={ServerIcon}
            emptyTitle={t("ldap.list.empty")}
            skeletonRows={3}
          >
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t("ldap.columns.name")}</TableHead>
                  <TableHead>{t("ldap.columns.server")}</TableHead>
                  <TableHead>{t("ldap.columns.status")}</TableHead>
                  <TableHead>{t("ldap.columns.lastLogin")}</TableHead>
                  <TableHead className="text-right">{t("ldap.columns.actions")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((c) => (
                  <TableRow key={c.id}>
                    <TableCell className="font-medium">{c.name}</TableCell>
                    <TableCell className="max-w-65 truncate font-mono text-xs text-muted-foreground">
                      {c.server_url}
                    </TableCell>
                    <TableCell>
                      <StatusPill status={c.status} />
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {c.last_login_at ? <TimeSince value={c.last_login_at} /> : "—"}
                    </TableCell>
                    <TableCell className="text-right whitespace-nowrap">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => testM.mutate(c.id)}
                        disabled={testM.isPending}
                        title={t("ldap.testTitle")}
                      >
                        <PlugIcon /> {t("ldap.testBtn")}
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
                        {c.status === "active" ? t("ldap.disable") : t("ldap.enable")}
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() =>
                          openConfirm({
                            title: t("ldap.confirm.title", { name: c.name }),
                            variant: "destructive",
                            confirmLabel: t("ldap.confirm.label"),
                            onConfirm: () => deleteM.mutate(c.id),
                          })
                        }
                        disabled={deleteM.isPending}
                      >
                        <Trash2Icon /> {t("ldap.deleteBtn")}
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

function CreateConnectionSheet({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
}) {
  const { t } = useTranslation("auth");
  const createM = useCreateLdapConnection();
  const [status, setStatus] = useState<LdapConnection["status"]>("draft");
  const [startTls, setStartTls] = useState(false);
  const [skipVerify, setSkipVerify] = useState(false);

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
                server_url: String(data.get("server_url") ?? "").trim(),
                bind_dn: String(data.get("bind_dn") ?? "").trim(),
                bind_password: String(data.get("bind_password") ?? ""),
                base_dn: String(data.get("base_dn") ?? "").trim(),
                user_filter: String(data.get("user_filter") ?? "").trim(),
                email_attribute: String(data.get("email_attribute") ?? "").trim(),
                name_attribute: String(data.get("name_attribute") ?? "").trim(),
                start_tls: startTls,
                skip_tls_verify: skipVerify,
                status,
              },
              { onSuccess: () => onOpenChange(false) },
            );
          }}
        >
          <SheetHeader>
            <SheetTitle>{t("ldap.create.title")}</SheetTitle>
            <SheetDescription>{t("ldap.create.description")}</SheetDescription>
          </SheetHeader>
          <div className="flex-1 overflow-y-auto p-4">
            <FieldGroup>
              <Field>
                <FieldLabel htmlFor="ldap-name">{t("ldap.create.nameLabel")}</FieldLabel>
                <Input id="ldap-name" name="name" placeholder="Corp AD" required />
              </Field>
              <Field>
                <FieldLabel htmlFor="ldap-server_url">{t("ldap.create.serverLabel")}</FieldLabel>
                <Input id="ldap-server_url" name="server_url" className="font-mono text-xs" placeholder="ldaps://ldap.corp.example.com:636" required />
                <FieldDescription>{t("ldap.create.serverHelp")}</FieldDescription>
              </Field>
              <Field>
                <FieldLabel htmlFor="ldap-bind_dn">{t("ldap.create.bindDnLabel")}</FieldLabel>
                <Input id="ldap-bind_dn" name="bind_dn" className="font-mono text-xs" placeholder="cn=qeetid-svc,ou=ServiceAccounts,dc=corp,dc=example,dc=com" required />
              </Field>
              <Field>
                <FieldLabel htmlFor="ldap-bind_password">{t("ldap.create.bindPasswordLabel")}</FieldLabel>
                <Input id="ldap-bind_password" name="bind_password" type="password" placeholder="••••••••" required />
                <FieldDescription>{t("ldap.create.bindPasswordHelp")}</FieldDescription>
              </Field>
              <Field>
                <FieldLabel htmlFor="ldap-base_dn">{t("ldap.create.baseDnLabel")}</FieldLabel>
                <Input id="ldap-base_dn" name="base_dn" className="font-mono text-xs" placeholder="ou=People,dc=corp,dc=example,dc=com" required />
              </Field>
              <Field>
                <FieldLabel htmlFor="ldap-user_filter">{t("ldap.create.filterLabel")}</FieldLabel>
                <Input id="ldap-user_filter" name="user_filter" className="font-mono text-xs" placeholder="(uid=%s)" defaultValue="(uid=%s)" />
                <FieldDescription>
                  <code>%s</code> is replaced with the (escaped) username. AD often uses{" "}
                  <code>(sAMAccountName=%s)</code>.
                </FieldDescription>
              </Field>
              <div className="grid grid-cols-2 gap-3">
                <Field>
                  <FieldLabel htmlFor="ldap-email_attribute">{t("ldap.create.emailAttrLabel")}</FieldLabel>
                  <Input id="ldap-email_attribute" name="email_attribute" placeholder="mail" defaultValue="mail" />
                </Field>
                <Field>
                  <FieldLabel htmlFor="ldap-name_attribute">{t("ldap.create.nameAttrLabel")}</FieldLabel>
                  <Input id="ldap-name_attribute" name="name_attribute" placeholder="cn" defaultValue="cn" />
                </Field>
              </div>
              <Field>
                <div className="flex items-center justify-between gap-4">
                  <div>
                    <FieldLabel>{t("ldap.create.startTlsLabel")}</FieldLabel>
                    <FieldDescription>{t("ldap.create.startTlsHelp")}</FieldDescription>
                  </div>
                  <Switch checked={startTls} onCheckedChange={setStartTls} />
                </div>
              </Field>
              <Field>
                <div className="flex items-center justify-between gap-4">
                  <div>
                    <FieldLabel>{t("ldap.create.skipVerifyLabel")}</FieldLabel>
                    <FieldDescription>{t("ldap.create.skipVerifyHelp")}</FieldDescription>
                  </div>
                  <Switch checked={skipVerify} onCheckedChange={setSkipVerify} />
                </div>
              </Field>
              <Field>
                <FieldLabel>{t("ldap.create.statusLabel")}</FieldLabel>
                <Select value={status} onValueChange={(v) => setStatus(v as LdapConnection["status"])}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="draft">{t("ldap.create.statusDraft")}</SelectItem>
                    <SelectItem value="active">{t("ldap.create.statusActive")}</SelectItem>
                  </SelectContent>
                </Select>
              </Field>
              {createM.error && (
                <Field>
                  <FieldError>{(createM.error as ApiError).message}</FieldError>
                </Field>
              )}
            </FieldGroup>
          </div>
          <SheetFooter className="flex-row justify-end gap-2 border-t">
            <SheetClose render={<Button type="button" variant="outline" />}>{t("ldap.create.cancelBtn")}</SheetClose>
            <Button type="submit" disabled={createM.isPending}>
              {createM.isPending && <Loader2Icon className="animate-spin" />}
              {createM.isPending ? t("ldap.create.creatingBtn") : t("ldap.create.createBtn")}
            </Button>
          </SheetFooter>
        </form>
      </SheetContent>
    </Sheet>
  );
}
