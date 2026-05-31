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
  const listQ = useLdapConnections();
  const updateM = useUpdateLdapConnection();
  const deleteM = useDeleteLdapConnection();
  const testM = useTestLdapConnection();
  const [creating, setCreating] = useState(false);

  const items = listQ.data?.items ?? [];

  return (
    <div className="flex min-w-0 flex-col gap-6">
      <PageHeader
        description="Bridge on-prem Active Directory or generic LDAPv3 directories. Users authenticate with their directory credentials and are provisioned on first login."
        actions={
          <Button size="sm" onClick={() => setCreating(true)}>
            <PlusIcon className="mr-2 size-4" />
            New connection
          </Button>
        }
      />

      <Card>
        <CardHeader>
          <CardTitle>Connections</CardTitle>
          <CardDescription>
            Qeet ID binds with the service account, finds the user under the base DN, then re-binds
            as that user to verify the password.
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <DataState
            isLoading={listQ.isLoading}
            isError={listQ.isError}
            error={listQ.error}
            isEmpty={items.length === 0}
            emptyIcon={ServerIcon}
            emptyTitle="No LDAP connections yet."
            skeletonRows={3}
          >
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Server</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Last login</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((c) => (
                  <TableRow key={c.id}>
                    <TableCell className="font-medium">{c.name}</TableCell>
                    <TableCell className="max-w-[260px] truncate font-mono text-xs text-muted-foreground">
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
                        title="Bind with the service account to verify settings"
                      >
                        <PlugIcon /> Test
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
                        {c.status === "active" ? "Disable" : "Enable"}
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => {
                          if (confirm(`Delete LDAP connection "${c.name}"?`)) deleteM.mutate(c.id);
                        }}
                        disabled={deleteM.isPending}
                      >
                        <Trash2Icon /> Delete
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
            <SheetTitle>New LDAP connection</SheetTitle>
            <SheetDescription>Point at your directory and supply a read-only service account.</SheetDescription>
          </SheetHeader>
          <div className="flex-1 overflow-y-auto p-4">
            <FieldGroup>
              <Field>
                <FieldLabel htmlFor="name">Connection name</FieldLabel>
                <Input id="name" name="name" placeholder="Corp AD" required />
              </Field>
              <Field>
                <FieldLabel htmlFor="server_url">Server URL</FieldLabel>
                <Input id="server_url" name="server_url" className="font-mono text-xs" placeholder="ldaps://ldap.corp.example.com:636" required />
                <FieldDescription>Use ldaps:// (636) for TLS, or ldap:// (389) with StartTLS below.</FieldDescription>
              </Field>
              <Field>
                <FieldLabel htmlFor="bind_dn">Bind DN (service account)</FieldLabel>
                <Input id="bind_dn" name="bind_dn" className="font-mono text-xs" placeholder="cn=qeetid-svc,ou=ServiceAccounts,dc=corp,dc=example,dc=com" required />
              </Field>
              <Field>
                <FieldLabel htmlFor="bind_password">Bind password</FieldLabel>
                <Input id="bind_password" name="bind_password" type="password" placeholder="••••••••" required />
                <FieldDescription>Stored server-side and never returned by the API.</FieldDescription>
              </Field>
              <Field>
                <FieldLabel htmlFor="base_dn">User base DN</FieldLabel>
                <Input id="base_dn" name="base_dn" className="font-mono text-xs" placeholder="ou=People,dc=corp,dc=example,dc=com" required />
              </Field>
              <Field>
                <FieldLabel htmlFor="user_filter">User filter</FieldLabel>
                <Input id="user_filter" name="user_filter" className="font-mono text-xs" placeholder="(uid=%s)" defaultValue="(uid=%s)" />
                <FieldDescription>
                  <code>%s</code> is replaced with the (escaped) username. AD often uses{" "}
                  <code>(sAMAccountName=%s)</code>.
                </FieldDescription>
              </Field>
              <div className="grid grid-cols-2 gap-3">
                <Field>
                  <FieldLabel htmlFor="email_attribute">Email attribute</FieldLabel>
                  <Input id="email_attribute" name="email_attribute" placeholder="mail" defaultValue="mail" />
                </Field>
                <Field>
                  <FieldLabel htmlFor="name_attribute">Name attribute</FieldLabel>
                  <Input id="name_attribute" name="name_attribute" placeholder="cn" defaultValue="cn" />
                </Field>
              </div>
              <Field>
                <div className="flex items-center justify-between gap-4">
                  <div>
                    <FieldLabel>StartTLS</FieldLabel>
                    <FieldDescription>Upgrade an ldap:// connection to TLS.</FieldDescription>
                  </div>
                  <Switch checked={startTls} onCheckedChange={setStartTls} />
                </div>
              </Field>
              <Field>
                <div className="flex items-center justify-between gap-4">
                  <div>
                    <FieldLabel>Skip TLS verification</FieldLabel>
                    <FieldDescription>Accept self-signed certs (lab only — not recommended).</FieldDescription>
                  </div>
                  <Switch checked={skipVerify} onCheckedChange={setSkipVerify} />
                </div>
              </Field>
              <Field>
                <FieldLabel>Initial status</FieldLabel>
                <Select value={status} onValueChange={(v) => setStatus(v as LdapConnection["status"])}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="draft">Draft</SelectItem>
                    <SelectItem value="active">Active</SelectItem>
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
            <SheetClose render={<Button type="button" variant="outline" />}>Cancel</SheetClose>
            <Button type="submit" disabled={createM.isPending}>
              {createM.isPending && <Loader2Icon className="animate-spin" />}
              {createM.isPending ? "Creating…" : "Create connection"}
            </Button>
          </SheetFooter>
        </form>
      </SheetContent>
    </Sheet>
  );
}
