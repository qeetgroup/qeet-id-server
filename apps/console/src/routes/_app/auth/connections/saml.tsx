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

import { PageHeader } from "@/components/page-header";
import { ApiError } from "@/lib/api";
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

export const Route = createFileRoute("/_app/auth/connections/saml")({ component: SamlPage });

function SamlPage() {
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
      <PageHeader
        description="Service-provider–initiated SAML 2.0 connections to enterprise IdPs. Assertions are validated against the IdP signing certificate; users are provisioned on first login."
        actions={
          <Button size="sm" onClick={() => setCreating(true)}>
            <PlusIcon className="mr-2 size-4" />
            New connection
          </Button>
        }
      />

      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardDescription>Active connections</CardDescription>
            <WorkflowIcon className="size-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold tracking-tight">{active}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardDescription>Total connections</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold tracking-tight">{items.length}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardDescription>Last SSO login</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold tracking-tight">
              {lastLogin ? <TimeSince value={lastLogin} /> : "Never"}
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Connections</CardTitle>
          <CardDescription>
            One row per IdP. JIT provisioning runs on every successful assertion.
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <DataState
            isLoading={listQ.isLoading}
            isError={listQ.isError}
            error={listQ.error}
            isEmpty={items.length === 0}
            emptyIcon={WorkflowIcon}
            emptyTitle="No SAML connections yet."
            skeletonRows={3}
          >
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>IdP entity ID</TableHead>
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
                        title="Open the IdP login to test this connection"
                      >
                        <ExternalLinkIcon /> Test SSO
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => window.open(samlMetadataUrl(c.id), "_blank", "noopener")}
                        title="Download SP metadata to hand to your IdP"
                      >
                        <DownloadIcon /> Metadata
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
                          if (confirm(`Delete SAML connection "${c.name}"?`)) deleteM.mutate(c.id);
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

// ValidateConnection runs an offline config preflight (POST .../saml/{id}/test)
// and shows the per-check results in a side panel — complementary to "Test SSO"
// (a live IdP round-trip), this catches config errors before any login.
function ValidateConnection({ id }: { id: string }) {
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
        title="Validate this connection's configuration (offline preflight)"
      >
        {testM.isPending ? <Loader2Icon className="animate-spin" /> : <ShieldCheckIcon />} Validate
      </Button>
      <Sheet open={open} onOpenChange={setOpen}>
        <SheetContent side="right" className="w-full sm:max-w-md">
          <div className="flex h-full flex-col">
            <SheetHeader>
              <SheetTitle>Connection check</SheetTitle>
              <SheetDescription>
                Offline preflight of this connection&apos;s configuration. Run a full Test SSO for
                an end-to-end check against the IdP.
              </SheetDescription>
            </SheetHeader>
            <div className="flex-1 overflow-y-auto p-4">
              {testM.isPending && <p className="text-sm text-muted-foreground">Running checks…</p>}
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
            <SheetTitle>New SAML connection</SheetTitle>
            <SheetDescription>
              Paste the IdP&apos;s SSO URL, issuer and signing certificate (from its metadata).
            </SheetDescription>
          </SheetHeader>
          <div className="flex-1 overflow-y-auto p-4">
            <FieldGroup>
              <Field>
                <FieldLabel htmlFor="name">Connection name</FieldLabel>
                <Input id="name" name="name" placeholder="Acme — Okta" required />
              </Field>
              <Field>
                <FieldLabel htmlFor="idp_entity_id">IdP entity ID / issuer</FieldLabel>
                <Input
                  id="idp_entity_id"
                  name="idp_entity_id"
                  placeholder="http://www.okta.com/exk1abc"
                  required
                />
              </Field>
              <Field>
                <FieldLabel htmlFor="idp_sso_url">IdP SSO URL</FieldLabel>
                <Input
                  id="idp_sso_url"
                  name="idp_sso_url"
                  type="url"
                  placeholder="https://acme.okta.com/app/.../sso/saml"
                  required
                />
              </Field>
              <Field>
                <FieldLabel htmlFor="idp_certificate">IdP signing certificate</FieldLabel>
                <Textarea
                  id="idp_certificate"
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
                <FieldLabel htmlFor="email_attribute">Email attribute</FieldLabel>
                <Input
                  id="email_attribute"
                  name="email_attribute"
                  placeholder="email (blank = use NameID)"
                />
              </Field>
              <Field>
                <FieldLabel htmlFor="name_attribute">Display-name attribute</FieldLabel>
                <Input
                  id="name_attribute"
                  name="name_attribute"
                  placeholder="displayName (optional)"
                />
              </Field>
              <Field>
                <FieldLabel>Initial status</FieldLabel>
                <Select
                  value={status}
                  onValueChange={(v) => setStatus(v as SamlConnection["status"])}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="draft">Draft</SelectItem>
                    <SelectItem value="active">Active</SelectItem>
                  </SelectContent>
                </Select>
                <FieldDescription>
                  Draft connections accept test logins but aren&apos;t advertised.
                </FieldDescription>
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
