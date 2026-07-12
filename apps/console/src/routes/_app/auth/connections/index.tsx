import {
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  Checkbox,
  CopyableSecret,
  DataState,
  Field,
  FieldLabel,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  StatusPill,
} from "@qeetrix/ui";
import { createFileRoute, Link } from "@tanstack/react-router";
import { KeyRoundIcon, LinkIcon, Loader2Icon, ShieldCheckIcon, Trash2Icon } from "lucide-react";
import { useState } from "react";

import { useConfirmDialog } from "@/components/confirm-dialog";
import { PageHeader } from "@/components/page-header";
import { ApiError } from "@/lib/api";
import {
  isAdminPortalLinkActive,
  useAdminPortalLinks,
  useGenerateAdminPortalLink,
  useRevokeAdminPortalLink,
  type AdminPortalCapability,
  type AdminPortalLink,
} from "@/lib/admin-portal";

export const Route = createFileRoute("/_app/auth/connections/")({ component: ConnectionsPage });

const TTL_OPTIONS = [
  { label: "1 hour", seconds: 60 * 60 },
  { label: "24 hours", seconds: 24 * 60 * 60 },
  { label: "3 days", seconds: 3 * 24 * 60 * 60 },
  { label: "7 days", seconds: 7 * 24 * 60 * 60 },
];

function ConnectionsPage() {
  return (
    <div className="flex min-w-0 flex-col gap-6">
      <PageHeader description="OIDC, SAML, SCIM, and LDAP connections for this tenant, plus a self-serve Admin Portal your own IT admin can use without a Qeet ID account." />

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <ConnectionCard to="/auth/connections/saml" title="SAML 2.0" description="Consume an external IdP." />
        <ConnectionCard to="/auth/connections/saml-idp" title="SAML IdP" description="Serve downstream SPs." />
        <ConnectionCard to="/auth/connections/oidc" title="OIDC / OAuth 2.0" description="Registered applications." />
        <ConnectionCard to="/auth/connections/scim" title="SCIM Provisioning" description="IdP-driven user sync." />
      </div>

      <AdminPortalCard />
    </div>
  );
}

function ConnectionCard({
  to,
  title,
  description,
}: {
  to: string;
  title: string;
  description: string;
}) {
  return (
    <Link to={to}>
      <Card className="h-full transition-colors hover:border-primary/50">
        <CardHeader>
          <CardTitle className="text-base">{title}</CardTitle>
          <CardDescription>{description}</CardDescription>
        </CardHeader>
      </Card>
    </Link>
  );
}

function AdminPortalCard() {
  const [confirmDialog, openConfirm] = useConfirmDialog();
  const linksQ = useAdminPortalLinks();
  const generateM = useGenerateAdminPortalLink();
  const revokeM = useRevokeAdminPortalLink();

  const [capabilities, setCapabilities] = useState<Set<AdminPortalCapability>>(
    () => new Set(["saml", "scim"]),
  );
  const [ttl, setTtl] = useState(String(TTL_OPTIONS[1].seconds));

  const toggle = (cap: AdminPortalCapability, checked: boolean) => {
    setCapabilities((prev) => {
      const next = new Set(prev);
      if (checked) next.add(cap);
      else next.delete(cap);
      return next;
    });
  };

  const items = linksQ.data?.items ?? [];
  const generated = generateM.data;

  return (
    <>
      {confirmDialog}
      <Card>
      <CardHeader>
        <CardTitle className="text-base">Self-serve Admin Portal</CardTitle>
        <CardDescription>
          Generate a link your own IT admin can follow to configure this tenant&rsquo;s SAML
          connection and/or roll its SCIM token &mdash; no Qeet ID account or console access
          needed. The link carries no identity of its own; whoever holds it can act until it
          expires or you revoke it.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-end">
          <Field>
            <FieldLabel>Capabilities</FieldLabel>
            <div className="flex items-center gap-4 pt-1">
              <label className="flex items-center gap-2 text-sm">
                <Checkbox
                  checked={capabilities.has("saml")}
                  onCheckedChange={(c) => toggle("saml", c === true)}
                />
                SAML
              </label>
              <label className="flex items-center gap-2 text-sm">
                <Checkbox
                  checked={capabilities.has("scim")}
                  onCheckedChange={(c) => toggle("scim", c === true)}
                />
                SCIM
              </label>
            </div>
          </Field>
          <Field className="sm:w-40">
            <FieldLabel htmlFor="ttl">Expires in</FieldLabel>
            <Select value={ttl} onValueChange={(v) => v && setTtl(v)}>
              <SelectTrigger id="ttl">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {TTL_OPTIONS.map((o) => (
                  <SelectItem key={o.seconds} value={String(o.seconds)}>
                    {o.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </Field>
          <Button
            disabled={capabilities.size === 0 || generateM.isPending}
            onClick={() =>
              generateM.mutate({
                capabilities: Array.from(capabilities),
                ttl_seconds: Number(ttl),
              })
            }
          >
            {generateM.isPending && <Loader2Icon className="animate-spin" />}
            <LinkIcon />
            Generate link
          </Button>
        </div>
        {generateM.error && (
          <p className="text-destructive text-sm">{(generateM.error as ApiError).message}</p>
        )}

        {generated && (
          <div className="rounded-lg border border-amber-500/40 bg-amber-50/40 p-4 dark:bg-amber-950/20">
            <p className="mb-2 text-sm font-medium">
              Link generated &mdash; copy it now (it won&apos;t be shown again):
            </p>
            <CopyableSecret value={generated.url} size="sm" />
            <div className="mt-3">
              <Button variant="outline" size="sm" onClick={() => generateM.reset()}>
                I&apos;ve saved it
              </Button>
            </div>
          </div>
        )}

        <DataState
          isLoading={linksQ.isLoading}
          isError={linksQ.isError}
          error={linksQ.error}
          isEmpty={items.length === 0}
          emptyIcon={ShieldCheckIcon}
          emptyTitle="No admin portal links yet."
          emptyDescription="Generate one above to delegate SSO/SCIM setup."
          skeletonRows={2}
        >
          <ul className="divide-y">
            {items.map((l) => (
              <AdminPortalLinkRow
                key={l.id}
                link={l}
                onRevoke={() =>
                  openConfirm({
                    title: "Revoke this admin portal link?",
                    description: "It will stop working immediately.",
                    variant: "destructive",
                    confirmLabel: "Revoke",
                    onConfirm: () => revokeM.mutate(l.id),
                  })
                }
                busy={revokeM.isPending}
              />
            ))}
          </ul>
        </DataState>
      </CardContent>
    </Card>
    </>
  );
}

function AdminPortalLinkRow({
  link: l,
  onRevoke,
  busy,
}: {
  link: AdminPortalLink;
  onRevoke: () => void;
  busy: boolean;
}) {
  const active = isAdminPortalLinkActive(l);
  const status = l.revoked_at ? "revoked" : active ? "active" : "expired";

  return (
    <li className="flex items-center justify-between gap-4 py-3">
      <div className="min-w-0">
        <p className="flex items-center gap-2 text-sm font-medium">
          <KeyRoundIcon className="size-4 text-muted-foreground" />
          {l.capabilities.join(" + ")}
          <StatusPill status={status} />
        </p>
        <p className="truncate text-xs text-muted-foreground">
          Expires {new Date(l.expires_at).toLocaleString()}
          {l.last_used_at ? ` · last used ${new Date(l.last_used_at).toLocaleString()}` : " · never used"}
        </p>
      </div>
      {active && (
        <Button variant="ghost" size="sm" disabled={busy} onClick={onRevoke}>
          <Trash2Icon /> Revoke
        </Button>
      )}
    </li>
  );
}
