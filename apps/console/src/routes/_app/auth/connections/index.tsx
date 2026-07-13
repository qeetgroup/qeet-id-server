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
import { useTranslation } from "react-i18next";

import { useConfirmDialog } from "@/components/confirm-dialog";
import { PageHeader } from "@/components/page-header";
import {
  type AdminPortalCapability,
  type AdminPortalLink,
  isAdminPortalLinkActive,
  useAdminPortalLinks,
  useGenerateAdminPortalLink,
  useRevokeAdminPortalLink,
} from "@/lib/admin-portal";
import type { ApiError } from "@/lib/api";

export const Route = createFileRoute("/_app/auth/connections/")({
  component: ConnectionsPage,
});

const TTL_SECONDS = [60 * 60, 24 * 60 * 60, 3 * 24 * 60 * 60, 7 * 24 * 60 * 60];

function ConnectionsPage() {
  const { t } = useTranslation("auth");

  const TTL_OPTIONS = [
    { label: t("connections.portal.ttl1h"), seconds: TTL_SECONDS[0] },
    { label: t("connections.portal.ttl24h"), seconds: TTL_SECONDS[1] },
    { label: t("connections.portal.ttl3d"), seconds: TTL_SECONDS[2] },
    { label: t("connections.portal.ttl7d"), seconds: TTL_SECONDS[3] },
  ];

  return (
    <div className="flex min-w-0 flex-col gap-6">
      <PageHeader description={t("connections.description")} />

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <ConnectionCard
          to="/auth/connections/saml"
          title={t("connections.cards.saml2Title")}
          description={t("connections.cards.saml2Desc")}
        />
        <ConnectionCard
          to="/auth/connections/saml-idp"
          title={t("connections.cards.samlIdpTitle")}
          description={t("connections.cards.samlIdpDesc")}
        />
        <ConnectionCard
          to="/auth/connections/oidc"
          title={t("connections.cards.oidcTitle")}
          description={t("connections.cards.oidcDesc")}
        />
        <ConnectionCard
          to="/auth/connections/scim"
          title={t("connections.cards.scimTitle")}
          description={t("connections.cards.scimDesc")}
        />
      </div>

      <AdminPortalCard ttlOptions={TTL_OPTIONS} />
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

function AdminPortalCard({ ttlOptions }: { ttlOptions: { label: string; seconds: number }[] }) {
  const { t } = useTranslation("auth");
  const [confirmDialog, openConfirm] = useConfirmDialog();
  const linksQ = useAdminPortalLinks();
  const generateM = useGenerateAdminPortalLink();
  const revokeM = useRevokeAdminPortalLink();

  const [capabilities, setCapabilities] = useState<Set<AdminPortalCapability>>(
    () => new Set(["saml", "scim"]),
  );
  const [ttl, setTtl] = useState(String(ttlOptions[1].seconds));

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
          <CardTitle className="text-base">{t("connections.portal.title")}</CardTitle>
          <CardDescription>{t("connections.portal.description")}</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-end">
            <Field>
              <FieldLabel>{t("connections.portal.capabilities")}</FieldLabel>
              <div className="flex items-center gap-4 pt-1">
                {/* Checkbox is a @base-ui custom element (not a native input),
                  so label+htmlFor association doesn't apply. Use aria-label
                  on the Checkbox and a sibling span for the visual text. */}
                <div className="flex items-center gap-2 text-sm">
                  <Checkbox
                    aria-label={t("connections.portal.samlCapability")}
                    checked={capabilities.has("saml")}
                    onCheckedChange={(c) => toggle("saml", c === true)}
                  />
                  <span aria-hidden>SAML</span>
                </div>
                <div className="flex items-center gap-2 text-sm">
                  <Checkbox
                    aria-label={t("connections.portal.scimCapability")}
                    checked={capabilities.has("scim")}
                    onCheckedChange={(c) => toggle("scim", c === true)}
                  />
                  <span aria-hidden>SCIM</span>
                </div>
              </div>
            </Field>
            <Field className="sm:w-40">
              <FieldLabel htmlFor="ttl">{t("connections.portal.expires")}</FieldLabel>
              <Select value={ttl} onValueChange={(v) => v && setTtl(v)}>
                <SelectTrigger id="ttl">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {ttlOptions.map((o) => (
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
              {t("connections.portal.generate")}
            </Button>
          </div>
          {generateM.error && (
            <p className="text-destructive text-sm">{(generateM.error as ApiError).message}</p>
          )}

          {generated && (
            <div className="rounded-lg border border-amber-500/40 bg-amber-50/40 p-4 dark:bg-amber-950/20">
              <p className="mb-2 text-sm font-medium">{t("connections.portal.copied")}</p>
              <CopyableSecret value={generated.url} size="sm" />
              <div className="mt-3">
                <Button variant="outline" size="sm" onClick={() => generateM.reset()}>
                  {t("connections.portal.saved")}
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
            emptyTitle={t("connections.portal.emptyTitle")}
            emptyDescription={t("connections.portal.emptyDescription")}
            skeletonRows={2}
          >
            <ul className="divide-y">
              {items.map((l) => (
                <AdminPortalLinkRow
                  key={l.id}
                  link={l}
                  onRevoke={() =>
                    openConfirm({
                      title: t("connections.portal.confirm.title"),
                      description: t("connections.portal.confirm.description"),
                      variant: "destructive",
                      confirmLabel: t("connections.portal.confirm.label"),
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
  const { t } = useTranslation("auth");
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
          {t("connections.portal.linkExpires", {
            date: new Date(l.expires_at).toLocaleString(),
          })}
          {l.last_used_at
            ? t("connections.portal.linkLastUsed", {
                date: new Date(l.last_used_at).toLocaleString(),
              })
            : t("connections.portal.linkNeverUsed")}
        </p>
      </div>
      {active && (
        <Button variant="ghost" size="sm" disabled={busy} onClick={onRevoke}>
          <Trash2Icon /> {t("connections.portal.revokeBtn")}
        </Button>
      )}
    </li>
  );
}
