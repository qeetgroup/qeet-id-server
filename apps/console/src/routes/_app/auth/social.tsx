import {
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  cn,
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
  Skeleton,
} from "@qeetrix/ui";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";
import {
  Apple,
  Atlassian,
  Auth0,
  Bitbucket,
  Box,
  Coinbase,
  Discord,
  Dropbox,
  Facebook,
  Figma,
  Github,
  Gitlab,
  Google,
  Kakao,
  Line,
  Linkedin,
  Microsoft,
  Naver,
  Notion,
  Okta,
  Reddit,
  Salesforce,
  Slack,
  Spotify,
  Twitch,
  X,
  Zoom,
} from "@thesvg/react";
import { Loader2Icon, NetworkIcon, PlusIcon, RefreshCwIcon } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { PageHeader } from "@/components/page-header";
import { type ApiError, api } from "@/lib/api";
import { useTenantId } from "@/lib/auth";

export const Route = createFileRoute("/_app/auth/social")({
  component: SocialPage,
});

type Provider = {
  tenant_id: string;
  provider: string;
  client_id: string;
  discovery_url: string;
  enabled: boolean;
  updated_at: string;
};

// iconClass handles dark-mode legibility: black-only marks (GitHub, X) invert in
// dark, white-only marks (Apple, Notion) invert in light. `fill` is set only for
// icons that ship without a baked color (Facebook) so they take currentColor.
// discovery is pre-filled for providers with a stable, tenant-independent OIDC
// well-known endpoint. The backend (domains/federation/social/social.go)
// requires a discovery_url on every provider unconditionally — there is no
// plain-OAuth2 fallback path (QID-03) — so a blank `discovery` here always
// means the admin must supply one themselves before sign-in will work, not
// that the provider works without one.
type KnownProvider = {
  id: string;
  label: string;
  // Either a @thesvg icon component, or a pair of theme-aware logo srcs (Qeet).
  Icon?: typeof Google;
  logoLight?: string;
  logoDark?: string;
  iconClass: string;
  fill?: string;
  discovery: string;
  // True only for vendors confirmed to have no OIDC discovery document at
  // all (plain OAuth 2.0-only APIs) — no discovery_url an admin could type
  // in will ever make these work against this backend today.
  oauth2Only?: boolean;
};

const KNOWN_PROVIDERS: KnownProvider[] = [
  {
    id: "qeet",
    label: "Qeet",
    logoLight: "/qeet-logo-on-light.svg",
    logoDark: "/qeet-logo-on-dark.svg",
    iconClass: "",
    discovery: "",
  },
  {
    id: "google",
    label: "Google",
    Icon: Google,
    iconClass: "",
    discovery: "https://accounts.google.com/.well-known/openid-configuration",
  },
  {
    id: "github",
    label: "GitHub",
    Icon: Github,
    iconClass: "dark:invert",
    discovery: "",
    oauth2Only: true,
  },
  {
    id: "microsoft",
    label: "Microsoft",
    Icon: Microsoft,
    iconClass: "",
    discovery: "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration",
  },
  {
    id: "apple",
    label: "Apple",
    Icon: Apple,
    iconClass: "invert dark:invert-0",
    discovery: "https://appleid.apple.com/.well-known/openid-configuration",
  },
  {
    id: "facebook",
    label: "Facebook",
    Icon: Facebook,
    iconClass: "text-[#1877F2]",
    fill: "currentColor",
    discovery: "",
    oauth2Only: true,
  },
  {
    id: "x",
    label: "X (Twitter)",
    Icon: X,
    iconClass: "dark:invert",
    discovery: "",
    oauth2Only: true,
  },
  {
    id: "linkedin",
    label: "LinkedIn",
    Icon: Linkedin,
    iconClass: "",
    discovery: "https://www.linkedin.com/oauth/.well-known/openid-configuration",
  },
  {
    id: "gitlab",
    label: "GitLab",
    Icon: Gitlab,
    iconClass: "",
    discovery: "https://gitlab.com/.well-known/openid-configuration",
  },
  {
    id: "bitbucket",
    label: "Bitbucket",
    Icon: Bitbucket,
    iconClass: "",
    discovery: "",
    oauth2Only: true,
  },
  {
    id: "discord",
    label: "Discord",
    Icon: Discord,
    iconClass: "",
    discovery: "",
    oauth2Only: true,
  },
  {
    id: "slack",
    label: "Slack",
    Icon: Slack,
    iconClass: "",
    discovery: "https://slack.com/.well-known/openid-configuration",
  },
  {
    id: "twitch",
    label: "Twitch",
    Icon: Twitch,
    iconClass: "",
    discovery: "https://id.twitch.tv/oauth2/.well-known/openid-configuration",
  },
  {
    id: "spotify",
    label: "Spotify",
    Icon: Spotify,
    iconClass: "",
    discovery: "",
  },
  {
    id: "reddit",
    label: "Reddit",
    Icon: Reddit,
    iconClass: "",
    discovery: "",
    oauth2Only: true,
  },
  {
    id: "atlassian",
    label: "Atlassian",
    Icon: Atlassian,
    iconClass: "",
    discovery: "",
  },
  {
    id: "salesforce",
    label: "Salesforce",
    Icon: Salesforce,
    iconClass: "",
    discovery: "https://login.salesforce.com/.well-known/openid-configuration",
  },
  { id: "okta", label: "Okta", Icon: Okta, iconClass: "", discovery: "" },
  { id: "auth0", label: "Auth0", Icon: Auth0, iconClass: "", discovery: "" },
  {
    id: "notion",
    label: "Notion",
    Icon: Notion,
    iconClass: "invert dark:invert-0",
    discovery: "",
  },
  { id: "figma", label: "Figma", Icon: Figma, iconClass: "", discovery: "" },
  { id: "zoom", label: "Zoom", Icon: Zoom, iconClass: "", discovery: "" },
  { id: "box", label: "Box", Icon: Box, iconClass: "", discovery: "" },
  {
    id: "dropbox",
    label: "Dropbox",
    Icon: Dropbox,
    iconClass: "",
    discovery: "",
  },
  {
    id: "line",
    label: "LINE",
    Icon: Line,
    iconClass: "",
    discovery: "https://access.line.me/.well-known/openid-configuration",
  },
  {
    id: "kakao",
    label: "Kakao",
    Icon: Kakao,
    iconClass: "",
    discovery: "https://kauth.kakao.com/.well-known/openid-configuration",
  },
  { id: "naver", label: "Naver", Icon: Naver, iconClass: "", discovery: "" },
  {
    id: "coinbase",
    label: "Coinbase",
    Icon: Coinbase,
    iconClass: "",
    discovery: "",
  },
];

// Qeet ships as a full-bleed app-icon (its own background); the rest sit on a
// neutral tile. Theme-aware logo swap mirrors the favicons in __root.tsx.
function ProviderChip({ provider }: { provider: KnownProvider }) {
  if (provider.logoLight) {
    return (
      <span className="size-9 shrink-0 overflow-hidden rounded-lg border">
        <img src={provider.logoLight} alt="" className="size-full object-cover dark:hidden" />
        <img src={provider.logoDark} alt="" className="hidden size-full object-cover dark:block" />
      </span>
    );
  }
  const Icon = provider.Icon;
  return (
    <span className="flex size-9 shrink-0 items-center justify-center rounded-lg border bg-muted/40">
      {Icon && (
        <Icon
          className={cn("size-5", provider.iconClass)}
          {...(provider.fill ? { fill: provider.fill } : {})}
        />
      )}
    </span>
  );
}

function SocialPage() {
  const { t } = useTranslation("auth");
  const tenantId = useTenantId();
  const qc = useQueryClient();
  const [editingProvider, setEditingProvider] = useState<string | null>(null);

  const listQ = useQuery({
    queryKey: ["social-providers", tenantId],
    queryFn: () => api<{ items: Provider[] }>(`/v1/tenants/${tenantId}/social/providers`),
    enabled: !!tenantId,
  });

  const configured = new Map((listQ.data?.items ?? []).map((p) => [p.provider, p]));

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <PageHeader
        description={t("social.description")}
        actions={
          <Button
            variant="outline"
            size="sm"
            onClick={() => listQ.refetch()}
            disabled={listQ.isFetching}
          >
            <RefreshCwIcon className={listQ.isFetching ? "animate-spin" : ""} />
            {t("social.refreshBtn")}
          </Button>
        }
      />

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
        {KNOWN_PROVIDERS.map((p) => {
          const cfg = configured.get(p.id);
          return (
            <Card key={p.id}>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <ProviderChip provider={p} />
                    <div>
                      <CardTitle className="text-base">{p.label}</CardTitle>
                      <CardDescription>
                        {cfg ? t("social.configured") : t("social.notConfigured")}
                      </CardDescription>
                    </div>
                  </div>
                  {p.oauth2Only ? (
                    <Badge variant="outline">{t("social.badges.notSupported")}</Badge>
                  ) : cfg ? (
                    cfg.enabled ? (
                      <Badge variant="success">{t("social.badges.enabled")}</Badge>
                    ) : (
                      <Badge variant="muted">{t("social.badges.disabled")}</Badge>
                    )
                  ) : (
                    <Badge variant="outline">{t("social.badges.off")}</Badge>
                  )}
                </div>
              </CardHeader>
              <CardContent className="space-y-2">
                {p.oauth2Only ? (
                  <p className="text-xs text-muted-foreground">
                    {t("social.oauth2OnlyDesc", { label: p.label })}
                  </p>
                ) : listQ.isLoading ? (
                  <Skeleton className="h-12 w-full" />
                ) : cfg ? (
                  <code className="block break-all text-xs text-muted-foreground">
                    client_id={cfg.client_id.slice(0, 20)}…
                  </code>
                ) : (
                  <p className="text-xs text-muted-foreground">
                    {t("social.noCredentials")}
                    {!p.discovery && t("social.requiresDiscovery")}
                  </p>
                )}
                <Button
                  variant="outline"
                  size="sm"
                  className="w-full"
                  disabled={p.oauth2Only}
                  onClick={() => setEditingProvider(p.id)}
                >
                  <PlusIcon /> {cfg ? t("social.updateBtn") : t("social.configureBtn")}
                </Button>
              </CardContent>
            </Card>
          );
        })}
      </div>

      {!listQ.isLoading && !configured.size && (
        <Card>
          <CardContent className="flex flex-col items-center gap-2 p-10 text-center">
            <NetworkIcon className="size-8 text-muted-foreground" />
            <p className="text-sm text-muted-foreground">{t("social.emptyTitle")}</p>
          </CardContent>
        </Card>
      )}

      {editingProvider && (
        <ConfigureProviderSheet
          provider={editingProvider}
          tenantId={tenantId}
          existing={configured.get(editingProvider)}
          onClose={() => setEditingProvider(null)}
          onSaved={() => qc.invalidateQueries({ queryKey: ["social-providers"] })}
        />
      )}
    </div>
  );
}

type ConfigureSheetProps = {
  provider: string;
  tenantId: string | null;
  existing?: Provider;
  onClose: () => void;
  onSaved: () => void;
};

function ConfigureProviderSheet({
  provider,
  tenantId,
  existing,
  onClose,
  onSaved,
}: ConfigureSheetProps) {
  const { t } = useTranslation("auth");
  const meta = KNOWN_PROVIDERS.find((p) => p.id === provider);
  const upsertM = useMutation({
    mutationFn: (body: {
      tenant_id: string;
      provider: string;
      client_id: string;
      client_secret: string;
      discovery_url: string;
    }) => api<Provider>("/v1/social/providers", { method: "POST", body }),
    onSuccess: () => {
      onSaved();
      onClose();
    },
  });

  return (
    <Sheet open onOpenChange={(o) => !o && onClose()}>
      <SheetContent side="right" className="w-full sm:max-w-md">
        <form
          className="flex h-full flex-col"
          onSubmit={(e) => {
            e.preventDefault();
            if (!tenantId) return;
            const data = new FormData(e.currentTarget);
            upsertM.mutate({
              tenant_id: tenantId,
              provider,
              client_id: String(data.get("client_id") ?? "").trim(),
              client_secret: String(data.get("client_secret") ?? "").trim(),
              discovery_url: String(data.get("discovery_url") ?? "").trim(),
            });
          }}
        >
          <SheetHeader>
            <SheetTitle className="flex items-center gap-2">
              {meta?.logoLight ? (
                <>
                  <img src={meta.logoLight} alt="" className="size-5 dark:hidden" />
                  <img src={meta.logoDark} alt="" className="hidden size-5 dark:block" />
                </>
              ) : (
                meta?.Icon && (
                  <meta.Icon
                    className={cn("size-5", meta.iconClass)}
                    {...(meta.fill ? { fill: meta.fill } : {})}
                  />
                )
              )}
              {t("social.configure.title", { label: meta?.label ?? provider })}
            </SheetTitle>
            <SheetDescription>{t("social.configure.description")}</SheetDescription>
          </SheetHeader>
          <div className="flex-1 overflow-y-auto p-4">
            <FieldGroup>
              <Field>
                <FieldLabel>{t("social.configure.providerLabel")}</FieldLabel>
                <Select value={provider} disabled>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {KNOWN_PROVIDERS.map((p) => (
                      <SelectItem key={p.id} value={p.id}>
                        {p.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </Field>
              <Field>
                <FieldLabel htmlFor="social-client_id">
                  {t("social.configure.clientIdLabel")}
                </FieldLabel>
                <Input
                  id="social-client_id"
                  name="client_id"
                  defaultValue={existing?.client_id}
                  required
                />
              </Field>
              <Field>
                <FieldLabel htmlFor="social-client_secret">
                  {t("social.configure.clientSecretLabel")}
                </FieldLabel>
                <Input
                  id="social-client_secret"
                  name="client_secret"
                  type="password"
                  required
                  placeholder={existing ? "Leave blank to keep existing" : ""}
                />
                <FieldDescription>{t("social.configure.clientSecretHelp")}</FieldDescription>
              </Field>
              <Field>
                <FieldLabel htmlFor="social-discovery_url">
                  {t("social.configure.discoveryLabel")}
                </FieldLabel>
                <Input
                  id="social-discovery_url"
                  name="discovery_url"
                  type="url"
                  required
                  defaultValue={existing?.discovery_url ?? meta?.discovery}
                  placeholder="https://provider.example/.well-known/openid-configuration"
                />
                <FieldDescription>
                  Required — sign-in fails without it. Some providers (Okta, Auth0, self-hosted
                  GitLab, …) don&apos;t have a fixed URL; find yours in the provider&apos;s own
                  OIDC/SSO settings, usually {"{your-domain}"}/.well-known/openid-configuration.
                </FieldDescription>
              </Field>
              {upsertM.error && (
                <Field>
                  <FieldError>{(upsertM.error as ApiError).message}</FieldError>
                </Field>
              )}
            </FieldGroup>
          </div>
          <SheetFooter className="flex-row justify-end gap-2 border-t">
            <SheetClose render={<Button type="button" variant="outline" />}>
              {t("social.configure.cancelBtn")}
            </SheetClose>
            <Button type="submit" disabled={upsertM.isPending}>
              {upsertM.isPending && <Loader2Icon className="animate-spin" />}
              {upsertM.isPending ? t("social.configure.savingBtn") : t("social.configure.saveBtn")}
            </Button>
          </SheetFooter>
        </form>
      </SheetContent>
    </Sheet>
  );
}
