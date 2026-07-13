import {
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  ColorPicker,
  Field,
  FieldDescription,
  FieldError,
  FieldGroup,
  FieldLabel,
  Input,
  Skeleton,
} from "@qeetrix/ui";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";
import { CheckIcon, Loader2Icon } from "lucide-react";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { LogoField } from "@/components/logo-field";
import { PageHeader } from "@/components/page-header";
import { type ApiError, api } from "@/lib/api";
import { useTenantId } from "@/lib/auth";

export const Route = createFileRoute("/_app/settings/branding")({
  component: BrandingPage,
});

type Branding = {
  tenant_id: string;
  logo_url?: string | null;
  primary_color?: string | null;
  secondary_color?: string | null;
  custom_domain?: string | null;
  email_from_name?: string | null;
  email_from_address?: string | null;
  settings?: Record<string, unknown>;
};

const empty: Branding = {
  tenant_id: "",
  logo_url: "",
  primary_color: "#5b21b6",
  secondary_color: "#ffffff",
  custom_domain: "",
  email_from_name: "",
  email_from_address: "",
};

function BrandingPage() {
  const { t } = useTranslation("settings");
  const tenantId = useTenantId();
  const qc = useQueryClient();
  const [draft, setDraft] = useState<Branding>(empty);
  const [savedAt, setSavedAt] = useState<Date | null>(null);

  const brandQ = useQuery({
    queryKey: ["branding", tenantId],
    queryFn: () => api<Branding>(`/v1/tenants/${tenantId}/branding`),
    enabled: !!tenantId,
  });

  useEffect(() => {
    if (brandQ.data) setDraft({ ...empty, ...brandQ.data });
  }, [brandQ.data]);

  const saveM = useMutation({
    mutationFn: (body: Branding) =>
      api<Branding>(`/v1/tenants/${tenantId}/branding`, {
        method: "PUT",
        body,
      }),
    onSuccess: () => {
      setSavedAt(new Date());
      qc.invalidateQueries({ queryKey: ["branding", tenantId] });
    },
    meta: { successMessage: t("branding.toast.saved") },
  });

  const set = <K extends keyof Branding>(key: K, value: Branding[K]) =>
    setDraft((d) => ({ ...d, [key]: value }));

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <PageHeader description={t("branding.description")} />

      {brandQ.isLoading ? (
        <Card>
          <CardContent className="space-y-3 p-6">
            {[...Array(5)].map((_, i) => (
              <Skeleton key={i} className="h-10 w-full" />
            ))}
          </CardContent>
        </Card>
      ) : (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            saveM.mutate(draft);
          }}
        >
          <div className="grid gap-4 lg:grid-cols-3">
            {/* Form column */}
            <div className="space-y-4 lg:col-span-2">
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">{t("branding.visualIdentity.title")}</CardTitle>
                  <CardDescription>{t("branding.visualIdentity.description")}</CardDescription>
                </CardHeader>
                <CardContent>
                  <FieldGroup>
                    <Field>
                      <FieldLabel>{t("branding.visualIdentity.logo")}</FieldLabel>
                      <LogoField
                        value={draft.logo_url ?? ""}
                        onChange={(next) => set("logo_url", next)}
                        hint="Square SVG or PNG, at least 64×64. Drag a file or paste a URL."
                        maxSizeMB={2}
                      />
                    </Field>
                    <Field className="grid grid-cols-2 gap-4">
                      <Field>
                        <FieldLabel>{t("branding.visualIdentity.primaryColor")}</FieldLabel>
                        <ColorPicker
                          value={draft.primary_color ?? ""}
                          onChange={(hex) => set("primary_color", hex)}
                          placeholder="#5b21b6"
                          ariaLabel={t("branding.visualIdentity.primaryColor")}
                        />
                        <FieldDescription>
                          {t("branding.visualIdentity.primaryColorHelp")}
                        </FieldDescription>
                      </Field>
                      <Field>
                        <FieldLabel>{t("branding.visualIdentity.secondaryColor")}</FieldLabel>
                        <ColorPicker
                          value={draft.secondary_color ?? ""}
                          onChange={(hex) => set("secondary_color", hex)}
                          placeholder="#ffffff"
                          ariaLabel={t("branding.visualIdentity.secondaryColor")}
                        />
                        <FieldDescription>
                          {t("branding.visualIdentity.secondaryColorHelp")}
                        </FieldDescription>
                      </Field>
                    </Field>
                  </FieldGroup>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="text-base">{t("branding.customDomain.title")}</CardTitle>
                  <CardDescription>{t("branding.customDomain.description")}</CardDescription>
                </CardHeader>
                <CardContent>
                  <FieldGroup>
                    <Field>
                      <FieldLabel htmlFor="custom_domain">
                        {t("branding.customDomain.label")}
                      </FieldLabel>
                      <Input
                        id="custom_domain"
                        name="custom_domain"
                        type="text"
                        placeholder="auth.acme.com"
                        value={draft.custom_domain ?? ""}
                        onChange={(e) => set("custom_domain", e.target.value)}
                      />
                      <FieldDescription>{t("branding.customDomain.help")}</FieldDescription>
                      {draft.custom_domain && (
                        <div className="mt-2 flex items-center gap-1.5 text-xs text-muted-foreground">
                          <span className="inline-block h-1.5 w-1.5 rounded-full bg-amber-400" />
                          {t("branding.customDomain.pending")}
                        </div>
                      )}
                    </Field>
                  </FieldGroup>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="text-base">{t("branding.outgoingEmail.title")}</CardTitle>
                  <CardDescription>{t("branding.outgoingEmail.description")}</CardDescription>
                </CardHeader>
                <CardContent>
                  <FieldGroup>
                    <Field className="grid grid-cols-2 gap-4">
                      <Field>
                        <FieldLabel htmlFor="email_from_name">
                          {t("branding.outgoingEmail.fromName")}
                        </FieldLabel>
                        <Input
                          id="email_from_name"
                          name="email_from_name"
                          placeholder="Acme Auth"
                          value={draft.email_from_name ?? ""}
                          onChange={(e) => set("email_from_name", e.target.value)}
                        />
                      </Field>
                      <Field>
                        <FieldLabel htmlFor="email_from_address">
                          {t("branding.outgoingEmail.fromAddress")}
                        </FieldLabel>
                        <Input
                          id="email_from_address"
                          name="email_from_address"
                          type="email"
                          placeholder="noreply@acme.com"
                          value={draft.email_from_address ?? ""}
                          onChange={(e) => set("email_from_address", e.target.value)}
                        />
                      </Field>
                    </Field>
                  </FieldGroup>
                </CardContent>
              </Card>

              {saveM.error && (
                <Card className="border-destructive">
                  <CardContent className="p-4">
                    <FieldError>{(saveM.error as ApiError).message}</FieldError>
                  </CardContent>
                </Card>
              )}
            </div>

            {/* Preview column */}
            <div className="sticky top-24 space-y-4">
              <Card>
                <CardHeader className="pb-3">
                  <CardTitle className="text-base">{t("branding.preview.title")}</CardTitle>
                  <CardDescription>{t("branding.preview.description")}</CardDescription>
                </CardHeader>
                <CardContent className="p-0">
                  {/* Simulated browser chrome */}
                  <div className="overflow-hidden rounded-b-lg border-t">
                    {/* Fake URL bar */}
                    <div className="flex items-center gap-2 border-b bg-muted/60 px-3 py-2">
                      <div className="flex gap-1.5">
                        <span className="h-2.5 w-2.5 rounded-full bg-red-400/70" />
                        <span className="h-2.5 w-2.5 rounded-full bg-yellow-400/70" />
                        <span className="h-2.5 w-2.5 rounded-full bg-green-400/70" />
                      </div>
                      <div className="flex-1 truncate rounded bg-background/80 px-2 py-0.5 font-mono text-[10px] text-muted-foreground">
                        {draft.custom_domain
                          ? `https://${draft.custom_domain}`
                          : "https://auth.id.qeet.in"}
                      </div>
                    </div>
                    {/* Login card preview */}
                    <div
                      className="flex items-center justify-center p-6"
                      style={{
                        backgroundColor: draft.secondary_color || "#f8fafc",
                      }}
                    >
                      <div className="w-full max-w-60 overflow-hidden rounded-xl border bg-white shadow-lg">
                        {/* Card header with logo */}
                        <div className="px-6 pb-4 pt-6 text-center">
                          {draft.logo_url ? (
                            <img
                              src={draft.logo_url}
                              alt="Logo"
                              className="mx-auto mb-3 h-10 w-10 rounded-lg object-contain"
                            />
                          ) : (
                            <div
                              className="mx-auto mb-3 flex h-10 w-10 items-center justify-center rounded-lg text-sm font-bold text-white"
                              style={{
                                backgroundColor: draft.primary_color || "#5b21b6",
                              }}
                            >
                              {(draft.email_from_name || "Q").slice(0, 1).toUpperCase()}
                            </div>
                          )}
                          <h3 className="text-sm font-semibold text-slate-900">
                            {t("branding.preview.signInTo", {
                              name: draft.email_from_name || "your account",
                            })}
                          </h3>
                          <p className="mt-0.5 text-[10px] text-slate-500">
                            {t("branding.preview.emailPlaceholder")}
                          </p>
                        </div>
                        {/* Form fields */}
                        <div className="space-y-2 px-5 pb-5">
                          <div className="flex h-8 items-center rounded-md border border-slate-200 bg-slate-50 px-3">
                            <span className="text-[10px] text-slate-400">
                              {t("branding.preview.emailPlaceholder")}
                            </span>
                          </div>
                          <button
                            type="button"
                            className="h-8 w-full rounded-md text-[11px] font-medium text-white transition-opacity hover:opacity-90"
                            style={{
                              backgroundColor: draft.primary_color || "#5b21b6",
                            }}
                          >
                            {t("branding.preview.continue")}
                          </button>
                          <div className="flex items-center gap-2">
                            <div className="h-px flex-1 bg-slate-200" />
                            <span className="text-[9px] uppercase tracking-wider text-slate-400">
                              {t("branding.preview.or")}
                            </span>
                            <div className="h-px flex-1 bg-slate-200" />
                          </div>
                          {/* Social button mock */}
                          <div className="flex h-8 items-center justify-center gap-2 rounded-md border border-slate-200">
                            <svg className="h-3 w-3" viewBox="0 0 24 24" aria-hidden="true">
                              <path
                                d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
                                fill="#4285F4"
                              />
                              <path
                                d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
                                fill="#34A853"
                              />
                              <path
                                d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"
                                fill="#FBBC05"
                              />
                              <path
                                d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"
                                fill="#EA4335"
                              />
                            </svg>
                            <span className="text-[10px] text-slate-600">
                              {t("branding.preview.continueWithGoogle")}
                            </span>
                          </div>
                        </div>
                        {/* Footer */}
                        <div
                          className="border-t px-5 py-2.5 text-center"
                          style={{
                            backgroundColor: (draft.primary_color || "#5b21b6") + "0d",
                          }}
                        >
                          <p className="text-[9px] text-slate-500">
                            {t("branding.preview.securedBy")}{" "}
                            <span
                              className="font-medium"
                              style={{
                                color: draft.primary_color || "#5b21b6",
                              }}
                            >
                              {draft.email_from_name || "Qeet ID"}
                            </span>
                          </p>
                        </div>
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>

              {/* Color palette swatch preview */}
              <Card>
                <CardHeader className="pb-3">
                  <CardTitle className="text-base">{t("branding.palette.title")}</CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="flex items-center gap-3">
                    <div
                      className="h-10 w-10 shrink-0 rounded-lg border shadow-sm"
                      style={{
                        backgroundColor: draft.primary_color || "#5b21b6",
                      }}
                    />
                    <div>
                      <p className="text-xs font-medium">{t("branding.palette.primary")}</p>
                      <p className="font-mono text-xs text-muted-foreground">
                        {draft.primary_color || "#5b21b6"}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    <div
                      className="h-10 w-10 shrink-0 rounded-lg border shadow-sm"
                      style={{
                        backgroundColor: draft.secondary_color || "#ffffff",
                      }}
                    />
                    <div>
                      <p className="text-xs font-medium">{t("branding.palette.background")}</p>
                      <p className="font-mono text-xs text-muted-foreground">
                        {draft.secondary_color || "#ffffff"}
                      </p>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>
          </div>

          {/* Sticky save footer */}
          <div className="sticky bottom-0 z-10 mt-4 flex items-center justify-between rounded-b-lg border-t bg-background/95 px-4 py-3 backdrop-blur-sm">
            <p className="text-xs text-muted-foreground">
              {savedAt
                ? t("branding.footer.savedAt", {
                    time: savedAt.toLocaleTimeString(),
                  })
                : t("branding.footer.unsaved")}
            </p>
            <div className="flex gap-2">
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => brandQ.data && setDraft({ ...empty, ...brandQ.data })}
                disabled={saveM.isPending}
              >
                {t("branding.footer.reset")}
              </Button>
              <Button type="submit" size="sm" disabled={saveM.isPending}>
                {saveM.isPending && <Loader2Icon className="animate-spin" />}
                {saveM.isSuccess && !saveM.isPending && <CheckIcon />}
                {saveM.isPending ? t("branding.footer.saving") : t("branding.footer.save")}
              </Button>
            </div>
          </div>
        </form>
      )}
    </div>
  );
}
