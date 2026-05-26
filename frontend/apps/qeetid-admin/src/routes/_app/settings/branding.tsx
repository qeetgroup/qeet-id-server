import {
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  Field,
  FieldDescription,
  FieldError,
  FieldGroup,
  FieldLabel,
  Input,
  Skeleton,
} from "@qeetid/ui";
import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckIcon, Loader2Icon } from "lucide-react";
import { useEffect, useState } from "react";

import { PageHeader } from "@/components/page-header";
import { ApiError, api } from "@/lib/api";
import { useTenantId } from "@/lib/auth";

export const Route = createFileRoute("/_app/settings/branding")({ component: BrandingPage });

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
  const tenantId = useTenantId();
  const qc = useQueryClient();
  const [draft, setDraft] = useState<Branding>(empty);
  const [savedAt, setSavedAt] = useState<Date | null>(null);

  const brandQ = useQuery({
    queryKey: ["branding", tenantId],
    queryFn: () => api<Branding>(`/v1/tenants/${tenantId}/branding`),
    enabled: !!tenantId,
  });

  // Hydrate the form once the GET resolves.
  useEffect(() => {
    if (brandQ.data) setDraft({ ...empty, ...brandQ.data });
  }, [brandQ.data]);

  const saveM = useMutation({
    mutationFn: (body: Branding) =>
      api<Branding>(`/v1/tenants/${tenantId}/branding`, { method: "PUT", body }),
    onSuccess: () => {
      setSavedAt(new Date());
      qc.invalidateQueries({ queryKey: ["branding", tenantId] });
    },
    meta: { successMessage: "Branding saved" },
  });

  const set = <K extends keyof Branding>(key: K, value: Branding[K]) =>
    setDraft((d) => ({ ...d, [key]: value }));

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <PageHeader
        description="Logo, colors, custom domain, and outgoing email identity for this tenant. Changes apply to hosted login pages and transactional emails."
      />

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
                  <CardTitle className="text-base">Visual identity</CardTitle>
                  <CardDescription>
                    Used in hosted sign-in, emails, and the admin sidebar.
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <FieldGroup>
                    <Field>
                      <FieldLabel htmlFor="logo_url">Logo URL</FieldLabel>
                      <Input
                        id="logo_url"
                        name="logo_url"
                        type="url"
                        placeholder="https://cdn.example.com/logo.svg"
                        value={draft.logo_url ?? ""}
                        onChange={(e) => set("logo_url", e.target.value)}
                      />
                      <FieldDescription>Square SVG or PNG, at least 64×64.</FieldDescription>
                    </Field>
                    <Field className="grid grid-cols-2 gap-4">
                      <Field>
                        <FieldLabel htmlFor="primary_color">Primary color</FieldLabel>
                        <div className="flex items-center gap-2">
                          <Input
                            id="primary_color"
                            name="primary_color"
                            type="color"
                            value={draft.primary_color ?? "#5b21b6"}
                            onChange={(e) => set("primary_color", e.target.value)}
                            className="size-10 cursor-pointer p-1"
                          />
                          <Input
                            value={draft.primary_color ?? ""}
                            onChange={(e) => set("primary_color", e.target.value)}
                            placeholder="#5b21b6"
                          />
                        </div>
                      </Field>
                      <Field>
                        <FieldLabel htmlFor="secondary_color">Secondary color</FieldLabel>
                        <div className="flex items-center gap-2">
                          <Input
                            id="secondary_color"
                            name="secondary_color"
                            type="color"
                            value={draft.secondary_color ?? "#ffffff"}
                            onChange={(e) => set("secondary_color", e.target.value)}
                            className="size-10 cursor-pointer p-1"
                          />
                          <Input
                            value={draft.secondary_color ?? ""}
                            onChange={(e) => set("secondary_color", e.target.value)}
                            placeholder="#ffffff"
                          />
                        </div>
                      </Field>
                    </Field>
                  </FieldGroup>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Custom domain</CardTitle>
                  <CardDescription>
                    Where your hosted login pages are served (e.g. <code>auth.acme.com</code>).
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <FieldGroup>
                    <Field>
                      <FieldLabel htmlFor="custom_domain">Domain</FieldLabel>
                      <Input
                        id="custom_domain"
                        name="custom_domain"
                        type="text"
                        placeholder="auth.acme.com"
                        value={draft.custom_domain ?? ""}
                        onChange={(e) => set("custom_domain", e.target.value)}
                      />
                      <FieldDescription>
                        DNS + TLS provisioning happens out-of-band today. We'll show status here once
                        the custom-domain wizard ships.
                      </FieldDescription>
                    </Field>
                  </FieldGroup>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Outgoing email</CardTitle>
                  <CardDescription>
                    Sender identity used on magic links, OTP codes, password reset, invites.
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <FieldGroup>
                    <Field className="grid grid-cols-2 gap-4">
                      <Field>
                        <FieldLabel htmlFor="email_from_name">From name</FieldLabel>
                        <Input
                          id="email_from_name"
                          name="email_from_name"
                          placeholder="Acme Auth"
                          value={draft.email_from_name ?? ""}
                          onChange={(e) => set("email_from_name", e.target.value)}
                        />
                      </Field>
                      <Field>
                        <FieldLabel htmlFor="email_from_address">From address</FieldLabel>
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

              <div className="flex items-center justify-between">
                <p className="text-xs text-muted-foreground">
                  {savedAt ? `Last saved ${savedAt.toLocaleTimeString()}` : "Unsaved changes"}
                </p>
                <div className="flex gap-2">
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => brandQ.data && setDraft({ ...empty, ...brandQ.data })}
                    disabled={saveM.isPending}
                  >
                    Reset
                  </Button>
                  <Button type="submit" disabled={saveM.isPending}>
                    {saveM.isPending && <Loader2Icon className="animate-spin" />}
                    {saveM.isSuccess && !saveM.isPending && <CheckIcon />}
                    {saveM.isPending ? "Saving…" : "Save changes"}
                  </Button>
                </div>
              </div>
            </div>

            {/* Preview column */}
            <div>
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Live preview</CardTitle>
                  <CardDescription>How your sign-in card will look.</CardDescription>
                </CardHeader>
                <CardContent>
                  <div
                    className="space-y-3 rounded-lg border p-6"
                    style={{ backgroundColor: draft.secondary_color || "#fff" }}
                  >
                    {draft.logo_url ? (
                      <img
                        src={draft.logo_url}
                        alt="Logo preview"
                        className="mx-auto h-12 w-12 rounded-md object-contain"
                      />
                    ) : (
                      <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-md bg-muted text-xs text-muted-foreground">
                        Logo
                      </div>
                    )}
                    <h2 className="text-center text-lg font-semibold text-slate-900">
                      Welcome back
                    </h2>
                    <div className="space-y-2 text-sm">
                      <div className="h-9 rounded-md border bg-white" />
                      <div className="h-9 rounded-md border bg-white" />
                      <button
                        type="button"
                        className="h-9 w-full rounded-md font-medium text-white"
                        style={{ backgroundColor: draft.primary_color || "#5b21b6" }}
                      >
                        Sign in
                      </button>
                    </div>
                    <p className="text-center text-xs text-slate-500">
                      Powered by{" "}
                      {draft.email_from_name || "Qeetid"}
                    </p>
                  </div>
                </CardContent>
              </Card>
            </div>
          </div>
        </form>
      )}
    </div>
  );
}
