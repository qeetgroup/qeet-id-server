import { AuthShell } from "@/components/auth-shell";
import { type BrandingDTO, normalizeBranding } from "@/lib/branding";

import { ForgotPasswordForm } from "./forgot-password-form";

const API = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:4001";

function clientIDFromReturnTo(returnTo: string): string {
  try {
    return new URL(returnTo).searchParams.get("client_id") ?? "";
  } catch {
    return "";
  }
}

// The reset lookup is scoped by tenant, so we resolve the tenant from the
// originating client (same login-context the sign-in page uses) when a
// return_to is present. Absent that, the form still submits — the backend is
// enumeration-safe and answers identically whether or not the email resolves.
// We also read the tenant branding so the page renders on-brand.
async function fetchContext(
  clientID: string,
): Promise<{ tenantId: string; branding?: BrandingDTO }> {
  if (!clientID) return { tenantId: "" };
  try {
    const res = await fetch(
      `${API}/v1/oauth/login-context?client_id=${encodeURIComponent(clientID)}`,
      {
        cache: "no-store",
      },
    );
    if (!res.ok) return { tenantId: "" };
    const ctx = (await res.json()) as {
      tenant_id?: string;
      branding?: BrandingDTO;
    };
    return { tenantId: ctx.tenant_id ?? "", branding: ctx.branding };
  } catch {
    return { tenantId: "" };
  }
}

export default async function ForgotPasswordPage({
  searchParams,
}: {
  searchParams: Promise<{ return_to?: string }>;
}) {
  const { return_to } = await searchParams;
  const returnTo = return_to ?? "";
  const { tenantId, branding: brandingDTO } = await fetchContext(clientIDFromReturnTo(returnTo));
  const branding = normalizeBranding(brandingDTO);
  return (
    <AuthShell branding={branding}>
      <ForgotPasswordForm returnTo={returnTo} tenantId={tenantId} branding={branding} />
    </AuthShell>
  );
}
