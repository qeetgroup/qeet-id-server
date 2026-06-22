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
async function fetchTenantID(clientID: string): Promise<string> {
  if (!clientID) return "";
  try {
    const res = await fetch(
      `${API}/v1/oauth/login-context?client_id=${encodeURIComponent(clientID)}`,
      {
        cache: "no-store",
      },
    );
    if (!res.ok) return "";
    const ctx = (await res.json()) as { tenant_id?: string };
    return ctx.tenant_id ?? "";
  } catch {
    return "";
  }
}

export default async function ForgotPasswordPage({
  searchParams,
}: {
  searchParams: Promise<{ return_to?: string }>;
}) {
  const { return_to } = await searchParams;
  const returnTo = return_to ?? "";
  const tenantId = await fetchTenantID(clientIDFromReturnTo(returnTo));
  return <ForgotPasswordForm returnTo={returnTo} tenantId={tenantId} />;
}
