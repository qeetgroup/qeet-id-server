import { SignupForm } from "./signup-form";

const API = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:4001";

type LoginContext = {
  client_name?: string;
  tenant_id?: string;
  self_registration_enabled?: boolean;
};

function clientIDFromReturnTo(returnTo: string): string {
  try {
    return new URL(returnTo).searchParams.get("client_id") ?? "";
  } catch {
    return "";
  }
}

// Self-registration is a per-tenant policy. We resolve the tenant + whether
// signup is open from the originating client (same login-context the sign-in
// page uses); the backend re-checks the gate on POST, so this only drives UI.
async function fetchContext(clientID: string): Promise<LoginContext> {
  if (!clientID) return {};
  try {
    const res = await fetch(
      `${API}/v1/oauth/login-context?client_id=${encodeURIComponent(clientID)}`,
      {
        cache: "no-store",
      },
    );
    if (!res.ok) return {};
    return (await res.json()) as LoginContext;
  } catch {
    return {};
  }
}

export default async function SignupPage({
  searchParams,
}: {
  searchParams: Promise<{ return_to?: string }>;
}) {
  const { return_to } = await searchParams;
  const returnTo = return_to ?? "";
  const ctx = await fetchContext(clientIDFromReturnTo(returnTo));
  return (
    <SignupForm
      returnTo={returnTo}
      clientName={ctx.client_name ?? ""}
      tenantId={ctx.tenant_id ?? ""}
      selfRegistrationEnabled={ctx.self_registration_enabled ?? false}
    />
  );
}
