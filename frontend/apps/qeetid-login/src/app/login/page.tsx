import { LoginForm } from "./login-form";

const API = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:4001";

type LoginContext = {
  client_name?: string;
  tenant_id?: string;
  providers?: string[];
  self_registration_enabled?: boolean;
  remember_device_enabled?: boolean;
};

function clientIDFromReturnTo(returnTo: string): string {
  try {
    return new URL(returnTo).searchParams.get("client_id") ?? "";
  } catch {
    return "";
  }
}

// Fetched server-side: the client's display name + the tenant's enabled social
// providers, so the form can greet the user and render the right buttons.
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

export default async function LoginPage({
  searchParams,
}: {
  searchParams: Promise<{ return_to?: string; error?: string }>;
}) {
  const { return_to, error } = await searchParams;
  const returnTo = return_to ?? "";
  const ctx = await fetchContext(clientIDFromReturnTo(returnTo));
  return (
    <LoginForm
      returnTo={returnTo}
      clientName={ctx.client_name ?? ""}
      tenantId={ctx.tenant_id ?? ""}
      providers={ctx.providers ?? []}
      selfRegistrationEnabled={ctx.self_registration_enabled ?? false}
      rememberDeviceEnabled={ctx.remember_device_enabled ?? false}
      errorCode={error ?? ""}
    />
  );
}
