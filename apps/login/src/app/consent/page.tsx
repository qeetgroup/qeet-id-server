import { AuthShell } from "@/components/auth-shell";
import { type BrandingDTO, normalizeBranding } from "@/lib/branding";

import { ConsentForm, type ConsentParams } from "./consent-form";

const API = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:4001";

// Resolve the client's friendly name + tenant branding from the same
// login-context endpoint the sign-in page uses, so consent renders on-brand
// and names the real application instead of a raw client_id.
async function fetchContext(
  clientID: string,
): Promise<{ clientName: string; branding?: BrandingDTO }> {
  if (!clientID) return { clientName: "" };
  try {
    const res = await fetch(
      `${API}/v1/oauth/login-context?client_id=${encodeURIComponent(clientID)}`,
      { cache: "no-store" },
    );
    if (!res.ok) return { clientName: "" };
    const ctx = (await res.json()) as {
      client_name?: string;
      branding?: BrandingDTO;
    };
    return { clientName: ctx.client_name ?? "", branding: ctx.branding };
  } catch {
    return { clientName: "" };
  }
}

export default async function ConsentPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | undefined>>;
}) {
  const sp = await searchParams;
  const params: ConsentParams = {
    client_id: sp.client_id ?? "",
    redirect_uri: sp.redirect_uri ?? "",
    scope: sp.scope ?? "",
    state: sp.state ?? "",
    nonce: sp.nonce ?? "",
    code_challenge: sp.code_challenge ?? "",
    code_challenge_method: sp.code_challenge_method ?? "",
  };
  const { clientName, branding: brandingDTO } = await fetchContext(params.client_id);
  const branding = normalizeBranding(brandingDTO);
  return (
    <AuthShell branding={branding}>
      <ConsentForm params={params} clientName={clientName} branding={branding} />
    </AuthShell>
  );
}
