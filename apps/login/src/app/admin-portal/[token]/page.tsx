import { AuthShell } from "@/components/auth-shell";
import { fetchPortalContext, type PortalContext } from "@/lib/admin-portal";
import { ApiError } from "@/lib/api";
import { normalizeBranding } from "@/lib/branding";

import { AdminPortalView } from "./admin-portal-view";

async function loadContext(token: string): Promise<{ context?: PortalContext; error?: string }> {
  try {
    return { context: await fetchPortalContext(token) };
  } catch (err) {
    return {
      error: err instanceof ApiError ? err.message : "This link could not be loaded.",
    };
  }
}

export default async function AdminPortalPage({ params }: { params: Promise<{ token: string }> }) {
  const { token } = await params;
  const { context, error } = await loadContext(token);
  const branding = normalizeBranding(context?.branding);

  return (
    <AuthShell branding={branding} className="lg:grid-cols-[0.85fr_1.15fr]">
      <AdminPortalView token={token} context={context} error={error} />
    </AuthShell>
  );
}
