import { AuthShell } from "@/components/auth-shell";

import { ResetForm } from "./reset-form";

export default async function ResetPage({
  searchParams,
}: {
  searchParams: Promise<{ token?: string }>;
}) {
  const { token } = await searchParams;
  // The reset link carries only an opaque token (no client_id), so there's no
  // tenant to resolve branding from — render the default Qeet shell.
  return (
    <AuthShell>
      <ResetForm token={token ?? ""} />
    </AuthShell>
  );
}
