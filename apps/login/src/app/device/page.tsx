import { AuthShell } from "@/components/auth-shell";

import { DeviceForm } from "./device-form";

export default async function DevicePage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | undefined>>;
}) {
  const sp = await searchParams;
  const userCode = sp.user_code ?? "";
  // The device flow arrives with only a user_code (no client_id), so there's no
  // tenant to resolve branding from — render the default Qeet shell.
  return (
    <AuthShell>
      <DeviceForm userCode={userCode} />
    </AuthShell>
  );
}
