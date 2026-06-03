import { DeviceForm } from "./device-form";

export default async function DevicePage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | undefined>>;
}) {
  const sp = await searchParams;
  const userCode = sp.user_code ?? "";
  return <DeviceForm userCode={userCode} />;
}
