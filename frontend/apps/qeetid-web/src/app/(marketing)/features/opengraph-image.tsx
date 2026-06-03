import { OG_CONTENT_TYPE, OG_SIZE, ogCard } from "@/lib/og";

export const alt = "Qeet ID — Features";
export const size = OG_SIZE;
export const contentType = OG_CONTENT_TYPE;

export default async function Image() {
  return ogCard({
    eyebrow: "Features",
    title: "Everything you need to ship secure auth",
    description:
      "SSO, MFA, passkeys, RBAC, and a tamper-evident audit log — in one open-source platform.",
  });
}
