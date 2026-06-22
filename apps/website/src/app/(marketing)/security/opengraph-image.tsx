import { OG_CONTENT_TYPE, OG_SIZE, ogCard } from "@/lib/og";

export const alt = "Qeet ID — Security";
export const size = OG_SIZE;
export const contentType = OG_CONTENT_TYPE;

export default async function Image() {
  return ogCard({
    eyebrow: "Security",
    title: "Security you can inspect, not just trust",
    description:
      "Phishing-resistant passkeys, a hash-chained audit log, and a self-hostable single binary.",
  });
}
