import { OG_CONTENT_TYPE, OG_SIZE, ogCard } from "@/lib/og";

export const alt = "Qeet ID — Compare";
export const size = OG_SIZE;
export const contentType = OG_CONTENT_TYPE;

export default async function Image() {
  return ogCard({
    eyebrow: "Compare",
    title: "How Qeet ID stacks up against the alternatives",
    description:
      "Open-source and self-hostable, with passkeys-first auth and a tamper-evident audit log.",
  });
}
