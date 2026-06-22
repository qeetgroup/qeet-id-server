import { OG_CONTENT_TYPE, OG_SIZE, ogCard } from "@/lib/og";

export const alt = "Qeet ID — Customer stories";
export const size = OG_SIZE;
export const contentType = OG_CONTENT_TYPE;

export default async function Image() {
  return ogCard({
    eyebrow: "Customers",
    title: "Teams that replaced home-grown auth with Qeet ID",
    description:
      "How developer platforms, fintechs, and healthcare teams ship identity without the maintenance burden.",
  });
}
