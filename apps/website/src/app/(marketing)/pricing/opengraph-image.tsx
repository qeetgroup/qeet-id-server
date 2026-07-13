import { OG_CONTENT_TYPE, OG_SIZE, ogCard } from "@/lib/og";

export const alt = "Qeet ID — Pricing";
export const size = OG_SIZE;
export const contentType = OG_CONTENT_TYPE;

export default async function Image() {
  return ogCard({
    eyebrow: "Pricing",
    title: "Simple pricing. Real free tier.",
    description: "Free up to 5,000 MAU, no card required. Predictable per-MAU pricing as you grow.",
  });
}
