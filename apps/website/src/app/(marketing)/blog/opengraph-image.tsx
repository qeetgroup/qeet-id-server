import { OG_CONTENT_TYPE, OG_SIZE, ogCard } from "@/lib/og";

export const alt = "Qeet ID — Engineering blog";
export const size = OG_SIZE;
export const contentType = OG_CONTENT_TYPE;

export default async function Image() {
  return ogCard({
    eyebrow: "Engineering",
    title: "Notes from the team building Qeet ID",
    description: "Security, identity, and the boring infra it takes to make auth feel boring.",
  });
}
