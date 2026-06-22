import { caseStudySlug } from "@/components/marketing/blocks/case-study-card";
import { getStory, stories } from "@/lib/customers";
import { OG_CONTENT_TYPE, OG_SIZE, ogCard } from "@/lib/og";

// Per-customer-story branded OG card. Renders the story headline + summary on
// the shared brand template. Statically generated at build time per slug.

export const alt = "Qeet ID customer story";
export const size = OG_SIZE;
export const contentType = OG_CONTENT_TYPE;

// Prerender one OG image per story at build time (statically optimized).
export function generateStaticParams() {
  return stories.map((s) => ({ slug: caseStudySlug(s.company) }));
}

export default async function Image({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const story = getStory(slug);

  return ogCard({
    eyebrow: story ? `${story.company} · ${story.segment}` : "Customer story",
    title: story?.headline ?? "Customer story",
    description: story?.summary,
    tags: story?.highlights,
  });
}
