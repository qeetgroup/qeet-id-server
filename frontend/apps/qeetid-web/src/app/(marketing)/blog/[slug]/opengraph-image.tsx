import { getPost } from "@/lib/blog";
import { OG_CONTENT_TYPE, OG_SIZE, ogCard } from "@/lib/og";

// Per-post branded OG card. Renders the post title + description on the shared
// brand template. Statically generated at build time (one image per slug).

export const alt = "Qeet ID engineering blog";
export const size = OG_SIZE;
export const contentType = OG_CONTENT_TYPE;

export default async function Image({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const post = getPost(slug);

  return ogCard({
    eyebrow: "Engineering",
    title: post?.title ?? "Qeet ID engineering blog",
    description: post?.description,
    tags: post?.tags,
  });
}
