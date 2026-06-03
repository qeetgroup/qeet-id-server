import type { MetadataRoute } from "next";

import { caseStudySlug } from "@/components/marketing/blocks/case-study-card";
import { listPosts } from "@/lib/blog";
import { listEntries } from "@/lib/changelog";
import { stories } from "@/lib/customers";

/**
 * Marketing-site sitemap (Next 16 `MetadataRoute.Sitemap`).
 *
 * Enumerates every public marketing route — including the dynamic
 * `blog/[slug]` and `customers/[slug]` pages, whose slugs are read from the
 * in-repo data modules so the sitemap stays in lock-step with the content.
 * The hand-maintained static list keeps non-public paths (drafts, `/api/`)
 * out by construction.
 *
 * `lastModified` is derived from real content dates where we have them
 * (latest blog post, latest changelog entry); otherwise the build date is a
 * sensible default. Priorities/frequencies follow the marketing hierarchy:
 * the home + top conversion pages rank highest and change most often.
 */

// Canonical marketing origin — must match `metadataBase` in app/layout.tsx,
// robots.ts, and the JSON-LD in structured-data.tsx (all `qeetid.com`).
const BASE_URL = "https://qeetid.com";

type ChangeFrequency = NonNullable<MetadataRoute.Sitemap[number]["changeFrequency"]>;

function entry(
  path: string,
  changeFrequency: ChangeFrequency,
  priority: number,
  lastModified: string | Date,
): MetadataRoute.Sitemap[number] {
  return {
    url: path === "/" ? BASE_URL : `${BASE_URL}${path}`,
    lastModified,
    changeFrequency,
    priority,
  };
}

export default function sitemap(): MetadataRoute.Sitemap {
  const now = new Date();

  const posts = listPosts();
  const latestPost = posts[0]?.publishedAt ?? now;
  const changelog = listEntries();
  const latestRelease = changelog[0]?.date ?? now;

  // Static marketing routes, highest-value first.
  const staticRoutes: MetadataRoute.Sitemap = [
    entry("/", "weekly", 1.0, now),
    entry("/features", "monthly", 0.9, now),
    entry("/pricing", "monthly", 0.9, now),
    entry("/security", "monthly", 0.8, now),
    entry("/customers", "weekly", 0.8, now),
    entry("/compare", "monthly", 0.7, now),
    entry("/blog", "weekly", 0.7, latestPost),
    entry("/changelog", "weekly", 0.6, latestRelease),
    entry("/about", "monthly", 0.6, now),
    entry("/careers", "weekly", 0.6, now),
    entry("/status", "daily", 0.4, now),
    entry("/contact", "yearly", 0.5, now),
    // Legal — important for trust/compliance, low crawl cadence.
    entry("/legal/privacy", "yearly", 0.3, now),
    entry("/legal/terms", "yearly", 0.3, now),
    entry("/legal/dpa", "yearly", 0.3, now),
    entry("/legal/subprocessors", "yearly", 0.3, now),
  ];

  // Competitor comparison landing pages — SEO bait for "Qeet ID vs X".
  const compareRoutes: MetadataRoute.Sitemap = ["auth0", "clerk", "stytch", "workos"].map(
    (slug) => entry(`/compare/${slug}`, "monthly", 0.6, now),
  );

  // Dynamic blog posts.
  const blogRoutes: MetadataRoute.Sitemap = posts.map((post) =>
    entry(`/blog/${post.slug}`, "yearly", 0.6, post.publishedAt),
  );

  // Dynamic customer stories.
  const customerRoutes: MetadataRoute.Sitemap = stories.map((story) =>
    entry(`/customers/${caseStudySlug(story.company)}`, "monthly", 0.6, now),
  );

  return [...staticRoutes, ...compareRoutes, ...blogRoutes, ...customerRoutes];
}
