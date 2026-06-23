import type { MetadataRoute } from "next";

// Crawl rules for the marketing + docs surface. The admin and account
// areas live on a different host (admin.id.qeet.in) and have their own
// robots; this file only covers the marketing-public origin.
export default function robots(): MetadataRoute.Robots {
  return {
    rules: [
      {
        userAgent: "*",
        allow: "/",
        // Compare pages are intentionally indexable — they're SEO bait
        // for high-intent queries like "Qeet ID vs Auth0".
        disallow: ["/api/", "/legal/draft/"],
      },
    ],
    sitemap: "https://id.qeet.in/sitemap.xml",
    host: "https://id.qeet.in",
  };
}
