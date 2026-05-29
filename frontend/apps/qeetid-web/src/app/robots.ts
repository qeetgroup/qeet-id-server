import type { MetadataRoute } from "next";

// Crawl rules for the marketing + docs surface. The admin and account
// areas live on a different host (admin.qeetid.com) and have their own
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
    sitemap: "https://qeetid.com/sitemap.xml",
    host: "https://qeetid.com",
  };
}
