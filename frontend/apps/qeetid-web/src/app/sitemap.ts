import type { MetadataRoute } from "next";

const BASE = "https://qeetid.com";

// Hand-maintained URL list. Lower-friction than a file-system walk for
// this size of site, and keeps non-public paths (drafts, legal stubs)
// out of the sitemap by construction. When the docs site adds a feed
// we'll merge it via fetch at build time.
const ROUTES: { path: string; changeFrequency: MetadataRoute.Sitemap[number]["changeFrequency"]; priority: number }[] = [
  { path: "/", changeFrequency: "weekly", priority: 1 },
  { path: "/features", changeFrequency: "monthly", priority: 0.9 },
  { path: "/pricing", changeFrequency: "monthly", priority: 0.9 },
  { path: "/security", changeFrequency: "monthly", priority: 0.8 },
  { path: "/customers", changeFrequency: "monthly", priority: 0.7 },
  { path: "/changelog", changeFrequency: "weekly", priority: 0.7 },
  { path: "/blog", changeFrequency: "weekly", priority: 0.7 },
  { path: "/contact", changeFrequency: "yearly", priority: 0.5 },
  { path: "/compare", changeFrequency: "monthly", priority: 0.8 },
  { path: "/compare/auth0", changeFrequency: "monthly", priority: 0.8 },
  { path: "/compare/clerk", changeFrequency: "monthly", priority: 0.8 },
  { path: "/compare/workos", changeFrequency: "monthly", priority: 0.8 },
  { path: "/compare/stytch", changeFrequency: "monthly", priority: 0.8 },
  { path: "/legal", changeFrequency: "yearly", priority: 0.3 },
  { path: "/privacy", changeFrequency: "yearly", priority: 0.3 },
];

export default function sitemap(): MetadataRoute.Sitemap {
  const now = new Date();
  return ROUTES.map((r) => ({
    url: BASE + r.path,
    lastModified: now,
    changeFrequency: r.changeFrequency,
    priority: r.priority,
  }));
}
