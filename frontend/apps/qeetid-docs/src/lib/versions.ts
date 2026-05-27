/**
 * Docs versioning scaffold.
 *
 * Pre-1.0 the docs serve unversioned content directly at `/docs/...`.
 * When we cut v1.0 we'll declare v1 as the current version here and
 * future-version docs (e.g. v2 alpha) live under their own tree.
 *
 * Migration steps when cutting v1.0:
 *
 *   1. Move existing content from `content/docs/...` to
 *      `content/docs/v1/...`.
 *   2. Add a redirect from `/docs/{slug}` → `/docs/v1/{slug}` so
 *      existing inbound links don't 404.
 *   3. Add a `[version]` dynamic segment to the docs route + a version
 *      switcher to the docs header.
 *   4. When v2 enters alpha, add its entry below with
 *      `status: "preview"` and a banner stripe on its pages.
 *
 * fumadocs supports multiple sourced trees behind one `loader()` —
 * see https://fumadocs.dev/docs/mdx/multiple-collections.
 */
export interface DocsVersion {
  /** URL slug — e.g. "v1", "v2-preview". */
  slug: string;
  /** Display label shown in the version dropdown. */
  label: string;
  /** Marketing-friendly badge text (Stable / Preview / Deprecated). */
  status: "stable" | "preview" | "deprecated";
  /** Set on exactly one version; clients default here when no slug is in the URL. */
  isDefault?: boolean;
}

export const VERSIONS: DocsVersion[] = [
  // Until v1.0 cuts, the docs are unversioned. The entry below is a
  // placeholder so the switcher renders something meaningful — flip
  // its `slug` to "v1" + move content under `content/docs/v1/` to
  // activate real versioning.
  {
    slug: "current",
    label: "Current (pre-1.0)",
    status: "preview",
    isDefault: true,
  },
];

export function getDefaultVersion(): DocsVersion {
  return VERSIONS.find((v) => v.isDefault) ?? VERSIONS[0]!;
}

export function getVersion(slug: string): DocsVersion | undefined {
  return VERSIONS.find((v) => v.slug === slug);
}
