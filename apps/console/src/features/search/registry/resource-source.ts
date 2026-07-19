// Resource source helpers: convert API SearchHit[] → SearchItem[].
// The actual async query lives in UniversalSearch (useQuery); this module
// provides the pure transformation so it can be reused or tested independently.

import type { SearchHit, SearchItem } from "./types";

function typeToCategory(type: string): string {
  // e.g. "user" → "Users", "organization" → "Organizations"
  const s = type.charAt(0).toUpperCase() + type.slice(1).toLowerCase();
  return s.endsWith("s") ? s : `${s}s`;
}

/**
 * Convert raw API search hits into canonical SearchItem objects.
 * Resource items have `kind: "resource"` and carry status/metadata for the
 * preview pane.
 */
export function resourceHitsToSearchItems(hits: SearchHit[]): SearchItem[] {
  return hits.map(
    (hit): SearchItem => ({
      id: `resource.${hit.type}.${hit.id}`,
      kind: "resource",
      category: typeToCategory(hit.type),
      title: hit.title,
      subtitle: hit.subtitle,
      url: hit.url,
      status: hit.status,
      updatedAt: hit.updated_at,
      metadata: hit.metadata,
      keywords: [hit.type, hit.title.toLowerCase()],
    }),
  );
}
