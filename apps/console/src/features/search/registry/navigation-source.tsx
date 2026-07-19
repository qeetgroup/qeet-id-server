// Navigation source: converts the sidebar nav tree into SearchItem[].
// Capability-filtered, parallel to buildCommandPaletteItems in the launcher
// but producing SearchItem[] (with kind/category) instead of CommandPaletteItem[].

import type { NavGroup } from "@/config/navigation";
import { navGroups } from "@/config/navigation";
import type { Capability } from "@/features/access-control/capability-model";

import type { SearchContext, SearchItem, SearchSource } from "./types";

/**
 * Flatten a capability-filtered nav tree into SearchItem[].
 * Parent nodes that are "pure groups" (their url matches a child) are omitted
 * at the parent level (the child covers it). Sub-items inherit the parent
 * title as their subtitle for disambiguation.
 */
export function buildNavSearchItems(
  groups: NavGroup[],
  can: (permission?: Capability) => boolean = () => true,
): SearchItem[] {
  const out: SearchItem[] = [];

  for (const group of groups) {
    for (const item of group.items) {
      if (item.items && item.items.length > 0) {
        // A pure group = one of its children shares the parent url.
        const isPureGroup = item.items.some((s) => s.url === item.url);
        if (!isPureGroup && can(item.requiredPermission)) {
          out.push({
            id: item.url,
            kind: "navigation",
            category: group.label,
            title: item.title,
            icon: item.icon ? <span className="[&_svg]:size-4 flex">{item.icon}</span> : undefined,
            keywords: [group.label.toLowerCase(), item.title.toLowerCase()],
            url: item.url,
            capability: item.requiredPermission,
          });
        }
        for (const sub of item.items) {
          if (can(sub.requiredPermission)) {
            out.push({
              id: sub.url,
              kind: "navigation",
              category: group.label,
              title: sub.title,
              subtitle: item.title,
              keywords: [
                group.label.toLowerCase(),
                item.title.toLowerCase(),
                sub.title.toLowerCase(),
              ],
              url: sub.url,
              capability: sub.requiredPermission,
            });
          }
        }
      } else {
        if (can(item.requiredPermission)) {
          out.push({
            id: item.url,
            kind: "navigation",
            category: group.label,
            title: item.title,
            icon: item.icon ? <span className="[&_svg]:size-4 flex">{item.icon}</span> : undefined,
            keywords: [group.label.toLowerCase(), item.title.toLowerCase()],
            url: item.url,
            capability: item.requiredPermission,
          });
        }
      }
    }
  }

  return out;
}

export function createNavigationSource(): SearchSource {
  return {
    id: "navigation",
    getItems(_query: string, ctx: SearchContext): SearchItem[] {
      const can = (permission?: Capability): boolean =>
        permission === undefined || ctx.capabilities.has(permission);
      return buildNavSearchItems(navGroups, can);
    },
  };
}
