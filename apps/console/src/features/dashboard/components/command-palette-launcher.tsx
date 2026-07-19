// CommandPaletteLauncher — global ⌘K / Ctrl-K entry point.
//
// Preserves the original open/onOpenChange contract so _app.tsx requires no
// changes. Renders UniversalSearch (the evolved palette) wrapped in
// SearchProvider, which assembles navigation + command sources and builds
// SearchContext from the router + capability hooks.

import type { CommandPaletteItem } from "@qeetrix/ui";
import { useEffect } from "react";

import type { NavGroup } from "@/config/navigation";
import type { Capability } from "@/features/access-control/capability-model";
import { useCapabilities } from "@/features/access-control/capability-provider";
import { SearchProvider, UniversalSearch } from "@/features/search";

/**
 * Flatten the sidebar nav tree into a CommandPaletteItem[] list.
 * Kept here for backward-compatibility; the universal search uses
 * buildNavSearchItems from registry/navigation-source.tsx instead.
 */
export function buildCommandPaletteItems(
  groups: NavGroup[],
  can: (permission?: Capability) => boolean = () => true,
): CommandPaletteItem[] {
  const out: CommandPaletteItem[] = [];
  for (const group of groups) {
    for (const item of group.items) {
      if (item.items && item.items.length > 0) {
        const isPureGroup = item.items.some((s) => s.url === item.url);
        if (!isPureGroup && can(item.requiredPermission)) {
          out.push({
            id: item.url,
            title: item.title,
            group: group.label,
            icon: item.icon ? <span className="[&_svg]:size-4 flex">{item.icon}</span> : undefined,
            keywords: [item.title.toLowerCase()],
          });
        }
        for (const sub of item.items) {
          out.push({
            id: sub.url,
            title: sub.title,
            group: group.label,
            keywords: [item.title.toLowerCase(), sub.title.toLowerCase()],
          });
        }
      } else {
        out.push({
          id: item.url,
          title: item.title,
          group: group.label,
          icon: item.icon ? <span className="[&_svg]:size-4 flex">{item.icon}</span> : undefined,
          keywords: [item.title.toLowerCase()],
        });
      }
    }
  }
  return out;
}

interface CommandPaletteLauncherProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

/**
 * CommandPaletteLauncher wires the ⌘K / Ctrl-K shortcut to the UniversalSearch
 * palette. Lives inside CapabilityProvider (via the ConsoleFrame in _app.tsx)
 * so the shortcut can gate on access.state before opening.
 */
export function CommandPaletteLauncher({ open, onOpenChange }: CommandPaletteLauncherProps) {
  const access = useCapabilities();

  // Own the ⌘K shortcut here — same design as the original launcher so the
  // keyboard behaviour is unchanged from the operator's perspective.
  useEffect(() => {
    if (access.state !== "ready") {
      if (open) onOpenChange(false);
      return;
    }
    function onKey(e: KeyboardEvent) {
      const isMod = e.metaKey || e.ctrlKey;
      if (isMod && e.key.toLowerCase() === "k") {
        e.preventDefault();
        onOpenChange(!open);
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [access.state, open, onOpenChange]);

  return (
    <SearchProvider>
      <UniversalSearch open={open} onOpenChange={onOpenChange} />
    </SearchProvider>
  );
}
