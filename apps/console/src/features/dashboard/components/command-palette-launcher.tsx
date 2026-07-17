import { CommandPalette, type CommandPaletteItem } from "@qeetrix/ui";
import { useNavigate } from "@tanstack/react-router";
import { useEffect, useMemo } from "react";

import { filterNavigation, type NavGroup, navGroups } from "@/config/navigation";
import type { Capability } from "@/features/access-control/capability-model";
import { useCapabilities } from "@/features/access-control/capability-provider";

/**
 * Flatten the sidebar nav tree into a single searchable list. Sub-items
 * inherit the parent's group label and prefix the parent title so a
 * search for "Audit" surfaces "Audit Logs" without ambiguity. Items
 * without a `url` (parent-only nodes) are skipped — they exist only to
 * organise children.
 */
export function buildCommandPaletteItems(
  groups: NavGroup[],
  can: (permission?: Capability) => boolean = () => true,
): CommandPaletteItem[] {
  const out: CommandPaletteItem[] = [];
  for (const group of groups) {
    for (const item of group.items) {
      if (item.items && item.items.length > 0) {
        // Parent with children: surface the parent itself only if its url
        // is a leaf route (i.e. doesn't match any child's url).
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
 * CommandPaletteLauncher wires the global Cmd-K / Ctrl-K shortcut to a
 * navigation palette populated from the sidebar config. Lives inside
 * the app layout so the keyboard handler and the navigate hook share
 * the same router context.
 */
export function CommandPaletteLauncher({ open, onOpenChange }: CommandPaletteLauncherProps) {
  const navigate = useNavigate();
  const access = useCapabilities();
  const groups = useMemo(
    () => (access.state === "ready" ? filterNavigation(navGroups, access.can) : []),
    [access.can, access.state],
  );
  const items = useMemo(() => buildCommandPaletteItems(groups, access.can), [access.can, groups]);

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
    <CommandPalette
      open={open}
      onOpenChange={onOpenChange}
      items={items}
      placeholder="Jump to…"
      onSelect={(item) => {
        // item.id is the route URL.
        navigate({ to: item.id });
      }}
    />
  );
}
