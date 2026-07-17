import { Sidebar, SidebarContent, SidebarFooter, SidebarHeader, SidebarRail } from "@qeetrix/ui";
import { QeetLogoMark } from "@qeetrix/ui/brand";
import { LockKeyholeIcon } from "lucide-react";
import type * as React from "react";

import { navGroups } from "@/config/navigation";

import { NavMain } from "./nav-main";
import { TeamSwitcher } from "./team-switcher";

export function AppSidebar(props: React.ComponentProps<typeof Sidebar>) {
  return (
    <Sidebar collapsible="icon" className="console-sidebar" {...props}>
      <SidebarHeader className="gap-3 p-3">
        <a
          href="/"
          className="flex h-10 items-center gap-3 overflow-hidden rounded-lg px-1.5 outline-none ring-sidebar-ring focus-visible:ring-2"
          aria-label="Qeet ID overview"
        >
          <span className="grid size-8 shrink-0 place-items-center rounded-lg bg-white/8 ring-1 ring-white/10">
            <QeetLogoMark variant="on-dark" size={22} title="Qeet" />
          </span>
          <span className="min-w-0 leading-tight group-data-[collapsible=icon]:hidden">
            <span className="block truncate font-heading text-sm font-semibold tracking-tight">
              Qeet ID
            </span>
            <span className="block truncate text-[10px] font-medium uppercase tracking-[0.16em] text-sidebar-foreground/50">
              Control plane
            </span>
          </span>
        </a>
        <TeamSwitcher />
      </SidebarHeader>
      <SidebarContent className="px-1 pb-3">
        <NavMain groups={navGroups} />
      </SidebarContent>
      <SidebarFooter className="p-3 pt-2">
        <div className="flex items-center gap-2 overflow-hidden rounded-lg border border-sidebar-border/70 bg-white/3 px-2.5 py-2 text-[11px] text-sidebar-foreground/60 group-data-[collapsible=icon]:justify-center group-data-[collapsible=icon]:px-0">
          <LockKeyholeIcon className="size-3.5 shrink-0 text-sidebar-foreground/70" />
          <span className="truncate group-data-[collapsible=icon]:hidden">
            Protected operator session
          </span>
        </div>
      </SidebarFooter>
      <SidebarRail />
    </Sidebar>
  );
}
