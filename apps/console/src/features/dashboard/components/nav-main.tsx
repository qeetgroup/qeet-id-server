import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
  SidebarGroup,
  SidebarGroupLabel,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarMenuSub,
  SidebarMenuSubButton,
  SidebarMenuSubItem,
} from "@qeetrix/ui";
import { Link, useLocation } from "@tanstack/react-router";
import { ChevronRightIcon } from "lucide-react";

import type { NavGroup, NavItem } from "@/config/navigation";
import { isNavBranchActive, isNavPathActive } from "@/config/navigation-state";

function NavMenuItem({ item, pathname }: { item: NavItem; pathname: string }) {
  const isActive = isNavPathActive(pathname, item.url);
  const isBranchActive = isNavBranchActive(pathname, item);

  if (!item.items?.length) {
    return (
      <SidebarMenuItem>
        <SidebarMenuButton
          tooltip={item.title}
          isActive={isActive}
          className="console-nav-item"
          render={<Link to={item.url as never} aria-current={isActive ? "page" : undefined} />}
        >
          {item.icon}
          <span>{item.title}</span>
        </SidebarMenuButton>
      </SidebarMenuItem>
    );
  }

  return (
    <Collapsible
      key={`${item.url}:${isBranchActive}`}
      defaultOpen={isBranchActive}
      className="group/collapsible"
      render={<SidebarMenuItem />}
    >
      <CollapsibleTrigger
        render={
          <SidebarMenuButton
            tooltip={item.title}
            isActive={isBranchActive}
            className="console-nav-item"
          />
        }
      >
        {item.icon}
        <span>{item.title}</span>
        <ChevronRightIcon className="ms-auto transition-transform duration-200 ease-(--ease-decelerate) group-data-open/collapsible:rotate-90" />
      </CollapsibleTrigger>
      <CollapsibleContent>
        <SidebarMenuSub>
          {item.items.map((subItem) => {
            const subActive = pathname === subItem.url;
            return (
              <SidebarMenuSubItem key={subItem.title}>
                <SidebarMenuSubButton
                  isActive={subActive}
                  className="console-nav-subitem"
                  render={
                    <Link to={subItem.url as never} aria-current={subActive ? "page" : undefined} />
                  }
                >
                  <span>{subItem.title}</span>
                </SidebarMenuSubButton>
              </SidebarMenuSubItem>
            );
          })}
        </SidebarMenuSub>
      </CollapsibleContent>
    </Collapsible>
  );
}

export function NavMain({ groups }: { groups: NavGroup[] }) {
  const { pathname } = useLocation();

  return (
    <>
      {groups.map((group) => (
        <SidebarGroup key={group.label} className="py-1.5">
          <SidebarGroupLabel className="h-7 px-2 text-[10px] font-semibold uppercase tracking-[0.14em] text-sidebar-foreground/45">
            {group.label}
          </SidebarGroupLabel>
          <SidebarMenu className="gap-0.5">
            {group.items.map((item) => (
              <NavMenuItem key={item.title} item={item} pathname={pathname} />
            ))}
          </SidebarMenu>
        </SidebarGroup>
      ))}
    </>
  );
}
