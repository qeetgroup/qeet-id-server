// Builds the ConsoleContext the copilot is grounded with — automatically, from
// the router and capability providers, with no prompting. Feature 1 wires the
// route + tenant + capability signals; the page-published `selection`/`filters`
// (via context-registry) are layered on in the context-awareness feature.

import { useRouterState } from "@tanstack/react-router";
import { useMemo } from "react";

import { lookupNavTitle } from "@/config/navigation";
import { type Capability, CONSOLE_CAPABILITIES } from "@/features/access-control/capability-model";
import { useCapabilities } from "@/features/access-control/capability-provider";

import { useContextRegistry } from "./context-registry";
import type { ConsoleContext } from "./context-types";

export function useConsoleContext(): ConsoleContext {
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  const access = useCapabilities();
  const published = useContextRegistry(pathname);

  return useMemo(() => {
    const nav = lookupNavTitle(pathname);
    const capabilities = CONSOLE_CAPABILITIES.filter((c): c is Capability =>
      access.permissions.has(c),
    );
    return {
      route: { pathname, title: nav.title, group: nav.group },
      tenantId: access.tenantId,
      userId: access.userId,
      capabilities,
      selection: published.selection,
      filters: published.filters,
    };
  }, [pathname, access.permissions, access.tenantId, access.userId, published]);
}
