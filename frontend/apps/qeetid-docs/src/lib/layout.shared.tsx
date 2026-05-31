import type { BaseLayoutProps } from "fumadocs-ui/layouts/shared";
import { ShieldCheckIcon } from "lucide-react";
import { appName, dashboardUrl, gitConfig, productUrl } from "./shared";
import { QeetLogo} from "@qeetrix/brand";


export function baseOptions(): BaseLayoutProps {
  return {
    nav: {
      title: (
        <span className="flex items-center gap-2 font-semibold tracking-tight">
          <span className="grid size-7 place-items-center rounded-md bg-foreground text-background">
            <QeetLogo className="size-4" />
          </span>
          <span className="text-[15px]">{appName}</span>
        </span>
      ),
      url: "/",
    },
    githubUrl: `https://github.com/${gitConfig.user}/${gitConfig.repo}`,
    links: [
      {
        type: "main",
        text: "Documentation",
        url: "/docs",
        active: "nested-url",
      },
      {
        type: "main",
        text: "API reference",
        url: "/docs/api",
        active: "nested-url",
      },
      {
        type: "main",
        text: "SDKs",
        url: "/docs/sdks",
        active: "nested-url",
      },
      {
        type: "main",
        text: "Changelog",
        url: "/docs/changelog",
        active: "nested-url",
      },
      {
        type: "main",
        text: "Website",
        url: productUrl,
        external: true,
      },
      {
        type: "button",
        text: "Dashboard",
        url: dashboardUrl,
        external: true,
        secondary: true,
      },
    ],
  };
}
