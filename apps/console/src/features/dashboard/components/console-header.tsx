import { Button, Separator, SidebarTrigger } from "@qeetrix/ui";
import { KeyboardIcon, SearchIcon } from "lucide-react";

import { DynamicBreadcrumb } from "./dynamic-breadcrumb";
import { HeaderUser } from "./header-user";
import { LanguageSwitcher } from "./language-switcher";
import { NotificationsInbox } from "./notifications-inbox";
import { ThemeToggle } from "./theme-toggle";
import { WhatsNewDropdown } from "./whats-new-dropdown";

type ConsoleHeaderProps = {
  onOpenPalette: () => void;
  onOpenShortcuts: () => void;
  searchAvailable: boolean;
};

/** Persistent operator chrome shared by every admin route. */
export function ConsoleHeader({
  onOpenPalette,
  onOpenShortcuts,
  searchAvailable,
}: ConsoleHeaderProps) {
  return (
    <header className="console-topbar">
      <div className="flex min-w-0 items-center gap-2">
        <SidebarTrigger className="-ms-1" />
        <Separator orientation="vertical" className="mx-1 hidden h-5 lg:block" />
        <DynamicBreadcrumb />
      </div>

      <button
        type="button"
        onClick={onOpenPalette}
        className="console-command-trigger"
        aria-label={
          searchAvailable ? "Search the control plane" : "Search unavailable while access loads"
        }
        disabled={!searchAvailable}
      >
        <SearchIcon className="size-4 shrink-0" aria-hidden="true" />
        <span className="min-w-0 flex-1 truncate">Search the control plane</span>
        <kbd className="console-keycap">⌘K</kbd>
      </button>

      <div className="ms-auto flex shrink-0 items-center gap-0.5">
        <Button
          variant="ghost"
          size="icon"
          className="md:hidden"
          aria-label="Search"
          onClick={onOpenPalette}
          disabled={!searchAvailable}
        >
          <SearchIcon />
        </Button>
        <Button
          variant="ghost"
          size="icon"
          className="hidden 2xl:inline-flex"
          aria-label="Keyboard shortcuts"
          title="Keyboard shortcuts (?)"
          onClick={onOpenShortcuts}
        >
          <KeyboardIcon />
        </Button>
        <WhatsNewDropdown />
        <NotificationsInbox />
        <div className="hidden xl:block">
          <LanguageSwitcher />
        </div>
        <ThemeToggle />
        <Separator orientation="vertical" className="mx-1.5 hidden h-6 sm:block" />
        <HeaderUser />
      </div>
    </header>
  );
}
