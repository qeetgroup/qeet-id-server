import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuLabel,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
  SidebarMenuButton,
  useSidebar,
} from "@qeetrix/ui";
import { LanguagesIcon } from "lucide-react";
import { useTranslation } from "react-i18next";

import { LANGUAGE_LABELS, SUPPORTED_LANGUAGES, type SupportedLanguage } from "@/i18n";

/**
 * Compact language picker for the sidebar footer. Lists every locale the app
 * ships catalogs for (`SUPPORTED_LANGUAGES`) and persists the choice via the
 * i18next language detector (`localStorage: qeetid.lang`). Renders cleanly
 * with a single language today; new locales appear automatically once their
 * JSON catalogs are registered in `src/i18n`.
 */
export function LanguageSwitcher() {
  const { isMobile } = useSidebar();
  const { i18n } = useTranslation();

  const current = (
    SUPPORTED_LANGUAGES.includes(i18n.resolvedLanguage as SupportedLanguage)
      ? (i18n.resolvedLanguage as SupportedLanguage)
      : SUPPORTED_LANGUAGES[0]
  ) as SupportedLanguage;

  return (
    <DropdownMenu>
      <DropdownMenuTrigger
        render={<SidebarMenuButton size="sm" className="aria-expanded:bg-muted" />}
      >
        <LanguagesIcon className="size-4" />
        <span className="truncate">{LANGUAGE_LABELS[current]}</span>
      </DropdownMenuTrigger>
      <DropdownMenuContent
        className="min-w-44 rounded-lg"
        side={isMobile ? "bottom" : "right"}
        align="end"
        sideOffset={4}
      >
        <DropdownMenuLabel className="text-xs text-muted-foreground">
          Language
        </DropdownMenuLabel>
        <DropdownMenuSeparator />
        <DropdownMenuRadioGroup
          value={current}
          onValueChange={(lng) => lng && void i18n.changeLanguage(lng)}
        >
          {SUPPORTED_LANGUAGES.map((lng) => (
            <DropdownMenuRadioItem key={lng} value={lng}>
              {LANGUAGE_LABELS[lng]}
            </DropdownMenuRadioItem>
          ))}
        </DropdownMenuRadioGroup>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
