import {
  Button,
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuLabel,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@qeetrix/ui";
import { LanguagesIcon } from "lucide-react";
import { useTranslation } from "react-i18next";

import { LANGUAGE_LABELS, SUPPORTED_LANGUAGES, type SupportedLanguage } from "@/i18n";

/**
 * Language picker for the top header. A globe icon button opens a dropdown of
 * every locale the app ships catalogs for (`SUPPORTED_LANGUAGES`); the choice
 * persists via the i18next language detector (`localStorage: qeetid.lang`).
 * New locales appear automatically once their JSON catalogs register in
 * `src/i18n`.
 */
export function LanguageSwitcher() {
  const { i18n } = useTranslation();

  const current = (
    SUPPORTED_LANGUAGES.includes(i18n.resolvedLanguage as SupportedLanguage)
      ? (i18n.resolvedLanguage as SupportedLanguage)
      : SUPPORTED_LANGUAGES[0]
  ) as SupportedLanguage;

  return (
    <DropdownMenu>
      <DropdownMenuTrigger
        render={
          <Button
            variant="ghost"
            size="icon"
            aria-label={`Language: ${LANGUAGE_LABELS[current]}`}
            title="Change language"
          />
        }
      >
        <LanguagesIcon />
      </DropdownMenuTrigger>
      <DropdownMenuContent className="min-w-44 rounded-lg" align="end" sideOffset={4}>
        <DropdownMenuLabel className="text-xs text-muted-foreground">Language</DropdownMenuLabel>
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
