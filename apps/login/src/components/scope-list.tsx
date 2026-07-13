"use client";

import { useTranslation } from "react-i18next";

/**
 * The permissions list shown on the consent + device-authorization screens:
 * each requested OAuth scope rendered as a friendly, human-readable row with a
 * brand-colored check. Falls back to a "sign you in" line when no scopes are
 * requested. Scope labels come from the shared `common:scopes.*` catalog.
 */
export function ScopeList({ scopes }: { scopes: string[] }) {
  const { t } = useTranslation();
  if (scopes.length === 0) {
    return <p className="text-muted-foreground text-sm">{t("common:fallbacks.signYouIn")}</p>;
  }
  return (
    <ul className="border-border/60 divide-border/60 divide-y overflow-hidden rounded-lg border">
      {scopes.map((s) => (
        <li key={s} className="flex items-center gap-3 px-3.5 py-2.5 text-sm">
          <span
            className="bg-primary/10 text-primary flex size-5 shrink-0 items-center justify-center rounded-full"
            aria-hidden
          >
            <svg
              viewBox="0 0 16 16"
              className="size-3"
              fill="none"
              stroke="currentColor"
              strokeWidth="2.2"
            >
              <path d="M3.5 8.5l3 3 6-6.5" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          </span>
          <span>{t(`common:scopes.${s}`, { defaultValue: s })}</span>
        </li>
      ))}
    </ul>
  );
}
