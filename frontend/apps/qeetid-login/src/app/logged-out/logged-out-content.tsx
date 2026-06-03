"use client";

import { useTranslation } from "react-i18next";

// Client subcomponent so the visible copy can go through `t()`. The page that
// renders it stays a Server Component.
export function LoggedOutContent() {
  const { t } = useTranslation("loggedOut");
  return (
    <>
      <h1 className="text-xl font-semibold tracking-tight">{t("title")}</h1>
      <p className="text-muted-foreground text-sm">{t("body")}</p>
    </>
  );
}
