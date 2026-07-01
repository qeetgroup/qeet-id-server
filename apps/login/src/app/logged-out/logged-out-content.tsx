"use client";

import { useTranslation } from "react-i18next";

import { AuthCard } from "@/components/auth-card";

// Client subcomponent so the visible copy can go through `t()`. The page that
// renders it stays a Server Component.
export function LoggedOutContent() {
  const { t } = useTranslation("loggedOut");
  return (
    <AuthCard title={t("title")}>
      <p className="text-muted-foreground text-center text-sm">{t("body")}</p>
    </AuthCard>
  );
}
