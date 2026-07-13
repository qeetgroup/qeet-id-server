"use client";

import { cn } from "@qeetrix/ui";
import { QeetLogoOnDark } from "@qeetrix/ui/brand";
import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";

import { type Branding, brandingVars } from "@/lib/branding";

type AuthShellProps = {
  /** Per-tenant branding; drives the panel logo, gradient, and token overrides. */
  branding?: Branding;
  children: ReactNode;
  className?: string;
};

/**
 * The premium split-screen frame for every hosted-login screen: a branded
 * gradient panel on the left (≥lg) and a centered content column on the right.
 * Applies the tenant's brand colors as CSS-token overrides on the root, so the
 * form's buttons/links/focus rings inherit the tenant color with no per-screen
 * wiring. Collapses to a single centered column on small screens.
 */
export function AuthShell({ branding, children, className }: AuthShellProps) {
  return (
    <div
      style={brandingVars(branding)}
      className={cn("relative grid min-h-dvh lg:grid-cols-[1.05fr_1fr]", className)}
    >
      <BrandPanel branding={branding} />
      <div className="flex min-h-dvh items-center justify-center px-6 py-10 sm:px-10">
        <div className="auth-rise flex w-full justify-center">{children}</div>
      </div>
    </div>
  );
}

function BrandPanel({ branding }: { branding?: Branding }) {
  const { t } = useTranslation("common");
  const features = [
    t("brand.features.passkeys"),
    t("brand.features.sso"),
    t("brand.features.mfa"),
    t("brand.features.soc2"),
  ];
  return (
    <div className="auth-brand-panel relative hidden overflow-hidden lg:flex lg:flex-col lg:justify-between lg:p-12">
      <span className="auth-blob" aria-hidden />

      <div className="relative z-10 flex items-center gap-3">
        {branding?.logoUrl ? (
          <img src={branding.logoUrl} alt="" className="h-8 w-auto max-w-45 object-contain" />
        ) : (
          <>
            <QeetLogoOnDark size={34} title={null} />
            <span className="auth-title text-lg font-semibold tracking-tight">Qeet ID</span>
          </>
        )}
      </div>

      <div className="relative z-10 space-y-5">
        <h2 className="auth-title max-w-md text-4xl font-semibold leading-[1.1]">
          {t("brand.headline")}
        </h2>
        <p className="max-w-md text-base leading-relaxed text-white/80">{t("brand.subhead")}</p>
        <ul className="flex flex-wrap gap-x-5 gap-y-2 pt-1 text-sm text-white/75">
          {features.map((f) => (
            <li key={f} className="flex items-center gap-1.5">
              <span className="size-1.5 rounded-full bg-white/60" aria-hidden />
              {f}
            </li>
          ))}
        </ul>
      </div>

      <p className="relative z-10 text-xs text-white/55">{t("brand.footer")}</p>
    </div>
  );
}
