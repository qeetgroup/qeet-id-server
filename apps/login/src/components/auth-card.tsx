"use client";

import { Card, CardContent, cn } from "@qeetrix/ui";
import { QeetLogo } from "@qeetrix/ui/brand";
import type { ReactNode } from "react";

import type { Branding } from "@/lib/branding";

type AuthCardProps = {
  /** Per-tenant branding; renders the tenant logo in place of the Qeet mark. */
  branding?: Branding;
  title: ReactNode;
  subtitle?: ReactNode;
  children?: ReactNode;
  className?: string;
};

/**
 * The consistent card frame for every hosted-login form: a centered logo +
 * display-font title + subtitle, then the form body. Lives inside <AuthShell>'s
 * right column. Owns the logo so the tenant brand (or the Qeet mark) shows on
 * the light card surface — including on mobile, where the brand panel is hidden.
 */
export function AuthCard({ branding, title, subtitle, children, className }: AuthCardProps) {
  return (
    <Card
      className={cn(
        "w-full max-w-sm border-border/60 shadow-xl shadow-black/5 backdrop-blur-sm",
        className,
      )}
    >
      <CardContent className="space-y-6 pt-7 pb-7">
        <div className="space-y-4 text-center">
          <div className="flex justify-center">
            {branding?.logoUrl ? (
              // eslint-disable-next-line @next/next/no-img-element -- tenant logo is a dynamic URL from an arbitrary domain; next/image requires pre-configured remotePatterns per hostname
              <img
                src={branding.logoUrl}
                alt=""
                className="h-10 w-auto max-w-50 object-contain"
              />
            ) : (
              <QeetLogo size={40} />
            )}
          </div>
          <div className="space-y-1.5">
            <h1 className="auth-title text-2xl font-semibold tracking-tight">{title}</h1>
            {subtitle ? <p className="text-muted-foreground text-sm">{subtitle}</p> : null}
          </div>
        </div>
        {children}
      </CardContent>
    </Card>
  );
}
