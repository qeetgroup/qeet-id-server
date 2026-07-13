import { cn } from "@qeetrix/ui";
import { ArrowRightIcon } from "lucide-react";
import Link from "next/link";
import type { ReactNode } from "react";

/**
 * Primary "island" CTA — a fully-rounded brand-gradient pill with a nested,
 * button-in-button trailing icon. On hover the whole pill presses in slightly
 * while the inner icon disc translates diagonally and scales, creating internal
 * kinetic tension. Spring-like custom easing; no layout-triggering properties.
 */
type ArrowCtaProps = {
  href: string;
  children: ReactNode;
  className?: string;
  variant?: "brand" | "outline";
};

export function ArrowCta({ href, children, className, variant = "brand" }: ArrowCtaProps) {
  const brand = variant === "brand";
  return (
    <Link
      href={href}
      className={cn(
        "group inline-flex items-center gap-3 rounded-full py-2 pl-6 pr-2 text-sm font-semibold transition-[transform,box-shadow,background-color] duration-500 ease-[cubic-bezier(0.32,0.72,0,1)] focus-ring-brand active:scale-[0.98]",
        brand
          ? "bg-(image:--brand-gradient) text-brand-foreground shadow-lg shadow-brand/25 hover:shadow-xl hover:shadow-brand/30"
          : "border border-border/70 bg-background/60 text-foreground backdrop-blur-sm hover:border-brand/40 hover:bg-brand/5",
        className,
      )}
    >
      <span>{children}</span>
      <span
        aria-hidden
        className={cn(
          "grid size-8 place-items-center rounded-full transition-transform duration-500 ease-[cubic-bezier(0.32,0.72,0,1)] group-hover:translate-x-0.5 group-hover:-translate-y-px group-hover:scale-105",
          brand ? "bg-brand-foreground/15" : "bg-brand/10 text-brand",
        )}
      >
        <ArrowRightIcon className="size-4" />
      </span>
    </Link>
  );
}
