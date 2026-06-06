"use client";

import { Button, Sheet, SheetContent, SheetTrigger, cn } from "@qeetrix/ui";
import { MenuIcon } from "lucide-react";
import { motion, useMotionValueEvent, useReducedMotion, useScroll } from "motion/react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState } from "react";
import { ButtonLink } from "./button-link";
import { QeetMark } from "./qeet-mark";
import { ThemeToggle } from "./theme-toggle";
import { SIGN_IN_URL, SIGN_UP_URL } from "@/lib/links";

const nav = [
  { href: "/features", label: "Features" },
  { href: "/pricing", label: "Pricing" },
  { href: "/security", label: "Security" },
  { href: "/customers", label: "Customers" },
  { href: "/contact", label: "Contact" },
];

function NavLink({ href, label, active }: { href: string; label: string; active: boolean }) {
  return (
    <Link
      href={href}
      aria-current={active ? "page" : undefined}
      className={cn(
        "relative rounded-md px-3 py-1.5 text-sm transition-colors hover:text-foreground focus-ring-brand",
        active ? "text-foreground" : "text-muted-foreground",
      )}
    >
      {label}
      {active && (
        // Shared-layout underline that slides between the active items.
        <motion.span
          layoutId="nav-underline"
          className="absolute inset-x-2 -bottom-px h-0.5 rounded-full bg-[image:var(--brand-gradient)]"
          transition={{ type: "spring", stiffness: 380, damping: 30 }}
        />
      )}
    </Link>
  );
}

export function SiteHeader() {
  const pathname = usePathname();
  const [open, setOpen] = useState(false);
  const [scrolled, setScrolled] = useState(false);
  const reduce = useReducedMotion();
  const { scrollY } = useScroll();

  // Scroll-aware chrome: compact + stronger blur/elevation past a small threshold.
  useMotionValueEvent(scrollY, "change", (y) => {
    const next = y > 12;
    if (next !== scrolled) setScrolled(next);
  });

  return (
    <header
      className={cn(
        "sticky top-0 z-40 w-full border-b backdrop-blur-xl",
        // Reduced motion -> no height/elevation transition, only color/opacity snaps.
        reduce ? "" : "transition-[height,background-color,border-color,box-shadow] duration-300",
        scrolled
          ? "border-border/70 bg-background/85 shadow-lg shadow-black/5 supports-[backdrop-filter]:bg-background/70"
          : "border-transparent bg-background/40 supports-[backdrop-filter]:bg-background/30",
      )}
    >
      <div
        className={cn(
          "mx-auto flex max-w-7xl items-center gap-6 px-4 sm:px-6 lg:px-8",
          reduce ? "" : "transition-[height] duration-300",
          scrolled ? "h-14" : "h-16",
        )}
      >
        <Link
          href="/"
          className="flex items-center gap-2 font-semibold tracking-tight focus-ring-brand"
        >
          <QeetMark size={28} className="size-7" />
          <span className="text-base">Identity</span>
        </Link>

        <nav className="hidden flex-1 items-center gap-1 md:flex">
          {nav.map((item) => (
            <NavLink
              key={item.href}
              href={item.href}
              label={item.label}
              active={pathname === item.href}
            />
          ))}
        </nav>

        <div className="ml-auto hidden items-center gap-1 md:flex">
          <ThemeToggle />
          <ButtonLink variant="ghost" size="sm" href={SIGN_IN_URL}>
            Sign in
          </ButtonLink>
          <ButtonLink size="sm" href={SIGN_UP_URL}>
            Start free
          </ButtonLink>
        </div>

        <Sheet open={open} onOpenChange={setOpen}>
          <SheetTrigger
            render={
              <Button
                variant="ghost"
                size="icon"
                className="ml-auto md:hidden"
                aria-label="Open menu"
              >
                <MenuIcon />
              </Button>
            }
          />
          <SheetContent side="right" className="w-72">
            <div className="flex flex-col gap-1 p-4">
              <Link
                href="/"
                onClick={() => setOpen(false)}
                className="mb-2 flex items-center gap-2 px-3 font-semibold tracking-tight"
              >
                <QeetMark size={24} className="size-6" />
                <span className="text-base">Identity</span>
              </Link>
              {nav.map((item) => (
                <Link
                  key={item.href}
                  href={item.href}
                  onClick={() => setOpen(false)}
                  aria-current={pathname === item.href ? "page" : undefined}
                  className={cn(
                    "flex items-center justify-between rounded-md px-3 py-2 text-sm font-medium transition-colors hover:bg-accent",
                    pathname === item.href && "text-brand-text",
                  )}
                >
                  {item.label}
                  {pathname === item.href && (
                    <span className="size-1.5 rounded-full bg-brand" aria-hidden />
                  )}
                </Link>
              ))}
              <div className="mt-4 flex flex-col gap-2 border-t border-border/60 pt-4">
                <div className="flex items-center justify-between rounded-md border border-border/60 px-3 py-2 text-sm">
                  <span className="text-muted-foreground">Theme</span>
                  <ThemeToggle />
                </div>
                <ButtonLink
                  variant="outline"
                  href={SIGN_IN_URL}
                  onClick={() => setOpen(false)}
                >
                  Sign in
                </ButtonLink>
                <ButtonLink href={SIGN_UP_URL} onClick={() => setOpen(false)}>
                  Start free
                </ButtonLink>
              </div>
            </div>
          </SheetContent>
        </Sheet>
      </div>
    </header>
  );
}
