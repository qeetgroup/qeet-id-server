"use client";

import { Button, Sheet, SheetContent, SheetTrigger, cn } from "@qeetid/ui";
import { MenuIcon, ShieldCheckIcon } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState } from "react";
import { ButtonLink } from "./button-link";
import { ThemeToggle } from "./theme-toggle";

const nav = [
  { href: "/features", label: "Features" },
  { href: "/pricing", label: "Pricing" },
  { href: "/security", label: "Security" },
  { href: "/customers", label: "Customers" },
  { href: "/contact", label: "Contact" },
];

export function SiteHeader() {
  const pathname = usePathname();
  const [open, setOpen] = useState(false);

  return (
    <header className="sticky top-0 z-40 w-full border-b border-border/60 bg-background/80 backdrop-blur supports-[backdrop-filter]:bg-background/60">
      <div className="mx-auto flex h-16 max-w-7xl items-center gap-6 px-4 sm:px-6 lg:px-8">
        <Link href="/" className="flex items-center gap-2 font-semibold tracking-tight">
          <span className="grid size-7 place-items-center rounded-md bg-foreground text-background">
            <ShieldCheckIcon className="size-4" />
          </span>
          <span className="text-base">Identity</span>
        </Link>

        <nav className="hidden flex-1 items-center gap-1 md:flex">
          {nav.map((item) => (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                "rounded-md px-3 py-1.5 text-sm text-muted-foreground transition-colors hover:bg-accent hover:text-accent-foreground",
                pathname === item.href && "text-foreground",
              )}
            >
              {item.label}
            </Link>
          ))}
        </nav>

        <div className="ml-auto hidden items-center gap-1 md:flex">
          <ThemeToggle />
          <ButtonLink variant="ghost" size="sm" href="/sign-in">
            Sign in
          </ButtonLink>
          <ButtonLink size="sm" href="/sign-up">
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
              {nav.map((item) => (
                <Link
                  key={item.href}
                  href={item.href}
                  onClick={() => setOpen(false)}
                  className="rounded-md px-3 py-2 text-sm font-medium hover:bg-accent"
                >
                  {item.label}
                </Link>
              ))}
              <div className="mt-4 flex flex-col gap-2 border-t border-border/60 pt-4">
                <div className="flex items-center justify-between rounded-md border border-border/60 px-3 py-2 text-sm">
                  <span className="text-muted-foreground">Theme</span>
                  <ThemeToggle />
                </div>
                <ButtonLink variant="outline" href="/sign-in">
                  Sign in
                </ButtonLink>
                <ButtonLink href="/sign-up">Start free</ButtonLink>
              </div>
            </div>
          </SheetContent>
        </Sheet>
      </div>
    </header>
  );
}
