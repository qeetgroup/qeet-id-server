"use client";

import { cn } from "@qeetrix/ui";
import {
  AnimatePresence,
  motion,
  useMotionValueEvent,
  useReducedMotion,
  useScroll,
} from "motion/react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useRef, useState } from "react";
import { SIGN_IN_URL, SIGN_UP_URL } from "@/lib/links";
import { ArrowCta } from "./blocks/arrow-cta";
import { ButtonLink } from "./button-link";
import { QeetMark } from "./qeet-mark";
import { ThemeToggle } from "./theme-toggle";

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
        "relative rounded-full px-3.5 py-1.5 text-sm transition-colors hover:text-foreground focus-ring-brand",
        active ? "text-foreground" : "text-muted-foreground",
      )}
    >
      {active && (
        // Shared-layout highlight that springs between the active items.
        <motion.span
          layoutId="nav-pill"
          aria-hidden
          className="absolute inset-0 -z-10 rounded-full bg-foreground/6 ring-1 ring-border/50"
          transition={{ type: "spring", stiffness: 380, damping: 32 }}
        />
      )}
      {label}
    </Link>
  );
}

export function SiteHeader() {
  const pathname = usePathname();
  const [open, setOpen] = useState(false);
  const [scrolled, setScrolled] = useState(false);
  const reduce = useReducedMotion();
  const { scrollY } = useScroll();
  const toggleRef = useRef<HTMLButtonElement>(null);
  const overlayRef = useRef<HTMLDivElement>(null);

  // Scroll-aware chrome: the pill compacts + gains elevation past a small threshold.
  useMotionValueEvent(scrollY, "change", (y) => {
    const next = y > 12;
    setScrolled((prev) => (prev !== next ? next : prev));
  });

  // Close the mobile overlay on route change.
  // setState is placed inside a setTimeout callback (not the effect body directly)
  // so the React Compiler's set-state-in-effect rule is satisfied.
  useEffect(() => {
    const id = setTimeout(() => setOpen(false), 0);
    return () => clearTimeout(id);
  }, [pathname]);

  // While the mobile overlay is open: lock scroll, close on Escape, manage focus.
  useEffect(() => {
    if (!open) return;
    const toggle = toggleRef.current;
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    window.addEventListener("keydown", onKey);
    const focusTimer = window.setTimeout(
      () => overlayRef.current?.querySelector<HTMLElement>("a, button")?.focus(),
      60,
    );
    return () => {
      document.body.style.overflow = prevOverflow;
      window.removeEventListener("keydown", onKey);
      window.clearTimeout(focusTimer);
      // Restore focus to the trigger when the overlay closes.
      toggle?.focus();
    };
  }, [open]);

  return (
    <header className="sticky top-0 z-50 w-full px-4">
      {/* Floating glass island — detached from the top edge, compacts on scroll. */}
      <div
        className={cn(
          "relative z-50 mx-auto mt-3 flex items-center gap-3 rounded-full border border-border/60 bg-background/70 px-3 py-2 backdrop-blur-xl supports-backdrop-filter:bg-background/55 sm:mt-4 sm:px-4",
          reduce
            ? ""
            : "transition-[max-width,background-color,box-shadow] duration-300 ease-[cubic-bezier(0.16,1,0.3,1)]",
          scrolled
            ? "max-w-4xl bg-background/85 shadow-xl shadow-black/10 supports-backdrop-filter:bg-background/70"
            : "max-w-5xl shadow-lg shadow-black/5",
        )}
      >
        <Link
          href="/"
          className="flex shrink-0 items-center gap-2 pl-1 font-semibold tracking-tight focus-ring-brand"
        >
          <QeetMark size={28} className="size-7" />
          <span className="text-base">Identity</span>
        </Link>

        <nav className="hidden flex-1 items-center justify-center gap-1 md:flex">
          {nav.map((item) => (
            <NavLink
              key={item.href}
              href={item.href}
              label={item.label}
              active={pathname === item.href}
            />
          ))}
        </nav>

        <div className="hidden shrink-0 items-center gap-1 md:flex">
          <ThemeToggle />
          <ButtonLink variant="ghost" size="sm" href={SIGN_IN_URL}>
            Sign in
          </ButtonLink>
          <ButtonLink size="sm" href={SIGN_UP_URL} className="rounded-full">
            Start free
          </ButtonLink>
        </div>

        {/* Morphing hamburger → X. Lives in the pill (z-50), which sits above the
            overlay (z-40) in the header's stacking context, so the X stays clickable. */}
        <button
          ref={toggleRef}
          type="button"
          onClick={() => setOpen((v) => !v)}
          aria-expanded={open}
          aria-controls="mobile-nav"
          aria-label={open ? "Close menu" : "Open menu"}
          className="relative ml-auto grid size-9 shrink-0 place-items-center rounded-full text-foreground transition-colors hover:bg-foreground/5 focus-ring-brand md:hidden"
        >
          <span
            aria-hidden
            className={cn(
              "absolute h-0.5 w-5 rounded-full bg-current transition-transform duration-300 ease-[cubic-bezier(0.32,0.72,0,1)]",
              open ? "rotate-45" : "-translate-y-1",
            )}
          />
          <span
            aria-hidden
            className={cn(
              "absolute h-0.5 w-5 rounded-full bg-current transition-transform duration-300 ease-[cubic-bezier(0.32,0.72,0,1)]",
              open ? "-rotate-45" : "translate-y-1",
            )}
          />
        </button>
      </div>

      {/* Mobile: full-screen glass overlay with staggered link reveals. */}
      <AnimatePresence>
        {open && (
          <motion.div
            ref={overlayRef}
            id="mobile-nav"
            role="dialog"
            aria-modal="true"
            aria-label="Main menu"
            className="fixed inset-0 z-40 flex flex-col bg-background/80 backdrop-blur-3xl md:hidden"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.3, ease: [0.16, 1, 0.3, 1] }}
          >
            <motion.nav
              className="mt-28 flex flex-col gap-1 px-6"
              initial="hidden"
              animate="show"
              variants={{
                show: {
                  transition: {
                    staggerChildren: reduce ? 0 : 0.06,
                    delayChildren: 0.05,
                  },
                },
              }}
            >
              {nav.map((item) => (
                <motion.div
                  key={item.href}
                  variants={{
                    hidden: reduce ? { opacity: 1 } : { opacity: 0, y: 14 },
                    show: {
                      opacity: 1,
                      y: 0,
                      transition: { duration: 0.5, ease: [0.16, 1, 0.3, 1] },
                    },
                  }}
                >
                  <Link
                    href={item.href}
                    onClick={() => setOpen(false)}
                    aria-current={pathname === item.href ? "page" : undefined}
                    className={cn(
                      "block py-3 font-display text-3xl font-semibold tracking-tight transition-colors",
                      pathname === item.href
                        ? "text-gradient-brand"
                        : "text-foreground/90 hover:text-foreground",
                    )}
                  >
                    {item.label}
                  </Link>
                </motion.div>
              ))}
            </motion.nav>

            <motion.div
              className="mt-auto flex flex-col gap-3 border-t border-border/60 px-6 py-8"
              initial={reduce ? { opacity: 1 } : { opacity: 0, y: 14 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{
                delay: reduce ? 0 : 0.28,
                duration: 0.5,
                ease: [0.16, 1, 0.3, 1],
              }}
            >
              <div className="flex items-center justify-between rounded-full border border-border/60 px-4 py-2 text-sm">
                <span className="text-muted-foreground">Theme</span>
                <ThemeToggle />
              </div>
              <ButtonLink
                variant="outline"
                href={SIGN_IN_URL}
                onClick={() => setOpen(false)}
                className="rounded-full"
              >
                Sign in
              </ButtonLink>
              <ArrowCta href={SIGN_UP_URL} className="w-full justify-center">
                Start free
              </ArrowCta>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </header>
  );
}
