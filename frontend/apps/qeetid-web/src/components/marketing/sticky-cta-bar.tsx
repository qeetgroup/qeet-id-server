"use client";

import { Button, cn } from "@qeetrix/ui";
import { XIcon } from "lucide-react";
import { useEffect, useState } from "react";
import { ButtonLink } from "./button-link";
import { useReducedMotion } from "@/lib/use-reduced-motion";

/**
 * Slim bottom bar that appears after the visitor scrolls past the hero.
 * Reduced-motion aware (no slide-in when reduce is set) and dismissible
 * for the session.
 */
export function StickyCtaBar() {
  const [visible, setVisible] = useState(false);
  const [dismissed, setDismissed] = useState(false);
  const reduced = useReducedMotion();

  useEffect(() => {
    const onScroll = () => setVisible(window.scrollY > window.innerHeight * 0.9);
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  if (dismissed) return null;

  return (
    <div
      aria-hidden={!visible}
      className={cn(
        "fixed inset-x-0 bottom-0 z-40 px-4 pb-4 sm:px-6 lg:px-8",
        visible ? "pointer-events-auto" : "pointer-events-none",
        !reduced && "transition-[opacity,transform] duration-300",
        visible ? "translate-y-0 opacity-100" : "translate-y-4 opacity-0",
      )}
    >
      <div className="mx-auto flex max-w-3xl items-center gap-3 rounded-2xl border border-border/60 bg-background/80 p-3 shadow-2xl shadow-black/10 backdrop-blur-xl sm:gap-4 sm:p-4">
        <p className="hidden flex-1 text-sm font-medium sm:block">
          Ship production auth this week — free for 5,000 users.
        </p>
        <div className="flex flex-1 items-center gap-2 sm:flex-none">
          <ButtonLink size="sm" href="/sign-up" className="flex-1 sm:flex-none">
            Start free
          </ButtonLink>
          <ButtonLink size="sm" variant="outline" href="/contact" className="flex-1 sm:flex-none">
            Talk to sales
          </ButtonLink>
        </div>
        <Button
          variant="ghost"
          size="icon"
          aria-label="Dismiss"
          onClick={() => setDismissed(true)}
          className="shrink-0"
        >
          <XIcon className="size-4" />
        </Button>
      </div>
    </div>
  );
}
