"use client";

import { Button } from "@qeetrix/ui";
import { ArrowRightIcon, SparklesIcon, XIcon } from "lucide-react";
import { AnimatePresence, motion, useMotionValueEvent, useScroll } from "motion/react";
import { useState } from "react";
import { SIGN_UP_URL } from "@/lib/links";
import { useReducedMotion } from "@/lib/use-reduced-motion";
import { ButtonLink } from "./button-link";

/**
 * Premium bottom CTA that animates in once the visitor scrolls past the hero
 * (roughly one viewport). Brand-gradient framed, dismissible for the session,
 * and reduced-motion-safe — when reduce is set it appears/disappears instantly
 * with no slide/scale.
 */
export function StickyCtaBar() {
  const [visible, setVisible] = useState(false);
  const [dismissed, setDismissed] = useState(false);
  const reduce = useReducedMotion();
  const { scrollY } = useScroll();

  useMotionValueEvent(scrollY, "change", (y) => {
    const next = y > window.innerHeight * 0.9;
    if (next !== visible) setVisible(next);
  });

  const show = visible && !dismissed;

  // Reduced motion: no transform/scale, just opacity snap (duration ~0).
  const hidden = reduce ? { opacity: 0 } : { opacity: 0, y: 24, scale: 0.98 };
  const shown = reduce ? { opacity: 1 } : { opacity: 1, y: 0, scale: 1 };

  return (
    <AnimatePresence>
      {show && (
        <motion.div
          initial={hidden}
          animate={shown}
          exit={hidden}
          transition={
            reduce ? { duration: 0 } : { type: "spring", stiffness: 260, damping: 26, mass: 0.6 }
          }
          className="fixed inset-x-0 bottom-0 z-40 px-4 pb-4 sm:px-6 lg:px-8"
        >
          {/* Gradient frame -> inner card. The 1px brand gradient ring reads as premium. */}
          <div className="mx-auto max-w-3xl rounded-2xl bg-(image:--brand-gradient) p-px shadow-2xl shadow-brand/20">
            <div className="flex items-center gap-3 rounded-[calc(1rem-1px)] bg-background/90 p-3 backdrop-blur-xl sm:gap-4 sm:p-4">
              <span
                aria-hidden
                className="hidden size-9 shrink-0 place-items-center rounded-xl bg-brand/15 text-brand sm:grid"
              >
                <SparklesIcon className="size-4" />
              </span>
              <p className="hidden flex-1 text-sm font-medium sm:block">
                Ship production auth this week —{" "}
                <span className="text-brand-text">free for 5,000 users</span>.
              </p>
              <div className="flex flex-1 items-center gap-2 sm:flex-none">
                <ButtonLink size="sm" href={SIGN_UP_URL} className="flex-1 sm:flex-none">
                  Start free <ArrowRightIcon className="size-3.5" />
                </ButtonLink>
                <ButtonLink
                  size="sm"
                  variant="outline"
                  href="/contact"
                  className="flex-1 sm:flex-none"
                >
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
        </motion.div>
      )}
    </AnimatePresence>
  );
}
