"use client";

import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@qeetrix/ui";
import { PlusIcon } from "lucide-react";

export type FaqItem = { q: string; a: string };

/**
 * Brand-styled FAQ built on the @qeetrix/ui Accordion (Base UI under the hood).
 * Multiple panels can stay open; the trigger icon rotates on expand. The
 * Accordion handles keyboard + ARIA semantics; reduced-motion is respected by
 * the global CSS transition clamp.
 */
export function FaqAccordion({ items }: { items: FaqItem[] }) {
  return (
    <Accordion className="mt-10 flex flex-col gap-3" multiple defaultValue={[0]}>
      {items.map((f, i) => (
        <AccordionItem
          key={f.q}
          value={i}
          className="overflow-hidden rounded-2xl border border-border/60 bg-background"
        >
          <AccordionTrigger className="group flex w-full items-center justify-between gap-4 px-6 py-5 text-left font-medium focus-ring-brand">
            <span>{f.q}</span>
            <PlusIcon
              aria-hidden
              className="size-4 shrink-0 text-brand transition-transform duration-200 group-data-[panel-open]:rotate-45"
            />
          </AccordionTrigger>
          <AccordionContent className="px-6 pb-5 text-sm text-muted-foreground">
            {f.a}
          </AccordionContent>
        </AccordionItem>
      ))}
    </Accordion>
  );
}
