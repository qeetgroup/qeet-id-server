"use client";

import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@qeetrix/ui";

export type FaqItem = { q: string; a: string };

export function FaqAccordion({ items }: { items: FaqItem[] }) {
  return (
    <Accordion className="mt-10 flex flex-col gap-3" multiple defaultValue={[0]}>
      {items.map((f, i) => (
        <AccordionItem
          key={f.q}
          value={i}
          className="overflow-hidden rounded-2xl border border-border/60 bg-background"
        >
          <AccordionTrigger className="px-6 py-5 text-left font-medium focus-ring-brand">
            <span>{f.q}</span>
          </AccordionTrigger>
          <AccordionContent className="px-6 pb-5 text-sm text-muted-foreground">
            {f.a}
          </AccordionContent>
        </AccordionItem>
      ))}
    </Accordion>
  );
}
