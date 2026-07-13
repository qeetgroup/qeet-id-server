import { cn } from "@qeetrix/ui";
import { ArrowRightIcon } from "lucide-react";
import Link from "next/link";

import { caseStudySlug } from "@/components/marketing/blocks/case-study-card";
import { Tilt } from "@/components/marketing/motion";
import type { CustomerStory } from "@/lib/customers";

/**
 * Compact customer-story tile for the index grid: a glyph logo, the segment
 * label, the headline, a single highlighted metric, and a short quote snippet.
 * The whole card is a link to the detail story; a subtle `Tilt` adds depth on
 * pointer devices (no-op for touch / reduced motion). Server-rendered shell —
 * only the `Tilt` wrapper is a client island.
 */
export function CustomerCard({ story, className }: { story: CustomerStory; className?: string }) {
  const slug = caseStudySlug(story.company);
  const metric = story.metrics?.[0];

  return (
    <Tilt max={4} className={cn("h-full", className)}>
      <Link
        href={`/customers/${slug}`}
        aria-label={`Read the ${story.company} story`}
        className="group flex h-full flex-col gap-5 rounded-2xl border border-border/60 bg-card p-6 transition-colors hover:border-brand/50 focus-ring-brand"
      >
        <div className="flex items-center justify-between gap-3">
          <span className="grid size-10 place-items-center rounded-lg bg-foreground font-display text-lg font-semibold text-background">
            {story.logo}
          </span>
          <span className="rounded-full border border-border/60 px-2.5 py-0.5 text-[11px] font-medium text-muted-foreground">
            {story.segment}
          </span>
        </div>

        <h3 className="font-display text-lg font-semibold tracking-tight text-balance">
          {story.headline}
        </h3>

        {story.quote && (
          <p className="text-sm text-muted-foreground line-clamp-3">
            &ldquo;{story.quote.text}&rdquo;
          </p>
        )}

        {metric && (
          <dl className="mt-auto flex items-baseline gap-2 border-t border-border/60 pt-4">
            <dt className="sr-only">{metric.label}</dt>
            <dd className="font-display text-xl font-semibold tracking-tight text-gradient-brand">
              {metric.value}
            </dd>
            <span className="text-xs text-muted-foreground">{metric.label}</span>
          </dl>
        )}

        <span className="inline-flex items-center gap-1 text-sm font-medium text-brand-text">
          Read the story
          <ArrowRightIcon
            className="size-4 transition-transform group-hover:translate-x-0.5"
            aria-hidden
          />
        </span>
      </Link>
    </Tilt>
  );
}
