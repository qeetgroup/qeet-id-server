import { Avatar, AvatarFallback, AvatarImage, cn } from "@qeetrix/ui";
import { ArrowRightIcon, QuoteIcon } from "lucide-react";

import { ButtonLink } from "@/components/marketing/button-link";

/**
 * One full case-study tile: company badge + headline + summary +
 * metrics grid + pull quote with photo + "read the full story" link.
 *
 * Drop one of these on any marketing page to surface social proof
 * without re-skinning a custom layout each time. Use multiple stacked
 * vertically on the customers page; use a single one as a sidebar
 * feature on a vertical-specific landing page.
 */
export interface CaseStudyMetric {
  value: string;
  label: string;
}

export interface CaseStudyQuote {
  text: string;
  name: string;
  role: string;
  avatar?: string;
}

export interface CaseStudy {
  /** Customer company name (used in the header badge and aria). */
  company: string;
  /** Short logo glyph (1–3 chars) for the badge. */
  logo: string;
  headline: string;
  summary: string;
  metrics?: CaseStudyMetric[];
  quote?: CaseStudyQuote;
  /** URL for the "read full story" link. Defaults to `/customers/{slug}`. */
  href?: string;
}

export interface CaseStudyCardProps {
  data: CaseStudy;
  className?: string;
}

export function CaseStudyCard({ data, className }: CaseStudyCardProps) {
  const slug = data.company.toLowerCase().replace(/[^a-z0-9]+/g, "-");
  const href = data.href ?? `/customers/${slug}`;
  return (
    <article
      className={cn(
        "grid gap-8 rounded-3xl border border-border/60 bg-background p-8 lg:grid-cols-[1.4fr_1fr] lg:p-12",
        className,
      )}
      aria-labelledby={`cs-${slug}-headline`}
    >
      <div className="flex flex-col gap-6">
        <div className="flex items-center gap-3">
          <span className="grid size-10 place-items-center rounded-lg bg-foreground font-display text-lg font-semibold text-background">
            {data.logo}
          </span>
          <span className="text-sm font-medium uppercase tracking-widest text-muted-foreground">
            {data.company}
          </span>
        </div>
        <h2
          id={`cs-${slug}-headline`}
          className="font-display text-2xl font-semibold tracking-tight text-balance sm:text-3xl"
        >
          {data.headline}
        </h2>
        <p className="text-muted-foreground">{data.summary}</p>
        {data.metrics && data.metrics.length > 0 && (
          <dl className="grid grid-cols-3 gap-4">
            {data.metrics.map((m) => (
              <div key={m.label} className="rounded-xl border border-border/60 p-4">
                <dt className="text-xs text-muted-foreground">{m.label}</dt>
                <dd className="mt-1 font-display text-xl font-semibold tracking-tight">{m.value}</dd>
              </div>
            ))}
          </dl>
        )}
        <ButtonLink variant="outline" className="w-fit" href={href}>
          Read the full story <ArrowRightIcon className="size-4" />
        </ButtonLink>
      </div>
      {data.quote && (
        <figure className="flex flex-col gap-6 rounded-2xl bg-muted/40 p-6">
          <QuoteIcon className="size-6 text-primary" />
          <blockquote className="text-base leading-relaxed text-foreground/90 sm:text-lg">
            &ldquo;{data.quote.text}&rdquo;
          </blockquote>
          <figcaption className="mt-auto flex items-center gap-3">
            <Avatar className="size-10">
              {data.quote.avatar && (
                <AvatarImage src={data.quote.avatar} alt={data.quote.name} />
              )}
              <AvatarFallback>{data.quote.name.charAt(0)}</AvatarFallback>
            </Avatar>
            <div className="flex flex-col">
              <span className="text-sm font-medium">{data.quote.name}</span>
              <span className="text-xs text-muted-foreground">{data.quote.role}</span>
            </div>
          </figcaption>
        </figure>
      )}
    </article>
  );
}
