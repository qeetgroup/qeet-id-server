import { caseStudySlug } from "@/components/marketing/blocks/case-study-card";
import { InitialsAvatar } from "@/components/marketing/blocks/initials-avatar";
import { ButtonLink } from "@/components/marketing/button-link";
import { CTA } from "@/components/marketing/sections/cta";
import { getStory, stories } from "@/lib/customers";
import { ArrowLeftIcon, QuoteIcon } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";

interface Props {
  params: Promise<{ slug: string }>;
}

export function generateStaticParams() {
  return stories.map((s) => ({ slug: caseStudySlug(s.company) }));
}

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const { slug } = await params;
  const story = getStory(slug);
  if (!story) return { title: "Not found" };
  return {
    title: `${story.company} customer story`,
    description: story.summary,
    openGraph: { title: story.headline, description: story.summary, type: "article" },
  };
}

export default async function CustomerStoryPage({ params }: Props) {
  const { slug } = await params;
  const story = getStory(slug);
  if (!story) notFound();

  return (
    <>
      <section className="border-b border-border/60">
        <div className="mx-auto max-w-4xl px-4 py-20 sm:px-6 lg:px-8 lg:py-28">
          <Link
            href="/customers"
            className="inline-flex items-center gap-1 text-sm text-muted-foreground transition-colors hover:text-foreground"
          >
            <ArrowLeftIcon className="size-3.5" /> All customers
          </Link>

          <div className="mt-8 flex items-center gap-3">
            <span className="grid size-11 place-items-center rounded-lg bg-foreground font-display text-xl font-semibold text-background">
              {story.logo}
            </span>
            <div className="flex flex-col">
              <span className="text-sm font-medium uppercase tracking-widest text-muted-foreground">
                {story.company}
              </span>
              <span className="text-xs text-muted-foreground">{story.industry}</span>
            </div>
          </div>

          <h1 className="mt-6 font-display text-4xl font-semibold tracking-tight text-balance sm:text-5xl">
            {story.headline}
          </h1>
          <p className="mt-5 max-w-2xl text-lg text-muted-foreground text-balance">
            {story.summary}
          </p>
        </div>
      </section>

      {story.metrics && story.metrics.length > 0 && (
        <section className="border-b border-border/60 bg-muted/30">
          <div className="mx-auto max-w-4xl px-4 py-12 sm:px-6 lg:px-8">
            <dl className="grid grid-cols-1 gap-px overflow-hidden rounded-2xl bg-border/60 sm:grid-cols-3">
              {story.metrics.map((m) => (
                <div key={m.label} className="flex flex-col gap-1 bg-background p-6">
                  <dt className="text-xs text-muted-foreground">{m.label}</dt>
                  <dd className="font-display text-3xl font-semibold tracking-tight">{m.value}</dd>
                </div>
              ))}
            </dl>
          </div>
        </section>
      )}

      <section className="border-b border-border/60">
        <div className="mx-auto max-w-3xl px-4 py-20 sm:px-6 lg:px-8 lg:py-28">
          <div className="flex flex-col gap-6 text-foreground/90 leading-relaxed">
            {story.story.map((p) => (
              <p key={p.slice(0, 24)} className="text-base sm:text-lg">
                {p}
              </p>
            ))}
          </div>

          {story.quote && (
            <figure className="mt-12 flex flex-col gap-6 rounded-2xl border border-border/60 bg-card p-8">
              <QuoteIcon aria-hidden className="size-8 text-primary/70" />
              <blockquote className="font-display text-xl font-medium leading-relaxed text-foreground text-balance sm:text-2xl">
                {story.quote.text}
              </blockquote>
              <figcaption className="flex items-center gap-3 border-t border-border/60 pt-5">
                <InitialsAvatar name={story.quote.name} size="lg" />
                <div className="flex flex-col">
                  <span className="text-sm font-semibold text-foreground">{story.quote.name}</span>
                  <span className="text-xs text-muted-foreground">
                    {story.quote.role} · {story.company}
                  </span>
                </div>
              </figcaption>
            </figure>
          )}

          <div className="mt-10 flex flex-col items-start gap-3 sm:flex-row sm:items-center">
            <ButtonLink href="/sign-up">Start free</ButtonLink>
            <ButtonLink variant="outline" href="/contact">
              Talk to sales
            </ButtonLink>
          </div>
        </div>
      </section>

      <CTA />
    </>
  );
}
