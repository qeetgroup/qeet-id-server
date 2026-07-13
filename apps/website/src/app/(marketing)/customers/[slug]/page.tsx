import { ArrowLeftIcon, ArrowRightIcon, QuoteIcon } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";

import { caseStudySlug } from "@/components/marketing/blocks/case-study-card";
import { InitialsAvatar } from "@/components/marketing/blocks/initials-avatar";
import { ButtonLink } from "@/components/marketing/button-link";
import { FadeRise, Reveal, Stagger, StaggerItem } from "@/components/marketing/motion";
import { Section } from "@/components/marketing/section";
import { CTA } from "@/components/marketing/sections/cta";
import { BreadcrumbJsonLd } from "@/components/marketing/structured-data";
import { getStory, relatedStories, stories } from "@/lib/customers";
import { SIGN_UP_URL } from "@/lib/links";

interface Props {
  params: Promise<{ slug: string }>;
}

export function generateStaticParams() {
  return stories.map((s) => ({ slug: caseStudySlug(s.company) }));
}

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const { slug } = await params;
  const story = getStory(slug);
  if (!story) return { title: "Customer story not found" };
  return {
    title: `${story.company} — customer story`,
    description: story.summary,
    openGraph: {
      title: story.headline,
      description: story.summary,
      type: "article",
    },
  };
}

export default async function CustomerStoryPage({ params }: Props) {
  const { slug } = await params;
  const story = getStory(slug);
  if (!story) notFound();

  const related = relatedStories(slug);

  return (
    <>
      <BreadcrumbJsonLd
        items={[
          { name: "Home", url: "/" },
          { name: "Customers", url: "/customers" },
          { name: story.company, url: `/customers/${slug}` },
        ]}
      />

      {/* Hero */}
      <section className="relative overflow-hidden border-b border-border/60">
        <div className="relative mx-auto max-w-4xl px-4 py-16 sm:px-6 lg:px-8 lg:py-24">
          <Reveal>
            <Link
              href="/customers"
              className="inline-flex items-center gap-1 text-sm text-muted-foreground transition-colors hover:text-foreground focus-ring-brand"
            >
              <ArrowLeftIcon className="size-3.5" aria-hidden /> All customers
            </Link>
          </Reveal>

          <Reveal delay={0.05}>
            <div className="mt-8 flex items-center gap-3">
              <span className="grid size-11 place-items-center rounded-lg bg-foreground font-display text-xl font-semibold text-background">
                {story.logo}
              </span>
              <div className="flex flex-col">
                <span className="text-sm font-medium uppercase tracking-widest text-brand-text">
                  {story.company}
                </span>
                <span className="text-xs text-muted-foreground">
                  {story.industry} · {story.scale}
                </span>
              </div>
            </div>
          </Reveal>

          <Reveal delay={0.1}>
            <h1 className="mt-6 font-display text-4xl font-semibold leading-[1.05] tracking-tight text-balance sm:text-5xl">
              {story.headline}
            </h1>
            <p className="mt-5 max-w-2xl text-lg text-muted-foreground text-balance">
              {story.summary}
            </p>
          </Reveal>

          {story.highlights.length > 0 && (
            <Reveal delay={0.15} className="mt-6 flex flex-wrap gap-2">
              {story.highlights.map((h) => (
                <span
                  key={h}
                  className="rounded-full border border-border/60 bg-card px-3 py-1 text-xs font-medium text-muted-foreground"
                >
                  {h}
                </span>
              ))}
            </Reveal>
          )}
        </div>
      </section>

      {/* At-a-glance metrics */}
      {story.metrics && story.metrics.length > 0 && (
        <section className="border-b border-border/60 bg-muted/30">
          <div className="mx-auto max-w-4xl px-4 py-12 sm:px-6 lg:px-8">
            <h2 className="sr-only">At a glance</h2>
            <Stagger
              staggerDelay={0.08}
              className="grid grid-cols-1 gap-px overflow-hidden rounded-2xl bg-border/60 sm:grid-cols-3"
            >
              {story.metrics.map((m) => (
                <StaggerItem key={m.label}>
                  <div className="flex h-full flex-col gap-1 bg-background p-6">
                    <dt className="text-xs text-muted-foreground">{m.label}</dt>
                    <dd className="font-display text-2xl font-semibold tracking-tight text-gradient-brand sm:text-3xl">
                      {m.value}
                    </dd>
                  </div>
                </StaggerItem>
              ))}
            </Stagger>
          </div>
        </section>
      )}

      {/* Story: challenge → solution → results */}
      <Section innerClassName="mx-auto max-w-3xl px-4 py-16 sm:px-6 lg:px-8 lg:py-24">
        <div className="flex flex-col gap-12">
          {story.sections.map((sec) => (
            <FadeRise key={sec.heading} className="flex flex-col gap-4">
              <h2 className="font-display text-sm font-medium uppercase tracking-widest text-brand-text">
                {sec.heading}
              </h2>
              <div className="flex flex-col gap-4 leading-relaxed text-foreground/90">
                {sec.body.map((p) => (
                  <p key={p.slice(0, 28)} className="text-base sm:text-lg">
                    {p}
                  </p>
                ))}
              </div>
            </FadeRise>
          ))}
        </div>

        {/* Pull-quote */}
        {story.quote && (
          <Reveal className="mt-14">
            <figure className="relative flex flex-col gap-6 overflow-hidden rounded-2xl border border-border/60 bg-card p-8">
              <QuoteIcon aria-hidden className="size-8 text-brand/70" />
              <blockquote className="font-display text-xl font-medium leading-relaxed text-foreground text-balance sm:text-2xl">
                &ldquo;{story.quote.text}&rdquo;
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
          </Reveal>
        )}

        <div className="mt-10 flex flex-col items-start gap-3 sm:flex-row sm:items-center">
          <ButtonLink href={SIGN_UP_URL}>Start free</ButtonLink>
          <ButtonLink variant="outline" href="/contact">
            Talk to sales
          </ButtonLink>
        </div>
      </Section>

      {/* Related stories */}
      {related.length > 0 && (
        <Section muted>
          <h2 className="font-display text-2xl font-semibold tracking-tight">Related stories</h2>
          <Stagger staggerDelay={0.08} className="mt-8 grid gap-6 sm:grid-cols-2">
            {related.map((r) => {
              const rSlug = caseStudySlug(r.company);
              return (
                <StaggerItem key={r.company} className="h-full">
                  <Link
                    href={`/customers/${rSlug}`}
                    className="group flex h-full flex-col gap-3 rounded-2xl border border-border/60 bg-background p-6 transition-colors hover:border-brand/50 focus-ring-brand"
                  >
                    <span className="text-xs font-medium uppercase tracking-widest text-muted-foreground">
                      {r.company} · {r.segment}
                    </span>
                    <span className="font-display text-lg font-semibold tracking-tight text-balance">
                      {r.headline}
                    </span>
                    <span className="mt-auto inline-flex items-center gap-1 text-sm font-medium text-brand-text">
                      Read the story
                      <ArrowRightIcon
                        className="size-4 transition-transform group-hover:translate-x-0.5"
                        aria-hidden
                      />
                    </span>
                  </Link>
                </StaggerItem>
              );
            })}
          </Stagger>
        </Section>
      )}

      <CTA />
    </>
  );
}
