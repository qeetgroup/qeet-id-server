import { ArrowRightIcon } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";
import { InitialsAvatar } from "@/components/marketing/blocks/initials-avatar";
import { Reveal, Stagger, StaggerItem } from "@/components/marketing/motion";
import { listPosts } from "@/lib/blog";

export const metadata: Metadata = {
  title: "Engineering blog",
  description:
    "Notes from the team building Qeet ID. Security, identity, and the boring infra it takes to make auth feel boring.",
  openGraph: {
    title: "Engineering blog",
    description:
      "Notes from the team building Qeet ID. Security, identity, and the boring infra it takes to make auth feel boring.",
    type: "website",
  },
};

function formatDate(iso: string) {
  return new Date(`${iso}T00:00:00Z`).toLocaleDateString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
    timeZone: "UTC",
  });
}

function Meta({ date, readingTime }: { date: string; readingTime: string }) {
  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground">
      <time dateTime={date}>{formatDate(date)}</time>
      <span aria-hidden className="text-brand/50">
        •
      </span>
      <span>{readingTime}</span>
    </div>
  );
}

function Tags({ tags }: { tags: string[] }) {
  return (
    <div className="flex flex-wrap gap-1.5">
      {tags.map((t) => (
        <span
          key={t}
          className="rounded-full border border-brand/20 bg-brand/5 px-2 py-0.5 text-[10px] font-medium uppercase tracking-wider text-brand-text"
        >
          {t}
        </span>
      ))}
    </div>
  );
}

export default function BlogIndexPage() {
  const posts = listPosts();
  const [featured, ...rest] = posts;

  return (
    <section className="border-b border-border/60">
      <div className="mx-auto max-w-5xl px-4 py-20 sm:px-6 lg:px-8 lg:py-28">
        <Reveal className="text-center">
          <p className="text-sm font-medium uppercase tracking-widest text-brand-text">
            Engineering
          </p>
          <h1 className="mt-2 font-display text-4xl font-semibold tracking-tight text-balance sm:text-5xl">
            Notes from the <span className="text-gradient-brand">team</span>
          </h1>
          <p className="mx-auto mt-5 max-w-2xl text-muted-foreground text-balance sm:text-lg">
            Security, identity, and the boring infra it takes to make auth feel boring.
          </p>
        </Reveal>

        {/* Featured (latest) post — larger, brand-edged card. */}
        {featured && (
          <Reveal delay={0.05} className="mt-14">
            <Link
              href={`/blog/${featured.slug}`}
              className="group relative flex flex-col gap-5 overflow-hidden rounded-3xl border border-brand/30 bg-card p-8 transition-colors hover:border-brand/50 focus-ring-brand sm:p-10"
            >
              <span
                aria-hidden
                className="pointer-events-none absolute inset-x-0 top-0 h-px bg-[image:var(--brand-gradient)]"
              />
              <div className="flex flex-wrap items-center gap-3">
                <span className="rounded-full bg-[image:var(--brand-gradient)] px-2.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-brand-foreground">
                  Latest
                </span>
                <Meta date={featured.publishedAt} readingTime={featured.readingTime} />
              </div>
              <h2 className="font-display text-3xl font-semibold tracking-tight text-balance group-hover:text-brand-text sm:text-4xl">
                {featured.title}
              </h2>
              <p className="max-w-3xl text-muted-foreground sm:text-lg">{featured.description}</p>
              <div className="flex flex-wrap items-center justify-between gap-4">
                <div className="flex items-center gap-2.5">
                  <InitialsAvatar name={featured.author} size="sm" />
                  <span className="text-sm font-medium text-foreground">{featured.author}</span>
                </div>
                <Tags tags={featured.tags} />
              </div>
            </Link>
          </Reveal>
        )}

        {/* The rest, in a responsive grid. */}
        {rest.length > 0 && (
          <Stagger staggerDelay={0.08} className="mt-6 grid gap-5 sm:grid-cols-2">
            {rest.map((p) => (
              <StaggerItem key={p.slug} className="h-full">
                <Link
                  href={`/blog/${p.slug}`}
                  className="group flex h-full flex-col gap-3 rounded-2xl border border-border/60 bg-background p-6 transition-colors hover:border-brand/40 hover:bg-muted/30 focus-ring-brand sm:p-7"
                >
                  <Meta date={p.publishedAt} readingTime={p.readingTime} />
                  <h2 className="font-display text-xl font-semibold tracking-tight text-balance group-hover:text-brand-text sm:text-2xl">
                    {p.title}
                  </h2>
                  <p className="text-sm text-muted-foreground">{p.description}</p>
                  <div className="mt-auto flex items-center justify-between gap-3 pt-2">
                    <div className="flex items-center gap-2">
                      <InitialsAvatar name={p.author} size="sm" />
                      <span className="text-xs font-medium text-foreground">{p.author}</span>
                    </div>
                    <ArrowRightIcon
                      className="size-4 text-brand-text transition-transform group-hover:translate-x-0.5"
                      aria-hidden
                    />
                  </div>
                </Link>
              </StaggerItem>
            ))}
          </Stagger>
        )}
      </div>
    </section>
  );
}
