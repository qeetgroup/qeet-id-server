import { InitialsAvatar } from "@/components/marketing/blocks/initials-avatar";
import { CodeBlock } from "@/components/marketing/effects/code-block";
import { Reveal } from "@/components/marketing/motion";
import {
  ArticleJsonLd,
  BreadcrumbJsonLd,
} from "@/components/marketing/structured-data";
import { getPost, listPosts, parseBody, relatedPosts } from "@/lib/blog";
import { SIGN_UP_URL } from "@/lib/links";
import { ArrowLeftIcon, ArrowRightIcon } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";

interface Props {
  params: Promise<{ slug: string }>;
}

export function generateStaticParams() {
  return listPosts().map((p) => ({ slug: p.slug }));
}

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const { slug } = await params;
  const post = getPost(slug);
  if (!post) return { title: "Not found" };
  return {
    title: post.title,
    description: post.description,
    alternates: { canonical: `/blog/${post.slug}` },
    openGraph: {
      title: post.title,
      description: post.description,
      type: "article",
      url: `/blog/${post.slug}`,
      publishedTime: post.publishedAt,
      authors: [post.author],
      tags: post.tags,
      // The colocated `opengraph-image.tsx` is auto-detected by Next; this
      // keeps the article-specific OG metadata explicit alongside it.
    },
    twitter: { card: "summary_large_image", title: post.title, description: post.description },
  };
}

function formatDate(iso: string) {
  return new Date(`${iso}T00:00:00Z`).toLocaleDateString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
    timeZone: "UTC",
  });
}

export default async function BlogPostPage({ params }: Props) {
  const { slug } = await params;
  const post = getPost(slug);
  if (!post) notFound();

  const blocks = parseBody(post.body);
  const related = relatedPosts(slug);

  return (
    <>
      <ArticleJsonLd
        title={post.title}
        description={post.description}
        url={`/blog/${post.slug}`}
        datePublished={post.publishedAt}
        author={post.author}
        image={`/blog/${post.slug}/opengraph-image`}
      />
      <BreadcrumbJsonLd
        items={[
          { name: "Home", url: "/" },
          { name: "Blog", url: "/blog" },
          { name: post.title, url: `/blog/${post.slug}` },
        ]}
      />

      <article className="border-b border-border/60">
        {/* Header */}
        <header className="relative overflow-hidden border-b border-border/60">
          <span
            aria-hidden
            className="pointer-events-none absolute inset-x-0 top-0 h-px bg-[image:var(--brand-gradient)]"
          />
          <div className="mx-auto max-w-3xl px-4 py-16 sm:px-6 lg:px-8 lg:py-20">
            <Reveal>
              <Link
                href="/blog"
                className="inline-flex items-center gap-1 text-sm text-muted-foreground transition-colors hover:text-foreground focus-ring-brand"
              >
                <ArrowLeftIcon className="size-3.5" aria-hidden /> All posts
              </Link>
            </Reveal>

            <Reveal delay={0.05}>
              <div className="mt-8 flex flex-wrap gap-1.5">
                {post.tags.map((t) => (
                  <span
                    key={t}
                    className="rounded-full border border-brand/20 bg-brand/5 px-2 py-0.5 text-[10px] font-medium uppercase tracking-wider text-brand-text"
                  >
                    {t}
                  </span>
                ))}
              </div>
              <h1 className="mt-4 font-display text-4xl font-semibold leading-[1.05] tracking-tight text-balance sm:text-5xl">
                {post.title}
              </h1>
              <p className="mt-5 text-lg text-muted-foreground text-balance">
                {post.description}
              </p>
            </Reveal>

            <Reveal delay={0.1}>
              <div className="mt-8 flex flex-wrap items-center gap-3 border-t border-border/60 pt-6">
                <InitialsAvatar name={post.author} />
                <div className="flex flex-col">
                  <span className="text-sm font-semibold text-foreground">{post.author}</span>
                  <div className="flex items-center gap-2 text-xs text-muted-foreground">
                    <time dateTime={post.publishedAt}>{formatDate(post.publishedAt)}</time>
                    <span aria-hidden className="text-brand/50">
                      •
                    </span>
                    <span>{post.readingTime}</span>
                  </div>
                </div>
              </div>
            </Reveal>
          </div>
        </header>

        {/* Body */}
        <div className="mx-auto max-w-3xl px-4 py-16 sm:px-6 lg:px-8 lg:py-20">
          <div className="flex flex-col gap-7 text-foreground/90 leading-relaxed">
            {blocks.map((b, i) => {
              if (b.kind === "h2") {
                return (
                  <h2
                    key={i}
                    className="mt-6 scroll-mt-24 font-display text-2xl font-semibold tracking-tight text-balance sm:text-3xl"
                  >
                    <span className="text-gradient-brand">{b.text}</span>
                  </h2>
                );
              }
              if (b.kind === "code") {
                return (
                  <CodeBlock key={i} language={b.lang} className="my-2 text-[13px]">
                    {b.text}
                  </CodeBlock>
                );
              }
              return (
                <p key={i} className="text-base sm:text-lg">
                  {b.text}
                </p>
              );
            })}
          </div>

          {/* Footer CTA */}
          <div className="mt-14 flex flex-col items-start gap-4 rounded-2xl border border-border/60 bg-muted/30 p-6 sm:flex-row sm:items-center sm:justify-between sm:p-8">
            <div className="flex flex-col gap-1">
              <span className="font-display text-lg font-semibold tracking-tight">
                Want auth that gets out of your way?
              </span>
              <span className="text-sm text-muted-foreground">
                Free up to 5,000 MAU. No card required.
              </span>
            </div>
            <Link
              href={SIGN_UP_URL}
              className="inline-flex shrink-0 items-center gap-1.5 rounded-full bg-[image:var(--brand-gradient)] px-5 py-2.5 text-sm font-medium text-brand-foreground transition-transform hover:scale-[1.02] focus-ring-brand"
            >
              Start free
              <ArrowRightIcon className="size-4" aria-hidden />
            </Link>
          </div>
        </div>

        {/* Related posts */}
        {related.length > 0 && (
          <div className="border-t border-border/60 bg-muted/30">
            <div className="mx-auto max-w-3xl px-4 py-14 sm:px-6 lg:px-8">
              <h2 className="font-display text-xl font-semibold tracking-tight">Keep reading</h2>
              <div className="mt-6 grid gap-4 sm:grid-cols-2">
                {related.map((r) => (
                  <Link
                    key={r.slug}
                    href={`/blog/${r.slug}`}
                    className="group flex h-full flex-col gap-2 rounded-2xl border border-border/60 bg-background p-5 transition-colors hover:border-brand/40 focus-ring-brand"
                  >
                    <span className="text-xs text-muted-foreground">{formatDate(r.publishedAt)}</span>
                    <span className="font-display text-base font-semibold tracking-tight text-balance group-hover:text-brand-text">
                      {r.title}
                    </span>
                    <span className="mt-auto inline-flex items-center gap-1 pt-1 text-sm font-medium text-brand-text">
                      Read
                      <ArrowRightIcon
                        className="size-3.5 transition-transform group-hover:translate-x-0.5"
                        aria-hidden
                      />
                    </span>
                  </Link>
                ))}
              </div>
            </div>
          </div>
        )}
      </article>
    </>
  );
}
