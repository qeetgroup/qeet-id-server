import { getPost, listPosts, parseBody } from "@/lib/blog";
import { ArrowLeftIcon } from "lucide-react";
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
    openGraph: { title: post.title, description: post.description, type: "article" },
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
  return (
    <section className="border-b border-border/60">
      <div className="mx-auto max-w-3xl px-4 py-20 sm:px-6 lg:px-8 lg:py-28">
        <Link
          href="/blog"
          className="inline-flex items-center gap-1 text-sm text-muted-foreground transition-colors hover:text-foreground"
        >
          <ArrowLeftIcon className="size-3.5" /> All posts
        </Link>

        <header className="mt-8">
          <div className="flex flex-wrap items-center gap-3 text-xs text-muted-foreground">
            <time dateTime={post.publishedAt}>{formatDate(post.publishedAt)}</time>
            <span aria-hidden>·</span>
            <span>{post.readingTime}</span>
            {post.tags.map((t) => (
              <span
                key={t}
                className="rounded-full bg-muted px-2 py-0.5 text-[10px] uppercase tracking-wider"
              >
                {t}
              </span>
            ))}
          </div>
          <h1 className="mt-3 font-display text-4xl font-semibold tracking-tight text-balance sm:text-5xl">
            {post.title}
          </h1>
          <p className="mt-4 text-lg text-muted-foreground">{post.description}</p>
          <p className="mt-6 text-sm text-muted-foreground">By {post.author}</p>
        </header>

        <article className="mt-12 flex flex-col gap-6 text-foreground/90 leading-relaxed">
          {blocks.map((b, i) => {
            if (b.kind === "h2") {
              return (
                <h2
                  key={i}
                  className="mt-4 font-display text-2xl font-semibold tracking-tight text-balance"
                >
                  {b.text}
                </h2>
              );
            }
            if (b.kind === "code") {
              return (
                <pre
                  key={i}
                  className="overflow-x-auto rounded-xl border border-border/60 bg-muted/40 p-4 text-sm leading-snug"
                >
                  <code>{b.text}</code>
                </pre>
              );
            }
            return (
              <p key={i} className="text-base sm:text-lg">
                {b.text}
              </p>
            );
          })}
        </article>
      </div>
    </section>
  );
}
