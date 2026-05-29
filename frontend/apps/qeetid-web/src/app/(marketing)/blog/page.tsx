import { listPosts } from "@/lib/blog";
import { ArrowRightIcon } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = {
  title: "Engineering blog",
  description:
    "Notes from the team building Qeet ID. Security, identity, and the boring infra it takes to make auth feel boring.",
};

function formatDate(iso: string) {
  return new Date(`${iso}T00:00:00Z`).toLocaleDateString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
    timeZone: "UTC",
  });
}

export default function BlogIndexPage() {
  const posts = listPosts();
  return (
    <section className="border-b border-border/60">
      <div className="mx-auto max-w-4xl px-4 py-20 sm:px-6 lg:px-8 lg:py-28">
        <div className="text-center">
          <p className="text-sm font-medium uppercase tracking-widest text-primary">Engineering</p>
          <h1 className="mt-2 font-display text-4xl font-semibold tracking-tight text-balance sm:text-5xl">
            Notes from the team
          </h1>
          <p className="mt-5 text-muted-foreground text-balance sm:text-lg">
            Security, identity, and the boring infra it takes to make auth feel boring.
          </p>
        </div>

        <div className="mt-14 flex flex-col gap-3">
          {posts.map((p) => (
            <Link
              key={p.slug}
              href={`/blog/${p.slug}`}
              className="group rounded-2xl border border-border/60 bg-background p-6 transition-colors hover:border-primary/40 hover:bg-muted/30 sm:p-8"
            >
              <div className="flex flex-wrap items-center gap-3 text-xs text-muted-foreground">
                <time dateTime={p.publishedAt}>{formatDate(p.publishedAt)}</time>
                <span aria-hidden>·</span>
                <span>{p.readingTime}</span>
                {p.tags.map((t) => (
                  <span
                    key={t}
                    className="rounded-full bg-muted px-2 py-0.5 text-[10px] uppercase tracking-wider"
                  >
                    {t}
                  </span>
                ))}
              </div>
              <h2 className="mt-3 font-display text-2xl font-semibold tracking-tight text-balance group-hover:text-primary">
                {p.title}
              </h2>
              <p className="mt-2 text-muted-foreground">{p.description}</p>
              <div className="mt-4 inline-flex items-center gap-1.5 text-sm font-medium text-primary">
                Read more
                <ArrowRightIcon className="size-3.5 transition-transform group-hover:translate-x-0.5" />
              </div>
            </Link>
          ))}
        </div>
      </div>
    </section>
  );
}
