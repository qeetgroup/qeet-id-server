import type { Metadata } from "next";
import Link from "next/link";
import { ArrowRightIcon } from "lucide-react";

export const metadata: Metadata = {
  title: "Compare Qeet ID",
  description:
    "Honest, side-by-side comparisons of Qeet ID against Auth0, Clerk, WorkOS, and Stytch — feature parity, deployment, pricing.",
};

const competitors = [
  {
    slug: "auth0",
    name: "Auth0",
    tagline:
      "Auth0 (Okta) is the enterprise CIAM market leader. Compare on self-hosting, transparent pricing, and federation parity.",
  },
  {
    slug: "clerk",
    name: "Clerk",
    tagline:
      "Clerk is the developer-friendly React-first auth-as-a-service. Compare on self-hosting, multi-tenant B2B, and infrastructure ownership.",
  },
  {
    slug: "workos",
    name: "WorkOS",
    tagline:
      "WorkOS sells enterprise-readiness APIs (SSO, SCIM, Audit). Compare on whether you also want the user store and admin UI in one place.",
  },
  {
    slug: "stytch",
    name: "Stytch",
    tagline:
      "Stytch is a passwordless-first auth API with strong fraud signals. Compare on built-in admin UI, multi-tenant B2B, and self-hosting.",
  },
];

export default function ComparePage() {
  return (
    <div className="mx-auto w-full max-w-5xl px-4 py-16 sm:px-6 sm:py-24">
      <div className="mb-12">
        <p className="text-sm font-semibold uppercase tracking-wider text-muted-foreground">
          Compare
        </p>
        <h1 className="mt-2 text-3xl font-bold tracking-tight sm:text-5xl">
          How does Qeet ID stack up?
        </h1>
        <p className="mt-4 max-w-2xl text-balance text-lg text-muted-foreground">
          We&apos;ve put together honest, side-by-side comparisons against the identity
          platforms you&apos;ve probably already evaluated. Each comparison links to public
          docs so you can verify our claims.
        </p>
      </div>

      <ul className="grid gap-4 sm:grid-cols-2">
        {competitors.map((c) => (
          <li key={c.slug}>
            <Link
              href={`/compare/${c.slug}`}
              className="group flex h-full flex-col gap-3 rounded-2xl border bg-card p-6 transition-colors hover:border-primary"
            >
              <div className="flex items-center justify-between">
                <h2 className="text-xl font-semibold tracking-tight">
                  Qeet ID <span className="text-muted-foreground">vs.</span> {c.name}
                </h2>
                <ArrowRightIcon className="size-4 text-muted-foreground transition-transform group-hover:translate-x-1 group-hover:text-foreground" />
              </div>
              <p className="text-sm text-muted-foreground">{c.tagline}</p>
            </Link>
          </li>
        ))}
      </ul>

      <p className="mt-12 text-xs text-muted-foreground">
        Comparisons are based on publicly-available product information at the time of
        writing. Spotted something inaccurate?{" "}
        <Link href="/contact" className="underline">
          Let us know
        </Link>
        .
      </p>
    </div>
  );
}
