import { ShieldCheckIcon } from "lucide-react";
import Link from "next/link";

function GithubGlyph() {
  return (
    <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden className="size-4">
      <path d="M12 .5A11.5 11.5 0 0 0 .5 12a11.5 11.5 0 0 0 7.86 10.92c.58.11.79-.25.79-.55v-2c-3.2.7-3.87-1.36-3.87-1.36-.52-1.34-1.28-1.7-1.28-1.7-1.05-.72.08-.7.08-.7 1.16.08 1.78 1.2 1.78 1.2 1.03 1.77 2.7 1.26 3.36.96.1-.75.4-1.26.73-1.55-2.55-.29-5.24-1.28-5.24-5.7 0-1.26.45-2.29 1.19-3.1-.12-.3-.52-1.48.11-3.07 0 0 .97-.31 3.18 1.18a11 11 0 0 1 5.8 0c2.21-1.5 3.18-1.18 3.18-1.18.63 1.59.23 2.77.11 3.07.74.81 1.19 1.84 1.19 3.1 0 4.43-2.69 5.41-5.25 5.69.41.36.78 1.06.78 2.14v3.18c0 .3.21.67.8.55A11.5 11.5 0 0 0 23.5 12 11.5 11.5 0 0 0 12 .5z" />
    </svg>
  );
}

function XGlyph() {
  return (
    <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden className="size-4">
      <path d="M18.244 2H21l-6.52 7.45L22 22h-6.828l-4.78-6.252L4.8 22H2l7.06-8.06L2 2h6.97l4.33 5.72L18.244 2zm-1.197 18h1.832L7.04 4H5.07l11.977 16z" />
    </svg>
  );
}

const columns = [
  {
    title: "Product",
    links: [
      { href: "/features", label: "Features" },
      { href: "/pricing", label: "Pricing" },
      { href: "/security", label: "Security" },
      { href: "/changelog", label: "Changelog" },
    ],
  },
  {
    title: "Developers",
    links: [
      { href: "/docs", label: "Documentation" },
      { href: "/docs/quickstart", label: "Quickstart" },
      { href: "/docs/api", label: "API reference" },
      { href: "https://github.com/qeetid", label: "GitHub" },
    ],
  },
  {
    title: "Company",
    links: [
      { href: "/customers", label: "Customers" },
      { href: "/about", label: "About" },
      { href: "/careers", label: "Careers" },
      { href: "/contact", label: "Contact" },
    ],
  },
  {
    title: "Legal",
    links: [
      { href: "/legal/terms", label: "Terms" },
      { href: "/legal/privacy", label: "Privacy" },
      { href: "/legal/dpa", label: "DPA" },
      { href: "/legal/subprocessors", label: "Subprocessors" },
    ],
  },
];

export function SiteFooter() {
  return (
    <footer className="border-t border-border/60 bg-background">
      <div className="mx-auto grid max-w-7xl gap-10 px-4 py-12 sm:px-6 md:grid-cols-[1.5fr_repeat(4,1fr)] lg:px-8">
        <div className="flex flex-col gap-4">
          <Link href="/" className="flex items-center gap-2 font-semibold tracking-tight">
            <span className="grid size-7 place-items-center rounded-md bg-foreground text-background">
              <ShieldCheckIcon className="size-4" />
            </span>
            <span className="text-base">Identity</span>
          </Link>
          <p className="max-w-xs text-sm text-muted-foreground">
            One identity. Every platform. Auth infrastructure for modern teams.
          </p>
          <div className="flex items-center gap-2 text-muted-foreground">
            <Link
              href="https://github.com/qeetid"
              aria-label="GitHub"
              className="rounded-md p-1.5 hover:bg-accent hover:text-foreground"
            >
              <GithubGlyph />
            </Link>
            <Link
              href="https://twitter.com/qeetid"
              aria-label="X (Twitter)"
              className="rounded-md p-1.5 hover:bg-accent hover:text-foreground"
            >
              <XGlyph />
            </Link>
          </div>
        </div>

        {columns.map((col) => (
          <div key={col.title} className="flex flex-col gap-3">
            <h4 className="text-sm font-medium">{col.title}</h4>
            <ul className="flex flex-col gap-2">
              {col.links.map((l) => (
                <li key={l.href}>
                  <Link
                    href={l.href}
                    className="text-sm text-muted-foreground hover:text-foreground"
                  >
                    {l.label}
                  </Link>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>

      <div className="border-t border-border/60">
        <div className="mx-auto flex max-w-7xl flex-col items-start justify-between gap-2 px-4 py-6 text-xs text-muted-foreground sm:flex-row sm:items-center sm:px-6 lg:px-8">
          <p>© {new Date().getFullYear()} Qeet Group, Inc. All rights reserved.</p>
          <p className="flex flex-wrap items-center gap-3">
            <span className="inline-flex items-center gap-1.5">
              <span className="size-1.5 rounded-full bg-emerald-500" /> All systems normal
            </span>
            <span>·</span>
            <span>SOC 2 Type II</span>
            <span>·</span>
            <span>ISO 27001</span>
            <span>·</span>
            <span>GDPR</span>
          </p>
        </div>
      </div>
    </footer>
  );
}
