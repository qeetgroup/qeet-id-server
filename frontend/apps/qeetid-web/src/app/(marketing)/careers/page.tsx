import { ButtonLink } from "@/components/marketing/button-link";
import { Badge } from "@qeetrix/ui";
import {
  ArrowRightIcon,
  GlobeIcon,
  HeartPulseIcon,
  LaptopIcon,
  PlaneIcon,
  SproutIcon,
  WalletIcon,
} from "lucide-react";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Careers",
  description:
    "Help us make secure identity the default for every product team. Remote-first, async, and deeply technical.",
};

const perks = [
  { icon: GlobeIcon, title: "Remote-first", body: "Work from anywhere across nine time zones. Async by default." },
  { icon: WalletIcon, title: "Top-of-market pay", body: "Competitive salary, meaningful equity, transparent bands." },
  { icon: HeartPulseIcon, title: "Health & wellness", body: "Full medical, dental, vision, and a wellness stipend." },
  { icon: PlaneIcon, title: "Real time off", body: "Minimum PTO we actually enforce, plus company-wide recharge weeks." },
  { icon: LaptopIcon, title: "Home-office budget", body: "Pick your hardware. We cover the setup that makes you productive." },
  { icon: SproutIcon, title: "Growth", body: "Learning budget, conference travel, and mentorship from day one." },
];

const roles = [
  { title: "Senior Backend Engineer (Go)", team: "Platform", location: "Remote · Global" },
  { title: "Security Engineer", team: "Security", location: "Remote · Global" },
  { title: "Developer Advocate", team: "DevRel", location: "Remote · Americas" },
  { title: "Product Designer", team: "Design", location: "Remote · EU/UK" },
  { title: "Site Reliability Engineer", team: "Infrastructure", location: "Remote · Global" },
];

export default function CareersPage() {
  return (
    <>
      <section className="border-b border-border/60">
        <div className="mx-auto max-w-7xl px-4 py-20 sm:px-6 lg:px-8 lg:py-28">
          <div className="mx-auto max-w-3xl text-center">
            <p className="text-sm font-medium uppercase tracking-widest text-primary">Careers</p>
            <h1 className="mt-2 font-display text-4xl font-semibold tracking-tight text-balance sm:text-5xl">
              Build the identity layer the internet runs on
            </h1>
            <p className="mt-5 text-muted-foreground text-balance sm:text-lg">
              We&apos;re a small, senior, remote-first team that cares deeply about security and
              craft. If you want your work in the critical path of thousands of products, you&apos;ll
              fit right in.
            </p>
            <div className="mt-8 flex justify-center">
              <ButtonLink href="#open-roles">
                See open roles <ArrowRightIcon className="size-4" />
              </ButtonLink>
            </div>
          </div>
        </div>
      </section>

      <section className="border-b border-border/60 bg-muted/30">
        <div className="mx-auto max-w-7xl px-4 py-20 sm:px-6 lg:px-8 lg:py-28">
          <h2 className="font-display text-3xl font-semibold tracking-tight text-balance sm:text-4xl">
            Why you&apos;ll like it here
          </h2>
          <div className="mt-12 grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
            {perks.map(({ icon: Icon, title, body }) => (
              <div
                key={title}
                className="flex flex-col gap-3 rounded-2xl border border-border/60 bg-background p-6"
              >
                <span className="grid size-10 place-items-center rounded-lg bg-primary/10 text-primary">
                  <Icon className="size-5" />
                </span>
                <h3 className="font-display text-lg font-semibold tracking-tight">{title}</h3>
                <p className="text-sm text-muted-foreground">{body}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section id="open-roles" className="scroll-mt-20 border-b border-border/60">
        <div className="mx-auto max-w-7xl px-4 py-20 sm:px-6 lg:px-8 lg:py-28">
          <h2 className="font-display text-3xl font-semibold tracking-tight text-balance sm:text-4xl">
            Open roles
          </h2>
          <ul className="mt-10 flex flex-col gap-3">
            {roles.map((r) => (
              <li key={r.title}>
                <a
                  href="mailto:careers@qeetid.com"
                  className="group flex flex-col gap-2 rounded-2xl border border-border/60 bg-card p-6 transition-colors hover:border-foreground/20 sm:flex-row sm:items-center sm:justify-between"
                >
                  <div className="flex flex-col gap-2">
                    <span className="font-display text-lg font-semibold tracking-tight">
                      {r.title}
                    </span>
                    <div className="flex flex-wrap items-center gap-2 text-sm text-muted-foreground">
                      <Badge variant="secondary">{r.team}</Badge>
                      <span>{r.location}</span>
                    </div>
                  </div>
                  <span className="inline-flex items-center gap-1 text-sm font-medium text-primary">
                    Apply{" "}
                    <ArrowRightIcon className="size-4 transition-transform group-hover:translate-x-0.5" />
                  </span>
                </a>
              </li>
            ))}
          </ul>

          <div className="mt-12 flex flex-col items-start gap-3 rounded-2xl border border-border/60 bg-muted/30 p-8 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex flex-col gap-1">
              <h3 className="font-display text-lg font-semibold tracking-tight">
                Don&apos;t see your role?
              </h3>
              <p className="text-sm text-muted-foreground">
                We&apos;re always glad to meet exceptional people. Tell us what you&apos;d build.
              </p>
            </div>
            <ButtonLink variant="outline" href="mailto:careers@qeetid.com">
              Get in touch
            </ButtonLink>
          </div>
        </div>
      </section>
    </>
  );
}
