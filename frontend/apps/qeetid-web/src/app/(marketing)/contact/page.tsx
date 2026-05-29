import { Button, Input, Label, Textarea } from "@qeetid/ui";
import { BuildingIcon, LifeBuoyIcon, MailIcon, NewspaperIcon } from "lucide-react";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Contact",
  description: "Talk to Qeet ID sales, support, or press. Or just say hello.",
};

const channels = [
  {
    icon: BuildingIcon,
    title: "Talk to sales",
    body: "Pricing, enterprise contracts, custom deployments, security reviews.",
    cta: "sales@qeetid.com",
    href: "mailto:sales@qeetid.com",
  },
  {
    icon: LifeBuoyIcon,
    title: "Support",
    body: "Existing customers — we'll get back to you within your plan's SLA.",
    cta: "support@qeetid.com",
    href: "mailto:support@qeetid.com",
  },
  {
    icon: NewspaperIcon,
    title: "Press & media",
    body: "Story pitches, exec interviews, brand assets.",
    cta: "press@qeetid.com",
    href: "mailto:press@qeetid.com",
  },
  {
    icon: MailIcon,
    title: "General",
    body: "Anything else — we read every message.",
    cta: "hello@qeetid.com",
    href: "mailto:hello@qeetid.com",
  },
];

export default function ContactPage() {
  return (
    <>
      <section className="border-b border-border/60">
        <div className="mx-auto max-w-7xl px-4 py-20 sm:px-6 lg:px-8 lg:py-24">
          <div className="mx-auto max-w-2xl text-center">
            <p className="text-sm font-medium uppercase tracking-widest text-primary">Contact</p>
            <h1 className="mt-2 font-display text-4xl font-semibold tracking-tight text-balance sm:text-5xl">
              We&apos;d love to hear from you
            </h1>
            <p className="mt-5 text-muted-foreground text-balance sm:text-lg">
              Pick the channel that fits — or fill out the form and we&apos;ll route it for you.
            </p>
          </div>
        </div>
      </section>

      <section className="border-b border-border/60 bg-muted/30">
        <div className="mx-auto grid max-w-7xl gap-12 px-4 py-20 sm:px-6 lg:grid-cols-[1fr_1.4fr] lg:px-8 lg:py-28">
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-1">
            {channels.map(({ icon: Icon, title, body, cta, href }) => (
              <a
                key={title}
                href={href}
                className="flex flex-col gap-2 rounded-2xl border border-border/60 bg-background p-5 transition-colors hover:border-primary"
              >
                <span className="grid size-9 place-items-center rounded-lg bg-primary/10 text-primary">
                  <Icon className="size-5" />
                </span>
                <h3 className="mt-1 font-medium">{title}</h3>
                <p className="text-sm text-muted-foreground">{body}</p>
                <span className="mt-1 text-sm font-medium text-primary">{cta}</span>
              </a>
            ))}
          </div>

          <form
            className="flex flex-col gap-5 rounded-2xl border border-border/60 bg-background p-6 lg:p-8"
            action="/api/contact"
            method="post"
          >
            <h2 className="font-display text-2xl font-semibold tracking-tight">
              Send us a message
            </h2>

            <div className="grid gap-4 sm:grid-cols-2">
              <div className="grid gap-2">
                <Label htmlFor="firstName">First name</Label>
                <Input id="firstName" name="firstName" required autoComplete="given-name" />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="lastName">Last name</Label>
                <Input id="lastName" name="lastName" required autoComplete="family-name" />
              </div>
            </div>

            <div className="grid gap-2">
              <Label htmlFor="email">Work email</Label>
              <Input id="email" name="email" type="email" required autoComplete="email" />
            </div>

            <div className="grid gap-2">
              <Label htmlFor="company">Company</Label>
              <Input id="company" name="company" autoComplete="organization" />
            </div>

            <div className="grid gap-2">
              <Label htmlFor="topic">How can we help?</Label>
              <Input id="topic" name="topic" placeholder="Sales, support, partnership…" />
            </div>

            <div className="grid gap-2">
              <Label htmlFor="message">Message</Label>
              <Textarea id="message" name="message" rows={5} required />
            </div>

            <div className="flex flex-col items-start gap-3 sm:flex-row sm:items-center sm:justify-between">
              <p className="text-xs text-muted-foreground">
                By submitting, you agree to our privacy policy.
              </p>
              <Button type="submit">Send message</Button>
            </div>
          </form>
        </div>
      </section>
    </>
  );
}
