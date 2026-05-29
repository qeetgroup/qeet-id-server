import { Aurora } from "@/components/marketing/effects/aurora";
import { BorderBeam } from "@/components/marketing/effects/border-beam";
import { DotPattern } from "@/components/marketing/effects/dot-pattern";
import { ButtonLink } from "@/components/marketing/button-link";
import { Avatar, AvatarFallback, AvatarImage, cn } from "@qeetid/ui";
import {
  ArrowRightIcon,
  CheckCircle2Icon,
  FingerprintIcon,
  KeyRoundIcon,
  ShieldCheckIcon,
  SparklesIcon,
  ZapIcon,
} from "lucide-react";

const trustAvatars = [
  "https://i.pravatar.cc/96?img=5",
  "https://i.pravatar.cc/96?img=12",
  "https://i.pravatar.cc/96?img=32",
  "https://i.pravatar.cc/96?img=47",
  "https://i.pravatar.cc/96?img=68",
];

function GoogleGlyph() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden className="size-4">
      <path
        fill="#EA4335"
        d="M5.27 9.76A7.08 7.08 0 0 1 16.45 6.7l3-3A11.97 11.97 0 0 0 12 .5 12 12 0 0 0 1.27 7.32l4 3.1z"
      />
      <path
        fill="#34A853"
        d="M16.04 18.01A7.4 7.4 0 0 1 12 19.1a7.08 7.08 0 0 1-6.72-4.82l-4 3.07A12 12 0 0 0 12 23.5a11.45 11.45 0 0 0 7.96-2.9l-3.92-2.6z"
      />
      <path
        fill="#4A90E2"
        d="M19.96 20.6A11.7 11.7 0 0 0 23.5 12c0-.77-.13-1.6-.32-2.36H12v4.74h6.47a5.4 5.4 0 0 1-2.43 3.63l3.92 2.6z"
      />
      <path
        fill="#FBBC05"
        d="M5.28 14.27a7.12 7.12 0 0 1 0-4.52L1.28 6.68A12 12 0 0 0 0 12c0 1.93.45 3.76 1.27 5.36l4-3.1z"
      />
    </svg>
  );
}

function AuthMockup() {
  return (
    <div className="relative w-full max-w-md sm:max-w-lg lg:max-w-xl">
      {/* Soft glow under card */}
      <div
        aria-hidden
        className="absolute -inset-x-6 -bottom-8 -top-4 -z-10 rounded-[2rem] bg-[radial-gradient(60%_60%_at_50%_50%,var(--color-primary)/0.35,transparent_70%)] opacity-50 blur-3xl"
      />

      <div className="relative overflow-hidden rounded-2xl border border-border/80 bg-card/90 shadow-2xl shadow-primary/10 backdrop-blur-xl animate-scale-in">
        <BorderBeam size={260} duration={9} />

        {/* Window chrome */}
        <div className="flex items-center justify-between border-b border-border/60 bg-muted/40 px-4 py-2.5">
          <div className="flex items-center gap-1.5">
            <span className="size-2.5 rounded-full bg-rose-400/70" />
            <span className="size-2.5 rounded-full bg-amber-400/70" />
            <span className="size-2.5 rounded-full bg-emerald-400/70" />
          </div>
          <span className="font-mono text-[11px] text-muted-foreground">auth.acme.com</span>
          <span className="text-[11px] text-emerald-500/80">● Secure</span>
        </div>

        {/* Auth body */}
        <div className="grid gap-6 p-6 sm:p-8">
          <div className="flex flex-col gap-1.5">
            <div className="flex items-center gap-2 text-xs font-medium uppercase tracking-widest text-muted-foreground">
              <span className="grid size-6 place-items-center rounded-md bg-foreground text-background">
                <ShieldCheckIcon className="size-3.5" />
              </span>
              Acme · Sign in
            </div>
            <h3 className="font-display text-xl font-semibold tracking-tight">Welcome back</h3>
            <p className="text-sm text-muted-foreground">Use a passkey, your provider, or email.</p>
          </div>

          {/* Primary action — passkey */}
          <button
            type="button"
            className="group relative flex w-full items-center justify-between rounded-lg border border-primary/30 bg-primary/10 px-3.5 py-2.5 text-sm font-medium text-foreground transition-colors hover:bg-primary/20"
            aria-label="Continue with passkey"
          >
            <span className="flex items-center gap-2.5">
              <FingerprintIcon className="size-4 text-primary" />
              Continue with passkey
            </span>
            <span className="rounded-md bg-primary/15 px-1.5 py-0.5 font-mono text-[10px] text-primary">
              ⌘ ↵
            </span>
          </button>

          {/* Provider grid */}
          <div className="grid grid-cols-3 gap-2">
            {[
              { label: "Google", icon: <GoogleGlyph /> },
              {
                label: "GitHub",
                icon: (
                  <svg viewBox="0 0 24 24" aria-hidden fill="currentColor" className="size-4">
                    <path d="M12 .5A11.5 11.5 0 0 0 .5 12a11.5 11.5 0 0 0 7.86 10.92c.58.11.79-.25.79-.55v-2c-3.2.7-3.87-1.36-3.87-1.36-.52-1.34-1.28-1.7-1.28-1.7-1.05-.72.08-.7.08-.7 1.16.08 1.78 1.2 1.78 1.2 1.03 1.77 2.7 1.26 3.36.96.1-.75.4-1.26.73-1.55-2.55-.29-5.24-1.28-5.24-5.7 0-1.26.45-2.29 1.19-3.1-.12-.3-.52-1.48.11-3.07 0 0 .97-.31 3.18 1.18a11 11 0 0 1 5.8 0c2.21-1.5 3.18-1.18 3.18-1.18.63 1.59.23 2.77.11 3.07.74.81 1.19 1.84 1.19 3.1 0 4.43-2.69 5.41-5.25 5.69.41.36.78 1.06.78 2.14v3.18c0 .3.21.67.8.55A11.5 11.5 0 0 0 23.5 12 11.5 11.5 0 0 0 12 .5z" />
                  </svg>
                ),
              },
              {
                label: "Apple",
                icon: (
                  <svg viewBox="0 0 24 24" aria-hidden fill="currentColor" className="size-4">
                    <path d="M16.37 13.05c.02 2.3 2.03 3.07 2.05 3.08-.02.05-.32 1.1-1.06 2.18-.64.94-1.3 1.87-2.34 1.89-1.02.02-1.35-.6-2.52-.6-1.17 0-1.54.58-2.51.62-1 .04-1.77-1.02-2.42-1.95-1.32-1.9-2.34-5.36-.97-7.7a3.74 3.74 0 0 1 3.16-1.92c.99-.02 1.93.67 2.55.67.61 0 1.74-.83 2.94-.71.5.02 1.92.2 2.83 1.52-.07.04-1.7.99-1.71 2.94zM14.4 6.05c.55-.66.92-1.58.82-2.5-.79.03-1.74.53-2.31 1.18-.5.58-.95 1.52-.83 2.42.88.07 1.78-.45 2.32-1.1z" />
                  </svg>
                ),
              },
            ].map((p) => (
              <button
                key={p.label}
                type="button"
                className="flex items-center justify-center gap-2 rounded-lg border border-border bg-background px-2 py-2 text-xs font-medium text-foreground/80 transition-colors hover:bg-muted"
                aria-label={`Continue with ${p.label}`}
              >
                {p.icon}
                <span className="hidden sm:inline">{p.label}</span>
              </button>
            ))}
          </div>

          <div className="flex items-center gap-3">
            <span className="h-px flex-1 bg-border" />
            <span className="text-[10px] font-medium uppercase tracking-widest text-muted-foreground">
              or email
            </span>
            <span className="h-px flex-1 bg-border" />
          </div>

          <div className="flex flex-col gap-2">
            <div className="flex h-9 items-center rounded-lg border border-border bg-background px-3 text-sm text-muted-foreground">
              you@acme.com
              <span className="ml-auto block h-4 w-px animate-pulse bg-foreground" />
            </div>
            <button
              type="button"
              className="flex items-center justify-center gap-1.5 rounded-lg bg-foreground px-3 py-2 text-sm font-medium text-background transition-opacity hover:opacity-90"
            >
              Send magic link <ArrowRightIcon className="size-3.5" />
            </button>
          </div>

          <p className="text-center text-[11px] text-muted-foreground">
            Protected by Qeet ID. <span className="underline">Why a passkey?</span>
          </p>
        </div>
      </div>

      {/* Floating chips */}
      <FloatingChip
        className="absolute -left-3 top-12 sm:-left-10 sm:top-20"
        delay={0}
        icon={<FingerprintIcon className="size-3.5 text-primary" />}
        label="Passkey"
        sub="Phishing-resistant"
      />
      <FloatingChip
        className="absolute -right-3 top-2 sm:-right-12 sm:top-6"
        delay={1.5}
        icon={<KeyRoundIcon className="size-3.5 text-violet-500" />}
        label="SAML 2.0"
        sub="Enterprise SSO"
      />
      <FloatingChip
        className="absolute -right-3 bottom-24 sm:-right-14 sm:bottom-32"
        delay={3}
        icon={<ZapIcon className="size-3.5 text-amber-500" />}
        label="< 50 ms"
        sub="p99 worldwide"
      />
      <FloatingChip
        className="absolute -bottom-3 left-6 sm:-bottom-6 sm:left-10"
        delay={2}
        icon={<CheckCircle2Icon className="size-3.5 text-emerald-500" />}
        label="SOC 2 · GDPR"
        sub="Audit-ready"
      />
    </div>
  );
}

function FloatingChip({
  className,
  icon,
  label,
  sub,
  delay = 0,
}: {
  className?: string;
  icon: React.ReactNode;
  label: string;
  sub: string;
  delay?: number;
}) {
  return (
    <div
      className={cn(
        "z-10 flex items-center gap-2 rounded-full border border-border/80 bg-background/95 px-3 py-1.5 text-xs font-medium shadow-lg shadow-black/5 backdrop-blur animate-float",
        className,
      )}
      style={{ animationDelay: `${delay}s` }}
    >
      <span className="grid size-6 place-items-center rounded-full bg-muted/70">{icon}</span>
      <span className="flex flex-col leading-tight">
        <span className="text-[11px] font-semibold">{label}</span>
        <span className="text-[10px] font-normal text-muted-foreground">{sub}</span>
      </span>
    </div>
  );
}

export function Hero() {
  return (
    <section className="relative min-h-screen flex flex-col justify-center overflow-hidden border-b border-border/60">
      <Aurora />
      <DotPattern className="[mask-image:radial-gradient(ellipse_at_top,black,transparent_75%)] opacity-20 dark:opacity-30" />

      <div className="relative mx-auto grid max-w-7xl items-center gap-16 px-4 py-20 sm:px-6 lg:grid-cols-[1.05fr_1fr] lg:gap-12 lg:px-8">
        {/* Left — copy */}
        <div className="flex flex-col items-start gap-7 text-left animate-fade-up">
          <a
            href="/changelog"
            className="group inline-flex items-center gap-2 rounded-full border border-border/80 bg-background/70 py-1 pl-1 pr-3 text-xs font-medium shadow-sm backdrop-blur transition-colors hover:bg-background"
          >
            <span className="inline-flex items-center gap-1 rounded-full bg-primary/15 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-widest text-primary">
              <SparklesIcon className="size-3" /> New
            </span>
            <span className="bg-[linear-gradient(110deg,var(--color-foreground)_45%,var(--color-muted-foreground)_55%,var(--color-foreground))] bg-[length:200%_100%] bg-clip-text text-transparent animate-shimmer">
              Passkey-first auth is now generally available
            </span>
            <ArrowRightIcon className="size-3 text-muted-foreground transition-transform group-hover:translate-x-0.5" />
          </a>

          <h1 className="font-display text-5xl font-semibold tracking-tight text-balance sm:text-6xl lg:text-7xl">
            One identity.{" "}
            <span className="bg-[linear-gradient(110deg,var(--color-primary),#7c5cff_50%,#22d3ee)] bg-clip-text text-transparent">
              Every platform.
            </span>
          </h1>

          <p className="max-w-xl text-base text-muted-foreground text-balance sm:text-lg">
            Qeet ID is the auth platform engineers wish they&apos;d had. SSO, MFA, passkeys, RBAC,
            and stateful sessions — backed by a single, audit-ready identity graph. Drop it in. Ship
            in days.
          </p>

          <div className="flex flex-col items-start gap-3 sm:flex-row sm:items-center">
            <div className="relative">
              <ButtonLink size="lg" href="/sign-up" className="h-11 px-5 text-sm">
                Start free <ArrowRightIcon className="size-4" />
              </ButtonLink>
              <div
                aria-hidden
                className="absolute -inset-1 -z-10 rounded-xl bg-primary/40 opacity-30 blur-lg"
              />
            </div>
            <ButtonLink size="lg" variant="outline" href="/docs" className="h-11 px-5 text-sm">
              Read the docs
            </ButtonLink>
          </div>

          <div className="flex items-center gap-3 pt-2">
            <div className="flex -space-x-2">
              {trustAvatars.map((src, i) => (
                <Avatar
                  // Static decorative list has no stable source id.
                  key={i}
                  className="size-7 border-2 border-background"
                >
                  <AvatarImage src={src} alt="" />
                  <AvatarFallback>·</AvatarFallback>
                </Avatar>
              ))}
            </div>
            <div className="flex flex-col text-xs text-muted-foreground">
              <span className="flex items-center gap-1 font-medium text-foreground">
                <span aria-hidden className="text-amber-500">
                  ★★★★★
                </span>{" "}
                4.9 · G2 leader
              </span>
              <span>Trusted by 4,000+ engineering teams</span>
            </div>
          </div>
        </div>

        {/* Right — auth mockup */}
        <div className="relative flex w-full items-center justify-center lg:justify-end">
          <AuthMockup />
        </div>
      </div>
    </section>
  );
}
