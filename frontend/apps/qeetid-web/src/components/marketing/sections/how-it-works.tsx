"use client";

import { cn } from "@qeetrix/ui";
import { AnimatePresence, motion, useReducedMotion } from "motion/react";
import { useId, useState } from "react";

import { CodeBlock } from "@/components/marketing/effects/code-block";
import { Reveal, Stagger, StaggerItem, WordReveal } from "@/components/marketing/motion";

type Lang = "TypeScript" | "Go" | "Python" | "Rust";
const langs: Lang[] = ["TypeScript", "Go", "Python", "Rust"];

type Step = {
  n: string;
  title: string;
  body: string;
  filename: Record<Lang, string>;
  code: Record<Lang, string>;
};

const steps: Step[] = [
  {
    n: "01",
    title: "Install the SDK",
    body: "One line in your app. TypeScript, Go, Python, and Rust — all first-class.",
    filename: {
      TypeScript: "terminal",
      Go: "terminal",
      Python: "terminal",
      Rust: "terminal",
    },
    code: {
      TypeScript: "$ pnpm add @qeetid/react\n\n✓ Resolved 1 package\n✓ Added @qeetid/sdk@1.4.0 in 1.2s",
      Go: "$ go get github.com/qeetid/qeetid-go\n\ngo: added github.com/qeetid/qeetid-go v1.4.0",
      Python: "$ pip install qeetid\n\nSuccessfully installed qeetid-1.4.0",
      Rust: "$ cargo add qeetid\n\n      Adding qeetid v1.4.0 to dependencies",
    },
  },
  {
    n: "02",
    title: "Configure providers",
    body: "Toggle SAML, OIDC, social, passwords, and passkeys from the dashboard — no deploys.",
    filename: {
      TypeScript: "qeetid.ts",
      Go: "qeetid.go",
      Python: "qeetid.py",
      Rust: "main.rs",
    },
    code: {
      TypeScript:
        'import { QeetID } from "@qeetid/sdk";\n\nconst qg = new QeetID({\n  tenant: "acme",\n  providers: ["google", "passkey", "saml"],\n});',
      Go: 'client := qeetid.New(qeetid.Config{\n  Tenant:    "acme",\n  Providers: []string{"google", "passkey", "saml"},\n})',
      Python:
        'from qeetid import QeetID\n\nqg = QeetID(\n  tenant="acme",\n  providers=["google", "passkey", "saml"],\n)',
      Rust: 'let qg = QeetId::new(Config {\n  tenant: "acme".into(),\n  providers: vec!["google", "passkey", "saml"],\n});',
    },
  },
  {
    n: "03",
    title: "Ship in days",
    body: "Drop-in components handle sign-in, MFA enrollment, and account recovery.",
    filename: {
      TypeScript: "app/page.tsx",
      Go: "handler.go",
      Python: "app.py",
      Rust: "routes.rs",
    },
    code: {
      TypeScript:
        'import { SignIn } from "@qeetid/react";\n\nexport default function Page() {\n  return <SignIn redirectTo="/dashboard" />;\n}',
      Go: 'http.Handle("/signin", qeetid.SignInHandler(\n  qeetid.SignIn{RedirectTo: "/dashboard"},\n))',
      Python:
        '@app.get("/signin")\ndef signin():\n    return qg.sign_in(redirect_to="/dashboard")',
      Rust: 'async fn signin(qg: QeetId) -> impl IntoResponse {\n  qg.sign_in(SignIn::redirect("/dashboard")).await\n}',
    },
  },
];

/** Animated language tab bar — sliding brand indicator via shared `layoutId`. */
function LangTabs({
  lang,
  onChange,
  tablistId,
}: {
  lang: Lang;
  onChange: (l: Lang) => void;
  tablistId: string;
}) {
  const reduce = useReducedMotion();
  return (
    <div
      role="tablist"
      aria-label="SDK language"
      id={tablistId}
      className="inline-flex flex-wrap justify-center gap-1 rounded-xl border border-border/60 bg-background/60 p-1 backdrop-blur"
    >
      {langs.map((l) => {
        const selected = l === lang;
        return (
          <button
            key={l}
            type="button"
            role="tab"
            aria-selected={selected}
            onClick={() => onChange(l)}
            className={cn(
              "relative rounded-lg px-3.5 py-1.5 text-sm font-medium transition-colors focus-ring-brand",
              selected ? "text-background" : "text-muted-foreground hover:text-foreground",
            )}
          >
            {selected &&
              (reduce ? (
                <span
                  aria-hidden
                  className="absolute inset-0 -z-10 rounded-lg bg-foreground"
                />
              ) : (
                <motion.span
                  aria-hidden
                  layoutId={`${tablistId}-indicator`}
                  className="absolute inset-0 -z-10 rounded-lg bg-foreground"
                  transition={{ type: "spring", stiffness: 380, damping: 32 }}
                />
              ))}
            <span className="relative">{l}</span>
          </button>
        );
      })}
    </div>
  );
}

/** Code surface that re-reveals when the active language changes. */
function StepCode({ filename, code }: { filename: string; code: string }) {
  const reduce = useReducedMotion();
  if (reduce) {
    return (
      <CodeBlock filename={filename} className="flex-1">
        {code}
      </CodeBlock>
    );
  }
  return (
    <div className="relative flex-1">
      <AnimatePresence mode="wait" initial={false}>
        <motion.div
          key={code}
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -8 }}
          transition={{ duration: 0.28, ease: [0.16, 1, 0.3, 1] }}
          className="h-full"
        >
          <CodeBlock filename={filename} className="h-full">
            {code}
          </CodeBlock>
        </motion.div>
      </AnimatePresence>
    </div>
  );
}

export function HowItWorks() {
  const [lang, setLang] = useState<Lang>("TypeScript");
  const tablistId = useId();

  return (
    <section className="border-b border-border/60 bg-muted/30">
      <div className="mx-auto max-w-7xl px-4 py-20 sm:px-6 lg:px-8 lg:py-28">
        <Reveal className="mx-auto max-w-2xl text-center">
          <p className="text-sm font-medium uppercase tracking-widest text-brand-text">
            How it works
          </p>
          <h2 className="mt-2 font-display text-3xl font-semibold tracking-tight text-balance sm:text-4xl">
            <WordReveal text="From npm install to production auth in an afternoon" />
          </h2>
        </Reveal>

        <Reveal delay={0.1} className="mt-10 flex justify-center">
          <LangTabs lang={lang} onChange={setLang} tablistId={tablistId} />
        </Reveal>

        <Stagger
          staggerDelay={0.1}
          className="mt-10 grid auto-rows-fr gap-6 lg:grid-cols-3"
        >
          {steps.map((s) => (
            <StaggerItem key={s.n} className="h-full">
              <li className="relative flex h-full list-none flex-col gap-4 overflow-hidden rounded-2xl border border-border/60 bg-background p-6 transition-colors hover:border-foreground/20">
                <span
                  aria-hidden
                  className="pointer-events-none absolute -left-10 -top-10 size-32 rounded-full bg-linear-to-br from-brand/25 to-transparent opacity-50 blur-3xl"
                />
                <div className="relative flex items-center gap-3">
                  <span className="grid size-9 place-items-center rounded-lg bg-[image:var(--brand-gradient)] font-mono text-xs font-semibold text-brand-foreground shadow-sm shadow-brand/30">
                    {s.n}
                  </span>
                  <h3 className="font-display text-xl font-semibold tracking-tight">{s.title}</h3>
                </div>
                <p className="relative text-sm text-muted-foreground">{s.body}</p>
                <StepCode filename={s.filename[lang]} code={s.code[lang]} />
              </li>
            </StaggerItem>
          ))}
        </Stagger>
      </div>
    </section>
  );
}
