"use client";

import { cn } from "@qeetrix/ui";
import { AnimatePresence, motion, useReducedMotion } from "motion/react";
import type { ReactNode } from "react";
import { useId, useState } from "react";

import { CodeBlock, Tok } from "@/components/marketing/effects/code-block";
import { Reveal, Stagger, StaggerItem, WordReveal } from "@/components/marketing/motion";

type Lang = "TypeScript" | "Next.js" | "Go" | "Python";
const langs: Lang[] = ["TypeScript", "Next.js", "Go", "Python"];

type Step = {
  n: string;
  title: string;
  body: string;
  filename: Record<Lang, string>;
  code: Record<Lang, ReactNode>;
};

// ─── Reusable terminal prompt line ───────────────────────────────────────────
function Prompt({ pm, pkg }: { pm: string; pkg: string }) {
  return (
    <>
      <Tok.t>$</Tok.t>
      <Tok.c> {pm} </Tok.c>
      <Tok.s>{pkg}</Tok.s>
    </>
  );
}

// ─── Step 01 — Install ───────────────────────────────────────────────────────
const installCode: Record<Lang, ReactNode> = {
  TypeScript: (
    <>
      <Prompt pm="bun add" pkg="@qeet-id/react" />
      {"\n\n"}
      <Tok.c>{"✓ Resolved 1 package\n"}</Tok.c>
      <Tok.c>{"✓ Added "}</Tok.c>
      <Tok.s>@qeet-id/react</Tok.s>
      <Tok.c>@</Tok.c>
      <Tok.n>1.4.0</Tok.n>
      <Tok.c>{" in 1.2s"}</Tok.c>
    </>
  ),
  "Next.js": (
    <>
      <Prompt pm="bun add" pkg="@qeet-id/nextjs" />
      {"\n\n"}
      <Tok.c>{"✓ Resolved 1 package\n"}</Tok.c>
      <Tok.c>{"✓ Added "}</Tok.c>
      <Tok.s>@qeet-id/nextjs</Tok.s>
      <Tok.c>@</Tok.c>
      <Tok.n>1.4.0</Tok.n>
      <Tok.c>{" in 1.1s"}</Tok.c>
    </>
  ),
  Go: (
    <>
      <Prompt pm="go get" pkg="github.com/qeetgroup/qeetid-go" />
      {"\n\n"}
      <Tok.c>{"go: added "}</Tok.c>
      <Tok.s>github.com/qeetgroup/qeetid-go</Tok.s>
      <Tok.c>{" v"}</Tok.c>
      <Tok.n>1.4.0</Tok.n>
    </>
  ),
  Python: (
    <>
      <Prompt pm="pip install" pkg="qeetid" />
      {"\n\n"}
      <Tok.c>{"Successfully installed "}</Tok.c>
      <Tok.s>qeetid</Tok.s>
      <Tok.c>-</Tok.c>
      <Tok.n>1.4.0</Tok.n>
    </>
  ),
};

// ─── Step 02 — Configure ─────────────────────────────────────────────────────
const configCode: Record<Lang, ReactNode> = {
  TypeScript: (
    <>
      <Tok.k>import</Tok.k>
      {" { "}
      <Tok.f>QeetID</Tok.f>
      {" } "}
      <Tok.k>from</Tok.k> <Tok.s>{'"@qeet-id/node"'}</Tok.s>
      {";\n\n"}
      <Tok.k>const</Tok.k> <Tok.v>qg</Tok.v>
      {" = "}
      <Tok.k>new</Tok.k> <Tok.f>QeetID</Tok.f>
      {"({\n"}
      {"  "}
      <Tok.p>tenant</Tok.p>
      {": "}
      <Tok.s>{'"acme"'}</Tok.s>
      {",\n"}
      {"  "}
      <Tok.p>providers</Tok.p>
      {": ["}
      <Tok.s>{'"google"'}</Tok.s>
      {", "}
      <Tok.s>{'"passkey"'}</Tok.s>
      {", "}
      <Tok.s>{'"saml"'}</Tok.s>
      {"],\n"}
      {"});"}
    </>
  ),
  "Next.js": (
    <>
      <Tok.k>import</Tok.k>
      {" { "}
      <Tok.f>qeetID</Tok.f>
      {" } "}
      <Tok.k>from</Tok.k> <Tok.s>{'"@qeet-id/nextjs"'}</Tok.s>
      {";\n\n"}
      <Tok.k>export const</Tok.k>
      {" { "}
      <Tok.v>auth</Tok.v>
      {", "}
      <Tok.v>signIn</Tok.v>
      {", "}
      <Tok.v>signOut</Tok.v>
      {" } = "}
      <Tok.f>qeetID</Tok.f>
      {"({\n"}
      {"  "}
      <Tok.p>tenant</Tok.p>
      {": "}
      <Tok.s>{'"acme"'}</Tok.s>
      {",\n"}
      {"  "}
      <Tok.p>providers</Tok.p>
      {": ["}
      <Tok.s>{'"google"'}</Tok.s>
      {", "}
      <Tok.s>{'"passkey"'}</Tok.s>
      {", "}
      <Tok.s>{'"saml"'}</Tok.s>
      {"],\n"}
      {"});"}
    </>
  ),
  Go: (
    <>
      <Tok.v>client</Tok.v>
      {" := "}
      <Tok.f>qeetid.New</Tok.f>
      {"("}
      <Tok.t>qeetid.Config</Tok.t>
      {"{\n"}
      {"    "}
      <Tok.p>Tenant</Tok.p>
      {":    "}
      <Tok.s>{'"acme"'}</Tok.s>
      {",\n"}
      {"    "}
      <Tok.p>Providers</Tok.p>
      {": []"}
      <Tok.t>string</Tok.t>
      {"{\n"}
      {"        "}
      <Tok.s>{'"google"'}</Tok.s>
      {", "}
      <Tok.s>{'"passkey"'}</Tok.s>
      {", "}
      <Tok.s>{'"saml"'}</Tok.s>
      {",\n"}
      {"    },\n"}
      {"})"}
    </>
  ),
  Python: (
    <>
      <Tok.k>from</Tok.k> <Tok.v>qeetid</Tok.v> <Tok.k>import</Tok.k> <Tok.f>QeetID</Tok.f>
      {"\n\n"}
      <Tok.v>qg</Tok.v>
      {" = "}
      <Tok.f>QeetID</Tok.f>
      {"(\n"}
      {"    "}
      <Tok.p>tenant</Tok.p>
      {"="}
      <Tok.s>{'"acme"'}</Tok.s>
      {",\n"}
      {"    "}
      <Tok.p>providers</Tok.p>
      {"=["}
      <Tok.s>{'"google"'}</Tok.s>
      {", "}
      <Tok.s>{'"passkey"'}</Tok.s>
      {", "}
      <Tok.s>{'"saml"'}</Tok.s>
      {"],\n"}
      {")"}
    </>
  ),
};

// ─── Step 03 — Ship ───────────────────────────────────────────────────────────
const shipCode: Record<Lang, ReactNode> = {
  TypeScript: (
    <>
      <Tok.k>import</Tok.k>
      {" { "}
      <Tok.t>SignIn</Tok.t>
      {" } "}
      <Tok.k>from</Tok.k> <Tok.s>{'"@qeet-id/react"'}</Tok.s>
      {";\n\n"}
      <Tok.k>export default function</Tok.k> <Tok.f>Page</Tok.f>
      {"() {\n"}
      {"  "}
      <Tok.k>return</Tok.k>
      {" <"}
      <Tok.t>SignIn</Tok.t> <Tok.p>redirectTo</Tok.p>
      {"="}
      <Tok.s>{'"/dashboard"'}</Tok.s>
      {" />;\n}"}
    </>
  ),
  "Next.js": (
    <>
      <Tok.k>import</Tok.k>
      {" { "}
      <Tok.t>SignIn</Tok.t>
      {" } "}
      <Tok.k>from</Tok.k> <Tok.s>{'"@qeet-id/nextjs"'}</Tok.s>
      {";\n\n"}
      <Tok.k>export default function</Tok.k> <Tok.f>Page</Tok.f>
      {"() {\n"}
      {"  "}
      <Tok.k>return</Tok.k>
      {" <"}
      <Tok.t>SignIn</Tok.t> <Tok.p>redirectTo</Tok.p>
      {"="}
      <Tok.s>{'"/dashboard"'}</Tok.s>
      {" />;\n}"}
    </>
  ),
  Go: (
    <>
      <Tok.v>http</Tok.v>
      {"."}
      <Tok.f>Handle</Tok.f>
      {"("}
      <Tok.s>{'"/signin"'}</Tok.s>
      {",\n"}
      {"    "}
      <Tok.f>qeetid.SignInHandler</Tok.f>
      {"("}
      <Tok.t>qeetid.SignIn</Tok.t>
      {"{\n"}
      {"        "}
      <Tok.p>RedirectTo</Tok.p>
      {": "}
      <Tok.s>{'"/dashboard"'}</Tok.s>
      {",\n"}
      {"    }),\n"}
      {")"}
    </>
  ),
  Python: (
    <>
      <Tok.v>@app</Tok.v>
      {"."}
      <Tok.f>get</Tok.f>
      {"("}
      <Tok.s>{'"/signin"'}</Tok.s>
      {")\n"}
      <Tok.k>def</Tok.k> <Tok.f>signin</Tok.f>
      {"():\n"}
      {"    "}
      <Tok.k>return</Tok.k> <Tok.v>qg</Tok.v>
      {"."}
      <Tok.f>sign_in</Tok.f>
      {"(\n        "}
      <Tok.p>redirect_to</Tok.p>
      {"="}
      <Tok.s>{'"/dashboard"'}</Tok.s>
      {"\n    )"}
    </>
  ),
};

// ─── Steps data ───────────────────────────────────────────────────────────────
const steps: Step[] = [
  {
    n: "01",
    title: "Install the SDK",
    body: "One line in your app. TypeScript, Next.js, Go, and Python — all first-class.",
    filename: {
      TypeScript: "terminal",
      "Next.js": "terminal",
      Go: "terminal",
      Python: "terminal",
    },
    code: installCode,
  },
  {
    n: "02",
    title: "Configure providers",
    body: "Toggle SAML, OIDC, social, passwords, and passkeys from the dashboard — no deploys.",
    filename: {
      TypeScript: "qeetid.ts",
      "Next.js": "auth.ts",
      Go: "qeetid.go",
      Python: "qeetid.py",
    },
    code: configCode,
  },
  {
    n: "03",
    title: "Ship in days",
    body: "Drop-in components handle sign-in, MFA enrollment, and account recovery.",
    filename: {
      TypeScript: "app/page.tsx",
      "Next.js": "app/page.tsx",
      Go: "handler.go",
      Python: "app.py",
    },
    code: shipCode,
  },
];

// ─── Language tab bar ─────────────────────────────────────────────────────────
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
                <span aria-hidden className="absolute inset-0 -z-10 rounded-lg bg-foreground" />
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

// ─── Per-step code surface ────────────────────────────────────────────────────
function StepCode({ filename, code }: { filename: string; code: ReactNode }) {
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
          key={filename}
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

// ─── Section ──────────────────────────────────────────────────────────────────
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
          className="mt-10 grid auto-rows-fr grid-cols-1 gap-6 lg:grid-cols-3"
        >
          {steps.map((s) => (
            <StaggerItem key={s.n} className="h-full">
              <li className="relative flex h-full list-none flex-col gap-4 overflow-hidden rounded-2xl border border-border/60 bg-background p-6 transition-colors hover:border-foreground/20">
                <span
                  aria-hidden
                  className="pointer-events-none absolute -left-10 -top-10 size-32 rounded-full bg-linear-to-br from-brand/25 to-transparent opacity-50 blur-3xl"
                />
                <div className="relative flex items-center gap-3">
                  <span className="grid size-9 place-items-center rounded-lg bg-(image:--brand-gradient) font-mono text-xs font-semibold text-brand-foreground shadow-sm shadow-brand/30">
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
