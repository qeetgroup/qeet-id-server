import { CodeBlock, Tok } from "@/components/marketing/effects/code-block";
import type { ReactNode } from "react";

type Step = {
  n: string;
  title: string;
  body: string;
  code: ReactNode;
  filename: string;
};

const steps: Step[] = [
  {
    n: "01",
    title: "Install the SDK",
    body: "One line in your app. TypeScript, Go, Python, and Rust — all first-class.",
    filename: "terminal",
    code: (
      <>
        <span className="text-[#7ee787]">$</span> <Tok.v>pnpm</Tok.v> <Tok.f>add</Tok.f>{" "}
        <Tok.s>@qeetid/react</Tok.s>
        {"\n\n"}
        <Tok.c>✓ Resolved 1 package</Tok.c>
        {"\n"}
        <Tok.c>✓ Added @qeetid/sdk@1.4.0 in 1.2s</Tok.c>
      </>
    ),
  },
  {
    n: "02",
    title: "Configure providers",
    body: "Toggle SAML, OIDC, social, passwords, and passkeys from the dashboard — no deploys.",
    filename: "qeetid.ts",
    code: (
      <>
        <Tok.k>import</Tok.k> <Tok.punct>{`{ `}</Tok.punct>
        <Tok.t>Qeet ID</Tok.t>
        <Tok.punct>{` }`}</Tok.punct> <Tok.k>from</Tok.k> <Tok.s>{`"@qeetid/sdk"`}</Tok.s>
        <Tok.punct>;</Tok.punct>
        {"\n\n"}
        <Tok.k>const</Tok.k> <Tok.v>QG</Tok.v> <Tok.punct>=</Tok.punct> <Tok.k>new</Tok.k>{" "}
        <Tok.t>Qeet ID</Tok.t>
        <Tok.punct>{`({`}</Tok.punct>
        {"\n  "}
        <Tok.p>tenant</Tok.p>
        <Tok.punct>:</Tok.punct> <Tok.s>{`"acme"`}</Tok.s>
        <Tok.punct>,</Tok.punct>
        {"\n  "}
        <Tok.p>providers</Tok.p>
        <Tok.punct>{`: [`}</Tok.punct>
        <Tok.s>{`"google"`}</Tok.s>
        <Tok.punct>,</Tok.punct> <Tok.s>{`"passkey"`}</Tok.s>
        <Tok.punct>,</Tok.punct> <Tok.s>{`"saml"`}</Tok.s>
        <Tok.punct>{`],`}</Tok.punct>
        {"\n"}
        <Tok.punct>{`});`}</Tok.punct>
      </>
    ),
  },
  {
    n: "03",
    title: "Ship in days",
    body: "Drop-in components handle sign-in, MFA enrollment, and account recovery.",
    filename: "app/page.tsx",
    code: (
      <>
        <Tok.k>import</Tok.k> <Tok.punct>{`{ `}</Tok.punct>
        <Tok.t>SignIn</Tok.t>
        <Tok.punct>{` }`}</Tok.punct> <Tok.k>from</Tok.k> <Tok.s>{`"@qeetid/react"`}</Tok.s>
        <Tok.punct>;</Tok.punct>
        {"\n\n"}
        <Tok.k>export default function</Tok.k> <Tok.f>Page</Tok.f>
        <Tok.punct>{`() {`}</Tok.punct>
        {"\n  "}
        <Tok.k>return</Tok.k> <Tok.punct>{`(`}</Tok.punct>
        {"\n    "}
        <Tok.punct>{`<`}</Tok.punct>
        <Tok.t>SignIn</Tok.t>
        {"\n      "}
        <Tok.p>redirectTo</Tok.p>
        <Tok.punct>=</Tok.punct>
        <Tok.s>{`"/dashboard"`}</Tok.s>
        {"\n    "}
        <Tok.punct>{`/>`}</Tok.punct>
        {"\n  "}
        <Tok.punct>{`);`}</Tok.punct>
        {"\n"}
        <Tok.punct>{`}`}</Tok.punct>
      </>
    ),
  },
];

export function HowItWorks() {
  return (
    <section className="border-b border-border/60 bg-muted/30">
      <div className="mx-auto max-w-7xl px-4 py-20 sm:px-6 lg:px-8 lg:py-28">
        <div className="mx-auto max-w-2xl text-center">
          <p className="text-sm font-medium uppercase tracking-widest text-primary">How it works</p>
          <h2 className="mt-2 font-display text-3xl font-semibold tracking-tight text-balance sm:text-4xl">
            From npm install to production auth in an afternoon
          </h2>
        </div>

        <ol className="mt-14 grid auto-rows-fr gap-6 lg:grid-cols-3">
          {steps.map((s) => (
            <li
              key={s.n}
              className="relative flex h-full flex-col gap-4 rounded-2xl border border-border/60 bg-background p-6"
            >
              <div className="flex items-center gap-3">
                <span className="grid size-9 place-items-center rounded-lg bg-primary/10 font-mono text-xs font-medium text-primary">
                  {s.n}
                </span>
                <h3 className="font-display text-xl font-semibold tracking-tight">{s.title}</h3>
              </div>
              <p className="text-sm text-muted-foreground">{s.body}</p>
              <CodeBlock filename={s.filename} className="flex-1">
                {s.code}
              </CodeBlock>
            </li>
          ))}
        </ol>
      </div>
    </section>
  );
}
