import { ArrowRightIcon, BookOpenIcon, CompassIcon, PackageIcon, RocketIcon } from "lucide-react";
import type { Metadata } from "next";
import { type CodeTab, CodeTabs } from "@/components/marketing/blocks/code-tabs";
import { ButtonLink } from "@/components/marketing/button-link";

export const metadata: Metadata = {
  title: "Documentation",
  description:
    "Get started with Qeet ID. SDK quickstarts for TypeScript, Go, Python, and Rust, plus the full API reference and guides.",
};

const quickstartTabs: CodeTab[] = [
  {
    label: "TypeScript",
    language: "shell",
    caption: "terminal",
    value: `# Install the SDK
bun add @qeet-id/node

# Initialize the client
import { QeetID } from "@qeet-id/node";

const qg = new QeetID({ tenant: "acme" });
const session = await qg.signIn({ provider: "passkey" });`,
  },
  {
    label: "Go",
    language: "shell",
    caption: "terminal",
    value: `# Install the SDK
go get github.com/qeetid/qeetid-go

# Initialize the client
client := qeetid.New(qeetid.Config{Tenant: "acme"})
session, err := client.SignIn(ctx, qeetid.SignInOpts{
    Provider: qeetid.ProviderPasskey,
})`,
  },
  {
    label: "Python",
    language: "shell",
    caption: "terminal",
    value: `# Install the SDK
pip install qeetid

# Initialize the client
from qeetid import QeetID

qg = QeetID(tenant="acme")
session = qg.sign_in(provider="passkey")`,
  },
  {
    label: "Rust",
    language: "shell",
    caption: "terminal",
    value: `# Add the crate
cargo add qeetid

# Initialize the client
let qg = QeetId::new(Config { tenant: "acme".into() });
let session = qg.sign_in(SignIn::passkey()).await?;`,
  },
];

const resources = [
  {
    icon: RocketIcon,
    title: "Quickstart",
    body: "Wire up sign-in, MFA, and sessions in under ten minutes.",
    href: "#quickstart",
  },
  {
    icon: BookOpenIcon,
    title: "API reference",
    body: "Every endpoint, parameter, and response — REST and OpenAPI.",
    href: "#api-reference",
  },
  {
    icon: PackageIcon,
    title: "SDKs",
    body: "First-class TypeScript, Go, Python, and Rust clients.",
    href: "#sdks",
  },
  {
    icon: CompassIcon,
    title: "Guides",
    body: "SSO, SCIM, RBAC, audit export, and migration playbooks.",
    href: "#guides",
  },
];

export default function DocsPage() {
  return (
    <>
      <section className="border-b border-border/60">
        <div className="mx-auto max-w-7xl px-4 py-20 sm:px-6 lg:px-8 lg:py-28">
          <div className="max-w-3xl">
            <p className="text-sm font-medium uppercase tracking-widest text-primary">
              Documentation
            </p>
            <h1 className="mt-2 font-display text-4xl font-semibold tracking-tight text-balance sm:text-5xl">
              Ship auth in an afternoon
            </h1>
            <p className="mt-5 text-muted-foreground text-balance sm:text-lg">
              Pick your language, install the SDK, and drop in production-grade sign-in. Everything
              you need is one config away.
            </p>
          </div>

          <div className="mt-12 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            {resources.map(({ icon: Icon, title, body, href }) => (
              <a
                key={title}
                href={href}
                className="group flex flex-col gap-3 rounded-2xl border border-border/60 bg-card p-6 transition-colors hover:border-foreground/20"
              >
                <span className="grid size-10 place-items-center rounded-lg bg-primary/10 text-primary">
                  <Icon className="size-5" />
                </span>
                <h2 className="font-display text-lg font-semibold tracking-tight">{title}</h2>
                <p className="text-sm text-muted-foreground">{body}</p>
                <span className="mt-auto inline-flex items-center gap-1 text-sm font-medium text-primary">
                  Open{" "}
                  <ArrowRightIcon className="size-3.5 transition-transform group-hover:translate-x-0.5" />
                </span>
              </a>
            ))}
          </div>
        </div>
      </section>

      <section id="quickstart" className="scroll-mt-20 border-b border-border/60 bg-muted/30">
        <div className="mx-auto grid max-w-7xl grid-cols-1 gap-12 px-4 py-20 sm:px-6 lg:grid-cols-[1fr_1.4fr] lg:px-8 lg:py-28">
          <div className="flex flex-col gap-4">
            <p className="text-sm font-medium uppercase tracking-widest text-primary">Quickstart</p>
            <h2 className="font-display text-3xl font-semibold tracking-tight text-balance sm:text-4xl">
              Install the SDK and sign in
            </h2>
            <p className="text-muted-foreground text-balance">
              The same three steps in every language: install, initialize a client with your tenant,
              and call sign-in. Passkeys are the default.
            </p>
            <ButtonLink variant="outline" className="mt-2 w-fit" href="#sdks">
              See all SDKs <ArrowRightIcon className="size-4" />
            </ButtonLink>
          </div>
          <CodeTabs tabs={quickstartTabs} />
        </div>
      </section>

      <section id="api-reference" className="scroll-mt-20 border-b border-border/60">
        <div className="mx-auto max-w-7xl px-4 py-20 sm:px-6 lg:px-8 lg:py-28">
          <div className="max-w-2xl">
            <p className="text-sm font-medium uppercase tracking-widest text-primary">
              API reference
            </p>
            <h2 className="mt-2 font-display text-3xl font-semibold tracking-tight text-balance sm:text-4xl">
              A REST API you can hold in your head
            </h2>
            <p className="mt-4 text-muted-foreground text-balance">
              Predictable resource-oriented URLs, JSON request and response bodies, and standard
              HTTP status codes. The full OpenAPI spec drives our SDKs and your generated clients.
            </p>
          </div>
          <div id="sdks" className="mt-12 scroll-mt-20 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            {["TypeScript", "Go", "Python", "Rust"].map((lang) => (
              <div
                key={lang}
                className="flex items-center justify-between rounded-xl border border-border/60 bg-card px-5 py-4"
              >
                <span className="font-medium">{lang}</span>
                <span className="font-mono text-xs text-muted-foreground">v1.x</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section id="guides" className="scroll-mt-20 border-b border-border/60 bg-muted/30">
        <div className="mx-auto max-w-7xl px-4 py-20 sm:px-6 lg:px-8 lg:py-28">
          <div className="max-w-2xl">
            <p className="text-sm font-medium uppercase tracking-widest text-primary">Guides</p>
            <h2 className="mt-2 font-display text-3xl font-semibold tracking-tight text-balance sm:text-4xl">
              Go deeper
            </h2>
          </div>
          <div className="mt-12 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {[
              "Configure SAML 2.0 SSO",
              "SCIM provisioning end to end",
              "Model roles with RBAC & ABAC",
              "Stream audit logs to your SIEM",
              "Migrate from Auth0 or Clerk",
              "Per-tenant branding & domains",
            ].map((g) => (
              <div
                key={g}
                className="flex items-center gap-3 rounded-xl border border-border/60 bg-background px-5 py-4 text-sm"
              >
                <CompassIcon aria-hidden className="size-4 shrink-0 text-primary" />
                <span>{g}</span>
              </div>
            ))}
          </div>
        </div>
      </section>
    </>
  );
}
