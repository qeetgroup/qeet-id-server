import { ArrowRightIcon } from "lucide-react";
import { ButtonLink } from "../button-link";

const providers = [
  {
    group: "Social",
    items: ["Google", "Microsoft", "Apple", "GitHub", "GitLab", "Facebook", "LinkedIn", "X"],
  },
  {
    group: "Enterprise SSO",
    items: [
      "Okta SAML",
      "Azure AD",
      "Auth0",
      "OneLogin",
      "PingIdentity",
      "JumpCloud",
      "Generic SAML",
      "Generic OIDC",
    ],
  },
  {
    group: "Directory",
    items: [
      "SCIM 2.0",
      "LDAP",
      "Active Directory",
      "Workday",
      "BambooHR",
      "Rippling",
      "Google Workspace",
      "Okta",
    ],
  },
];

export function Integrations() {
  return (
    <section className="border-b border-border/60">
      <div className="mx-auto max-w-7xl px-4 py-20 sm:px-6 lg:px-8 lg:py-28">
        <div className="grid gap-12 lg:grid-cols-[1fr_2fr]">
          <div className="flex flex-col gap-4">
            <p className="text-sm font-medium uppercase tracking-widest text-primary">
              Integrations
            </p>
            <h2 className="font-display text-3xl font-semibold tracking-tight text-balance sm:text-4xl">
              Connect to every IdP your customers ask for
            </h2>
            <p className="text-muted-foreground text-balance">
              50+ identity providers and directories supported out of the box. Add your own SAML or
              OIDC source in minutes.
            </p>
            <ButtonLink variant="outline" className="mt-2 w-fit" href="/docs#guides">
              Browse all integrations <ArrowRightIcon className="size-4" />
            </ButtonLink>
          </div>

          <div className="grid gap-6 sm:grid-cols-3">
            {providers.map((p) => (
              <div key={p.group} className="flex flex-col gap-3">
                <h3 className="text-sm font-medium">{p.group}</h3>
                <ul className="flex flex-col gap-2">
                  {p.items.map((item) => (
                    <li
                      key={item}
                      className="rounded-md border border-border/60 bg-background px-3 py-2 text-xs text-muted-foreground"
                    >
                      {item}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
