import { IconOidcConnector, IconSamlConnector, IconScimSync, type QeetIconProps } from "@qeetrix/ui/brand";
import { ArrowRightIcon } from "lucide-react";
import type { ComponentType } from "react";

import { ButtonLink } from "../button-link";
import { Reveal, Stagger, StaggerItem, WordReveal } from "@/components/marketing/motion";

type Group = {
  group: string;
  icon: ComponentType<QeetIconProps>;
  items: string[];
};

const providers: Group[] = [
  {
    group: "Social",
    icon: IconOidcConnector,
    items: ["Google", "Microsoft", "Apple", "GitHub", "GitLab", "Facebook", "LinkedIn", "X"],
  },
  {
    group: "Enterprise SSO",
    icon: IconSamlConnector,
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
    icon: IconScimSync,
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
          <Reveal className="flex flex-col gap-4">
            <p className="text-sm font-medium uppercase tracking-widest text-brand-text">
              Integrations
            </p>
            <h2 className="font-display text-3xl font-semibold tracking-tight text-balance sm:text-4xl">
              <WordReveal text="Connect to every IdP your customers ask for" />
            </h2>
            <p className="text-muted-foreground text-balance">
              50+ identity providers and directories supported out of the box. Add your own SAML or
              OIDC source in minutes.
            </p>
            <ButtonLink variant="outline" className="mt-2 w-fit" href="/docs#guides">
              Browse all integrations <ArrowRightIcon className="size-4" />
            </ButtonLink>
          </Reveal>

          <div className="grid gap-6 sm:grid-cols-3">
            {providers.map((p, gi) => {
              const Icon = p.icon;
              return (
                <Reveal key={p.group} delay={0.1 + gi * 0.08} className="flex flex-col gap-3">
                  <h3 className="flex items-center gap-2 text-sm font-semibold">
                    <span className="grid size-7 place-items-center rounded-lg bg-brand/10 text-brand ring-1 ring-brand/20">
                      <Icon size={15} />
                    </span>
                    {p.group}
                  </h3>
                  <Stagger staggerDelay={0.04} className="flex flex-col gap-2">
                    {p.items.map((item) => (
                      <StaggerItem key={item} distance={8}>
                        <span className="group flex items-center justify-between rounded-md border border-border/60 bg-background px-3 py-2 text-xs text-muted-foreground transition-colors hover:border-brand/40 hover:bg-brand/5 hover:text-foreground">
                          {item}
                          <ArrowRightIcon
                            aria-hidden
                            className="size-3 -translate-x-1 text-brand opacity-0 transition-all group-hover:translate-x-0 group-hover:opacity-100"
                          />
                        </span>
                      </StaggerItem>
                    ))}
                  </Stagger>
                </Reveal>
              );
            })}
          </div>
        </div>
      </div>
    </section>
  );
}
