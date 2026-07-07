import {
  Apple,
  Auth0,
  Facebook,
  Github,
  Gitlab,
  Google,
  Linkedin,
  Microsoft,
  Okta,
  Onelogin,
  PingIdentity,
  Workday,
  X,
} from "@thesvg/react";
import { IconOidcConnector, IconSamlConnector, IconScimSync, type QeetIconProps } from "@qeetrix/ui/brand";
import { ArrowRightIcon, NetworkIcon } from "lucide-react";
import type { ComponentType, SVGProps } from "react";

import { ButtonLink } from "../button-link";
import { Eyebrow } from "@/components/marketing/blocks/eyebrow";
import { Reveal, Stagger, StaggerItem, WordReveal } from "@/components/marketing/motion";

type ProviderItem = { name: string; icon: ComponentType<{ className?: string } & SVGProps<SVGSVGElement>> };

type Group = {
  group: string;
  icon: ComponentType<QeetIconProps>;
  items: ProviderItem[];
};

const providers: Group[] = [
  {
    group: "Social",
    icon: IconOidcConnector,
    items: [
      { name: "Google", icon: Google },
      { name: "Microsoft", icon: Microsoft },
      { name: "Apple", icon: Apple },
      { name: "GitHub", icon: Github },
      { name: "GitLab", icon: Gitlab },
      { name: "Facebook", icon: Facebook },
      { name: "LinkedIn", icon: Linkedin },
      { name: "X", icon: X },
    ],
  },
  {
    group: "Enterprise SSO",
    icon: IconSamlConnector,
    items: [
      { name: "Okta SAML", icon: Okta },
      { name: "Azure AD", icon: Microsoft },
      { name: "Auth0", icon: Auth0 },
      { name: "OneLogin", icon: Onelogin },
      { name: "PingIdentity", icon: PingIdentity },
      { name: "Generic SAML", icon: IconSamlConnector },
      { name: "Generic OIDC", icon: IconOidcConnector },
    ],
  },
  {
    group: "Directory",
    icon: IconScimSync,
    items: [
      { name: "SCIM 2.0", icon: IconScimSync },
      { name: "LDAP", icon: NetworkIcon },
      { name: "Active Directory", icon: Microsoft },
      { name: "Workday", icon: Workday },
      { name: "Google Workspace", icon: Google },
      { name: "Okta", icon: Okta },
    ],
  },
];

export function Integrations() {
  return (
    <section className="border-b border-border/60">
      <div className="mx-auto max-w-7xl px-4 py-20 sm:px-6 lg:px-8 lg:py-28">
        <div className="grid gap-12 lg:grid-cols-[1fr_2fr]">
          <Reveal className="flex flex-col gap-4">
            <Eyebrow className="w-fit">Integrations</Eyebrow>
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
                      <StaggerItem key={item.name} distance={8}>
                        <span className="group flex items-center justify-between rounded-md border border-border/60 bg-background px-3 py-2 text-xs text-muted-foreground transition-colors hover:border-brand/40 hover:bg-brand/5 hover:text-foreground">
                          <span className="flex min-w-0 items-center gap-2">
                            <item.icon aria-hidden className="size-4 shrink-0" />
                            <span className="truncate">{item.name}</span>
                          </span>
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
