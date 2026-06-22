import { cn } from "@qeetrix/ui";
import {
  Apple,
  Atlassian,
  Auth0,
  Bitbucket,
  Box,
  Coinbase,
  Discord,
  Dropbox,
  Facebook,
  Figma,
  Github,
  Gitlab,
  Google,
  Kakao,
  Line,
  Linkedin,
  Microsoft,
  Naver,
  Notion,
  Okta,
  Reddit,
  Salesforce,
  Slack,
  Spotify,
  Twitch,
  X,
  Zoom,
} from "@thesvg/react";

// Provider → brand-logo map for the hosted login's social buttons. Mirrors the
// catalog in the admin app's auth/social.tsx (kept as a focused copy rather than
// a shared package to keep this change small; extract to @qeetid/providers if it
// drifts). iconClass handles dark-mode legibility (black-only marks invert in
// dark, white-only marks invert in light); `fill` is set only for marks that
// ship without a baked color.
type IconDef = { Icon: typeof Google; iconClass?: string; fill?: string };

const ICONS: Record<string, IconDef> = {
  google: { Icon: Google },
  github: { Icon: Github, iconClass: "dark:invert" },
  microsoft: { Icon: Microsoft },
  apple: { Icon: Apple, iconClass: "invert dark:invert-0" },
  facebook: { Icon: Facebook, iconClass: "text-[#1877F2]", fill: "currentColor" },
  x: { Icon: X, iconClass: "dark:invert" },
  linkedin: { Icon: Linkedin },
  gitlab: { Icon: Gitlab },
  bitbucket: { Icon: Bitbucket },
  discord: { Icon: Discord },
  slack: { Icon: Slack },
  twitch: { Icon: Twitch },
  spotify: { Icon: Spotify },
  reddit: { Icon: Reddit },
  atlassian: { Icon: Atlassian },
  salesforce: { Icon: Salesforce },
  okta: { Icon: Okta },
  auth0: { Icon: Auth0 },
  notion: { Icon: Notion, iconClass: "invert dark:invert-0" },
  figma: { Icon: Figma },
  zoom: { Icon: Zoom },
  box: { Icon: Box },
  dropbox: { Icon: Dropbox },
  line: { Icon: Line },
  kakao: { Icon: Kakao },
  naver: { Icon: Naver },
  coinbase: { Icon: Coinbase },
};

/** A provider's brand logo, or a neutral letter chip for unknown providers. */
export function ProviderIcon({ provider, className }: { provider: string; className?: string }) {
  const def = ICONS[provider];
  if (!def) {
    return (
      <span
        aria-hidden
        className={cn(
          "bg-muted inline-flex size-5 items-center justify-center rounded-sm text-[11px] font-semibold",
          className,
        )}
      >
        {(provider[0] ?? "?").toUpperCase()}
      </span>
    );
  }
  const { Icon, iconClass, fill } = def;
  return <Icon className={cn("size-5", iconClass, className)} {...(fill ? { fill } : {})} />;
}
