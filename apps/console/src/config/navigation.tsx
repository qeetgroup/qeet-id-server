import {
  ActivityIcon,
  BadgeCheckIcon,
  BlocksIcon,
  BotIcon,
  Building2Icon,
  ChartColumnIcon,
  CreditCardIcon,
  FingerprintIcon,
  FlaskConicalIcon,
  GaugeIcon,
  KeyRoundIcon,
  LayoutDashboardIcon,
  LockKeyholeIcon,
  LogInIcon,
  MonitorSmartphoneIcon,
  PaletteIcon,
  ScrollTextIcon,
  ServerCogIcon,
  Settings2Icon,
  ShieldAlertIcon,
  ShieldCheckIcon,
  SparklesIcon,
  UsersIcon,
  UsersRoundIcon,
  WebhookIcon,
  WorkflowIcon,
  ZapIcon,
} from "lucide-react";
import type { ReactNode } from "react";

import type { Capability } from "@/features/access-control/capability-model";

export type NavSubItem = {
  title: string;
  url: string;
  requiredPermission?: Capability;
};

export type NavItem = {
  title: string;
  url: string;
  icon?: ReactNode;
  requiredPermission?: Capability;
  items?: NavSubItem[];
};

export type NavGroup = {
  label: string;
  items: NavItem[];
};

export const navGroups: NavGroup[] = [
  {
    label: "Workspace",
    items: [
      {
        title: "Overview",
        url: "/",
        icon: <LayoutDashboardIcon />,
      },
      {
        title: "Activity",
        url: "/activity",
        icon: <ActivityIcon />,
        requiredPermission: "audit.read",
      },
      {
        title: "Analytics",
        url: "/analytics",
        icon: <ChartColumnIcon />,
        requiredPermission: "analytics.read",
      },
    ],
  },
  {
    label: "Directory",
    items: [
      {
        title: "Users",
        url: "/users",
        icon: <UsersIcon />,
        requiredPermission: "user.read",
        items: [
          { title: "All Users", url: "/users", requiredPermission: "user.read" },
          { title: "Invitations", url: "/invitations", requiredPermission: "user.read" },
          { title: "Sessions", url: "/users/sessions", requiredPermission: "user.read" },
          { title: "Deleted", url: "/users/deleted", requiredPermission: "user.read" },
        ],
      },
      {
        title: "Organizations",
        url: "/organizations/tenants",
        icon: <Building2Icon />,
        items: [
          { title: "Tenants", url: "/organizations/tenants" },
          { title: "Members", url: "/organizations/members", requiredPermission: "user.read" },
          { title: "Domains", url: "/organizations/domains", requiredPermission: "tenant.read" },
        ],
      },
      {
        title: "Groups",
        url: "/groups",
        icon: <UsersRoundIcon />,
        requiredPermission: "group.read",
      },
    ],
  },
  {
    label: "Authentication",
    items: [
      {
        title: "Login methods",
        url: "/auth/login-methods/password",
        icon: <LogInIcon />,
        requiredPermission: "policy.read",
        items: [
          {
            title: "Password",
            url: "/auth/login-methods/password",
            requiredPermission: "policy.read",
          },
          {
            title: "Passwordless",
            url: "/auth/login-methods/passwordless",
            requiredPermission: "policy.read",
          },
          { title: "Passkeys", url: "/auth/login-methods/passkeys" },
          {
            title: "Magic links",
            url: "/auth/login-methods/magic-links",
            requiredPermission: "policy.read",
          },
        ],
      },
      {
        title: "Connections",
        url: "/auth/connections",
        icon: <WorkflowIcon />,
        requiredPermission: "connection.read",
        items: [
          { title: "Catalogue", url: "/auth/connections", requiredPermission: "connection.read" },
          { title: "Social providers", url: "/auth/social", requiredPermission: "connection.read" },
          {
            title: "SAML 2.0",
            url: "/auth/connections/saml",
            requiredPermission: "connection.read",
          },
          {
            title: "SAML IdP",
            url: "/auth/connections/saml-idp",
            requiredPermission: "connection.read",
          },
          {
            title: "OIDC / OAuth 2.0",
            url: "/auth/connections/oidc",
            requiredPermission: "connection.read",
          },
          {
            title: "SCIM provisioning",
            url: "/auth/connections/scim",
            requiredPermission: "connection.read",
          },
          {
            title: "LDAP / AD",
            url: "/auth/connections/ldap",
            requiredPermission: "connection.read",
          },
        ],
      },
      {
        title: "Multi-factor auth",
        url: "/auth/mfa/totp",
        icon: <FingerprintIcon />,
        items: [
          { title: "TOTP", url: "/auth/mfa/totp" },
          { title: "SMS / email", url: "/auth/mfa/sms-email" },
          { title: "Recovery codes", url: "/auth/mfa/recovery-codes" },
        ],
      },
      {
        title: "API access",
        url: "/auth/api/keys",
        icon: <KeyRoundIcon />,
        requiredPermission: "apikey.read",
        items: [
          { title: "API keys", url: "/auth/api/keys", requiredPermission: "apikey.read" },
          {
            title: "Machine identities",
            url: "/auth/api/machine-identities",
            requiredPermission: "apikey.read",
          },
          {
            title: "Access tokens",
            url: "/auth/api/tokens",
            requiredPermission: "connection.read",
          },
          {
            title: "Consent grants",
            url: "/auth/api/consent-grants",
            requiredPermission: "connection.read",
          },
          {
            title: "Signing keys",
            url: "/auth/api/signing-keys",
            requiredPermission: "connection.read",
          },
          { title: "Secrets", url: "/auth/api/secrets", requiredPermission: "secret.read" },
        ],
      },
    ],
  },
  {
    label: "Authorization",
    items: [
      {
        title: "Overview",
        url: "/authorization",
        icon: <GaugeIcon />,
        requiredPermission: "role.read",
      },
      {
        title: "Access model",
        url: "/authorization/roles",
        icon: <ShieldCheckIcon />,
        requiredPermission: "role.read",
        items: [
          { title: "Roles", url: "/authorization/roles", requiredPermission: "role.read" },
          {
            title: "Permissions",
            url: "/authorization/permissions",
            requiredPermission: "role.read",
          },
          { title: "Resources", url: "/authorization/resources", requiredPermission: "role.read" },
          { title: "RBAC", url: "/authorization/rbac", requiredPermission: "role.read" },
          { title: "ABAC", url: "/authorization/abac", requiredPermission: "policy.read" },
          { title: "ReBAC", url: "/authorization/rebac", requiredPermission: "role.read" },
        ],
      },
      {
        title: "Policy lifecycle",
        url: "/authorization/builder",
        icon: <BlocksIcon />,
        requiredPermission: "policy.read",
        items: [
          {
            title: "Policy builder",
            url: "/authorization/builder",
            requiredPermission: "policy.read",
          },
          {
            title: "Templates",
            url: "/authorization/templates",
            requiredPermission: "policy.read",
          },
          {
            title: "Version history",
            url: "/authorization/versions",
            requiredPermission: "policy.read",
          },
        ],
      },
      {
        title: "Decision tools",
        url: "/authorization/simulator",
        icon: <FlaskConicalIcon />,
        requiredPermission: "role.read",
        items: [
          {
            title: "Policy simulator",
            url: "/authorization/simulator",
            requiredPermission: "role.read",
          },
          {
            title: "Decision explorer",
            url: "/authorization/explorer",
            requiredPermission: "role.read",
          },
          {
            title: "Access tester",
            url: "/authorization/access-tester",
            requiredPermission: "role.read",
          },
        ],
      },
      {
        title: "Audit",
        url: "/authorization/audit",
        icon: <ScrollTextIcon />,
        requiredPermission: "audit.read",
      },
      {
        title: "AI assistant",
        url: "/authorization/assistant",
        icon: <SparklesIcon />,
        requiredPermission: "policy.read",
      },
      {
        title: "Settings",
        url: "/authorization/settings",
        icon: <Settings2Icon />,
        requiredPermission: "role.read",
      },
    ],
  },
  {
    label: "Security",
    items: [
      { title: "Overview", url: "/security", icon: <ShieldCheckIcon /> },
      {
        title: "Threat protection",
        url: "/security/threats/bots",
        icon: <ShieldAlertIcon />,
        requiredPermission: "policy.read",
        items: [
          {
            title: "Bot detection",
            url: "/security/threats/bots",
            requiredPermission: "policy.read",
          },
          {
            title: "Anomalies",
            url: "/security/threats/anomalies",
            requiredPermission: "audit.read",
          },
          {
            title: "Risk settings",
            url: "/security/threats/risk-settings",
            requiredPermission: "policy.read",
          },
          {
            title: "Threat rate limits",
            url: "/security/threats/rate-limits",
            requiredPermission: "policy.read",
          },
          {
            title: "IP allowlist",
            url: "/security/threats/ip-allowlist",
            requiredPermission: "policy.read",
          },
        ],
      },
      {
        title: "Sessions & devices",
        url: "/security/sessions",
        icon: <MonitorSmartphoneIcon />,
        requiredPermission: "user.read",
        items: [
          { title: "Sessions", url: "/security/sessions", requiredPermission: "user.read" },
          {
            title: "Device authorizations",
            url: "/security/device-authorizations",
            requiredPermission: "connection.read",
          },
        ],
      },
      {
        title: "Rate limit policies",
        url: "/security/rate-limits",
        icon: <GaugeIcon />,
        requiredPermission: "policy.read",
      },
      {
        title: "Monitoring",
        url: "/security/audit-logs",
        icon: <ScrollTextIcon />,
        requiredPermission: "audit.read",
        items: [
          { title: "Audit logs", url: "/security/audit-logs", requiredPermission: "audit.read" },
          {
            title: "Audit intelligence",
            url: "/security/audit-intelligence",
            requiredPermission: "audit.read",
          },
          {
            title: "Log streaming",
            url: "/security/log-streaming",
            requiredPermission: "audit.read",
          },
        ],
      },
      {
        title: "Compliance",
        url: "/security/compliance/soc2",
        icon: <LockKeyholeIcon />,
        requiredPermission: "audit.read",
        items: [
          { title: "SOC 2", url: "/security/compliance/soc2", requiredPermission: "audit.read" },
          { title: "GDPR", url: "/security/compliance/gdpr", requiredPermission: "gdpr.write" },
          {
            title: "ISO 27001",
            url: "/security/compliance/iso27001",
            requiredPermission: "audit.read",
          },
          {
            title: "Data retention",
            url: "/security/compliance/retention",
            requiredPermission: "policy.read",
          },
        ],
      },
    ],
  },
  {
    label: "Developer",
    items: [
      {
        title: "Webhooks",
        url: "/developer/webhooks",
        icon: <WebhookIcon />,
        requiredPermission: "webhook.read",
      },
      {
        title: "Auth hooks",
        url: "/developer/auth-hooks",
        icon: <ZapIcon />,
        requiredPermission: "connection.read",
      },
      {
        title: "Agent governance",
        url: "/developer/agents",
        icon: <SparklesIcon />,
        requiredPermission: "apikey.read",
      },
      {
        title: "Verifiable credentials",
        url: "/developer/credentials",
        icon: <BadgeCheckIcon />,
        requiredPermission: "apikey.read",
      },
      {
        title: "Bots & automations",
        url: "/developer/bots",
        icon: <BotIcon />,
      },
      {
        title: "Infrastructure",
        url: "/developer/infrastructure",
        icon: <ServerCogIcon />,
        requiredPermission: "audit.read",
      },
    ],
  },
  {
    label: "Administration",
    items: [
      {
        title: "Workspace",
        url: "/settings/workspace/general",
        icon: <Settings2Icon />,
        requiredPermission: "tenant.read",
        items: [
          {
            title: "General",
            url: "/settings/workspace/general",
            requiredPermission: "tenant.read",
          },
          {
            title: "Security policy",
            url: "/settings/workspace/security-policy",
            requiredPermission: "policy.read",
          },
          {
            title: "Domains",
            url: "/settings/workspace/domains",
            requiredPermission: "tenant.read",
          },
          {
            title: "Email templates",
            url: "/settings/workspace/email-templates",
            requiredPermission: "branding.write",
          },
        ],
      },
      {
        title: "Branding",
        url: "/settings/branding",
        icon: <PaletteIcon />,
        requiredPermission: "branding.write",
      },
      {
        title: "Billing & plan",
        url: "/settings/billing",
        icon: <CreditCardIcon />,
        requiredPermission: "billing.read",
      },
    ],
  },
];

export type NavTitleLookup = {
  group?: string;
  parent?: { title: string; url: string };
  title: string;
};

const ROUTE_REQUIREMENT_OVERRIDES: ReadonlyArray<{
  path: string;
  requiredPermission: Capability;
}> = [{ path: "/users/import", requiredPermission: "user.write" }];

const SAFE_DESTINATIONS = new Set(["/", "/organizations/tenants"]);

function normalizePathname(pathname: string): string {
  const path = pathname.split(/[?#]/, 1)[0] || "/";
  if (path === "/") return path;
  return path.replace(/\/+$/, "") || "/";
}

function pathMatchesBranch(pathname: string, destination: string): boolean {
  return (
    pathname === destination || (destination !== "/" && pathname.startsWith(`${destination}/`))
  );
}

function destinations(): Array<NavItem | NavSubItem> {
  return navGroups.flatMap((group) => group.items.flatMap((item) => [item, ...(item.items ?? [])]));
}

export function getRequiredCapabilityForPath(pathname: string): Capability | undefined {
  const normalized = normalizePathname(pathname);
  const override = ROUTE_REQUIREMENT_OVERRIDES.find((entry) => entry.path === normalized);
  if (override) return override.requiredPermission;

  return destinations()
    .filter((item) => pathMatchesBranch(normalized, item.url))
    .sort((a, b) => b.url.length - a.url.length)[0]?.requiredPermission;
}

export function filterNavigation(
  groups: NavGroup[],
  can: (permission?: Capability) => boolean,
): NavGroup[] {
  return groups.flatMap((group) => {
    const items = group.items.flatMap((item) => {
      const visibleChildren = item.items?.filter((child) => can(child.requiredPermission));
      const ownRouteVisible = can(item.requiredPermission);
      if (!ownRouteVisible && (!visibleChildren || visibleChildren.length === 0)) return [];
      return [{ ...item, items: visibleChildren }];
    });
    return items.length > 0 ? [{ ...group, items }] : [];
  });
}

export function safeNavigation(groups: NavGroup[]): NavGroup[] {
  return groups.flatMap((group) => {
    const items = group.items.flatMap((item) => {
      const visibleChildren = item.items?.filter((child) => SAFE_DESTINATIONS.has(child.url));
      const ownRouteVisible = SAFE_DESTINATIONS.has(item.url);
      if (!ownRouteVisible && (!visibleChildren || visibleChildren.length === 0)) return [];
      return [{ ...item, items: visibleChildren }];
    });
    return items.length > 0 ? [{ ...group, items }] : [];
  });
}

function titleFromSlug(slug: string) {
  return slug
    .split("-")
    .map((p) => p.charAt(0).toUpperCase() + p.slice(1))
    .join(" ");
}

export function lookupNavTitle(pathname: string): NavTitleLookup {
  for (const group of navGroups) {
    for (const item of group.items) {
      if (item.url === pathname) {
        return { group: group.label, title: item.title };
      }
      const sub = item.items?.find((s) => s.url === pathname);
      if (sub) {
        return {
          group: group.label,
          parent: { title: item.title, url: item.url },
          title: sub.title,
        };
      }
    }
  }
  const segments = pathname.split("/").filter(Boolean);
  return { title: titleFromSlug(segments[segments.length - 1] ?? "Page") };
}
