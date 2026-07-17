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

export type NavItem = {
  title: string;
  url: string;
  icon?: ReactNode;
  items?: { title: string; url: string }[];
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
      { title: "Activity", url: "/activity", icon: <ActivityIcon /> },
      { title: "Analytics", url: "/analytics", icon: <ChartColumnIcon /> },
    ],
  },
  {
    label: "Directory",
    items: [
      {
        title: "Users",
        url: "/users",
        icon: <UsersIcon />,
        items: [
          { title: "All Users", url: "/users" },
          { title: "Invitations", url: "/invitations" },
          { title: "Sessions", url: "/users/sessions" },
          { title: "Deleted", url: "/users/deleted" },
        ],
      },
      {
        title: "Organizations",
        url: "/organizations/tenants",
        icon: <Building2Icon />,
        items: [
          { title: "Tenants", url: "/organizations/tenants" },
          { title: "Members", url: "/organizations/members" },
          { title: "Domains", url: "/organizations/domains" },
        ],
      },
      { title: "Groups", url: "/groups", icon: <UsersRoundIcon /> },
    ],
  },
  {
    label: "Authentication",
    items: [
      {
        title: "Login methods",
        url: "/auth/login-methods/password",
        icon: <LogInIcon />,
        items: [
          { title: "Password", url: "/auth/login-methods/password" },
          { title: "Passwordless", url: "/auth/login-methods/passwordless" },
          { title: "Passkeys", url: "/auth/login-methods/passkeys" },
          { title: "Magic links", url: "/auth/login-methods/magic-links" },
        ],
      },
      {
        title: "Connections",
        url: "/auth/connections",
        icon: <WorkflowIcon />,
        items: [
          { title: "Catalogue", url: "/auth/connections" },
          { title: "Social providers", url: "/auth/social" },
          { title: "SAML 2.0", url: "/auth/connections/saml" },
          { title: "SAML IdP", url: "/auth/connections/saml-idp" },
          { title: "OIDC / OAuth 2.0", url: "/auth/connections/oidc" },
          { title: "SCIM provisioning", url: "/auth/connections/scim" },
          { title: "LDAP / AD", url: "/auth/connections/ldap" },
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
        items: [
          { title: "API keys", url: "/auth/api/keys" },
          { title: "Machine identities", url: "/auth/api/machine-identities" },
          { title: "Access tokens", url: "/auth/api/tokens" },
          { title: "Consent grants", url: "/auth/api/consent-grants" },
          { title: "Signing keys", url: "/auth/api/signing-keys" },
          { title: "Secrets", url: "/auth/api/secrets" },
        ],
      },
    ],
  },
  {
    label: "Authorization",
    items: [
      { title: "Overview", url: "/authorization", icon: <GaugeIcon /> },
      {
        title: "Access model",
        url: "/authorization/roles",
        icon: <ShieldCheckIcon />,
        items: [
          { title: "Roles", url: "/authorization/roles" },
          { title: "Permissions", url: "/authorization/permissions" },
          { title: "Resources", url: "/authorization/resources" },
          { title: "RBAC", url: "/authorization/rbac" },
          { title: "ABAC", url: "/authorization/abac" },
          { title: "ReBAC", url: "/authorization/rebac" },
        ],
      },
      {
        title: "Policy lifecycle",
        url: "/authorization/builder",
        icon: <BlocksIcon />,
        items: [
          { title: "Policy builder", url: "/authorization/builder" },
          { title: "Templates", url: "/authorization/templates" },
          { title: "Version history", url: "/authorization/versions" },
        ],
      },
      {
        title: "Decision tools",
        url: "/authorization/simulator",
        icon: <FlaskConicalIcon />,
        items: [
          { title: "Policy simulator", url: "/authorization/simulator" },
          { title: "Decision explorer", url: "/authorization/explorer" },
          { title: "Access tester", url: "/authorization/access-tester" },
        ],
      },
      { title: "Audit", url: "/authorization/audit", icon: <ScrollTextIcon /> },
      { title: "AI assistant", url: "/authorization/assistant", icon: <SparklesIcon /> },
      { title: "Settings", url: "/authorization/settings", icon: <Settings2Icon /> },
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
        items: [
          { title: "Bot detection", url: "/security/threats/bots" },
          { title: "Anomalies", url: "/security/threats/anomalies" },
          { title: "Risk settings", url: "/security/threats/risk-settings" },
          { title: "Threat rate limits", url: "/security/threats/rate-limits" },
          { title: "IP allowlist", url: "/security/threats/ip-allowlist" },
        ],
      },
      {
        title: "Sessions & devices",
        url: "/security/sessions",
        icon: <MonitorSmartphoneIcon />,
        items: [
          { title: "Sessions", url: "/security/sessions" },
          { title: "Device authorizations", url: "/security/device-authorizations" },
        ],
      },
      {
        title: "Rate limit policies",
        url: "/security/rate-limits",
        icon: <GaugeIcon />,
      },
      {
        title: "Monitoring",
        url: "/security/audit-logs",
        icon: <ScrollTextIcon />,
        items: [
          { title: "Audit logs", url: "/security/audit-logs" },
          { title: "Audit intelligence", url: "/security/audit-intelligence" },
          { title: "Log streaming", url: "/security/log-streaming" },
        ],
      },
      {
        title: "Compliance",
        url: "/security/compliance/soc2",
        icon: <LockKeyholeIcon />,
        items: [
          { title: "SOC 2", url: "/security/compliance/soc2" },
          { title: "GDPR", url: "/security/compliance/gdpr" },
          { title: "ISO 27001", url: "/security/compliance/iso27001" },
          { title: "Data retention", url: "/security/compliance/retention" },
        ],
      },
    ],
  },
  {
    label: "Developer",
    items: [
      { title: "Webhooks", url: "/developer/webhooks", icon: <WebhookIcon /> },
      { title: "Auth hooks", url: "/developer/auth-hooks", icon: <ZapIcon /> },
      {
        title: "Agent governance",
        url: "/developer/agents",
        icon: <SparklesIcon />,
      },
      {
        title: "Verifiable credentials",
        url: "/developer/credentials",
        icon: <BadgeCheckIcon />,
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
        items: [
          { title: "General", url: "/settings/workspace/general" },
          { title: "Security policy", url: "/settings/workspace/security-policy" },
          { title: "Domains", url: "/settings/workspace/domains" },
          {
            title: "Email templates",
            url: "/settings/workspace/email-templates",
          },
        ],
      },
      { title: "Branding", url: "/settings/branding", icon: <PaletteIcon /> },
      {
        title: "Billing & plan",
        url: "/settings/billing",
        icon: <CreditCardIcon />,
      },
    ],
  },
];

export type NavTitleLookup = {
  group?: string;
  parent?: { title: string; url: string };
  title: string;
};

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
