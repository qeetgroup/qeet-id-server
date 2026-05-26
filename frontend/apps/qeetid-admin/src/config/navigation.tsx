import {
  ActivityIcon,
  BotIcon,
  Building2Icon,
  ChartColumnIcon,
  CreditCardIcon,
  FingerprintIcon,
  GaugeIcon,
  KeyRoundIcon,
  LayoutDashboardIcon,
  LockKeyholeIcon,
  LogInIcon,
  MailIcon,
  NetworkIcon,
  PaletteIcon,
  ScrollTextIcon,
  ServerCogIcon,
  Settings2Icon,
  ShieldAlertIcon,
  ShieldCheckIcon,
  ShieldIcon,
  UsersIcon,
  UsersRoundIcon,
  WebhookIcon,
  WorkflowIcon,
} from "lucide-react";
import type { ReactNode } from "react";

export type NavItem = {
  title: string;
  url: string;
  icon?: ReactNode;
  isActive?: boolean;
  items?: { title: string; url: string }[];
};

export type NavGroup = {
  label: string;
  items: NavItem[];
};

export const navGroups: NavGroup[] = [
  {
    label: "Platform",
    items: [
      { title: "Dashboard", url: "/dashboard", icon: <LayoutDashboardIcon />, isActive: true },
      { title: "Activity", url: "/activity", icon: <ActivityIcon /> },
      { title: "Analytics", url: "/analytics", icon: <ChartColumnIcon /> },
    ],
  },
  {
    label: "Identity & Access",
    items: [
      {
        title: "Users",
        url: "/users",
        icon: <UsersIcon />,
        items: [
          { title: "All Users", url: "/users" },
          { title: "Invitations", url: "/users/invitations" },
          { title: "Sessions", url: "/users/sessions" },
          { title: "Deleted", url: "/users/deleted" },
        ],
      },
      {
        title: "Organizations",
        url: "/organizations",
        icon: <Building2Icon />,
        items: [
          { title: "Tenants", url: "/organizations/tenants" },
          { title: "Members", url: "/organizations/members" },
        ],
      },
      { title: "Groups", url: "/groups", icon: <UsersRoundIcon /> },
      {
        title: "Roles & Permissions",
        url: "/access",
        icon: <ShieldCheckIcon />,
        items: [
          { title: "Roles (RBAC)", url: "/access/roles" },
          { title: "Permissions", url: "/access/permissions" },
          { title: "Policies (ABAC)", url: "/access/policies" },
          { title: "Resources", url: "/access/resources" },
        ],
      },
      { title: "Invitations", url: "/invitations", icon: <MailIcon /> },
    ],
  },
  {
    label: "Authentication",
    items: [
      {
        title: "Login Methods",
        url: "/auth/login-methods",
        icon: <LogInIcon />,
        items: [
          { title: "Password", url: "/auth/login-methods/password" },
          { title: "Passwordless", url: "/auth/login-methods/passwordless" },
          { title: "Passkeys", url: "/auth/login-methods/passkeys" },
          { title: "Magic Links", url: "/auth/login-methods/magic-links" },
        ],
      },
      { title: "Social Providers", url: "/auth/social", icon: <NetworkIcon /> },
      {
        title: "Multi-Factor Auth",
        url: "/auth/mfa",
        icon: <FingerprintIcon />,
        items: [
          { title: "TOTP", url: "/auth/mfa/totp" },
          { title: "SMS / Email", url: "/auth/mfa/sms-email" },
          { title: "Recovery Codes", url: "/auth/mfa/recovery-codes" },
        ],
      },
      {
        title: "Connections",
        url: "/auth/connections",
        icon: <WorkflowIcon />,
        items: [
          { title: "SAML 2.0", url: "/auth/connections/saml" },
          { title: "OIDC / OAuth 2.0", url: "/auth/connections/oidc" },
          { title: "SCIM Provisioning", url: "/auth/connections/scim" },
          { title: "LDAP / AD", url: "/auth/connections/ldap" },
        ],
      },
      {
        title: "API Keys & Tokens",
        url: "/auth/api",
        icon: <KeyRoundIcon />,
        items: [
          { title: "API Keys", url: "/auth/api/keys" },
          { title: "Machine Identities", url: "/auth/api/machine-identities" },
          { title: "Access Tokens", url: "/auth/api/tokens" },
          { title: "Secrets", url: "/auth/api/secrets" },
        ],
      },
    ],
  },
  {
    label: "Security & Compliance",
    items: [
      {
        title: "Threat Protection",
        url: "/security/threats",
        icon: <ShieldAlertIcon />,
        items: [
          { title: "Bot Detection", url: "/security/threats/bots" },
          { title: "Anomalies", url: "/security/threats/anomalies" },
          { title: "Rate Limits", url: "/security/threats/rate-limits" },
          { title: "IP Allowlist", url: "/security/threats/ip-allowlist" },
        ],
      },
      { title: "Sessions", url: "/security/sessions", icon: <ShieldIcon /> },
      { title: "Rate Limits", url: "/security/rate-limits", icon: <GaugeIcon /> },
      { title: "Audit Logs", url: "/security/audit-logs", icon: <ScrollTextIcon /> },
      {
        title: "Compliance",
        url: "/security/compliance",
        icon: <LockKeyholeIcon />,
        items: [
          { title: "SOC 2", url: "/security/compliance/soc2" },
          { title: "GDPR", url: "/security/compliance/gdpr" },
          { title: "ISO 27001", url: "/security/compliance/iso27001" },
          { title: "Data Retention", url: "/security/compliance/retention" },
        ],
      },
    ],
  },
  {
    label: "Developer",
    items: [
      { title: "Webhooks", url: "/developer/webhooks", icon: <WebhookIcon /> },
      { title: "Bots & Automations", url: "/developer/bots", icon: <BotIcon /> },
      { title: "Infrastructure", url: "/developer/infrastructure", icon: <ServerCogIcon /> },
    ],
  },
  {
    label: "Settings",
    items: [
      {
        title: "Workspace",
        url: "/settings/workspace",
        icon: <Settings2Icon />,
        items: [
          { title: "General", url: "/settings/workspace/general" },
          { title: "Domains", url: "/settings/workspace/domains" },
          { title: "Email Templates", url: "/settings/workspace/email-templates" },
        ],
      },
      { title: "Branding", url: "/settings/branding", icon: <PaletteIcon /> },
      { title: "Billing & Plan", url: "/settings/billing", icon: <CreditCardIcon /> },
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
