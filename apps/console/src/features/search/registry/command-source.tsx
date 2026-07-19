// Command registry: executable admin commands with capability gating.
// Self-contained — no imports from features/copilot/* (the copilot registry
// reconciliation is a future task tracked in the spec §15).

import {
  ArchiveIcon,
  BadgeCheckIcon,
  BarChart3Icon,
  BotIcon,
  Building2Icon,
  FileDownIcon,
  FingerprintIcon,
  GaugeIcon,
  KeyRoundIcon,
  LayoutDashboardIcon,
  LogInIcon,
  MailIcon,
  PaletteIcon,
  RefreshCwIcon,
  Settings2Icon,
  ShieldCheckIcon,
  UserPlusIcon,
  UsersIcon,
  UsersRoundIcon,
  WebhookIcon,
  ZapIcon,
} from "lucide-react";
import type { ReactNode } from "react";

import type { Capability } from "@/features/access-control/capability-model";

import type { SearchContext, SearchItem, SearchSource } from "./types";

interface CommandDef {
  id: string;
  title: string;
  subtitle: string;
  keywords: string[];
  icon: ReactNode;
  capability?: Capability;
  run(ctx: SearchContext): void;
}

// ─── Command definitions ──────────────────────────────────────────────────────
// Each command navigates to the appropriate route (the target screen manages
// the create/action flow with URL-driven drawers or modals, consistent with
// how the rest of the console works).

const COMMANDS: CommandDef[] = [
  {
    id: "cmd.navigate.dashboard",
    title: "Open Dashboard",
    subtitle: "Go to the workspace overview",
    keywords: ["home", "overview", "main"],
    icon: <LayoutDashboardIcon className="size-4" />,
    run: ({ navigate }) => navigate("/"),
  },
  {
    id: "cmd.create.user",
    title: "Create User",
    subtitle: "Invite a new user to this workspace",
    keywords: ["invite", "add user", "new user", "onboard"],
    icon: <UserPlusIcon className="size-4" />,
    capability: "user.write",
    run: ({ navigate }) => navigate("/users"),
  },
  {
    id: "cmd.create.organization",
    title: "Create Organization",
    subtitle: "Add a new tenant or sub-organization",
    keywords: ["add org", "new tenant", "create tenant"],
    icon: <Building2Icon className="size-4" />,
    run: ({ navigate }) => navigate("/organizations/tenants"),
  },
  {
    id: "cmd.create.role",
    title: "Create Role",
    subtitle: "Define a new RBAC role with custom permissions",
    keywords: ["add role", "new role", "rbac"],
    icon: <ShieldCheckIcon className="size-4" />,
    capability: "role.write",
    run: ({ navigate }) => navigate("/authorization/roles"),
  },
  {
    id: "cmd.create.group",
    title: "Create Group",
    subtitle: "Create a user group for bulk access control",
    keywords: ["add group", "new group", "user group"],
    icon: <UsersRoundIcon className="size-4" />,
    capability: "group.write",
    run: ({ navigate }) => navigate("/groups"),
  },
  {
    id: "cmd.navigate.users",
    title: "Manage Users",
    subtitle: "View and manage all workspace users",
    keywords: ["users list", "all users", "user management"],
    icon: <UsersIcon className="size-4" />,
    capability: "user.read",
    run: ({ navigate }) => navigate("/users"),
  },
  {
    id: "cmd.navigate.invitations",
    title: "Invite User",
    subtitle: "Send a workspace invitation",
    keywords: ["send invite", "invitation", "onboard"],
    icon: <MailIcon className="size-4" />,
    capability: "user.write",
    run: ({ navigate }) => navigate("/invitations"),
  },
  {
    id: "cmd.navigate.api-keys",
    title: "Generate API Key",
    subtitle: "Create a new machine-access API key",
    keywords: ["api key", "machine identity", "service account", "token"],
    icon: <KeyRoundIcon className="size-4" />,
    capability: "apikey.write",
    run: ({ navigate }) => navigate("/auth/api/keys"),
  },
  {
    id: "cmd.navigate.signing-keys",
    title: "Rotate Signing Keys",
    subtitle: "Manage JWKS signing and encryption keys",
    keywords: ["jwks", "rotate keys", "signing", "encryption key"],
    icon: <RefreshCwIcon className="size-4" />,
    capability: "connection.read",
    run: ({ navigate }) => navigate("/auth/api/signing-keys"),
  },
  {
    id: "cmd.navigate.oauth-clients",
    title: "Create OAuth Client",
    subtitle: "Register an OIDC / OAuth 2.0 application",
    keywords: ["oauth", "oidc", "client", "application", "app"],
    icon: <LogInIcon className="size-4" />,
    capability: "connection.write",
    run: ({ navigate }) => navigate("/auth/connections/oidc"),
  },
  {
    id: "cmd.navigate.passkeys",
    title: "Configure Passkeys",
    subtitle: "Manage WebAuthn / passkey settings",
    keywords: ["webauthn", "fido2", "passkey", "biometric"],
    icon: <FingerprintIcon className="size-4" />,
    run: ({ navigate }) => navigate("/auth/login-methods/passkeys"),
  },
  {
    id: "cmd.navigate.mfa",
    title: "Multi-factor Auth Settings",
    subtitle: "Configure TOTP, SMS, and recovery codes",
    keywords: ["mfa", "totp", "2fa", "two factor", "authenticator"],
    icon: <ShieldCheckIcon className="size-4" />,
    run: ({ navigate }) => navigate("/auth/mfa/totp"),
  },
  {
    id: "cmd.navigate.audit-logs",
    title: "View Audit Logs",
    subtitle: "Browse and filter security audit events",
    keywords: ["audit", "logs", "events", "security"],
    icon: <ArchiveIcon className="size-4" />,
    capability: "audit.read",
    run: ({ navigate }) => navigate("/security/audit-logs"),
  },
  {
    id: "cmd.navigate.export-audit",
    title: "Export Audit Logs",
    subtitle: "Download audit events for compliance",
    keywords: ["export", "download", "compliance", "audit csv"],
    icon: <FileDownIcon className="size-4" />,
    capability: "audit.read",
    run: ({ navigate }) => navigate("/security/audit-logs"),
  },
  {
    id: "cmd.navigate.webhooks",
    title: "Manage Webhooks",
    subtitle: "Configure outbound event webhooks",
    keywords: ["webhooks", "events", "integrations", "outbound"],
    icon: <WebhookIcon className="size-4" />,
    capability: "webhook.read",
    run: ({ navigate }) => navigate("/developer/webhooks"),
  },
  {
    id: "cmd.navigate.auth-hooks",
    title: "Auth Hooks",
    subtitle: "Configure pre/post authentication hooks",
    keywords: ["hooks", "actions", "login hook", "auth pipeline"],
    icon: <ZapIcon className="size-4" />,
    capability: "connection.read",
    run: ({ navigate }) => navigate("/developer/auth-hooks"),
  },
  {
    id: "cmd.navigate.agents",
    title: "Agent Governance",
    subtitle: "Manage machine-to-machine and AI agents",
    keywords: ["agents", "bots", "m2m", "machine identity", "ai agent"],
    icon: <BotIcon className="size-4" />,
    capability: "apikey.read",
    run: ({ navigate }) => navigate("/developer/agents"),
  },
  {
    id: "cmd.navigate.credentials",
    title: "Verifiable Credentials",
    subtitle: "Issue and manage W3C verifiable credentials",
    keywords: ["vc", "credentials", "w3c", "ssi"],
    icon: <BadgeCheckIcon className="size-4" />,
    capability: "apikey.read",
    run: ({ navigate }) => navigate("/developer/credentials"),
  },
  {
    id: "cmd.navigate.analytics",
    title: "Analytics",
    subtitle: "Workspace usage metrics and trends",
    keywords: ["metrics", "stats", "analytics", "charts"],
    icon: <BarChart3Icon className="size-4" />,
    capability: "analytics.read",
    run: ({ navigate }) => navigate("/analytics"),
  },
  {
    id: "cmd.navigate.branding",
    title: "Manage Branding",
    subtitle: "Customise the hosted login UI",
    keywords: ["branding", "theme", "logo", "colors", "login page"],
    icon: <PaletteIcon className="size-4" />,
    capability: "branding.write",
    run: ({ navigate }) => navigate("/settings/branding"),
  },
  {
    id: "cmd.navigate.workspace-settings",
    title: "Workspace Settings",
    subtitle: "General, domains, security policy",
    keywords: ["settings", "workspace", "general", "config"],
    icon: <Settings2Icon className="size-4" />,
    capability: "tenant.read",
    run: ({ navigate }) => navigate("/settings/workspace/general"),
  },
  {
    id: "cmd.navigate.policy-builder",
    title: "Build Policy",
    subtitle: "Create and test authorization policies",
    keywords: ["policy", "abac", "rego", "cedar", "rules"],
    icon: <GaugeIcon className="size-4" />,
    capability: "policy.write",
    run: ({ navigate }) => navigate("/authorization/builder"),
  },
];

export function createCommandSource(): SearchSource {
  return {
    id: "commands",
    getItems(_query: string, ctx: SearchContext): SearchItem[] {
      return COMMANDS.filter(
        (def) => def.capability === undefined || ctx.capabilities.has(def.capability),
      ).map(
        (def): SearchItem => ({
          id: def.id,
          kind: "command",
          category: "Commands",
          title: def.title,
          subtitle: def.subtitle,
          icon: def.icon,
          keywords: def.keywords,
          capability: def.capability,
          run: def.run,
        }),
      );
    },
  };
}
