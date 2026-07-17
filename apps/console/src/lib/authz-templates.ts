// Starter policy templates. There is no template backend, so this is a curated
// static catalogue; "Use template" hydrates the Policy Builder with a real,
// persistable PolicyDoc that writes via the live ABAC endpoints on save.

import { type CondNode, nid, type Operator } from "./authz-abac";
import type { PolicyDoc } from "./authz-codegen";

function leaf(attr: string, op: Operator, value = ""): CondNode {
  return { id: nid("leaf"), kind: "leaf", attr, op, value };
}
function all(children: CondNode[]): CondNode {
  return { id: nid("grp"), kind: "group", combinator: "all", children };
}
function any(children: CondNode[]): CondNode {
  return { id: nid("grp"), kind: "group", combinator: "any", children };
}

function doc(partial: Partial<PolicyDoc>): PolicyDoc {
  return {
    name: "",
    description: "",
    effect: "allow",
    resourceType: "*",
    action: "*",
    requireRole: null,
    condition: null,
    relation: null,
    priority: 10,
    enabled: true,
    ...partial,
  };
}

export interface PolicyTemplate {
  id: string;
  name: string;
  vendor: string;
  category: "SaaS" | "Cloud" | "Regulated" | "Baseline";
  description: string;
  tags: string[];
  build: () => PolicyDoc;
}

export const TEMPLATE_CATEGORIES = ["SaaS", "Cloud", "Regulated", "Baseline"] as const;

export const POLICY_TEMPLATES: PolicyTemplate[] = [
  {
    id: "github-repo-admin",
    name: "Repository admin (org members)",
    vendor: "GitHub",
    category: "SaaS",
    description: "Allow org members with the maintainer role to administer repositories.",
    tags: ["rbac", "abac", "repository"],
    build: () =>
      doc({
        name: "github_repo_admin",
        description: "Org members who maintain a repo may administer it.",
        resourceType: "repository",
        action: "admin",
        requireRole: "maintainer",
        condition: all([leaf("subject.org_member", "eq", "true")]),
        priority: 40,
      }),
  },
  {
    id: "workspace-hr-profiles",
    name: "HR can view employee profiles",
    vendor: "Google Workspace",
    category: "SaaS",
    description: "Allow the HR department to read employee profile resources.",
    tags: ["abac", "department", "read"],
    build: () =>
      doc({
        name: "hr_view_profiles",
        description: "HR department may read employee profiles.",
        resourceType: "employee_profile",
        action: "read",
        condition: all([leaf("subject.department", "eq", "HR")]),
        priority: 30,
      }),
  },
  {
    id: "aws-prod-deploy-window",
    name: "Block production deploys after hours",
    vendor: "AWS IAM",
    category: "Cloud",
    description: "Deny deployments to production environments outside business hours.",
    tags: ["abac", "deny", "time-window"],
    build: () =>
      doc({
        name: "no_after_hours_prod_deploy",
        description: "Production deploys are only permitted during business hours.",
        effect: "deny",
        resourceType: "deployment",
        action: "create",
        condition: all([
          leaf("resource.environment", "eq", "production"),
          any([leaf("context.hour_of_day", "lt", "9"), leaf("context.hour_of_day", "gte", "18")]),
        ]),
        priority: 90,
      }),
  },
  {
    id: "azure-corp-network",
    name: "Corporate network only",
    vendor: "Azure Entra",
    category: "Cloud",
    description: "Allow access only from the corporate network CIDR ranges.",
    tags: ["abac", "network", "context"],
    build: () =>
      doc({
        name: "corp_network_only",
        description: "Restrict access to requests originating on the corporate network.",
        resourceType: "*",
        action: "*",
        condition: all([leaf("context.network", "eq", "corp")]),
        priority: 50,
      }),
  },
  {
    id: "slack-channel-owner",
    name: "Channel owners manage members",
    vendor: "Slack",
    category: "SaaS",
    description: "Allow the owner relation of a channel to manage its membership.",
    tags: ["rebac", "ownership"],
    build: () =>
      doc({
        name: "slack_channel_owner_manage",
        description: "The owner of a channel may manage its members.",
        resourceType: "channel",
        action: "manage_members",
        relation: { object: "channel:", relation: "owner" },
        priority: 40,
      }),
  },
  {
    id: "jira-project-lead",
    name: "Project leads edit issues",
    vendor: "Jira",
    category: "SaaS",
    description: "Allow the lead role to edit issues within their project.",
    tags: ["rbac", "abac", "project"],
    build: () =>
      doc({
        name: "jira_lead_edit_issues",
        description: "Project leads may edit issues in projects they lead.",
        resourceType: "issue",
        action: "edit",
        requireRole: "project_lead",
        priority: 35,
      }),
  },
  {
    id: "salesforce-region",
    name: "Region-scoped account access",
    vendor: "Salesforce",
    category: "SaaS",
    description: "Allow reps to read accounts only in their assigned region.",
    tags: ["abac", "attribute-match"],
    build: () =>
      doc({
        name: "sfdc_region_scoped_accounts",
        description: "Reps read accounts within their own region.",
        resourceType: "account",
        action: "read",
        condition: all([leaf("subject.region", "eq", "resource.region")]),
        priority: 30,
      }),
  },
  {
    id: "healthcare-phi",
    name: "PHI access with break-glass audit",
    vendor: "Healthcare / HIPAA",
    category: "Regulated",
    description: "Allow clinicians to read PHI for patients in their care team.",
    tags: ["abac", "hipaa", "sensitive"],
    build: () =>
      doc({
        name: "phi_care_team_read",
        description: "Clinicians read PHI only for patients on their care team.",
        resourceType: "patient_record",
        action: "read",
        condition: all([
          leaf("subject.role", "eq", "clinician"),
          leaf("subject.care_team_ids", "contains", "resource.patient_id"),
        ]),
        priority: 70,
      }),
  },
  {
    id: "finance-sod",
    name: "Separation of duties (payments)",
    vendor: "Finance / SOX",
    category: "Regulated",
    description: "Deny payment approval by the same user who created the payment.",
    tags: ["abac", "deny", "sox"],
    build: () =>
      doc({
        name: "sox_payment_sod",
        description: "A payment cannot be approved by its creator.",
        effect: "deny",
        resourceType: "payment",
        action: "approve",
        condition: all([leaf("subject.id", "eq", "resource.created_by")]),
        priority: 95,
      }),
  },
  {
    id: "gov-clearance",
    name: "Clearance-level document access",
    vendor: "Government",
    category: "Regulated",
    description: "Allow access to classified documents at or below the subject's clearance.",
    tags: ["abac", "clearance"],
    build: () =>
      doc({
        name: "gov_clearance_gate",
        description: "Subjects access documents at or below their clearance level.",
        resourceType: "document",
        action: "read",
        condition: all([leaf("subject.clearance_level", "gte", "resource.classification_level")]),
        priority: 80,
      }),
  },
  {
    id: "baseline-mfa",
    name: "Require MFA for sensitive actions",
    vendor: "Baseline",
    category: "Baseline",
    description: "Deny sensitive write actions when the session is not MFA-verified.",
    tags: ["abac", "deny", "mfa"],
    build: () =>
      doc({
        name: "require_mfa_sensitive",
        description: "Sensitive writes require an MFA-verified session.",
        effect: "deny",
        resourceType: "*",
        action: "delete",
        condition: all([leaf("context.mfa", "ne", "true")]),
        priority: 85,
      }),
  },
  {
    id: "baseline-owner",
    name: "Owners can do anything to their resource",
    vendor: "Baseline",
    category: "Baseline",
    description: "Allow the owner relation of a resource full access to it.",
    tags: ["rebac", "ownership"],
    build: () =>
      doc({
        name: "owner_full_access",
        description: "The owner of a resource has full access.",
        resourceType: "*",
        action: "*",
        relation: { object: "", relation: "owner" },
        priority: 20,
      }),
  },
];

export function findTemplate(id: string): PolicyTemplate | undefined {
  return POLICY_TEMPLATES.find((t) => t.id === id);
}
