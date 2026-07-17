export const CONSOLE_CAPABILITIES = [
  "tenant.read",
  "tenant.write",
  "user.read",
  "user.write",
  "role.read",
  "role.write",
  "group.read",
  "group.write",
  "policy.read",
  "policy.write",
  "apikey.read",
  "apikey.write",
  "connection.read",
  "connection.write",
  "webhook.read",
  "webhook.write",
  "secret.read",
  "secret.write",
  "branding.write",
  "gdpr.write",
  "audit.read",
  "audit.write",
  "billing.read",
  "billing.write",
  "analytics.read",
] as const;

export type Capability = (typeof CONSOLE_CAPABILITIES)[number];
export type CapabilitySet = ReadonlySet<string>;
export type AccessResolution = "resolving" | "ready" | "error";
export type AccessMode = "setup" | "full" | "read-only" | "restricted" | "none" | "unknown";

const CAPABILITY_LABELS: Record<Capability, string> = {
  "tenant.read": "View workspace settings",
  "tenant.write": "Manage workspace settings",
  "user.read": "View users",
  "user.write": "Manage users",
  "role.read": "View roles and permissions",
  "role.write": "Manage roles and permissions",
  "group.read": "View groups",
  "group.write": "Manage groups",
  "policy.read": "View security policies",
  "policy.write": "Manage security policies",
  "apikey.read": "View machine access",
  "apikey.write": "Manage machine access",
  "connection.read": "View identity connections",
  "connection.write": "Manage identity connections",
  "webhook.read": "View webhooks",
  "webhook.write": "Manage webhooks",
  "secret.read": "View secrets metadata",
  "secret.write": "Manage secrets",
  "branding.write": "Manage workspace branding",
  "gdpr.write": "Manage privacy requests",
  "audit.read": "View audit and security events",
  "audit.write": "Manage audit investigations",
  "billing.read": "View billing",
  "billing.write": "Manage billing",
  "analytics.read": "View workspace analytics",
};

export function createCapabilitySet(items: readonly string[] | undefined): CapabilitySet {
  return new Set((items ?? []).filter(Boolean));
}

export function hasCapability(
  permissions: CapabilitySet,
  permission: Capability | undefined,
): boolean {
  return permission === undefined || permissions.has(permission);
}

export function hasAllCapabilities(
  permissions: CapabilitySet,
  required: readonly Capability[],
): boolean {
  return required.every((permission) => permissions.has(permission));
}

export function hasAnyCapability(
  permissions: CapabilitySet,
  required: readonly Capability[],
): boolean {
  return required.some((permission) => permissions.has(permission));
}

export function classifyAccessMode(permissions: CapabilitySet, hasWorkspace: boolean): AccessMode {
  if (!hasWorkspace) return "setup";
  if (permissions.size === 0) return "none";
  if (CONSOLE_CAPABILITIES.every((permission) => permissions.has(permission))) return "full";

  const values = Array.from(permissions);
  const hasRead = values.some((permission) => permission.endsWith(".read"));
  const hasWrite = values.some((permission) => permission.endsWith(".write"));

  if (hasRead && !hasWrite) return "read-only";
  return "restricted";
}

export function capabilityLabel(permission: Capability): string {
  return CAPABILITY_LABELS[permission];
}
