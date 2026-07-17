export const AUTH_METHOD_KEYS = ["password", "passkey", "social", "saml", "oidc"] as const;

export type DashboardRange = "7d" | "14d";

export function takeLatest<T>(items: T[], count: number): T[] {
  return items.length > count ? items.slice(-count) : items;
}

export function formatDelta(value: number, unit: "%" | "pp" = "%"): string {
  return `${value >= 0 ? "+" : ""}${value.toFixed(1)}${unit}`;
}

export function authMethodColor(method: string): string {
  const key = method.toLowerCase().replace(/[^a-z]/g, "");
  const index = (AUTH_METHOD_KEYS as readonly string[]).indexOf(key);
  return index >= 0 ? `var(--chart-${index + 1})` : "var(--chart-1)";
}

export function mfaMethodColor(method: string): string {
  const key = method.toLowerCase();
  if (key.startsWith("totp")) return "var(--chart-1)";
  if (key.startsWith("passkey")) return "var(--chart-2)";
  if (key.startsWith("sms")) return "var(--chart-3)";
  if (key.startsWith("email")) return "var(--chart-4)";
  if (key.startsWith("recovery")) return "var(--chart-5)";
  return "var(--chart-1)";
}

export function formatAuditAction(action: string): string {
  return action.replace(/[._]/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}
