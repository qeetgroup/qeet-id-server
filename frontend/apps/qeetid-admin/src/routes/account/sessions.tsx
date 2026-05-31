import {
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  DataState,
  StatusPill,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  TimeSince,
} from "@qeetrix/ui";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";
import {
  MonitorIcon,
  MonitorSmartphoneIcon,
  SmartphoneIcon,
  TabletIcon,
} from "lucide-react";
import { useMemo } from "react";

import { api, tokenStore } from "@/lib/api";

export const Route = createFileRoute("/account/sessions")({ component: SessionsPage });

type Session = {
  id: string;
  user_id: string;
  tenant_id: string;
  ip?: string | null;
  user_agent?: string | null;
  created_at: string;
  last_seen_at: string;
  revoked_at?: string | null;
};

// Tiny user-agent classifier. Just enough to pick an icon + a friendly
// label — full UA parsing requires a 50 KB library we don't ship.
type DeviceKind = "mobile" | "tablet" | "desktop";

function parseUA(ua: string | null | undefined): { kind: DeviceKind; label: string } {
  if (!ua) return { kind: "desktop", label: "Unknown device" };
  const lower = ua.toLowerCase();
  let kind: DeviceKind = "desktop";
  if (/ipad|tablet/.test(lower)) kind = "tablet";
  else if (/iphone|android.*mobile|mobile/.test(lower)) kind = "mobile";

  // Browser
  let browser = "Browser";
  if (/edg\//.test(lower)) browser = "Edge";
  else if (/chrome\//.test(lower) && !/edg\//.test(lower)) browser = "Chrome";
  else if (/firefox\//.test(lower)) browser = "Firefox";
  else if (/safari\//.test(lower) && !/chrome\//.test(lower)) browser = "Safari";

  // OS
  let os = "";
  if (/mac os x/.test(lower)) os = "macOS";
  else if (/windows/.test(lower)) os = "Windows";
  else if (/android/.test(lower)) os = "Android";
  else if (/iphone|ipad|ios/.test(lower)) os = "iOS";
  else if (/linux/.test(lower)) os = "Linux";

  return { kind, label: os ? `${browser} on ${os}` : browser };
}

function DeviceIcon({ kind }: { kind: DeviceKind }) {
  if (kind === "mobile") return <SmartphoneIcon className="size-4" />;
  if (kind === "tablet") return <TabletIcon className="size-4" />;
  return <MonitorIcon className="size-4" />;
}

// Read the access token's `sid` (session id) claim — the session the
// browser is currently using, so we can mark it "This device" and stop
// the user from accidentally signing themselves out.
function getCurrentSessionId(): string | null {
  const raw = tokenStore.get();
  if (!raw) return null;
  const parts = raw.split(".");
  if (parts.length !== 3) return null;
  try {
    const payload = JSON.parse(
      atob(parts[1]!.replace(/-/g, "+").replace(/_/g, "/").padEnd(parts[1]!.length + ((4 - (parts[1]!.length % 4)) % 4), "=")),
    );
    const sid = (payload as { sid?: unknown }).sid;
    return typeof sid === "string" ? sid : null;
  } catch {
    return null;
  }
}

function SessionsPage() {
  const userId = tokenStore.getUserId();
  const qc = useQueryClient();
  const currentSessionId = useMemo(() => getCurrentSessionId(), []);

  const sessionsQ = useQuery({
    queryKey: ["account-sessions", userId],
    queryFn: () => api<{ items: Session[] }>(`/v1/users/${userId}/sessions`),
    enabled: !!userId,
  });

  const revokeM = useMutation({
    mutationFn: (id: string) => api<void>(`/v1/sessions/${id}`, { method: "DELETE" }),
    // Optimistic revoke: stamp `revoked_at` on the local row so the
    // status pill flips immediately. Roll back if the server rejects.
    onMutate: async (id) => {
      await qc.cancelQueries({ queryKey: ["account-sessions"] });
      const snapshots = qc.getQueriesData<{ items: Session[] }>({ queryKey: ["account-sessions"] });
      const now = new Date().toISOString();
      qc.setQueriesData<{ items: Session[] }>({ queryKey: ["account-sessions"] }, (prev) =>
        prev
          ? {
              ...prev,
              items: prev.items.map((s) => (s.id === id ? { ...s, revoked_at: now } : s)),
            }
          : prev,
      );
      return { snapshots };
    },
    onError: (_err, _id, ctx) => {
      ctx?.snapshots.forEach(([key, snap]) => qc.setQueryData(key, snap));
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ["account-sessions"] }),
    meta: { successMessage: "Session revoked" },
  });

  const revokeAllOtherM = useMutation({
    mutationFn: async (others: Session[]) => {
      // No bulk endpoint — fan out one DELETE per session at a small
      // concurrency. Same pattern as users.tsx bulk-delete.
      const CONCURRENCY = 4;
      const queue = [...others];
      let ok = 0;
      let failed = 0;
      async function worker() {
        for (;;) {
          const s = queue.shift();
          if (!s) return;
          try {
            await api<void>(`/v1/sessions/${s.id}`, { method: "DELETE" });
            ok++;
          } catch {
            failed++;
          }
        }
      }
      await Promise.all(
        Array.from({ length: Math.min(CONCURRENCY, others.length) }, worker),
      );
      return { ok, failed };
    },
    onSettled: () => qc.invalidateQueries({ queryKey: ["account-sessions"] }),
    meta: { silent: true }, // handled in onSuccess with combined counts
  });

  const items = sessionsQ.data?.items ?? [];
  const otherActive = items.filter((s) => !s.revoked_at && s.id !== currentSessionId);

  return (
    <Card>
      <CardHeader className="flex flex-row items-start justify-between gap-3">
        <div>
          <CardTitle className="text-base">Active sessions</CardTitle>
          <CardDescription>
            Every place you&apos;re currently signed in. Revoke any session you don&apos;t
            recognise.
          </CardDescription>
        </div>
        {otherActive.length > 0 && (
          <Button
            variant="outline"
            size="sm"
            disabled={revokeAllOtherM.isPending}
            onClick={() => {
              if (
                confirm(
                  `Sign out all ${otherActive.length} other session${otherActive.length === 1 ? "" : "s"}? This won't sign you out of this browser.`,
                )
              ) {
                revokeAllOtherM.mutate(otherActive);
              }
            }}
          >
            Sign out elsewhere ({otherActive.length})
          </Button>
        )}
      </CardHeader>
      <CardContent className="p-0">
        <DataState
          isLoading={sessionsQ.isLoading}
          isError={sessionsQ.isError}
          error={sessionsQ.error}
          isEmpty={items.filter((s) => !s.revoked_at).length === 0}
          emptyIcon={MonitorSmartphoneIcon}
          emptyTitle="No active sessions."
          skeletonRows={3}
        >
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Device</TableHead>
                <TableHead>IP</TableHead>
                <TableHead>Created</TableHead>
                <TableHead>Last seen</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((s) => {
                const device = parseUA(s.user_agent);
                const isCurrent = currentSessionId === s.id;
                return (
                  <TableRow key={s.id}>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <DeviceIcon kind={device.kind} />
                        <div className="flex flex-col">
                          <span className="text-sm font-medium">
                            {device.label}
                            {isCurrent && (
                              <span className="ml-2 rounded-full bg-emerald-500/15 px-1.5 py-px text-[10px] font-medium uppercase tracking-wider text-emerald-700 dark:text-emerald-400">
                                This device
                              </span>
                            )}
                          </span>
                          <span
                            className="max-w-md truncate text-xs text-muted-foreground"
                            title={s.user_agent ?? ""}
                          >
                            {s.user_agent ?? "—"}
                          </span>
                        </div>
                      </div>
                    </TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">
                      {s.ip ?? "—"}
                    </TableCell>
                    <TableCell>
                      <TimeSince value={s.created_at} />
                    </TableCell>
                    <TableCell>
                      <TimeSince value={s.last_seen_at} />
                    </TableCell>
                    <TableCell>
                      <StatusPill status={s.revoked_at ? "revoked" : "active"} />
                    </TableCell>
                    <TableCell className="text-right">
                      <Button
                        variant="ghost"
                        size="sm"
                        disabled={!!s.revoked_at || revokeM.isPending || isCurrent}
                        title={
                          isCurrent
                            ? "Use the sign-out menu to end the session you're currently using."
                            : undefined
                        }
                        onClick={() => {
                          if (
                            confirm("Revoke this session? Whoever holds it will be signed out.")
                          ) {
                            revokeM.mutate(s.id);
                          }
                        }}
                      >
                        Revoke
                      </Button>
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </DataState>
      </CardContent>
    </Card>
  );
}
