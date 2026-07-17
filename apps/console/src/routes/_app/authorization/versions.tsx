import {
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  DataState,
  JSONTree,
  Timeline,
  TimelineContent,
  TimelineDescription,
  TimelineIndicator,
  TimelineItem,
  TimelineTime,
  TimelineTitle,
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@qeetrix/ui";
import { createFileRoute } from "@tanstack/react-router";
import { HistoryIcon, RotateCcwIcon, SlidersHorizontalIcon } from "lucide-react";
import { useState } from "react";

import { PageHeader } from "@/components/page-header";
import { ComingSoon } from "@/features/authorization/components/shared/coming-soon";
import { useAbacPolicies } from "@/lib/authz-abac";
import { toVersionTimeline, useAuditEvents } from "@/lib/authz-audit";

export const Route = createFileRoute("/_app/authorization/versions")({
  component: VersionsPage,
});

function VersionsPage() {
  const policiesQ = useAbacPolicies();
  const auditQ = useAuditEvents({ resource_type: "abac_policy", limit: 500 });
  const policies = policiesQ.data?.items ?? [];
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const timeline = selectedId ? toVersionTimeline(auditQ.data?.items ?? [], selectedId) : [];

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <PageHeader description="Every policy change is reconstructed from the audit log. History is read-only — server-side rollback is not available yet." />

      <ComingSoon
        icon={RotateCcwIcon}
        title="One-click rollback is coming"
        description="The backend records every change but has no revert endpoint. For now, re-apply a prior state manually from the ABAC editor; rollback here is disabled."
        note="no POST /abac/policies/{id}/revert endpoint yet"
      />

      <div className="grid gap-4 lg:grid-cols-[320px_1fr]">
        <Card className="min-w-0">
          <CardHeader>
            <CardTitle className="text-base">Policies</CardTitle>
            <CardDescription>Select a policy to see its change history.</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <DataState
              isLoading={policiesQ.isLoading}
              isError={policiesQ.isError}
              error={policiesQ.error}
              isEmpty={policies.length === 0}
              emptyIcon={SlidersHorizontalIcon}
              emptyTitle="No policies to track"
              skeletonRows={4}
            >
              <ul className="divide-y">
                {policies.map((p) => (
                  <li key={p.id}>
                    <button
                      type="button"
                      onClick={() => setSelectedId(p.id)}
                      className={`flex w-full items-center gap-2 p-3 text-left hover:bg-muted/40 ${p.id === selectedId ? "bg-muted/60" : ""}`}
                    >
                      <Badge variant={p.effect === "deny" ? "destructive" : "success"}>
                        {p.effect}
                      </Badge>
                      <span className="truncate text-sm">{p.name}</span>
                    </button>
                  </li>
                ))}
              </ul>
            </DataState>
          </CardContent>
        </Card>

        <Card className="min-w-0">
          <CardHeader>
            <CardTitle className="text-base">Change history</CardTitle>
            <CardDescription>
              {selectedId ? `${timeline.length} recorded change(s)` : "No policy selected"}
            </CardDescription>
          </CardHeader>
          <CardContent>
            {!selectedId ? (
              <p className="py-8 text-center text-sm text-muted-foreground">
                Select a policy to reconstruct its timeline.
              </p>
            ) : (
              <DataState
                isLoading={auditQ.isLoading}
                isError={auditQ.isError}
                error={auditQ.error}
                isEmpty={timeline.length === 0}
                emptyIcon={HistoryIcon}
                emptyTitle="No changes recorded for this policy"
                skeletonRows={3}
              >
                <Timeline>
                  {timeline.map((v) => (
                    <TimelineItem key={v.id}>
                      <TimelineIndicator>
                        <span className="size-2 rounded-full bg-primary" />
                      </TimelineIndicator>
                      <TimelineContent>
                        <div className="flex items-center gap-2">
                          <TimelineTitle className="font-mono text-xs">{v.action}</TimelineTitle>
                          <TooltipProvider>
                            <Tooltip>
                              <TooltipTrigger
                                render={
                                  <Button
                                    variant="ghost"
                                    size="xs"
                                    disabled
                                    aria-label="Rollback (unavailable)"
                                  >
                                    <RotateCcwIcon />
                                  </Button>
                                }
                              />
                              <TooltipContent>Server-side rollback coming soon</TooltipContent>
                            </Tooltip>
                          </TooltipProvider>
                        </div>
                        <TimelineDescription>by {v.actor.slice(0, 8)}</TimelineDescription>
                        <TimelineTime>{new Date(v.at).toLocaleString()}</TimelineTime>
                        {v.metadata && Object.keys(v.metadata).length > 0 && (
                          <div className="mt-2 rounded-md border bg-muted/20 p-2">
                            <JSONTree
                              value={v.metadata}
                              initialOpenDepth={1}
                              rootLabel="metadata"
                            />
                          </div>
                        )}
                      </TimelineContent>
                    </TimelineItem>
                  ))}
                </Timeline>
              </DataState>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
