import {
  Badge,
  Button,
  Card,
  CardContent,
  Combobox,
  DataState,
  Input,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  TimeSince,
} from "@qeetrix/ui";
import { createFileRoute } from "@tanstack/react-router";
import { RefreshCwIcon, ScrollTextIcon } from "lucide-react";
import { useState } from "react";

import { PageHeader } from "@/components/page-header";
import { AUTHZ_RESOURCE_TYPES, isAuthzEvent, useAuditEvents } from "@/lib/authz-audit";

export const Route = createFileRoute("/_app/authorization/audit")({
  component: AuditPage,
});

const RESOURCE_ITEMS = [
  { label: "All authz resources", value: "" },
  ...AUTHZ_RESOURCE_TYPES.map((r) => ({ label: r, value: r })),
];

function AuditPage() {
  const [resourceType, setResourceType] = useState("");
  const [action, setAction] = useState("");
  const [q, setQ] = useState("");
  const auditQ = useAuditEvents({ resource_type: resourceType, action, q, limit: 200 });

  // When no specific resource type is chosen, keep the view to authz events only.
  const items = (auditQ.data?.items ?? []).filter((e) => (resourceType ? true : isAuthzEvent(e)));

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <PageHeader
        description="Every authorization change is recorded in the hash-chained, append-only audit log."
        actions={
          <Button
            variant="outline"
            size="sm"
            onClick={() => auditQ.refetch()}
            disabled={auditQ.isFetching}
          >
            <RefreshCwIcon className={auditQ.isFetching ? "animate-spin" : ""} /> Refresh
          </Button>
        }
      />

      <Card>
        <CardContent className="flex flex-wrap items-end gap-3 py-4">
          <div className="w-56">
            <Combobox
              items={RESOURCE_ITEMS}
              value={resourceType}
              onValueChange={(v) => setResourceType(v ?? "")}
              placeholder="Resource type"
            />
          </div>
          <Input
            className="w-52"
            placeholder="Filter by action…"
            value={action}
            onChange={(e) => setAction(e.target.value)}
            aria-label="Action filter"
          />
          <Input
            className="w-52"
            placeholder="Search…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            aria-label="Search audit"
          />
        </CardContent>
      </Card>

      <Card>
        <CardContent className="p-0">
          <DataState
            isLoading={auditQ.isLoading}
            isError={auditQ.isError}
            error={auditQ.error}
            isEmpty={items.length === 0}
            emptyIcon={ScrollTextIcon}
            emptyTitle="No authorization events"
            skeletonRows={6}
          >
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>When</TableHead>
                  <TableHead>Action</TableHead>
                  <TableHead>Resource</TableHead>
                  <TableHead>Actor</TableHead>
                  <TableHead>IP</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((e) => (
                  <TableRow key={e.id}>
                    <TableCell>
                      <TimeSince value={e.created_at} />
                    </TableCell>
                    <TableCell className="font-mono text-xs">{e.action}</TableCell>
                    <TableCell>
                      <Badge variant="muted">{e.resource_type}</Badge>
                    </TableCell>
                    <TableCell className="font-mono text-[11px] text-muted-foreground">
                      {e.actor_user_id ? e.actor_user_id.slice(0, 8) : e.actor_type}
                    </TableCell>
                    <TableCell className="font-mono text-[11px] text-muted-foreground">
                      {e.ip ?? "—"}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </DataState>
        </CardContent>
      </Card>
    </div>
  );
}
