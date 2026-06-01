import {
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  DataState,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  TimeSince,
} from "@qeetrix/ui";
import { createFileRoute } from "@tanstack/react-router";
import { KeyRoundIcon, Trash2Icon } from "lucide-react";

import { PageHeader } from "@/components/page-header";
import { useOAuthGrants, useRevokeOAuthGrant } from "@/lib/oauth-grants";

export const Route = createFileRoute("/_app/auth/api/tokens")({ component: TokensPage });

function TokensPage() {
  const listQ = useOAuthGrants();
  const revokeM = useRevokeOAuthGrant();
  const items = listQ.data?.items ?? [];

  return (
    <div className="flex min-w-0 flex-col gap-6">
      <PageHeader description="Active OAuth / OIDC grants. Access tokens are short-lived JWTs that expire on their own; revoking a grant invalidates its refresh-token chain so it can't be renewed." />

      <Card>
        <CardHeader>
          <CardTitle>Active grants</CardTitle>
          <CardDescription>
            One row per (client, user) refresh-token grant. {items.length} active.
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <DataState
            isLoading={listQ.isLoading}
            isError={listQ.isError}
            error={listQ.error}
            isEmpty={items.length === 0}
            emptyIcon={KeyRoundIcon}
            emptyTitle="No active OAuth grants."
            skeletonRows={3}
          >
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Client</TableHead>
                  <TableHead>User</TableHead>
                  <TableHead>Scopes</TableHead>
                  <TableHead>Issued</TableHead>
                  <TableHead>Expires</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((g) => (
                  <TableRow key={g.id}>
                    <TableCell className="max-w-[200px] truncate font-mono text-xs">{g.client_id}</TableCell>
                    <TableCell>{g.user_email || g.user_id}</TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        {g.scopes.map((s) => (
                          <Badge key={s} variant="muted" className="text-xs">
                            {s}
                          </Badge>
                        ))}
                      </div>
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      <TimeSince value={g.issued_at} />
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      <TimeSince value={g.expires_at} />
                    </TableCell>
                    <TableCell className="text-right">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => {
                          if (confirm(`Revoke ${g.user_email || "this user"}'s grant for ${g.client_id}?`)) {
                            revokeM.mutate(g.id);
                          }
                        }}
                        disabled={revokeM.isPending}
                      >
                        <Trash2Icon /> Revoke
                      </Button>
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
