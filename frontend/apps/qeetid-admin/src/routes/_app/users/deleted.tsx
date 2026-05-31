import {
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  Input,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@qeetrix/ui";
import { createFileRoute } from "@tanstack/react-router";
import { RotateCcwIcon, Trash2Icon, UserMinusIcon } from "lucide-react";

import { PageHeader } from "@/components/page-header";

export const Route = createFileRoute("/_app/users/deleted")({ component: DeletedUsersPage });

type Deleted = {
  id: string;
  email: string;
  deletedAt: string;
  by: string;
  reason: string;
  daysLeft: number;
};

const seed: Deleted[] = [
  { id: "1", email: "frank.miller@acme.com", deletedAt: "2026-05-22", by: "alice@acme.com", reason: "User request — account closure", daysLeft: 27 },
  { id: "2", email: "redacted-9f3a@acme.com", deletedAt: "2026-05-18", by: "system (GDPR purge)", reason: "GDPR Article 17", daysLeft: 23 },
  { id: "3", email: "test+1@acme.com", deletedAt: "2026-05-10", by: "alice@acme.com", reason: "Duplicate account", daysLeft: 15 },
  { id: "4", email: "ginny@acme.com", deletedAt: "2026-04-30", by: "carol@acme.com", reason: "Offboarding", daysLeft: 5 },
  { id: "5", email: "hugh@acme.com", deletedAt: "2026-04-27", by: "system (SCIM)", reason: "active=false from Okta", daysLeft: 2 },
  { id: "6", email: "redacted-1c44@acme.com", deletedAt: "2026-04-15", by: "system (GDPR purge)", reason: "GDPR Article 17 — purged", daysLeft: 0 },
];

function DeletedUsersPage() {
  return (
    <div className="flex min-w-0 flex-col gap-6">
      <PageHeader
        description="Soft-deleted users. PII is redacted on permanent purge; the row remains for audit trail."
        actions={
          <Button variant="outline">Export CSV</Button>
        }
      />

      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardDescription>In grace period</CardDescription>
            <UserMinusIcon className="size-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold tracking-tight">
              {seed.filter((d) => d.daysLeft > 0).length}
            </div>
            <p className="text-xs text-muted-foreground">restorable</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardDescription>Purged (90d)</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold tracking-tight">142</div>
            <p className="text-xs text-muted-foreground">PII redacted</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardDescription>Grace window</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold tracking-tight">30 days</div>
            <p className="text-xs text-muted-foreground">tenant policy</p>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <CardTitle>Soft-deleted users</CardTitle>
            <CardDescription>Newest first.</CardDescription>
          </div>
          <Input placeholder="Filter email or reason…" className="w-[280px]" />
        </CardHeader>
        <CardContent className="overflow-x-auto p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Email</TableHead>
                <TableHead>Deleted at</TableHead>
                <TableHead>By</TableHead>
                <TableHead>Reason</TableHead>
                <TableHead>Days left</TableHead>
                <TableHead className="w-[1%]" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {seed.map((d) => (
                <TableRow key={d.id}>
                  <TableCell className="font-mono text-xs">{d.email}</TableCell>
                  <TableCell className="text-sm">{d.deletedAt}</TableCell>
                  <TableCell className="text-sm">{d.by}</TableCell>
                  <TableCell className="max-w-[280px] truncate text-sm text-muted-foreground">
                    {d.reason}
                  </TableCell>
                  <TableCell>
                    {d.daysLeft === 0 ? (
                      <Badge variant="outline">purged</Badge>
                    ) : d.daysLeft < 7 ? (
                      <Badge variant="destructive">{d.daysLeft}d</Badge>
                    ) : (
                      <Badge variant="secondary">{d.daysLeft}d</Badge>
                    )}
                  </TableCell>
                  <TableCell>
                    <div className="flex justify-end gap-1">
                      {d.daysLeft > 0 && (
                        <Button size="sm" variant="ghost">
                          <RotateCcwIcon className="mr-2 size-3" />
                          Restore
                        </Button>
                      )}
                      <Button size="sm" variant="ghost">
                        <Trash2Icon className="mr-2 size-3" />
                        Purge now
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
