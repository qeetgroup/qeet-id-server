import {
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  Field,
  FieldDescription,
  FieldLabel,
  Input,
  Switch,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@qeetid/ui";
import { createFileRoute } from "@tanstack/react-router";
import { CopyIcon, RefreshCwIcon, UsersIcon } from "lucide-react";
import { useState } from "react";

import { PageHeader } from "@/components/page-header";

export const Route = createFileRoute("/_app/auth/connections/scim")({ component: ScimPage });

const groupMappings = [
  { idpGroup: "okta-admins", role: "admin" },
  { idpGroup: "okta-engineers", role: "developer" },
  { idpGroup: "okta-support", role: "support" },
  { idpGroup: "okta-billing", role: "billing-viewer" },
];

const syncErrors = [
  {
    id: "1",
    op: "PATCH /Users/u_4f12",
    error: "schema: 'phoneNumbers' value not E.164",
    when: "4m ago",
  },
  {
    id: "2",
    op: "POST /Users",
    error: "duplicate userName 'alice@acme.com'",
    when: "1h ago",
  },
];

const scimUrl = "https://auth.qeetid.com/scim/v2";

function ScimPage() {
  const [enabled, setEnabled] = useState(true);

  return (
    <div className="flex min-w-0 flex-col gap-6">
      <PageHeader
        description="SCIM 2.0 endpoint for automated provisioning and deprovisioning from your IdP."
        actions={
          <div className="flex items-center gap-2">
            <span className="text-sm text-muted-foreground">Endpoint enabled</span>
            <Switch checked={enabled} onCheckedChange={setEnabled} />
          </div>
        }
      />

      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardDescription>Provisioned users</CardDescription>
            <UsersIcon className="size-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold tracking-tight">6,140</div>
            <p className="text-xs text-muted-foreground">since 2026-01-04</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardDescription>Deprovisioned (30d)</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold tracking-tight">142</div>
            <p className="text-xs text-muted-foreground">Sessions terminated within 60s</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardDescription>Sync errors (24h)</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold tracking-tight">{syncErrors.length}</div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Endpoint &amp; token</CardTitle>
          <CardDescription>Paste these into Okta / Entra ID / Google when configuring the SCIM app.</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-4">
          <Field>
            <FieldLabel>SCIM base URL</FieldLabel>
            <div className="flex gap-2">
              <Input value={scimUrl} readOnly className="font-mono text-xs" />
              <Button variant="outline" size="icon">
                <CopyIcon className="size-4" />
              </Button>
            </div>
            <FieldDescription>Append <code>/Users</code> or <code>/Groups</code> for the resource endpoints.</FieldDescription>
          </Field>
          <Field>
            <FieldLabel>Bearer token</FieldLabel>
            <div className="flex gap-2">
              <Input value={"qf_scim_•••••••••••••••••••••••••••••••"} readOnly className="font-mono text-xs" />
              <Button variant="outline" size="icon">
                <CopyIcon className="size-4" />
              </Button>
              <Button variant="outline">
                <RefreshCwIcon className="mr-2 size-4" />
                Rotate
              </Button>
            </div>
            <FieldDescription>Shown once at rotation. The IdP authenticates as <code>qeetid:scim</code>.</FieldDescription>
          </Field>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <div>
            <CardTitle>Group → role mapping</CardTitle>
            <CardDescription>SCIM Group memberships translate to Qeet ID RBAC role assignments.</CardDescription>
          </div>
          <Button variant="outline">Add mapping</Button>
        </CardHeader>
        <CardContent className="overflow-x-auto p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>IdP group displayName</TableHead>
                <TableHead>Qeet ID role</TableHead>
                <TableHead className="w-[1%]" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {groupMappings.map((m) => (
                <TableRow key={m.idpGroup}>
                  <TableCell className="font-mono text-xs">{m.idpGroup}</TableCell>
                  <TableCell>
                    <Badge variant="outline">{m.role}</Badge>
                  </TableCell>
                  <TableCell>
                    <Button variant="ghost" size="sm">
                      Edit
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Recent sync errors</CardTitle>
          <CardDescription>Resolve by fixing the IdP source data or relaxing schema validation.</CardDescription>
        </CardHeader>
        <CardContent className="overflow-x-auto p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Operation</TableHead>
                <TableHead>Error</TableHead>
                <TableHead>When</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {syncErrors.map((e) => (
                <TableRow key={e.id}>
                  <TableCell className="font-mono text-xs">{e.op}</TableCell>
                  <TableCell className="text-sm text-muted-foreground">{e.error}</TableCell>
                  <TableCell className="text-xs text-muted-foreground">{e.when}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
