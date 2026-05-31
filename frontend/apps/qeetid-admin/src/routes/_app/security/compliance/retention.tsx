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
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Switch,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@qeetrix/ui";
import { createFileRoute } from "@tanstack/react-router";
import { DatabaseIcon, Trash2Icon } from "lucide-react";

import { PageHeader } from "@/components/page-header";

export const Route = createFileRoute("/_app/security/compliance/retention")({ component: RetentionPage });

const policies = [
  {
    key: "audit-events",
    label: "Audit events",
    hot: "30 days",
    cold: "12 months",
    legal: "tamper-evident",
    enforced: true,
  },
  {
    key: "admin-audit",
    label: "Admin / compliance audit",
    hot: "90 days",
    cold: "3 years",
    legal: "tamper-evident",
    enforced: true,
  },
  {
    key: "sessions",
    label: "Authentication sessions",
    hot: "expired-on-rotate",
    cold: "30 days",
    legal: "—",
    enforced: true,
  },
  {
    key: "deleted-users",
    label: "Soft-deleted users",
    hot: "30 days",
    cold: "180 days",
    legal: "Article 17 GDPR",
    enforced: true,
  },
  {
    key: "webhook-deliveries",
    label: "Webhook deliveries",
    hot: "7 days",
    cold: "—",
    legal: "—",
    enforced: false,
  },
  {
    key: "tokens",
    label: "Refresh tokens (hash)",
    hot: "until-rotated",
    cold: "—",
    legal: "—",
    enforced: true,
  },
];

function RetentionPage() {
  return (
    <div className="flex min-w-0 flex-col gap-6">
      <PageHeader description="Lifecycle policies that govern how long each data class is retained before deletion or archival." />

      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardDescription>Active policies</CardDescription>
            <DatabaseIcon className="size-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold tracking-tight">
              {policies.filter((p) => p.enforced).length}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardDescription>Data purged (30d)</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold tracking-tight">12.4M rows</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardDescription>Outstanding GDPR purges</CardDescription>
            <Trash2Icon className="size-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold tracking-tight">3</div>
            <p className="text-xs text-muted-foreground">complete in 30-day grace window</p>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Per-class policy</CardTitle>
          <CardDescription>Hot storage is queryable; cold storage is S3 / archive tier.</CardDescription>
        </CardHeader>
        <CardContent className="overflow-x-auto p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Data class</TableHead>
                <TableHead>Hot retention</TableHead>
                <TableHead>Cold retention</TableHead>
                <TableHead>Legal hold</TableHead>
                <TableHead>Enforced</TableHead>
                <TableHead className="w-[1%]" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {policies.map((p) => (
                <TableRow key={p.key}>
                  <TableCell className="font-medium">{p.label}</TableCell>
                  <TableCell className="text-sm">{p.hot}</TableCell>
                  <TableCell className="text-sm">{p.cold}</TableCell>
                  <TableCell>
                    {p.legal === "—" ? (
                      <span className="text-xs text-muted-foreground">—</span>
                    ) : (
                      <Badge variant="outline">{p.legal}</Badge>
                    )}
                  </TableCell>
                  <TableCell>
                    <Switch defaultChecked={p.enforced} />
                  </TableCell>
                  <TableCell>
                    <Button size="sm" variant="ghost">
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
          <CardTitle>Default tenant policy</CardTitle>
          <CardDescription>Applies to new data classes added in the future.</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-6 md:grid-cols-2">
          <Field>
            <FieldLabel>Default hot retention</FieldLabel>
            <Select defaultValue="30d">
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="7d">7 days</SelectItem>
                <SelectItem value="30d">30 days</SelectItem>
                <SelectItem value="90d">90 days</SelectItem>
                <SelectItem value="1y">12 months</SelectItem>
              </SelectContent>
            </Select>
          </Field>
          <Field>
            <FieldLabel>Default cold retention</FieldLabel>
            <Select defaultValue="1y">
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="6m">6 months</SelectItem>
                <SelectItem value="1y">12 months</SelectItem>
                <SelectItem value="3y">3 years</SelectItem>
                <SelectItem value="7y">7 years</SelectItem>
              </SelectContent>
            </Select>
            <FieldDescription>Some regulations require ≥ 7 years for financial-related audit data.</FieldDescription>
          </Field>
        </CardContent>
      </Card>
    </div>
  );
}
