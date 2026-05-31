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
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@qeetrix/ui";
import { createFileRoute } from "@tanstack/react-router";
import { CopyIcon, RotateCwIcon } from "lucide-react";
import { useState } from "react";

import { PageHeader } from "@/components/page-header";

export const Route = createFileRoute("/_app/auth/mfa/recovery-codes")({ component: RecoveryCodesPage });

const sampleCodes = [
  "3a4f-9b21-7c8e-1d50",
  "8f12-9a3b-c7d4-e056",
  "5b2c-7d18-9e3a-4f01",
  "1c4d-2e3f-5a6b-7c8d",
  "9e1f-2a3b-4c5d-6e7f",
  "0a1b-2c3d-4e5f-6071",
  "7c8d-9e0f-1a2b-3c4d",
  "4d5e-6f70-8192-a3b4",
  "b5c6-d7e8-f901-2a3b",
  "c6d7-e8f9-0a1b-2c3d",
];

const users = [
  { id: "1", email: "alice@acme.com", remaining: 8, total: 10, lastUsed: "2 days ago" },
  { id: "2", email: "bob@acme.com", remaining: 10, total: 10, lastUsed: "—" },
  { id: "3", email: "carol@acme.com", remaining: 3, total: 10, lastUsed: "today" },
  { id: "4", email: "dave@acme.com", remaining: 0, total: 10, lastUsed: "1 hour ago" },
  { id: "5", email: "eve@acme.com", remaining: 7, total: 10, lastUsed: "last week" },
];

function RecoveryCodesPage() {
  const [count, setCount] = useState("10");
  const [length, setLength] = useState("16");

  return (
    <div className="flex min-w-0 flex-col gap-6">
      <PageHeader description="Backup codes issued at MFA enrollment. Each is single-use and bcrypt-hashed server-side." />

      <Card>
        <CardHeader>
          <CardTitle>Defaults</CardTitle>
          <CardDescription>Settings for the next set of codes a user generates.</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-6 md:grid-cols-2">
          <Field>
            <FieldLabel>Codes per user</FieldLabel>
            <Select value={count} onValueChange={(v) => v && setCount(v)}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="6">6</SelectItem>
                <SelectItem value="8">8</SelectItem>
                <SelectItem value="10">10</SelectItem>
                <SelectItem value="12">12</SelectItem>
              </SelectContent>
            </Select>
            <FieldDescription>Generated once at enrollment. Users can regenerate at any time.</FieldDescription>
          </Field>
          <Field>
            <FieldLabel>Code length</FieldLabel>
            <Select value={length} onValueChange={(v) => v && setLength(v)}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="10">10 chars</SelectItem>
                <SelectItem value="12">12 chars</SelectItem>
                <SelectItem value="16">16 chars</SelectItem>
                <SelectItem value="20">20 chars</SelectItem>
              </SelectContent>
            </Select>
            <FieldDescription>Includes 4-character dashes for readability.</FieldDescription>
          </Field>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <CardTitle>Preview</CardTitle>
            <CardDescription>What end users see at enrollment. Codes are shown once.</CardDescription>
          </div>
          <div className="flex gap-2">
            <Button variant="outline">
              <CopyIcon className="mr-2 size-4" />
              Copy
            </Button>
            <Button variant="outline">
              <RotateCwIcon className="mr-2 size-4" />
              Regenerate
            </Button>
          </div>
        </CardHeader>
        <CardContent className="grid grid-cols-2 gap-2 font-mono text-sm md:grid-cols-5">
          {sampleCodes.map((c) => (
            <code key={c} className="rounded-md bg-muted px-3 py-2 tracking-wider">
              {c}
            </code>
          ))}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>User status</CardTitle>
          <CardDescription>Recovery-code health across enrolled users.</CardDescription>
        </CardHeader>
        <CardContent className="overflow-x-auto p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>User</TableHead>
                <TableHead>Codes remaining</TableHead>
                <TableHead>Last used</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="w-[1%]" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {users.map((u) => {
                const pct = (u.remaining / u.total) * 100;
                const status =
                  u.remaining === 0
                    ? <Badge variant="destructive">exhausted</Badge>
                    : pct < 50
                      ? <Badge variant="secondary">low</Badge>
                      : <Badge variant="outline">healthy</Badge>;
                return (
                  <TableRow key={u.id}>
                    <TableCell className="text-sm">{u.email}</TableCell>
                    <TableCell>
                      <span className="font-mono text-sm">{u.remaining}</span>
                      <span className="text-xs text-muted-foreground"> / {u.total}</span>
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">{u.lastUsed}</TableCell>
                    <TableCell>{status}</TableCell>
                    <TableCell>
                      <Button size="sm" variant="ghost">
                        Regenerate
                      </Button>
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
