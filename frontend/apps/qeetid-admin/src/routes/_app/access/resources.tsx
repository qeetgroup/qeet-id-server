import {
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  Input,
  Sheet,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
  Field,
  FieldDescription,
  FieldLabel,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@qeetid/ui";
import { createFileRoute } from "@tanstack/react-router";
import { BoxIcon, PlusIcon } from "lucide-react";
import { useState } from "react";

import { PageHeader } from "@/components/page-header";

export const Route = createFileRoute("/_app/access/resources")({ component: ResourcesPage });

type Resource = {
  id: string;
  identifier: string;
  name: string;
  audience: string;
  scopes: string[];
  permissions: number;
  status: "active" | "draft";
};

const seed: Resource[] = [
  {
    id: "1",
    identifier: "https://api.acme.com",
    name: "Acme Public API",
    audience: "acme-api",
    scopes: ["read:orders", "write:orders", "read:invoices"],
    permissions: 12,
    status: "active",
  },
  {
    id: "2",
    identifier: "https://billing.acme.com",
    name: "Billing service",
    audience: "billing",
    scopes: ["read:subscription", "write:subscription"],
    permissions: 4,
    status: "active",
  },
  {
    id: "3",
    identifier: "https://reports.internal",
    name: "Internal reports",
    audience: "reports",
    scopes: ["read:reports"],
    permissions: 2,
    status: "active",
  },
  {
    id: "4",
    identifier: "https://lab.acme.com",
    name: "Lab Sandbox",
    audience: "lab",
    scopes: [],
    permissions: 0,
    status: "draft",
  },
];

function ResourcesPage() {
  const [open, setOpen] = useState(false);
  const [resources, setResources] = useState(seed);

  return (
    <div className="flex min-w-0 flex-col gap-6">
      <PageHeader
        description="Protected resources — APIs and services this tenant issues access tokens for. Each one defines its own scopes."
        actions={
          <Button onClick={() => setOpen(true)}>
            <PlusIcon className="mr-2 size-4" />
            New resource
          </Button>
        }
      />

      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardDescription>Active resources</CardDescription>
            <BoxIcon className="size-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold tracking-tight">
              {resources.filter((r) => r.status === "active").length}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardDescription>Total scopes</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold tracking-tight">
              {resources.reduce((s, r) => s + r.scopes.length, 0)}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardDescription>Permissions defined</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold tracking-tight">
              {resources.reduce((s, r) => s + r.permissions, 0)}
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Resources</CardTitle>
          <CardDescription>Each row maps 1:1 to an OAuth audience (<code>aud</code> claim).</CardDescription>
        </CardHeader>
        <CardContent className="overflow-x-auto p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Identifier (audience URL)</TableHead>
                <TableHead>Scopes</TableHead>
                <TableHead>Permissions</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="w-[1%]" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {resources.map((r) => (
                <TableRow key={r.id}>
                  <TableCell className="font-medium">{r.name}</TableCell>
                  <TableCell className="max-w-[280px] truncate font-mono text-xs">
                    {r.identifier}
                  </TableCell>
                  <TableCell className="max-w-[260px]">
                    {r.scopes.length === 0 ? (
                      <span className="text-xs text-muted-foreground">—</span>
                    ) : (
                      <div className="flex flex-wrap gap-1">
                        {r.scopes.slice(0, 3).map((s) => (
                          <Badge key={s} variant="outline" className="font-mono text-[10px]">
                            {s}
                          </Badge>
                        ))}
                        {r.scopes.length > 3 && (
                          <Badge variant="outline" className="text-[10px]">
                            +{r.scopes.length - 3}
                          </Badge>
                        )}
                      </div>
                    )}
                  </TableCell>
                  <TableCell className="text-sm">{r.permissions}</TableCell>
                  <TableCell>
                    {r.status === "active" ? (
                      <Badge>active</Badge>
                    ) : (
                      <Badge variant="secondary">draft</Badge>
                    )}
                  </TableCell>
                  <TableCell>
                    <Button variant="ghost" size="sm">
                      Open
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Sheet open={open} onOpenChange={setOpen}>
        <SheetContent className="sm:max-w-md">
          <SheetHeader>
            <SheetTitle>New resource</SheetTitle>
            <SheetDescription>Define an API that Qeet ID issues access tokens for.</SheetDescription>
          </SheetHeader>
          <div className="mt-4 grid gap-4">
            <Field>
              <FieldLabel>Display name</FieldLabel>
              <Input placeholder="Acme Public API" />
            </Field>
            <Field>
              <FieldLabel>Identifier (audience)</FieldLabel>
              <Input placeholder="https://api.acme.com" className="font-mono" />
              <FieldDescription>
                Becomes the <code>aud</code> claim on issued tokens. Use the production URL.
              </FieldDescription>
            </Field>
            <Field>
              <FieldLabel>Initial scopes</FieldLabel>
              <Input placeholder="read:orders write:orders" />
              <FieldDescription>Whitespace-separated. Can be edited later.</FieldDescription>
            </Field>
          </div>
          <SheetFooter className="mt-6 flex justify-end gap-2">
            <Button variant="outline" onClick={() => setOpen(false)}>
              Cancel
            </Button>
            <Button
              onClick={() => {
                setResources((rs) => [
                  ...rs,
                  {
                    id: String(Date.now()),
                    identifier: "https://new.example.com",
                    name: "New resource",
                    audience: "new",
                    scopes: [],
                    permissions: 0,
                    status: "draft",
                  },
                ]);
                setOpen(false);
              }}
            >
              Create
            </Button>
          </SheetFooter>
        </SheetContent>
      </Sheet>
    </div>
  );
}
