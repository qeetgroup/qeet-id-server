import {
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  Sheet,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@qeetid/ui";
import { createFileRoute } from "@tanstack/react-router";
import { CheckCircle2Icon, DownloadIcon, PlusIcon, UploadIcon, WorkflowIcon } from "lucide-react";
import { useState } from "react";

import { PageHeader } from "@/components/page-header";

export const Route = createFileRoute("/_app/auth/connections/saml")({ component: SamlPage });

const connections = [
  {
    id: "1",
    name: "Acme — Entra ID",
    idp: "Microsoft Entra ID",
    entityId: "https://sts.windows.net/tenantid/",
    status: "active",
    users: 4218,
    lastSync: "12m ago",
  },
  {
    id: "2",
    name: "Acme — Okta",
    idp: "Okta",
    entityId: "http://www.okta.com/exk1abc23def",
    status: "active",
    users: 2104,
    lastSync: "8m ago",
  },
  {
    id: "3",
    name: "Contoso Pilot",
    idp: "Ping Identity",
    entityId: "https://pingidentity.com/idp/contoso",
    status: "draft",
    users: 0,
    lastSync: "—",
  },
];

const steps = [
  "Identify IdP",
  "Upload metadata",
  "Map attributes",
  "Test SSO",
  "Activate",
];

function SamlPage() {
  const [open, setOpen] = useState(false);
  const [step, setStep] = useState(0);

  return (
    <div className="flex min-w-0 flex-col gap-6">
      <PageHeader
        description="Service-provider–initiated SAML 2.0 connections to enterprise IdPs."
        actions={
          <>
            <Button variant="outline">
              <DownloadIcon className="mr-2 size-4" />
              Download SP metadata
            </Button>
            <Button onClick={() => setOpen(true)}>
              <PlusIcon className="mr-2 size-4" />
              New connection
            </Button>
          </>
        }
      />

      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardDescription>Active connections</CardDescription>
            <WorkflowIcon className="size-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold tracking-tight">
              {connections.filter((c) => c.status === "active").length}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardDescription>Federated users</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold tracking-tight">
              {connections.reduce((s, c) => s + c.users, 0).toLocaleString()}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardDescription>SSO logins (24h)</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold tracking-tight">3,420</div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Connections</CardTitle>
          <CardDescription>One row per IdP. JIT provisioning runs on every successful assertion.</CardDescription>
        </CardHeader>
        <CardContent className="overflow-x-auto p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>IdP</TableHead>
                <TableHead>Entity ID</TableHead>
                <TableHead>Users</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Last sync</TableHead>
                <TableHead className="w-[1%]" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {connections.map((c) => (
                <TableRow key={c.id}>
                  <TableCell className="font-medium">{c.name}</TableCell>
                  <TableCell>{c.idp}</TableCell>
                  <TableCell className="max-w-[260px] truncate font-mono text-xs">{c.entityId}</TableCell>
                  <TableCell className="text-sm">{c.users.toLocaleString()}</TableCell>
                  <TableCell>
                    {c.status === "active" ? (
                      <Badge variant="default">active</Badge>
                    ) : (
                      <Badge variant="secondary">draft</Badge>
                    )}
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">{c.lastSync}</TableCell>
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
        <SheetContent className="sm:max-w-xl">
          <SheetHeader>
            <SheetTitle>New SAML connection</SheetTitle>
            <SheetDescription>5-step setup wizard. Cancel any time — drafts are saved.</SheetDescription>
          </SheetHeader>

          <ol className="mt-4 flex flex-wrap gap-2 text-xs">
            {steps.map((s, i) => (
              <li
                key={s}
                className={`flex items-center gap-1 rounded-md border px-2 py-1 ${
                  i === step ? "border-primary bg-primary/10 text-primary" : "text-muted-foreground"
                }`}
              >
                <span className="font-mono">{i + 1}.</span>
                {s}
                {i < step && <CheckCircle2Icon className="size-3 text-emerald-500" />}
              </li>
            ))}
          </ol>

          <div className="mt-6 space-y-4 text-sm">
            {step === 0 && (
              <>
                <p>Choose your IdP to apply the right defaults.</p>
                <div className="grid grid-cols-2 gap-2">
                  {["Microsoft Entra ID", "Okta", "Google Workspace", "Ping Identity", "OneLogin", "Other"].map((p) => (
                    <Button key={p} variant="outline" className="justify-start">
                      {p}
                    </Button>
                  ))}
                </div>
              </>
            )}
            {step === 1 && (
              <>
                <p>Upload IdP metadata XML or paste a metadata URL.</p>
                <div className="flex flex-col gap-2 rounded-md border border-dashed p-4 text-center text-sm text-muted-foreground">
                  <UploadIcon className="mx-auto size-6" />
                  Drop metadata.xml here or click to browse
                </div>
              </>
            )}
            {step === 2 && (
              <p>Map IdP claims to Qeet ID attributes — email, given_name, family_name, groups.</p>
            )}
            {step === 3 && (
              <p>
                Click "Test SSO" — we'll redirect to your IdP and back. The assertion is decoded and validated
                without provisioning any users.
              </p>
            )}
            {step === 4 && <p>Flip the connection to active. JIT provisioning starts immediately.</p>}
          </div>

          <SheetFooter className="mt-6 flex justify-between">
            <Button variant="outline" disabled={step === 0} onClick={() => setStep(step - 1)}>
              Back
            </Button>
            {step < steps.length - 1 ? (
              <Button onClick={() => setStep(step + 1)}>Continue</Button>
            ) : (
              <Button onClick={() => setOpen(false)}>Activate</Button>
            )}
          </SheetFooter>
        </SheetContent>
      </Sheet>
    </div>
  );
}
