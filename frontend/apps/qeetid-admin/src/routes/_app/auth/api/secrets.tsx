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
  Textarea,
} from "@qeetrix/ui";
import { createFileRoute } from "@tanstack/react-router";
import { EyeIcon, EyeOffIcon, LockKeyholeIcon, PlusIcon, RotateCcwIcon } from "lucide-react";
import { useState } from "react";

import { PageHeader } from "@/components/page-header";

export const Route = createFileRoute("/_app/auth/api/secrets")({ component: SecretsPage });

type Secret = {
  id: string;
  name: string;
  scope: string;
  type: "value" | "certificate" | "private-key";
  lastRotated: string;
  rotatesIn: string;
};

const seed: Secret[] = [
  { id: "1", name: "stripe.api_key.live", scope: "billing", type: "value", lastRotated: "2 days ago", rotatesIn: "88 days" },
  { id: "2", name: "sendgrid.api_key", scope: "notifier", type: "value", lastRotated: "12 days ago", rotatesIn: "78 days" },
  { id: "3", name: "twilio.auth_token", scope: "notifier", type: "value", lastRotated: "4 hours ago", rotatesIn: "89 days" },
  { id: "4", name: "saml.signing.crt", scope: "saml", type: "certificate", lastRotated: "30 days ago", rotatesIn: "335 days" },
  { id: "5", name: "saml.signing.key", scope: "saml", type: "private-key", lastRotated: "30 days ago", rotatesIn: "335 days" },
  { id: "6", name: "oidc.signing.es256", scope: "oidc", type: "private-key", lastRotated: "5 days ago", rotatesIn: "85 days" },
];

function typeBadge(t: Secret["type"]) {
  if (t === "certificate") return <Badge variant="secondary">certificate</Badge>;
  if (t === "private-key") return <Badge variant="destructive">private-key</Badge>;
  return <Badge variant="outline">value</Badge>;
}

function SecretsPage() {
  const [open, setOpen] = useState(false);
  const [reveal, setReveal] = useState<Record<string, boolean>>({});

  return (
    <div className="flex min-w-0 flex-col gap-6">
      <PageHeader
        description="Vault-backed secrets used by the auth platform. Values are encrypted at rest with KMS-managed keys."
        actions={
          <Button onClick={() => setOpen(true)}>
            <PlusIcon className="mr-2 size-4" />
            New secret
          </Button>
        }
      />

      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardDescription>Total secrets</CardDescription>
            <LockKeyholeIcon className="size-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold tracking-tight">{seed.length}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardDescription>Rotated &lt; 30 days</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold tracking-tight">3</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardDescription>Stale (&gt; 90 days)</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold tracking-tight">0</div>
            <p className="text-xs text-muted-foreground">Auto-rotation enabled</p>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Secrets</CardTitle>
          <CardDescription>Reveal is logged to the audit trail.</CardDescription>
        </CardHeader>
        <CardContent className="overflow-x-auto p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Scope</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Value</TableHead>
                <TableHead>Last rotated</TableHead>
                <TableHead>Rotates in</TableHead>
                <TableHead className="w-[1%]" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {seed.map((s) => (
                <TableRow key={s.id}>
                  <TableCell className="font-mono text-xs">{s.name}</TableCell>
                  <TableCell>
                    <Badge variant="outline">{s.scope}</Badge>
                  </TableCell>
                  <TableCell>{typeBadge(s.type)}</TableCell>
                  <TableCell className="font-mono text-xs">
                    {reveal[s.id] ? "sk_live_abc123def456" : "•••••••••••••••••••••"}
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">{s.lastRotated}</TableCell>
                  <TableCell className="text-xs text-muted-foreground">{s.rotatesIn}</TableCell>
                  <TableCell>
                    <div className="flex justify-end gap-1">
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => setReveal((r) => ({ ...r, [s.id]: !r[s.id] }))}
                      >
                        {reveal[s.id] ? <EyeOffIcon className="size-3" /> : <EyeIcon className="size-3" />}
                      </Button>
                      <Button size="sm" variant="ghost">
                        <RotateCcwIcon className="size-3" />
                      </Button>
                    </div>
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
            <SheetTitle>New secret</SheetTitle>
            <SheetDescription>Values are encrypted with KMS before being written.</SheetDescription>
          </SheetHeader>
          <div className="mt-4 grid gap-4">
            <Field>
              <FieldLabel>Name</FieldLabel>
              <Input placeholder="my-service.api_key" />
              <FieldDescription>Letters, numbers, dot, underscore, dash.</FieldDescription>
            </Field>
            <Field>
              <FieldLabel>Scope</FieldLabel>
              <Input placeholder="billing" />
            </Field>
            <Field>
              <FieldLabel>Value</FieldLabel>
              <Textarea className="min-h-[120px] font-mono text-xs" placeholder="sk_live_..." />
            </Field>
          </div>
          <SheetFooter className="mt-6 flex justify-end gap-2">
            <Button variant="outline" onClick={() => setOpen(false)}>
              Cancel
            </Button>
            <Button>Create</Button>
          </SheetFooter>
        </SheetContent>
      </Sheet>
    </div>
  );
}
