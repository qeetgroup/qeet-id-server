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
  Textarea,
} from "@qeetrix/ui";
import { createFileRoute } from "@tanstack/react-router";
import { CheckCircle2Icon, GlobeIcon, PlusIcon, XCircleIcon } from "lucide-react";
import { useState } from "react";

import { PageHeader } from "@/components/page-header";

export const Route = createFileRoute("/_app/security/threats/ip-allowlist")({ component: IpAllowlistPage });

type Rule = {
  id: string;
  cidr: string;
  label: string;
  type: "allow" | "deny";
  scope: "admin" | "all";
};

const seedRules: Rule[] = [
  { id: "1", cidr: "10.0.0.0/8", label: "Internal VPN", type: "allow", scope: "all" },
  { id: "2", cidr: "203.0.113.0/24", label: "Office NYC", type: "allow", scope: "admin" },
  { id: "3", cidr: "198.51.100.0/24", label: "Office LDN", type: "allow", scope: "admin" },
  { id: "4", cidr: "185.220.100.0/22", label: "Tor exit nodes", type: "deny", scope: "all" },
  { id: "5", cidr: "104.244.72.0/21", label: "Reported abuse", type: "deny", scope: "all" },
];

function IpAllowlistPage() {
  const [rules, setRules] = useState(seedRules);
  const [enabled, setEnabled] = useState(true);
  const [cidr, setCidr] = useState("");
  const [label, setLabel] = useState("");

  const addAllow = () => {
    if (!cidr) return;
    setRules((rs) => [...rs, { id: String(Date.now()), cidr, label: label || cidr, type: "allow", scope: "all" }]);
    setCidr("");
    setLabel("");
  };

  return (
    <div className="flex min-w-0 flex-col gap-6">
      <PageHeader
        description="CIDR ranges that may or may not reach this tenant. Deny rules win over allow rules."
        actions={
          <div className="flex items-center gap-2">
            <span className="text-sm text-muted-foreground">Enforcement</span>
            <Switch checked={enabled} onCheckedChange={setEnabled} />
          </div>
        }
      />

      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardDescription>Allow rules</CardDescription>
            <CheckCircle2Icon className="size-4 text-emerald-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold tracking-tight">
              {rules.filter((r) => r.type === "allow").length}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardDescription>Deny rules</CardDescription>
            <XCircleIcon className="size-4 text-rose-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold tracking-tight">
              {rules.filter((r) => r.type === "deny").length}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardDescription>Last enforcement</CardDescription>
            <GlobeIcon className="size-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-sm">Blocked <span className="font-mono text-xs">185.220.101.42</span></div>
            <div className="text-xs text-muted-foreground">3 minutes ago</div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Quick add</CardTitle>
          <CardDescription>Append an allow rule. Use the form for full options.</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-3 sm:grid-cols-[1fr_1fr_auto]">
          <Field>
            <FieldLabel>CIDR</FieldLabel>
            <Input
              placeholder="203.0.113.0/24"
              value={cidr}
              onChange={(e) => setCidr(e.target.value)}
              className="font-mono"
            />
            <FieldDescription>IPv4 or IPv6 range</FieldDescription>
          </Field>
          <Field>
            <FieldLabel>Label</FieldLabel>
            <Input placeholder="Office NYC" value={label} onChange={(e) => setLabel(e.target.value)} />
          </Field>
          <div className="flex items-end">
            <Button onClick={addAllow}>
              <PlusIcon className="mr-2 size-4" />
              Add allow
            </Button>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Rules</CardTitle>
          <CardDescription>Edit or remove individual entries.</CardDescription>
        </CardHeader>
        <CardContent className="overflow-x-auto p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>CIDR</TableHead>
                <TableHead>Label</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Scope</TableHead>
                <TableHead className="w-[1%]" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {rules.map((r) => (
                <TableRow key={r.id}>
                  <TableCell className="font-mono text-xs">{r.cidr}</TableCell>
                  <TableCell className="text-sm">{r.label}</TableCell>
                  <TableCell>
                    {r.type === "allow" ? (
                      <Badge variant="outline" className="text-emerald-600">allow</Badge>
                    ) : (
                      <Badge variant="destructive">deny</Badge>
                    )}
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline">{r.scope}</Badge>
                  </TableCell>
                  <TableCell>
                    <Button variant="ghost" size="sm" onClick={() => setRules((rs) => rs.filter((x) => x.id !== r.id))}>
                      Remove
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
          <CardTitle>Bulk import</CardTitle>
          <CardDescription>One CIDR per line. Lines starting with <code>#</code> are ignored.</CardDescription>
        </CardHeader>
        <CardContent>
          <Textarea
            className="min-h-[120px] font-mono text-xs"
            placeholder={"# Office\n203.0.113.0/24\n198.51.100.0/24"}
          />
          <div className="mt-3 flex justify-end">
            <Button variant="outline">Import as allow rules</Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
