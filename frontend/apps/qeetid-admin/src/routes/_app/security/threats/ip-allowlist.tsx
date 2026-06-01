import {
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  DataState,
  Field,
  FieldDescription,
  FieldLabel,
  Input,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  StatusPill,
  Switch,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  TimeSince,
} from "@qeetrix/ui";
import { createFileRoute } from "@tanstack/react-router";
import { ShieldIcon, Trash2Icon } from "lucide-react";
import { useState } from "react";

import { PageHeader } from "@/components/page-header";
import {
  type IpAction,
  useAddIpRule,
  useCheckIp,
  useDeleteIpRule,
  useIpRules,
  useSetIpEnforcement,
} from "@/lib/ip-allowlist";

export const Route = createFileRoute("/_app/security/threats/ip-allowlist")({ component: IpAllowlistPage });

function IpAllowlistPage() {
  const listQ = useIpRules();
  const setEnforce = useSetIpEnforcement();
  const addM = useAddIpRule();
  const deleteM = useDeleteIpRule();
  const checkM = useCheckIp();

  const [cidr, setCidr] = useState("");
  const [label, setLabel] = useState("");
  const [action, setAction] = useState<IpAction>("allow");
  const [testIp, setTestIp] = useState("");

  const enabled = listQ.data?.enabled ?? false;
  const rules = listQ.data?.items ?? [];

  return (
    <div className="flex min-w-0 flex-col gap-6">
      <PageHeader
        description="CIDR ranges that may or may not reach this tenant. Deny rules win over allow rules; if any allow rule exists, an address must match one."
        actions={
          <div className="flex items-center gap-2">
            <span className="text-sm text-muted-foreground">Enforcement</span>
            <Switch
              checked={enabled}
              onCheckedChange={(v) => setEnforce.mutate(v)}
              disabled={setEnforce.isPending || listQ.isLoading}
            />
          </div>
        }
      />

      {!enabled && rules.length > 0 && (
        <p className="rounded-md border border-dashed px-3 py-2 text-sm text-muted-foreground">
          Enforcement is off — these rules are saved but not applied. Toggle it on once you&apos;ve confirmed your own address is allowed.
        </p>
      )}

      <Card>
        <CardHeader>
          <CardTitle>Quick add</CardTitle>
          <CardDescription>Add a CIDR range or a single IP address.</CardDescription>
        </CardHeader>
        <CardContent>
          <form
            className="flex flex-wrap items-end gap-3"
            onSubmit={(e) => {
              e.preventDefault();
              if (!cidr.trim()) return;
              addM.mutate(
                { cidr: cidr.trim(), label: label.trim(), action },
                { onSuccess: () => { setCidr(""); setLabel(""); } },
              );
            }}
          >
            <Field className="flex-1 min-w-[180px]">
              <FieldLabel>CIDR / IP</FieldLabel>
              <Input value={cidr} onChange={(e) => setCidr(e.target.value)} placeholder="203.0.113.0/24" className="font-mono" />
            </Field>
            <Field className="flex-1 min-w-[160px]">
              <FieldLabel>Label</FieldLabel>
              <Input value={label} onChange={(e) => setLabel(e.target.value)} placeholder="Office NYC" />
            </Field>
            <Field>
              <FieldLabel>Action</FieldLabel>
              <Select value={action} onValueChange={(v) => setAction(v as IpAction)}>
                <SelectTrigger className="w-[120px]">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="allow">Allow</SelectItem>
                  <SelectItem value="deny">Deny</SelectItem>
                </SelectContent>
              </Select>
            </Field>
            <Button type="submit" disabled={addM.isPending || !cidr.trim()}>
              Add rule
            </Button>
          </form>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Rules</CardTitle>
          <CardDescription>{rules.length} rule{rules.length === 1 ? "" : "s"}</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <DataState
            isLoading={listQ.isLoading}
            isError={listQ.isError}
            error={listQ.error}
            isEmpty={rules.length === 0}
            emptyIcon={ShieldIcon}
            emptyTitle="No IP rules yet."
            skeletonRows={3}
          >
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>CIDR</TableHead>
                  <TableHead>Label</TableHead>
                  <TableHead>Action</TableHead>
                  <TableHead>Added</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rules.map((rule) => (
                  <TableRow key={rule.id}>
                    <TableCell className="font-mono text-xs">{rule.cidr}</TableCell>
                    <TableCell>{rule.label || "—"}</TableCell>
                    <TableCell>
                      <Badge variant={rule.action === "deny" ? "destructive" : "default"}>{rule.action}</Badge>
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      <TimeSince value={rule.created_at} />
                    </TableCell>
                    <TableCell className="text-right">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => deleteM.mutate(rule.id)}
                        disabled={deleteM.isPending}
                      >
                        <Trash2Icon /> Remove
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </DataState>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Test an address</CardTitle>
          <CardDescription>Evaluate an IP against the current rules before turning enforcement on.</CardDescription>
        </CardHeader>
        <CardContent>
          <form
            className="flex flex-wrap items-end gap-3"
            onSubmit={(e) => {
              e.preventDefault();
              if (testIp.trim()) checkM.mutate(testIp.trim());
            }}
          >
            <Field className="flex-1 min-w-[200px]">
              <FieldLabel>IP address</FieldLabel>
              <Input value={testIp} onChange={(e) => setTestIp(e.target.value)} placeholder="198.51.100.7" className="font-mono" />
              <FieldDescription>Checked exactly as the rules would apply at request time.</FieldDescription>
            </Field>
            <Button type="submit" variant="outline" disabled={checkM.isPending || !testIp.trim()}>
              Check
            </Button>
            {checkM.data && (
              <div className="flex items-center gap-2 pb-2">
                <StatusPill kind={checkM.data.allowed ? "success" : "danger"}>
                  {checkM.data.allowed ? "Allowed" : "Blocked"}
                </StatusPill>
                <span className="text-xs text-muted-foreground">{checkM.data.reason}</span>
              </div>
            )}
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
