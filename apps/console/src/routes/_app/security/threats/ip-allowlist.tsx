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
import { useTranslation } from "react-i18next";

import { PageHeader } from "@/components/page-header";
import {
  type IpAction,
  useAddIpRule,
  useCheckIp,
  useDeleteIpRule,
  useIpRules,
  useSetIpEnforcement,
} from "@/lib/ip-allowlist";

export const Route = createFileRoute("/_app/security/threats/ip-allowlist")({
  component: IpAllowlistPage,
});

function IpAllowlistPage() {
  const { t } = useTranslation("security");
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
        description={t("threats.ipAllowlist.description")}
        actions={
          <div className="flex items-center gap-2">
            <span className="text-sm text-muted-foreground">
              {t("threats.ipAllowlist.enforcement")}
            </span>
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
          {t("threats.ipAllowlist.disabledBanner")}
        </p>
      )}

      <Card>
        <CardHeader>
          <CardTitle>{t("threats.ipAllowlist.quickAdd.title")}</CardTitle>
          <CardDescription>{t("threats.ipAllowlist.quickAdd.description")}</CardDescription>
        </CardHeader>
        <CardContent>
          <form
            className="flex flex-wrap items-end gap-3"
            onSubmit={(e) => {
              e.preventDefault();
              if (!cidr.trim()) return;
              addM.mutate(
                { cidr: cidr.trim(), label: label.trim(), action },
                {
                  onSuccess: () => {
                    setCidr("");
                    setLabel("");
                  },
                },
              );
            }}
          >
            <Field className="flex-1 min-w-45">
              <FieldLabel>{t("threats.ipAllowlist.quickAdd.cidrLabel")}</FieldLabel>
              <Input
                value={cidr}
                onChange={(e) => setCidr(e.target.value)}
                placeholder="203.0.113.0/24"
                className="font-mono"
              />
            </Field>
            <Field className="flex-1 min-w-40">
              <FieldLabel>{t("threats.ipAllowlist.quickAdd.labelLabel")}</FieldLabel>
              <Input
                value={label}
                onChange={(e) => setLabel(e.target.value)}
                placeholder="Office NYC"
              />
            </Field>
            <Field>
              <FieldLabel>{t("threats.ipAllowlist.quickAdd.actionLabel")}</FieldLabel>
              <Select value={action} onValueChange={(v) => setAction(v as IpAction)}>
                <SelectTrigger className="w-30">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="allow">
                    {t("threats.ipAllowlist.quickAdd.actionAllow")}
                  </SelectItem>
                  <SelectItem value="deny">
                    {t("threats.ipAllowlist.quickAdd.actionDeny")}
                  </SelectItem>
                </SelectContent>
              </Select>
            </Field>
            <Button type="submit" disabled={addM.isPending || !cidr.trim()}>
              {t("threats.ipAllowlist.quickAdd.add")}
            </Button>
          </form>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>{t("threats.ipAllowlist.rules.title")}</CardTitle>
          <CardDescription>
            {t("threats.ipAllowlist.rules.count", { count: rules.length })}
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <DataState
            isLoading={listQ.isLoading}
            isError={listQ.isError}
            error={listQ.error}
            isEmpty={rules.length === 0}
            emptyIcon={ShieldIcon}
            emptyTitle={t("threats.ipAllowlist.rules.empty")}
            skeletonRows={3}
          >
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t("threats.ipAllowlist.rules.columns.cidr")}</TableHead>
                  <TableHead>{t("threats.ipAllowlist.rules.columns.label")}</TableHead>
                  <TableHead>{t("threats.ipAllowlist.rules.columns.action")}</TableHead>
                  <TableHead>{t("threats.ipAllowlist.rules.columns.added")}</TableHead>
                  <TableHead className="text-right">
                    {t("threats.ipAllowlist.rules.columns.actions")}
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rules.map((rule) => (
                  <TableRow key={rule.id}>
                    <TableCell className="font-mono text-xs">{rule.cidr}</TableCell>
                    <TableCell>{rule.label || "—"}</TableCell>
                    <TableCell>
                      <Badge variant={rule.action === "deny" ? "destructive" : "default"}>
                        {rule.action}
                      </Badge>
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
                        <Trash2Icon /> {t("threats.ipAllowlist.rules.remove")}
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
          <CardTitle>{t("threats.ipAllowlist.test.title")}</CardTitle>
          <CardDescription>{t("threats.ipAllowlist.test.description")}</CardDescription>
        </CardHeader>
        <CardContent>
          <form
            className="flex flex-wrap items-end gap-3"
            onSubmit={(e) => {
              e.preventDefault();
              if (testIp.trim()) checkM.mutate(testIp.trim());
            }}
          >
            <Field className="flex-1 min-w-50">
              <FieldLabel>{t("threats.ipAllowlist.test.ipLabel")}</FieldLabel>
              <Input
                value={testIp}
                onChange={(e) => setTestIp(e.target.value)}
                placeholder="198.51.100.7"
                className="font-mono"
              />
              <FieldDescription>{t("threats.ipAllowlist.test.ipHelp")}</FieldDescription>
            </Field>
            <Button type="submit" variant="outline" disabled={checkM.isPending || !testIp.trim()}>
              {t("threats.ipAllowlist.test.check")}
            </Button>
            {checkM.data && (
              <div className="flex items-center gap-2 pb-2">
                <StatusPill kind={checkM.data.allowed ? "success" : "danger"}>
                  {checkM.data.allowed
                    ? t("threats.ipAllowlist.test.allowed")
                    : t("threats.ipAllowlist.test.blocked")}
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
