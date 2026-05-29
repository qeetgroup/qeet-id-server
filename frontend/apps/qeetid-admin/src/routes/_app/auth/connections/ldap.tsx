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
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Switch,
} from "@qeetid/ui";
import { createFileRoute } from "@tanstack/react-router";
import { ServerIcon, ShieldCheckIcon } from "lucide-react";
import { useState } from "react";

import { PageHeader } from "@/components/page-header";

export const Route = createFileRoute("/_app/auth/connections/ldap")({ component: LdapPage });

function LdapPage() {
  const [enabled, setEnabled] = useState(false);
  const [tls, setTls] = useState(true);

  return (
    <div className="flex min-w-0 flex-col gap-6">
      <PageHeader
        description="Bridge on-prem Active Directory or generic LDAPv3 directories. Scheduled for v1.5."
        actions={
          <Badge variant="secondary" className="gap-1">
            <ShieldCheckIcon className="size-3" />
            Preview · v1.5
          </Badge>
        }
      />

      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <div>
            <CardTitle>Connection</CardTitle>
            <CardDescription>Outbound from the Qeet ID LDAP connector to your directory.</CardDescription>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-sm text-muted-foreground">Enabled</span>
            <Switch checked={enabled} onCheckedChange={setEnabled} />
          </div>
        </CardHeader>
        <CardContent className="grid gap-6 md:grid-cols-2">
          <Field>
            <FieldLabel>Directory type</FieldLabel>
            <Select defaultValue="ad">
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="ad">Active Directory</SelectItem>
                <SelectItem value="openldap">OpenLDAP</SelectItem>
                <SelectItem value="freeipa">FreeIPA</SelectItem>
                <SelectItem value="generic">Generic LDAPv3</SelectItem>
              </SelectContent>
            </Select>
          </Field>
          <Field>
            <FieldLabel>Host</FieldLabel>
            <Input placeholder="ldap.corp.example.com" className="font-mono" />
            <FieldDescription>Port defaults to 636 (LDAPS) when TLS is on.</FieldDescription>
          </Field>
          <Field>
            <FieldLabel>Bind DN</FieldLabel>
            <Input placeholder="cn=qeetid-svc,ou=ServiceAccounts,dc=corp,dc=example,dc=com" className="font-mono" />
          </Field>
          <Field>
            <FieldLabel>Bind password</FieldLabel>
            <Input type="password" placeholder="••••••••" />
          </Field>
          <Field>
            <FieldLabel>User base DN</FieldLabel>
            <Input placeholder="ou=People,dc=corp,dc=example,dc=com" className="font-mono" />
          </Field>
          <Field>
            <FieldLabel>Group base DN</FieldLabel>
            <Input placeholder="ou=Groups,dc=corp,dc=example,dc=com" className="font-mono" />
          </Field>
          <Field>
            <FieldLabel>User filter</FieldLabel>
            <Input defaultValue="(&(objectClass=user)(mail=*))" className="font-mono text-xs" />
          </Field>
          <Field>
            <FieldLabel>Group filter</FieldLabel>
            <Input defaultValue="(objectClass=group)" className="font-mono text-xs" />
          </Field>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Security</CardTitle>
        </CardHeader>
        <CardContent className="grid gap-6 md:grid-cols-2">
          <Field>
            <div className="flex items-center justify-between gap-4">
              <div>
                <FieldLabel>Require TLS (LDAPS)</FieldLabel>
                <FieldDescription>Disallow plaintext LDAP. Strongly recommended.</FieldDescription>
              </div>
              <Switch checked={tls} onCheckedChange={setTls} />
            </div>
          </Field>
          <Field>
            <FieldLabel>Server certificate</FieldLabel>
            <Input type="file" accept=".pem,.crt" />
            <FieldDescription>Optional CA bundle for pinning self-signed certs.</FieldDescription>
          </Field>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Sync</CardTitle>
          <CardDescription>Run an incremental import every interval.</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div className="text-sm">
            <span className="text-muted-foreground">Status: </span>
            <Badge variant="outline">never run</Badge>
          </div>
          <div className="flex flex-wrap gap-2">
            <Select defaultValue="15m">
              <SelectTrigger className="w-[180px]">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="5m">Every 5 minutes</SelectItem>
                <SelectItem value="15m">Every 15 minutes</SelectItem>
                <SelectItem value="1h">Every hour</SelectItem>
                <SelectItem value="manual">Manual only</SelectItem>
              </SelectContent>
            </Select>
            <Button variant="outline">
              <ServerIcon className="mr-2 size-4" />
              Test connection
            </Button>
            <Button>Run sync now</Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
