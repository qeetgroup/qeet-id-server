import {
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  CopyableSecret,
  DataState,
  Field,
  FieldLabel,
  Input,
} from "@qeetrix/ui";
import { createFileRoute } from "@tanstack/react-router";
import { CheckCircle2Icon, GlobeIcon, Loader2Icon, Trash2Icon } from "lucide-react";
import { useState } from "react";

import { PageHeader } from "@/components/page-header";
import { ApiError } from "@/lib/api";
import {
  useAddDomain,
  useDomains,
  useRemoveDomain,
  useVerifyDomain,
  type TenantDomain,
} from "@/lib/domains";

export const Route = createFileRoute("/_app/organizations/domains")({ component: DomainsPage });

function DomainsPage() {
  const domainsQ = useDomains();
  const addM = useAddDomain();
  const [newDomain, setNewDomain] = useState("");
  const items = domainsQ.data?.items ?? [];

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <PageHeader description="Prove ownership of your email domains to enable organization SSO and just-in-time provisioning. Add a DNS TXT record, then verify." />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Add a domain</CardTitle>
          <CardDescription>Enter the email domain your members use, e.g. acme.com.</CardDescription>
        </CardHeader>
        <CardContent>
          <form
            className="flex items-end gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              if (newDomain.trim())
                addM.mutate(newDomain.trim(), { onSuccess: () => setNewDomain("") });
            }}
          >
            <Field className="flex-1">
              <FieldLabel htmlFor="domain">Domain</FieldLabel>
              <Input
                id="domain"
                placeholder="acme.com"
                value={newDomain}
                onChange={(e) => setNewDomain(e.target.value)}
              />
            </Field>
            <Button type="submit" disabled={addM.isPending || !newDomain.trim()}>
              {addM.isPending && <Loader2Icon className="animate-spin" />}
              Add domain
            </Button>
          </form>
          {addM.error && (
            <p className="mt-2 text-destructive text-sm">{(addM.error as ApiError).message}</p>
          )}
        </CardContent>
      </Card>

      <DataState
        isLoading={domainsQ.isLoading}
        isError={domainsQ.isError}
        error={domainsQ.error}
        isEmpty={items.length === 0}
        emptyIcon={GlobeIcon}
        emptyTitle="No domains added yet."
        emptyDescription="Add a domain above to start the verification flow."
        skeletonRows={2}
      >
        <div className="flex flex-col gap-4">
          {items.map((d) => (
            <DomainCard key={d.id} domain={d} />
          ))}
        </div>
      </DataState>
    </div>
  );
}

function DomainCard({ domain }: { domain: TenantDomain }) {
  const verifyM = useVerifyDomain();
  const removeM = useRemoveDomain();
  const verified = !!domain.verified_at;

  return (
    <Card>
      <CardHeader>
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0">
            <CardTitle className="flex items-center gap-2 text-base">
              <GlobeIcon className="size-4 text-muted-foreground" />
              <span className="font-mono">{domain.domain}</span>
              {verified ? (
                <Badge variant="success">
                  <CheckCircle2Icon className="size-3" /> Verified
                </Badge>
              ) : (
                <Badge variant="outline">Pending</Badge>
              )}
            </CardTitle>
          </div>
          <Button
            variant="ghost"
            size="sm"
            disabled={removeM.isPending}
            onClick={() => {
              if (confirm(`Remove ${domain.domain}?`)) removeM.mutate(domain.id);
            }}
          >
            <Trash2Icon /> Remove
          </Button>
        </div>
      </CardHeader>
      {!verified && (
        <CardContent className="flex flex-col gap-3">
          <CardDescription>
            Add this TXT record to your DNS, then click Verify. Changes can take a few minutes to
            propagate.
          </CardDescription>
          <div className="grid gap-2 sm:grid-cols-[auto_1fr]">
            <span className="text-sm text-muted-foreground">Name</span>
            <CopyableSecret value={domain.dns_record_name} size="sm" />
            <span className="text-sm text-muted-foreground">Type</span>
            <span className="font-mono text-sm">{domain.dns_record_type}</span>
            <span className="text-sm text-muted-foreground">Value</span>
            <CopyableSecret value={domain.dns_record_value} size="sm" />
          </div>
          {verifyM.error && (
            <p className="text-destructive text-sm">{(verifyM.error as ApiError).message}</p>
          )}
          <div>
            <Button onClick={() => verifyM.mutate(domain.id)} disabled={verifyM.isPending}>
              {verifyM.isPending && <Loader2Icon className="animate-spin" />}
              Verify
            </Button>
          </div>
        </CardContent>
      )}
    </Card>
  );
}
