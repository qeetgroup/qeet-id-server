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
  FieldError,
  FieldGroup,
  FieldLabel,
  Input,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Sheet,
  SheetClose,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
  Skeleton,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@qeetid/ui";
import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Building2Icon, Loader2Icon, PlusIcon, RefreshCwIcon } from "lucide-react";
import { useState } from "react";

import { PageHeader } from "@/components/page-header";
import { ApiError, api } from "@/lib/api";
import { tokenStore } from "@/lib/api";

export const Route = createFileRoute("/_app/organizations/tenants")({ component: TenantsPage });

type Tenant = {
  id: string;
  slug: string;
  name: string;
  status: "active" | "suspended" | "deleted";
  plan: string;
  region: string;
  created_at: string;
};

function TenantsPage() {
  const qc = useQueryClient();
  const currentTenantId = tokenStore.getTenantId();
  const [creating, setCreating] = useState(false);

  const listQ = useQuery({
    queryKey: ["tenants"],
    queryFn: () => api<{ items: Tenant[] }>("/v1/tenants"),
  });

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <PageHeader
        description="Every tenant your account has access to. Click a tenant to switch into it, or create a new one — you become its owner automatically."
        actions={
          <>
            <Button variant="outline" size="sm" onClick={() => listQ.refetch()} disabled={listQ.isFetching}>
              <RefreshCwIcon className={listQ.isFetching ? "animate-spin" : ""} />
              Refresh
            </Button>
            <Button size="sm" onClick={() => setCreating(true)}>
              <PlusIcon /> New tenant
            </Button>
          </>
        }
      />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Tenants</CardTitle>
          <CardDescription>{listQ.data?.items?.length ?? 0} total</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {listQ.isLoading ? (
            <div className="space-y-3 p-4">{[...Array(3)].map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}</div>
          ) : listQ.isError ? (
            <div className="p-6 text-sm text-destructive">{(listQ.error as Error).message}</div>
          ) : !listQ.data?.items?.length ? (
            <div className="flex flex-col items-center gap-2 p-10 text-center">
              <Building2Icon className="size-8 text-muted-foreground" />
              <p className="text-sm text-muted-foreground">No tenants yet.</p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Slug</TableHead>
                  <TableHead>Plan</TableHead>
                  <TableHead>Region</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {listQ.data.items.map((t) => (
                  <TableRow key={t.id}>
                    <TableCell className="font-medium">
                      {t.name}
                      {t.id === currentTenantId && (
                        <Badge variant="muted" className="ml-2">
                          Current
                        </Badge>
                      )}
                    </TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">{t.slug}</TableCell>
                    <TableCell><Badge variant="muted">{t.plan}</Badge></TableCell>
                    <TableCell className="text-muted-foreground">{t.region}</TableCell>
                    <TableCell>
                      <Badge variant={t.status === "active" ? "success" : "destructive"}>{t.status}</Badge>
                    </TableCell>
                    <TableCell className="text-muted-foreground">{new Date(t.created_at).toLocaleDateString()}</TableCell>
                    <TableCell className="text-right">
                      <Button
                        variant="ghost"
                        size="sm"
                        disabled={t.id === currentTenantId}
                        onClick={() => {
                          tokenStore.setTenantId(t.id);
                          qc.invalidateQueries();
                          window.location.href = "/dashboard";
                        }}
                      >
                        Switch
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <CreateTenantSheet
        open={creating}
        onOpenChange={setCreating}
        onCreated={() => qc.invalidateQueries({ queryKey: ["tenants"] })}
      />
    </div>
  );
}

type CreateTenantSheetProps = {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  onCreated: () => void;
};

function CreateTenantSheet({ open, onOpenChange, onCreated }: CreateTenantSheetProps) {
  const [plan, setPlan] = useState("free");
  const createM = useMutation({
    mutationFn: (body: { slug: string; name: string; plan: string; region: string }) =>
      api<Tenant>("/v1/tenants", { method: "POST", body }),
    onSuccess: () => {
      onCreated();
      onOpenChange(false);
    },
  });

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="w-full sm:max-w-md">
        <form
          className="flex h-full flex-col"
          onSubmit={(e) => {
            e.preventDefault();
            const data = new FormData(e.currentTarget);
            createM.mutate({
              slug: String(data.get("slug") ?? "").trim(),
              name: String(data.get("name") ?? "").trim(),
              plan,
              region: String(data.get("region") ?? "us-east-1").trim(),
            });
          }}
        >
          <SheetHeader>
            <SheetTitle>New tenant</SheetTitle>
            <SheetDescription>
              Note: this admin-scoped flow does NOT auto-assign you as owner. Use the public signup endpoint for that.
            </SheetDescription>
          </SheetHeader>
          <div className="flex-1 overflow-y-auto p-4">
            <FieldGroup>
              <Field>
                <FieldLabel htmlFor="name">Name</FieldLabel>
                <Input id="name" name="name" placeholder="Acme Corp" required />
              </Field>
              <Field>
                <FieldLabel htmlFor="slug">Slug</FieldLabel>
                <Input id="slug" name="slug" pattern="[a-z0-9-]+" minLength={2} maxLength={64} placeholder="acme" required />
                <FieldDescription>Lowercase letters, numbers, dashes. Used in URLs.</FieldDescription>
              </Field>
              <Field>
                <FieldLabel>Plan</FieldLabel>
                <Select value={plan} onValueChange={setPlan}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="free">Free</SelectItem>
                    <SelectItem value="pro">Pro</SelectItem>
                    <SelectItem value="enterprise">Enterprise</SelectItem>
                  </SelectContent>
                </Select>
              </Field>
              <Field>
                <FieldLabel htmlFor="region">Region</FieldLabel>
                <Input id="region" name="region" defaultValue="us-east-1" />
              </Field>
              {createM.error && <Field><FieldError>{(createM.error as ApiError).message}</FieldError></Field>}
            </FieldGroup>
          </div>
          <SheetFooter className="flex-row justify-end gap-2 border-t">
            <SheetClose render={<Button type="button" variant="outline" />}>Cancel</SheetClose>
            <Button type="submit" disabled={createM.isPending}>
              {createM.isPending && <Loader2Icon className="animate-spin" />}
              {createM.isPending ? "Creating…" : "Create"}
            </Button>
          </SheetFooter>
        </form>
      </SheetContent>
    </Sheet>
  );
}
