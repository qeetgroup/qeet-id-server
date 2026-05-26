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
import { Loader2Icon, PlusIcon, RefreshCwIcon, UserIcon } from "lucide-react";
import { useState } from "react";

import { PageHeader } from "@/components/page-header";
import { ApiError, api } from "@/lib/api";
import { useTenantId } from "@/lib/auth";

export const Route = createFileRoute("/_app/users")({ component: UsersPage });

type User = {
  id: string;
  tenant_id: string;
  email: string;
  display_name?: string | null;
  phone?: string | null;
  status: "active" | "invited" | "suspended" | "deleted";
  email_verified_at?: string | null;
  created_at: string;
};

type UsersResponse = { items: User[]; next_cursor?: string };

function statusVariant(s: User["status"]) {
  switch (s) {
    case "active":
      return "success" as const;
    case "invited":
      return "warning" as const;
    case "suspended":
      return "destructive" as const;
    default:
      return "muted" as const;
  }
}

function UsersPage() {
  const tenantId = useTenantId();
  const qc = useQueryClient();
  const [creating, setCreating] = useState(false);

  const usersQ = useQuery({
    queryKey: ["users", tenantId],
    queryFn: () => api<UsersResponse>("/v1/users"),
    enabled: !!tenantId,
  });

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <PageHeader
        description="Everyone who has access to this workspace. Invite or create members directly here."
        actions={
          <>
            <Button
              variant="outline"
              size="sm"
              onClick={() => usersQ.refetch()}
              disabled={usersQ.isFetching}
            >
              <RefreshCwIcon className={usersQ.isFetching ? "animate-spin" : ""} />
              Refresh
            </Button>
            <Button size="sm" onClick={() => setCreating(true)}>
              <PlusIcon /> New user
            </Button>
          </>
        }
      />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Members</CardTitle>
          <CardDescription>
            {usersQ.data?.items?.length ?? 0} user{usersQ.data?.items?.length === 1 ? "" : "s"} in
            this tenant
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {usersQ.isLoading ? (
            <UsersTableSkeleton />
          ) : usersQ.isError ? (
            <div className="p-6 text-sm text-destructive">
              {(usersQ.error as Error).message ?? "Failed to load users"}
            </div>
          ) : !usersQ.data?.items?.length ? (
            <div className="flex flex-col items-center gap-2 p-10 text-center">
              <UserIcon className="size-8 text-muted-foreground" />
              <p className="text-sm text-muted-foreground">
                No users yet. Click <strong>New user</strong> to add the first one.
              </p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Email</TableHead>
                  <TableHead>Name</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Email verified</TableHead>
                  <TableHead>Created</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {usersQ.data.items.map((u) => (
                  <TableRow key={u.id}>
                    <TableCell className="font-medium">{u.email}</TableCell>
                    <TableCell className="text-muted-foreground">
                      {u.display_name ?? "—"}
                    </TableCell>
                    <TableCell>
                      <Badge variant={statusVariant(u.status)}>{u.status}</Badge>
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      {u.email_verified_at ? new Date(u.email_verified_at).toLocaleDateString() : "—"}
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      {new Date(u.created_at).toLocaleDateString()}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <CreateUserSheet
        open={creating}
        onOpenChange={setCreating}
        tenantId={tenantId}
        onCreated={() => qc.invalidateQueries({ queryKey: ["users"] })}
      />
    </div>
  );
}

function UsersTableSkeleton() {
  return (
    <div className="space-y-3 p-4">
      {[...Array(4)].map((_, i) => (
        <Skeleton key={i} className="h-10 w-full" />
      ))}
    </div>
  );
}

type CreateUserSheetProps = {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  tenantId: string | null;
  onCreated: () => void;
};

function CreateUserSheet({ open, onOpenChange, tenantId, onCreated }: CreateUserSheetProps) {
  const createM = useMutation({
    mutationFn: (body: {
      tenant_id: string;
      email: string;
      password: string;
      display_name?: string;
      phone?: string;
    }) => api<User>("/v1/users", { method: "POST", body }),
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
            if (!tenantId) return;
            const data = new FormData(e.currentTarget);
            createM.mutate({
              tenant_id: tenantId,
              email: String(data.get("email") ?? "").trim(),
              password: String(data.get("password") ?? ""),
              display_name: String(data.get("display_name") ?? "").trim() || undefined,
              phone: String(data.get("phone") ?? "").trim() || undefined,
            });
          }}
        >
          <SheetHeader>
            <SheetTitle>New user</SheetTitle>
            <SheetDescription>
              Creates a user under the current tenant with a password credential.
            </SheetDescription>
          </SheetHeader>

          <div className="flex-1 overflow-y-auto p-4">
            <FieldGroup>
              <Field>
                <FieldLabel htmlFor="email">Email</FieldLabel>
                <Input id="email" name="email" type="email" required />
              </Field>
              <Field>
                <FieldLabel htmlFor="display_name">Display name</FieldLabel>
                <Input id="display_name" name="display_name" type="text" />
                <FieldDescription>Optional. Shown in the user list and audit logs.</FieldDescription>
              </Field>
              <Field>
                <FieldLabel htmlFor="phone">Phone</FieldLabel>
                <Input
                  id="phone"
                  name="phone"
                  type="tel"
                  placeholder="+15555550100"
                  pattern="\+[1-9]\d{1,14}"
                />
                <FieldDescription>E.164 format. Used for SMS OTP if MFA is enabled.</FieldDescription>
              </Field>
              <Field>
                <FieldLabel htmlFor="password">Initial password</FieldLabel>
                <Input id="password" name="password" type="password" minLength={8} required />
                <FieldDescription>At least 8 characters. The user can change it later.</FieldDescription>
              </Field>
              {createM.error && (
                <Field>
                  <FieldError>{(createM.error as ApiError).message}</FieldError>
                </Field>
              )}
            </FieldGroup>
          </div>

          <SheetFooter className="flex-row justify-end gap-2 border-t">
            <SheetClose render={<Button type="button" variant="outline" />}>Cancel</SheetClose>
            <Button type="submit" disabled={createM.isPending || !tenantId}>
              {createM.isPending && <Loader2Icon className="animate-spin" />}
              {createM.isPending ? "Creating…" : "Create user"}
            </Button>
          </SheetFooter>
        </form>
      </SheetContent>
    </Sheet>
  );
}
