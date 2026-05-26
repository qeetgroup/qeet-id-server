import {
  AlertDialog,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
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
  StatusPill,
  buttonVariants,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  TimeSince,
} from "@qeetid/ui";
import { Link, createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  KeyRoundIcon,
  Loader2Icon,
  PencilIcon,
  PlusIcon,
  RefreshCwIcon,
  Trash2Icon,
  UploadCloudIcon,
  UserIcon,
} from "lucide-react";
import { useState } from "react";

import { PageHeader } from "@/components/page-header";
import { ApiError, api, tokenStore } from "@/lib/api";
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

function UsersPage() {
  const tenantId = useTenantId();
  const currentUserId = tokenStore.getUserId();
  const qc = useQueryClient();
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<User | null>(null);
  const [settingPassword, setSettingPassword] = useState<User | null>(null);
  const [confirmingDelete, setConfirmingDelete] = useState<string | null>(null);

  const usersQ = useQuery({
    queryKey: ["users", tenantId],
    queryFn: () => api<UsersResponse>("/v1/users"),
    enabled: !!tenantId,
  });

  const deleteM = useMutation({
    mutationFn: (id: string) => api<void>(`/v1/users/${id}`, { method: "DELETE" }),
    onSuccess: () => {
      setConfirmingDelete(null);
      qc.invalidateQueries({ queryKey: ["users"] });
    },
    meta: { successMessage: "User deleted" },
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
            <Link
              to="/users/import"
              className={buttonVariants({ variant: "outline", size: "sm" })}
            >
              <UploadCloudIcon /> Import
            </Link>
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
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {usersQ.data.items.map((u) => {
                  const isSelf = u.id === currentUserId;
                  return (
                    <TableRow key={u.id}>
                      <TableCell className="font-medium">
                        {u.email}
                        {isSelf && (
                          <Badge variant="muted" className="ml-2">
                            You
                          </Badge>
                        )}
                      </TableCell>
                      <TableCell className="text-muted-foreground">
                        {u.display_name ?? "—"}
                      </TableCell>
                      <TableCell>
                        <StatusPill status={u.status} />
                      </TableCell>
                      <TableCell>
                        {u.email_verified_at ? (
                          <TimeSince value={u.email_verified_at} />
                        ) : (
                          <span className="text-muted-foreground">—</span>
                        )}
                      </TableCell>
                      <TableCell>
                        <TimeSince value={u.created_at} />
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex items-center justify-end gap-1">
                          <Button
                            variant="ghost"
                            size="icon"
                            aria-label="Edit user"
                            onClick={() => setEditing(u)}
                          >
                            <PencilIcon />
                          </Button>
                          <Button
                            variant="ghost"
                            size="icon"
                            aria-label="Set password"
                            onClick={() => setSettingPassword(u)}
                          >
                            <KeyRoundIcon />
                          </Button>
                          <Button
                            variant="ghost"
                            size="icon"
                            aria-label="Delete user"
                            disabled={isSelf}
                            title={isSelf ? "You can't delete your own account here" : "Delete user"}
                            onClick={() => setConfirmingDelete(u.id)}
                          >
                            <Trash2Icon className="text-destructive" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  );
                })}
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

      <EditUserSheet
        user={editing}
        isSelf={!!editing && editing.id === currentUserId}
        onOpenChange={(o) => !o && setEditing(null)}
        onSaved={() => {
          setEditing(null);
          qc.invalidateQueries({ queryKey: ["users"] });
        }}
      />

      <SetPasswordSheet
        user={settingPassword}
        onOpenChange={(o) => !o && setSettingPassword(null)}
        onSaved={() => setSettingPassword(null)}
      />

      <AlertDialog
        open={!!confirmingDelete}
        onOpenChange={(o) => {
          if (!o && !deleteM.isPending) setConfirmingDelete(null);
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete this user?</AlertDialogTitle>
            <AlertDialogDescription>
              {(() => {
                const target = usersQ.data?.items?.find((u) => u.id === confirmingDelete);
                return target ? (
                  <>
                    This soft-deletes{" "}
                    <span className="font-medium text-foreground">{target.email}</span>. Their
                    sessions and API keys keep working until they expire — revoke those separately
                    if you need an immediate cut-off.
                  </>
                ) : (
                  "This soft-deletes the user."
                );
              })()}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleteM.isPending}>Cancel</AlertDialogCancel>
            <Button
              variant="destructive"
              disabled={deleteM.isPending}
              onClick={() => confirmingDelete && deleteM.mutate(confirmingDelete)}
            >
              {deleteM.isPending && <Loader2Icon className="animate-spin" />}
              {deleteM.isPending ? "Deleting…" : "Delete"}
            </Button>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
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
    meta: { successMessage: "User created" },
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

type EditUserSheetProps = {
  user: User | null;
  isSelf: boolean;
  onOpenChange: (o: boolean) => void;
  onSaved: () => void;
};

type UpdateBody = {
  display_name?: string | null;
  phone?: string | null;
  status?: "active" | "suspended";
};

function EditUserSheet({ user, isSelf, onOpenChange, onSaved }: EditUserSheetProps) {
  // Reset selected status when the editing target changes.
  const [trackedId, setTrackedId] = useState<string | null>(null);
  const [status, setStatus] = useState<"active" | "suspended">(
    user?.status === "suspended" ? "suspended" : "active",
  );
  if (user && user.id !== trackedId) {
    setTrackedId(user.id);
    setStatus(user.status === "suspended" ? "suspended" : "active");
  }

  const updateM = useMutation({
    mutationFn: (body: UpdateBody) =>
      api<User>(`/v1/users/${user!.id}`, { method: "PATCH", body }),
    onSuccess: onSaved,
    meta: { successMessage: "User updated" },
  });

  return (
    <Sheet open={!!user} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="w-full sm:max-w-md">
        {user && (
          <form
            className="flex h-full flex-col"
            onSubmit={(e) => {
              e.preventDefault();
              const data = new FormData(e.currentTarget);
              const displayName = String(data.get("display_name") ?? "").trim();
              const phone = String(data.get("phone") ?? "").trim();
              updateM.mutate({
                display_name: displayName || null,
                phone: phone || null,
                // Don't allow suspending yourself.
                ...(isSelf ? {} : { status }),
              });
            }}
          >
            <SheetHeader>
              <SheetTitle>Edit user</SheetTitle>
              <SheetDescription>
                Email is immutable. To change a password use the Set password action.
              </SheetDescription>
            </SheetHeader>

            <div className="flex-1 overflow-y-auto p-4">
              <FieldGroup>
                <Field>
                  <FieldLabel htmlFor="edit-email">Email</FieldLabel>
                  <Input id="edit-email" value={user.email} readOnly disabled />
                </Field>
                <Field>
                  <FieldLabel htmlFor="edit-display-name">Display name</FieldLabel>
                  <Input
                    id="edit-display-name"
                    name="display_name"
                    defaultValue={user.display_name ?? ""}
                    maxLength={200}
                  />
                </Field>
                <Field>
                  <FieldLabel htmlFor="edit-phone">Phone</FieldLabel>
                  <Input
                    id="edit-phone"
                    name="phone"
                    type="tel"
                    defaultValue={user.phone ?? ""}
                    placeholder="+15555550100"
                    pattern="\+[1-9]\d{1,14}"
                  />
                  <FieldDescription>E.164 format. Leave blank to clear.</FieldDescription>
                </Field>
                <Field>
                  <FieldLabel>Status</FieldLabel>
                  <Select
                    value={status}
                    onValueChange={(v) => v && setStatus(v as "active" | "suspended")}
                    disabled={isSelf}
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="active">Active</SelectItem>
                      <SelectItem value="suspended">Suspended</SelectItem>
                    </SelectContent>
                  </Select>
                  <FieldDescription>
                    {isSelf
                      ? "You can't suspend your own account from this screen."
                      : "Suspending prevents sign-in but keeps the account."}
                  </FieldDescription>
                </Field>
                {updateM.error && (
                  <Field>
                    <FieldError>{(updateM.error as ApiError).message}</FieldError>
                  </Field>
                )}
              </FieldGroup>
            </div>

            <SheetFooter className="flex-row justify-end gap-2 border-t">
              <SheetClose render={<Button type="button" variant="outline" />}>Cancel</SheetClose>
              <Button type="submit" disabled={updateM.isPending}>
                {updateM.isPending && <Loader2Icon className="animate-spin" />}
                {updateM.isPending ? "Saving…" : "Save changes"}
              </Button>
            </SheetFooter>
          </form>
        )}
      </SheetContent>
    </Sheet>
  );
}

type SetPasswordSheetProps = {
  user: User | null;
  onOpenChange: (o: boolean) => void;
  onSaved: () => void;
};

function SetPasswordSheet({ user, onOpenChange, onSaved }: SetPasswordSheetProps) {
  const setM = useMutation({
    mutationFn: (body: { password: string }) =>
      api<void>(`/v1/users/${user!.id}/password`, { method: "POST", body }),
    onSuccess: onSaved,
    meta: { successMessage: "Password updated" },
  });

  return (
    <Sheet open={!!user} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="w-full sm:max-w-md">
        {user && (
          <form
            className="flex h-full flex-col"
            onSubmit={(e) => {
              e.preventDefault();
              const data = new FormData(e.currentTarget);
              const password = String(data.get("password") ?? "");
              const confirm = String(data.get("confirm") ?? "");
              if (password !== confirm) {
                setM.reset();
                // Surface the mismatch by throwing into the form. Easiest:
                // rely on browser validity by setting the custom message.
                const el = e.currentTarget.elements.namedItem("confirm") as HTMLInputElement;
                el.setCustomValidity("Passwords don't match");
                el.reportValidity();
                return;
              }
              setM.mutate({ password });
            }}
          >
            <SheetHeader>
              <SheetTitle>Set new password</SheetTitle>
              <SheetDescription>
                Sets a new password for{" "}
                <span className="font-medium text-foreground">{user.email}</span>. The user&apos;s
                existing sessions stay valid until they expire — revoke them from{" "}
                <span className="font-mono text-xs">Security › Sessions</span> if you need an
                immediate sign-out.
              </SheetDescription>
            </SheetHeader>

            <div className="flex-1 overflow-y-auto p-4">
              <FieldGroup>
                <Field>
                  <FieldLabel htmlFor="new-password">New password</FieldLabel>
                  <Input
                    id="new-password"
                    name="password"
                    type="password"
                    minLength={8}
                    maxLength={256}
                    required
                    autoComplete="new-password"
                  />
                  <FieldDescription>Minimum 8 characters.</FieldDescription>
                </Field>
                <Field>
                  <FieldLabel htmlFor="confirm-password">Confirm new password</FieldLabel>
                  <Input
                    id="confirm-password"
                    name="confirm"
                    type="password"
                    minLength={8}
                    maxLength={256}
                    required
                    autoComplete="new-password"
                    onInput={(e) => (e.currentTarget as HTMLInputElement).setCustomValidity("")}
                  />
                </Field>
                {setM.error && (
                  <Field>
                    <FieldError>{(setM.error as ApiError).message}</FieldError>
                  </Field>
                )}
                {setM.isSuccess && (
                  <Field>
                    <FieldDescription className="text-success">
                      Password updated.
                    </FieldDescription>
                  </Field>
                )}
              </FieldGroup>
            </div>

            <SheetFooter className="flex-row justify-end gap-2 border-t">
              <SheetClose render={<Button type="button" variant="outline" />}>Cancel</SheetClose>
              <Button type="submit" disabled={setM.isPending}>
                {setM.isPending && <Loader2Icon className="animate-spin" />}
                {setM.isPending ? "Saving…" : "Update password"}
              </Button>
            </SheetFooter>
          </form>
        )}
      </SheetContent>
    </Sheet>
  );
}
