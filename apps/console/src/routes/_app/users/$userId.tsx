import {
  Badge,
  Button,
  buttonVariants,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  DataState,
  Skeleton,
  StatusPill,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  TimeSince,
} from "@qeetrix/ui";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute, Link } from "@tanstack/react-router";
import { ArrowLeftIcon, FileSearchIcon, MailIcon, PhoneIcon } from "lucide-react";
import { useTranslation } from "react-i18next";

import { useConfirmDialog } from "@/components/confirm-dialog";
import { api } from "@/lib/api";
import { useTenantId } from "@/lib/auth";

export const Route = createFileRoute("/_app/users/$userId")({
  component: UserDetailPage,
});

type User = {
  id: string;
  tenant_id: string;
  email: string;
  display_name?: string | null;
  phone?: string | null;
  status: "active" | "invited" | "suspended" | "deleted";
  email_verified_at?: string | null;
  phone_verified_at?: string | null;
  metadata?: Record<string, unknown> | null;
  created_at: string;
  updated_at: string;
};

type AuditEvent = {
  id: string;
  action: string;
  resource_type: string;
  resource_id?: string | null;
  ip?: string | null;
  created_at: string;
};

function UserDetailPage() {
  const { t } = useTranslation("users");
  const [confirmDialog, openConfirm] = useConfirmDialog();
  const { userId } = Route.useParams();
  const tenantId = useTenantId();

  const userQ = useQuery({
    queryKey: ["user", userId],
    queryFn: () => api<User>(`/v1/users/${userId}`),
  });

  // Recent audit events authored by this user. Filtered server-side via
  // the actor_user_id parameter the audit list endpoint already accepts.
  const auditQ = useQuery({
    queryKey: ["user-activity", userId, tenantId],
    queryFn: () =>
      api<{ items: AuditEvent[] }>(`/v1/tenants/${tenantId}/audit`, {
        query: { actor_user_id: userId, limit: 10 },
      }),
    enabled: !!tenantId,
  });

  const qc = useQueryClient();
  // Admin account-recovery: clear the user's MFA so they can re-enroll. Gated
  // server-side on user.write; audited as mfa.admin_reset.
  const resetMfa = useMutation({
    mutationFn: () => api<{ message: string }>(`/v1/users/${userId}/mfa`, { method: "DELETE" }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["user", userId] });
      qc.invalidateQueries({ queryKey: ["user-activity", userId] });
    },
    meta: { successMessage: "Multi-factor authentication reset for this user" },
  });

  return (
    <div className="flex min-w-0 flex-col gap-4">
      {confirmDialog}
      <Link
        to="/users"
        className="inline-flex w-fit items-center gap-1 text-sm text-muted-foreground underline-offset-2 hover:text-foreground hover:underline"
      >
        <ArrowLeftIcon className="size-3" /> {t("detail.backLink")}
      </Link>

      {/* Identity card */}
      <Card>
        <CardHeader>
          {userQ.isLoading ? (
            <>
              <Skeleton className="h-5 w-48" />
              <Skeleton className="mt-2 h-4 w-64" />
            </>
          ) : userQ.isError ? (
            <CardTitle className="text-base text-destructive">
              {(userQ.error as Error).message}
            </CardTitle>
          ) : userQ.data ? (
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <CardTitle className="text-base">
                  {userQ.data.display_name || userQ.data.email}
                </CardTitle>
                <CardDescription className="flex flex-wrap items-center gap-2">
                  <span className="inline-flex items-center gap-1 font-mono text-xs">
                    <MailIcon className="size-3" /> {userQ.data.email}
                  </span>
                  {userQ.data.phone && (
                    <span className="inline-flex items-center gap-1 font-mono text-xs">
                      <PhoneIcon className="size-3" /> {userQ.data.phone}
                    </span>
                  )}
                </CardDescription>
              </div>
              <StatusPill status={userQ.data.status} />
            </div>
          ) : null}
        </CardHeader>
        {userQ.data && (
          <CardContent className="grid gap-3 sm:grid-cols-2">
            <Field label={t("detail.fieldUserId")} value={userQ.data.id} mono />
            <Field label={t("detail.fieldTenant")} value={userQ.data.tenant_id} mono />
            <Field
              label={t("detail.fieldEmailVerified")}
              valueNode={
                userQ.data.email_verified_at ? (
                  <TimeSince value={userQ.data.email_verified_at} />
                ) : (
                  <Badge variant="warning">{t("detail.unverified")}</Badge>
                )
              }
            />
            <Field
              label={t("detail.fieldPhoneVerified")}
              valueNode={
                userQ.data.phone_verified_at ? (
                  <TimeSince value={userQ.data.phone_verified_at} />
                ) : (
                  <span className="text-muted-foreground">—</span>
                )
              }
            />
            <Field
              label={t("detail.fieldCreated")}
              valueNode={<TimeSince value={userQ.data.created_at} />}
            />
            <Field
              label={t("detail.fieldLastUpdated")}
              valueNode={<TimeSince value={userQ.data.updated_at} />}
            />
          </CardContent>
        )}
      </Card>

      {/* Recent activity */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">{t("detail.activityTitle")}</CardTitle>
          <CardDescription>
            Last 10 audit events where this user was the actor.{" "}
            <Link to="/security/audit-logs" className="underline">
              View full audit log
            </Link>
            .
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <DataState
            isLoading={auditQ.isLoading}
            isError={auditQ.isError}
            error={auditQ.error}
            isEmpty={!auditQ.data?.items?.length}
            emptyIcon={FileSearchIcon}
            emptyTitle={t("detail.activityEmpty")}
            skeletonRows={3}
          >
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t("detail.colWhen")}</TableHead>
                  <TableHead>{t("detail.colAction")}</TableHead>
                  <TableHead>{t("detail.colResource")}</TableHead>
                  <TableHead>{t("detail.colIp")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {auditQ.data?.items?.map((e) => (
                  <TableRow key={e.id}>
                    <TableCell>
                      <TimeSince value={e.created_at} className="font-mono text-xs" />
                    </TableCell>
                    <TableCell className="font-medium">{e.action}</TableCell>
                    <TableCell className="text-muted-foreground">
                      {e.resource_type}
                      {e.resource_id && (
                        <span className="ml-1 font-mono text-xs">
                          ({e.resource_id.slice(0, 8)}…)
                        </span>
                      )}
                    </TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">
                      {e.ip ?? "—"}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </DataState>
        </CardContent>
      </Card>

      {/* Quick links */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">{t("detail.quickTitle")}</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-2">
          <Link to="/users/sessions" className={buttonVariants({ variant: "outline", size: "sm" })}>
            {t("detail.allSessionsBtn")}
          </Link>
          <Link to="/access/roles" className={buttonVariants({ variant: "outline", size: "sm" })}>
            {t("detail.manageRolesBtn")}
          </Link>
          <Button
            variant="outline"
            size="sm"
            disabled={resetMfa.isPending}
            onClick={() =>
              openConfirm({
                title: t("detail.resetMfaConfirmTitle"),
                description: t("detail.resetMfaConfirmDescription"),
                variant: "destructive",
                confirmLabel: t("detail.resetMfaConfirmLabel"),
                onConfirm: () => resetMfa.mutate(),
              })
            }
          >
            {resetMfa.isPending ? t("detail.resetMfaPendingBtn") : t("detail.resetMfaBtn")}
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}

interface FieldProps {
  label: string;
  value?: string;
  valueNode?: React.ReactNode;
  mono?: boolean;
}

function Field({ label, value, valueNode, mono }: FieldProps) {
  return (
    <div className="flex flex-col gap-0.5">
      <span className="text-xs uppercase tracking-wide text-muted-foreground">{label}</span>
      {valueNode ?? <span className={mono ? "font-mono text-xs" : "text-sm"}>{value ?? "—"}</span>}
    </div>
  );
}
