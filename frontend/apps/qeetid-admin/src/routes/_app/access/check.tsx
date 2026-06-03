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
} from "@qeetrix/ui";
import { createFileRoute } from "@tanstack/react-router";
import { CheckCircle2Icon, Loader2Icon, ShieldCheckIcon, XCircleIcon } from "lucide-react";
import { useTranslation } from "react-i18next";

import { PageHeader } from "@/components/page-header";
import { ApiError } from "@/lib/api";
import { type ExplainPath, useExplainCheck } from "@/lib/access-check";

export const Route = createFileRoute("/_app/access/check")({ component: AccessCheckPage });

function AccessCheckPage() {
  const { t } = useTranslation("rbac");
  const checkM = useExplainCheck();
  const result = checkM.data;

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <PageHeader title={t("check.title")} description={t("check.description")} />

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-1">
          <CardHeader>
            <CardTitle className="text-base">{t("check.runTitle")}</CardTitle>
            <CardDescription>{t("check.runDescription")}</CardDescription>
          </CardHeader>
          <CardContent>
            <form
              className="flex flex-col gap-5"
              onSubmit={(e) => {
                e.preventDefault();
                const data = new FormData(e.currentTarget);
                checkM.mutate({
                  user_id: String(data.get("user_id") ?? "").trim(),
                  permission: String(data.get("permission") ?? "").trim(),
                });
              }}
            >
              <FieldGroup>
                <Field>
                  <FieldLabel htmlFor="user_id">{t("check.userIdLabel")}</FieldLabel>
                  <Input
                    id="user_id"
                    name="user_id"
                    className="font-mono text-xs"
                    placeholder="00000000-0000-0000-0000-000000000000"
                    required
                  />
                  <FieldDescription>{t("check.userIdHelp")}</FieldDescription>
                </Field>
                <Field>
                  <FieldLabel htmlFor="permission">{t("check.permissionLabel")}</FieldLabel>
                  <Input id="permission" name="permission" placeholder="users:read" required />
                </Field>
                {checkM.error && (
                  <Field>
                    <FieldError>{(checkM.error as ApiError).message}</FieldError>
                  </Field>
                )}
              </FieldGroup>
              <div className="flex justify-end">
                <Button type="submit" disabled={checkM.isPending}>
                  {checkM.isPending ? <Loader2Icon className="animate-spin" /> : <ShieldCheckIcon />}
                  {checkM.isPending ? t("check.evaluating") : t("check.evaluate")}
                </Button>
              </div>
            </form>
          </CardContent>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="text-base">{t("check.resultTitle")}</CardTitle>
            <CardDescription>{t("check.resultDescription")}</CardDescription>
          </CardHeader>
          {/* Async result panel has no toast, so announce the allow/deny
              outcome to assistive tech via a polite live region. */}
          <CardContent aria-live="polite">
            {!result ? (
              <div className="flex flex-col items-center gap-2 py-12 text-center">
                <ShieldCheckIcon className="size-8 text-muted-foreground" />
                <p className="text-sm text-muted-foreground">{t("check.resultPlaceholder")}</p>
              </div>
            ) : (
              <div className="flex flex-col gap-5">
                <div
                  className={`flex items-start gap-3 rounded-lg border p-4 ${
                    result.allowed
                      ? "border-emerald-500/40 bg-emerald-50/50 dark:bg-emerald-950/20"
                      : "border-destructive/40 bg-destructive/5"
                  }`}
                >
                  {result.allowed ? (
                    <CheckCircle2Icon className="mt-0.5 size-5 shrink-0 text-emerald-600 dark:text-emerald-400" />
                  ) : (
                    <XCircleIcon className="mt-0.5 size-5 shrink-0 text-destructive" />
                  )}
                  <div>
                    <p className="text-sm font-semibold">
                      {result.allowed ? t("check.allowed") : t("check.denied")}
                    </p>
                    {result.reason && (
                      <p className="mt-0.5 text-sm text-muted-foreground">{result.reason}</p>
                    )}
                  </div>
                </div>

                {result.allowed && (
                  <section>
                    <h3 className="text-sm font-medium">{t("check.grantPathsTitle")}</h3>
                    <p className="mb-3 text-xs text-muted-foreground">{t("check.grantPathsHint")}</p>
                    {result.paths.length === 0 ? (
                      <p className="text-sm text-muted-foreground">{t("check.noGrantPath")}</p>
                    ) : (
                      <ul className="flex flex-col gap-2">
                        {result.paths.map((p, i) => (
                          <GrantPathRow key={`${p.role_id}-${p.via}-${i}`} path={p} />
                        ))}
                      </ul>
                    )}
                  </section>
                )}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

function GrantPathRow({ path }: { path: ExplainPath }) {
  const { t } = useTranslation("rbac");
  const isGroup = path.via.startsWith("group:");
  const viaLabel = isGroup
    ? t("check.viaGroup", { group: path.via.slice("group:".length) })
    : t("check.directAssignment");
  return (
    <li className="flex flex-col gap-2 rounded-md border bg-muted/20 p-3 sm:flex-row sm:items-center sm:justify-between">
      <div className="flex flex-wrap items-center gap-2">
        <Badge variant="default" className="font-mono">
          {path.permission}
        </Badge>
        <span className="text-xs text-muted-foreground">{t("check.grantedBy")}</span>
        <Badge variant="secondary">{path.granted_by}</Badge>
      </div>
      <div className="flex items-center gap-2">
        <Badge variant={isGroup ? "outline" : "muted"}>{viaLabel}</Badge>
        <span className="font-mono text-[10px] text-muted-foreground">
          {t("check.roleShort", { id: path.role_id.slice(0, 8) })}
        </span>
      </div>
    </li>
  );
}
