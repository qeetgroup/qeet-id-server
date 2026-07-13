import {
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  CodeBlock,
  CopyableSecret,
  DataState,
  Field,
  FieldDescription,
  FieldLabel,
  Input,
  Textarea,
  TimeSince,
} from "@qeetrix/ui";
import { createFileRoute } from "@tanstack/react-router";
import {
  BadgeCheckIcon,
  CheckCircle2Icon,
  Loader2Icon,
  Trash2Icon,
  XCircleIcon,
} from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { useConfirmDialog } from "@/components/confirm-dialog";
import { PageHeader } from "@/components/page-header";
import type { ApiError } from "@/lib/api";
import {
  type IssueResult,
  useCredentials,
  useIssueCredential,
  useRevokeCredential,
  useVerifyCredential,
} from "@/lib/credentials";

export const Route = createFileRoute("/_app/developer/credentials")({
  component: CredentialsPage,
});

function CredentialsPage() {
  const { t } = useTranslation("developer");
  const [confirmDialog, openConfirm] = useConfirmDialog();
  const listQ = useCredentials();
  const issueM = useIssueCredential();
  const revokeM = useRevokeCredential();

  const [subject, setSubject] = useState("");
  const [type, setType] = useState("");
  const [claims, setClaims] = useState("{\n  \n}");
  const [ttl, setTtl] = useState(0);
  const [issued, setIssued] = useState<IssueResult | null>(null);
  const [claimsErr, setClaimsErr] = useState<string | null>(null);

  const items = listQ.data?.items ?? [];

  return (
    <div className="flex min-w-0 flex-col gap-4">
      {confirmDialog}
      <PageHeader description={t("credentials.description")} />

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">{t("credentials.issue.title")}</CardTitle>
            <CardDescription>{t("credentials.issue.description")}</CardDescription>
          </CardHeader>
          <CardContent>
            <form
              className="flex flex-col gap-3"
              onSubmit={(e) => {
                e.preventDefault();
                setClaimsErr(null);
                let parsed: Record<string, unknown> = {};
                if (claims.trim()) {
                  try {
                    parsed = JSON.parse(claims);
                  } catch {
                    setClaimsErr(t("credentials.issue.claimsError"));
                    return;
                  }
                }
                if (subject.trim() && type.trim()) {
                  issueM.mutate(
                    {
                      subject: subject.trim(),
                      type: type.trim(),
                      claims: parsed,
                      ttl_seconds: ttl,
                    },
                    { onSuccess: (r) => setIssued(r) },
                  );
                }
              }}
            >
              <Field>
                <FieldLabel htmlFor="cred-subject">{t("credentials.issue.subject")}</FieldLabel>
                <Input
                  id="cred-subject"
                  placeholder={t("credentials.issue.subjectPlaceholder")}
                  value={subject}
                  onChange={(e) => setSubject(e.target.value)}
                />
              </Field>
              <Field>
                <FieldLabel htmlFor="cred-type">{t("credentials.issue.type")}</FieldLabel>
                <Input
                  id="cred-type"
                  placeholder={t("credentials.issue.typePlaceholder")}
                  value={type}
                  onChange={(e) => setType(e.target.value)}
                />
              </Field>
              <Field>
                <FieldLabel htmlFor="cred-claims">{t("credentials.issue.claims")}</FieldLabel>
                <Textarea
                  id="cred-claims"
                  rows={4}
                  className="font-mono text-xs"
                  value={claims}
                  onChange={(e) => setClaims(e.target.value)}
                />
                {claimsErr && (
                  <FieldDescription className="text-destructive">{claimsErr}</FieldDescription>
                )}
              </Field>
              <Field className="sm:w-40">
                <FieldLabel htmlFor="cred-ttl">{t("credentials.issue.ttl")}</FieldLabel>
                <Input
                  id="cred-ttl"
                  type="number"
                  min={0}
                  value={ttl}
                  onChange={(e) => setTtl(Number(e.target.value) || 0)}
                />
              </Field>
              {issueM.error && (
                <p className="text-destructive text-sm">{(issueM.error as ApiError).message}</p>
              )}
              <Button type="submit" disabled={issueM.isPending || !subject.trim() || !type.trim()}>
                {issueM.isPending && <Loader2Icon className="animate-spin" />}
                {t("credentials.issue.submit")}
              </Button>
            </form>
            {issued && (
              <div className="mt-4 flex flex-col gap-2 rounded-lg border border-amber-500/40 bg-amber-50/40 p-4 dark:bg-amber-950/20">
                <p className="text-sm font-medium">{t("credentials.issue.signedLabel")}</p>
                <CopyableSecret value={issued.jwt} size="sm" />
              </div>
            )}
          </CardContent>
        </Card>

        <VerifyCard />
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">{t("credentials.list.title")}</CardTitle>
          <CardDescription>{t("credentials.list.description")}</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <DataState
            isLoading={listQ.isLoading}
            isError={listQ.isError}
            error={listQ.error}
            isEmpty={items.length === 0}
            emptyIcon={BadgeCheckIcon}
            emptyTitle={t("credentials.list.empty")}
            skeletonRows={2}
          >
            <ul className="divide-y">
              {items.map((c) => (
                <li key={c.id} className="flex items-center justify-between gap-4 px-6 py-3">
                  <div className="min-w-0">
                    <p className="flex items-center gap-2 text-sm font-medium">
                      {c.type}
                      {c.revoked && (
                        <Badge variant="destructive">{t("credentials.list.revoked")}</Badge>
                      )}
                    </p>
                    <p className="truncate text-xs text-muted-foreground">
                      {c.subject} · issued <TimeSince value={c.issued_at} />
                      {c.expires_at ? (
                        <>
                          {" "}
                          · expires <TimeSince value={c.expires_at} />
                        </>
                      ) : (
                        <>{t("credentials.list.noExpiry")}</>
                      )}
                    </p>
                  </div>
                  {!c.revoked && (
                    <Button
                      variant="ghost"
                      size="sm"
                      disabled={revokeM.isPending}
                      onClick={() =>
                        openConfirm({
                          title: t("credentials.confirm.title"),
                          variant: "destructive",
                          confirmLabel: t("credentials.confirm.label"),
                          onConfirm: () => revokeM.mutate(c.id),
                        })
                      }
                    >
                      <Trash2Icon /> {t("credentials.list.revokeButton")}
                    </Button>
                  )}
                </li>
              ))}
            </ul>
          </DataState>
        </CardContent>
      </Card>
    </div>
  );
}

function VerifyCard() {
  const { t } = useTranslation("developer");
  const verifyM = useVerifyCredential();
  const [jwt, setJwt] = useState("");
  const result = verifyM.data;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">{t("credentials.verify.title")}</CardTitle>
        <CardDescription>{t("credentials.verify.description")}</CardDescription>
      </CardHeader>
      <CardContent>
        <form
          className="flex flex-col gap-3"
          onSubmit={(e) => {
            e.preventDefault();
            if (jwt.trim()) verifyM.mutate(jwt.trim());
          }}
        >
          <Textarea
            rows={4}
            className="font-mono text-xs"
            placeholder="eyJhbGci…"
            value={jwt}
            onChange={(e) => setJwt(e.target.value)}
          />
          <Button type="submit" variant="outline" disabled={verifyM.isPending || !jwt.trim()}>
            {verifyM.isPending && <Loader2Icon className="animate-spin" />}
            {t("credentials.verify.submit")}
          </Button>
        </form>
        {result && (
          <div className="mt-3 flex flex-col gap-2">
            <div className="flex items-center gap-2 text-sm font-medium">
              {result.valid ? (
                <>
                  <CheckCircle2Icon className="size-4 text-emerald-600 dark:text-emerald-400" />
                  <Badge variant="success">{t("credentials.badge.valid")}</Badge>
                </>
              ) : (
                <>
                  <XCircleIcon className="text-destructive size-4" />
                  <Badge variant="destructive">{t("credentials.badge.invalid")}</Badge>
                  {result.reason && <span className="text-muted-foreground">{result.reason}</span>}
                </>
              )}
            </div>
            {result.valid && result.vc && (
              <CodeBlock language="json" value={JSON.stringify(result.vc, null, 2)} />
            )}
          </div>
        )}
        {verifyM.error && (
          <p className="mt-2 text-destructive text-sm">{(verifyM.error as ApiError).message}</p>
        )}
      </CardContent>
    </Card>
  );
}
