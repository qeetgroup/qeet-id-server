import {
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
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  StatusPill,
  Switch,
} from "@qeetrix/ui";
import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { PageHeader } from "@/components/page-header";
import { type AuthPolicy, useAuthPolicy, useUpdateAuthPolicy } from "@/lib/auth-policy";

export const Route = createFileRoute("/_app/auth/login-methods/magic-links")({ component: MagicLinksPage });

const TTL_VALUES = [5, 15, 30, 60, 240, 1440];

function MagicLinksPage() {
  const { t } = useTranslation("auth");
  const policyQ = useAuthPolicy();
  return (
    <div className="flex min-w-0 flex-col gap-6">
      <PageHeader description={t("loginMethods.magicLinks.description")} />
      <DataState
        isLoading={policyQ.isLoading}
        isError={policyQ.isError}
        error={policyQ.error}
        isEmpty={false}
        skeletonRows={2}
      >
        {policyQ.data && <MagicLinkForm initial={policyQ.data} />}
      </DataState>
    </div>
  );
}

function MagicLinkForm({ initial }: { initial: AuthPolicy }) {
  const { t } = useTranslation("auth");
  const updateM = useUpdateAuthPolicy();
  const [draft, setDraft] = useState<AuthPolicy>(initial);

  const TTL_OPTIONS = [
    { value: TTL_VALUES[0], label: t("loginMethods.magicLinks.ttl5m") },
    { value: TTL_VALUES[1], label: t("loginMethods.magicLinks.ttl15m") },
    { value: TTL_VALUES[2], label: t("loginMethods.magicLinks.ttl30m") },
    { value: TTL_VALUES[3], label: t("loginMethods.magicLinks.ttl1h") },
    { value: TTL_VALUES[4], label: t("loginMethods.magicLinks.ttl4h") },
    { value: TTL_VALUES[5], label: t("loginMethods.magicLinks.ttl24h") },
  ];

  const dirty =
    draft.magic_link_enabled !== initial.magic_link_enabled ||
    draft.magic_link_ttl_minutes !== initial.magic_link_ttl_minutes;

  // Snap a possibly-custom TTL onto the nearest preset for the selector.
  const ttlValue = TTL_OPTIONS.some((o) => o.value === draft.magic_link_ttl_minutes)
    ? String(draft.magic_link_ttl_minutes)
    : "60";

  return (
    <>
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>{t("loginMethods.magicLinks.title")}</CardTitle>
              <CardDescription>{t("loginMethods.magicLinks.subtitle")}</CardDescription>
            </div>
            <div className="flex items-center gap-2">
              <StatusPill kind={draft.magic_link_enabled ? "success" : "muted"}>
                {draft.magic_link_enabled ? t("loginMethods.magicLinks.enabled") : t("loginMethods.magicLinks.disabled")}
              </StatusPill>
              <Switch
                checked={draft.magic_link_enabled}
                onCheckedChange={(v) => setDraft((d) => ({ ...d, magic_link_enabled: v }))}
              />
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <Field className="max-w-xs">
            <FieldLabel id="magic-link-ttl-label">{t("loginMethods.magicLinks.ttlLabel")}</FieldLabel>
            <Select
              value={ttlValue}
              onValueChange={(v) => setDraft((d) => ({ ...d, magic_link_ttl_minutes: Number(v) }))}
              disabled={!draft.magic_link_enabled}
            >
              <SelectTrigger aria-labelledby="magic-link-ttl-label">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {TTL_OPTIONS.map((o) => (
                  <SelectItem key={o.value} value={String(o.value)}>
                    {o.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <FieldDescription>{t("loginMethods.magicLinks.ttlHelp")}</FieldDescription>
          </Field>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">{t("loginMethods.magicLinks.howTitle")}</CardTitle>
          <CardDescription>
            The user enters their email, receives a single-use link, and is signed in when they open it.
            Links are consumed on first use and can&apos;t be replayed. Manage the email&apos;s wording under
            Settings → Email templates (the <code>magic_link</code> template).
          </CardDescription>
        </CardHeader>
      </Card>

      <div className="flex justify-end gap-2">
        <Button variant="outline" onClick={() => setDraft(initial)} disabled={updateM.isPending}>
          {t("loginMethods.magicLinks.resetBtn")}
        </Button>
        <Button onClick={() => updateM.mutate(draft)} disabled={updateM.isPending || !dirty}>
          {updateM.isPending ? t("loginMethods.magicLinks.savingBtn") : t("loginMethods.magicLinks.saveBtn")}
        </Button>
      </div>
    </>
  );
}
