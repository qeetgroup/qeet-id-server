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

import { PageHeader } from "@/components/page-header";
import { type AuthPolicy, useAuthPolicy, useUpdateAuthPolicy } from "@/lib/auth-policy";

export const Route = createFileRoute("/_app/auth/login-methods/magic-links")({ component: MagicLinksPage });

const TTL_OPTIONS = [
  { value: 5, label: "5 minutes" },
  { value: 15, label: "15 minutes" },
  { value: 30, label: "30 minutes" },
  { value: 60, label: "1 hour" },
  { value: 240, label: "4 hours" },
  { value: 1440, label: "24 hours" },
];

function MagicLinksPage() {
  const policyQ = useAuthPolicy();
  return (
    <div className="flex min-w-0 flex-col gap-6">
      <PageHeader description="Passwordless sign-in via a one-time link emailed to the user. Links are single-use and expire after the configured lifetime." />
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
  const updateM = useUpdateAuthPolicy();
  const [draft, setDraft] = useState<AuthPolicy>(initial);
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
              <CardTitle>Magic-link sign-in</CardTitle>
              <CardDescription>Allow members to sign in with a one-time email link.</CardDescription>
            </div>
            <div className="flex items-center gap-2">
              <StatusPill kind={draft.magic_link_enabled ? "success" : "muted"}>
                {draft.magic_link_enabled ? "Enabled" : "Disabled"}
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
            <FieldLabel>Link lifetime</FieldLabel>
            <Select
              value={ttlValue}
              onValueChange={(v) => setDraft((d) => ({ ...d, magic_link_ttl_minutes: Number(v) }))}
              disabled={!draft.magic_link_enabled}
            >
              <SelectTrigger>
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
            <FieldDescription>How long a link stays valid after it's sent. Shorter is safer.</FieldDescription>
          </Field>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">How it works</CardTitle>
          <CardDescription>
            The user enters their email, receives a single-use link, and is signed in when they open it.
            Links are consumed on first use and can&apos;t be replayed. Manage the email&apos;s wording under
            Settings → Email templates (the <code>magic_link</code> template).
          </CardDescription>
        </CardHeader>
      </Card>

      <div className="flex justify-end gap-2">
        <Button variant="outline" onClick={() => setDraft(initial)} disabled={updateM.isPending}>
          Reset
        </Button>
        <Button onClick={() => updateM.mutate(draft)} disabled={updateM.isPending || !dirty}>
          {updateM.isPending ? "Saving…" : "Save changes"}
        </Button>
      </div>
    </>
  );
}
