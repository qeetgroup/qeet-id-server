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
  Slider,
  Switch,
} from "@qeetrix/ui";
import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";

import { PageHeader } from "@/components/page-header";
import { type AuthPolicy, useAuthPolicy, useUpdateAuthPolicy } from "@/lib/auth-policy";

export const Route = createFileRoute("/_app/auth/login-methods/password")({ component: PasswordPage });

function PasswordPage() {
  const policyQ = useAuthPolicy();
  return (
    <div className="flex min-w-0 flex-col gap-6">
      <PageHeader description="Password sign-in and the complexity rules enforced when members set or change a password." />
      <DataState
        isLoading={policyQ.isLoading}
        isError={policyQ.isError}
        error={policyQ.error}
        isEmpty={false}
        skeletonRows={3}
      >
        {policyQ.data && <PasswordForm initial={policyQ.data} />}
      </DataState>
    </div>
  );
}

function PasswordForm({ initial }: { initial: AuthPolicy }) {
  const updateM = useUpdateAuthPolicy();
  const [draft, setDraft] = useState<AuthPolicy>(initial);
  const set = <K extends keyof AuthPolicy>(k: K, v: AuthPolicy[K]) => setDraft((d) => ({ ...d, [k]: v }));

  return (
    <>
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <div>
            <CardTitle>Password authentication</CardTitle>
            <CardDescription>Allow members to sign in with an email and password.</CardDescription>
          </div>
          <Switch checked={draft.password_enabled} onCheckedChange={(v) => set("password_enabled", v)} />
        </CardHeader>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Complexity</CardTitle>
          <CardDescription>Enforced when a member sets or changes their password.</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-6 md:grid-cols-2">
          <Field>
            <FieldLabel>Minimum length: {draft.password_min_length}</FieldLabel>
            <Slider
              value={[draft.password_min_length]}
              onValueChange={(v) => set("password_min_length", Array.isArray(v) ? (v[0] ?? 8) : v)}
              min={8}
              max={64}
              step={1}
            />
            <FieldDescription>Between 8 and 64 characters.</FieldDescription>
          </Field>
          <div className="flex flex-col gap-4">
            <Field>
              <div className="flex items-center justify-between gap-4">
                <FieldLabel>Require an uppercase letter</FieldLabel>
                <Switch
                  checked={draft.password_require_uppercase}
                  onCheckedChange={(v) => set("password_require_uppercase", v)}
                />
              </div>
            </Field>
            <Field>
              <div className="flex items-center justify-between gap-4">
                <FieldLabel>Require a number</FieldLabel>
                <Switch
                  checked={draft.password_require_number}
                  onCheckedChange={(v) => set("password_require_number", v)}
                />
              </div>
            </Field>
            <Field>
              <div className="flex items-center justify-between gap-4">
                <FieldLabel>Require a symbol</FieldLabel>
                <Switch
                  checked={draft.password_require_symbol}
                  onCheckedChange={(v) => set("password_require_symbol", v)}
                />
              </div>
            </Field>
          </div>
        </CardContent>
      </Card>

      <div className="flex justify-end gap-2">
        <Button variant="outline" onClick={() => setDraft(initial)} disabled={updateM.isPending}>
          Reset
        </Button>
        <Button onClick={() => updateM.mutate(draft)} disabled={updateM.isPending}>
          {updateM.isPending ? "Saving…" : "Save changes"}
        </Button>
      </div>
    </>
  );
}
