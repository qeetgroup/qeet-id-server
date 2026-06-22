import {
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  DataState,
  Switch,
} from "@qeetrix/ui";
import { createFileRoute } from "@tanstack/react-router";
import {
  FingerprintIcon,
  KeyRoundIcon,
  MailIcon,
  MessageSquareIcon,
  ShieldCheckIcon,
  WandSparklesIcon,
} from "lucide-react";
import { useState } from "react";
import type { ComponentType } from "react";

import { PageHeader } from "@/components/page-header";
import { type AuthPolicy, useAuthPolicy, useUpdateAuthPolicy } from "@/lib/auth-policy";

export const Route = createFileRoute("/_app/auth/login-methods/passwordless")({
  component: PasswordlessPage,
});

function PasswordlessPage() {
  const policyQ = useAuthPolicy();
  return (
    <div className="flex min-w-0 flex-col gap-6">
      <PageHeader description="Passwordless sign-in methods your members can use instead of a password." />
      <DataState
        isLoading={policyQ.isLoading}
        isError={policyQ.isError}
        error={policyQ.error}
        isEmpty={false}
        skeletonRows={3}
      >
        {policyQ.data && <PasswordlessForm initial={policyQ.data} />}
      </DataState>
    </div>
  );
}

type MethodKey = "passkey_enabled" | "magic_link_enabled" | "otp_email_enabled" | "otp_sms_enabled";

const METHODS: {
  key: MethodKey;
  title: string;
  description: string;
  icon: ComponentType<{ className?: string }>;
}[] = [
  {
    key: "passkey_enabled",
    title: "Passkeys",
    description: "WebAuthn / FIDO2 — phishing-resistant, the recommended default.",
    icon: FingerprintIcon,
  },
  {
    key: "magic_link_enabled",
    title: "Magic links",
    description: "A one-time sign-in link sent to the member's email.",
    icon: WandSparklesIcon,
  },
  {
    key: "otp_email_enabled",
    title: "Email OTP",
    description: "A one-time passcode delivered by email.",
    icon: MailIcon,
  },
  {
    key: "otp_sms_enabled",
    title: "SMS OTP",
    description: "A one-time passcode delivered by text message.",
    icon: MessageSquareIcon,
  },
];

function PasswordlessForm({ initial }: { initial: AuthPolicy }) {
  const updateM = useUpdateAuthPolicy();
  const [draft, setDraft] = useState<AuthPolicy>(initial);

  return (
    <>
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        {METHODS.map((m) => {
          const Icon = m.icon;
          const on = draft[m.key];
          return (
            <Card key={m.key}>
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-base">
                  <Icon className="size-4" />
                  {m.title}
                </CardTitle>
                <CardDescription>{m.description}</CardDescription>
              </CardHeader>
              <CardContent className="flex items-center justify-between">
                <span className="text-sm text-muted-foreground">{on ? "Enabled" : "Off"}</span>
                <Switch
                  checked={on}
                  aria-label={m.title}
                  onCheckedChange={(v) => setDraft((d) => ({ ...d, [m.key]: v }))}
                />
              </CardContent>
            </Card>
          );
        })}
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <ShieldCheckIcon className="size-4" /> Trusted devices (adaptive MFA)
          </CardTitle>
          <CardDescription>
            Let members who have completed two-factor verification skip the second factor on that
            device for 30 days. New or unrecognized devices are always challenged. Off by default.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex items-center justify-between">
          <span className="text-sm text-muted-foreground">
            {draft.remember_device_enabled ? "Enabled" : "Off"}
          </span>
          <Switch
            checked={draft.remember_device_enabled}
            aria-label="Trusted devices (adaptive MFA)"
            onCheckedChange={(v) => setDraft((d) => ({ ...d, remember_device_enabled: v }))}
          />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <KeyRoundIcon className="size-4" /> Passkeys management
          </CardTitle>
          <CardDescription>
            Individual passkeys are registered and revoked per device under Login methods →
            Passkeys.
          </CardDescription>
        </CardHeader>
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
