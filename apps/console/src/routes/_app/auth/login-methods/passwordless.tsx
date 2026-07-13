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
import type { ComponentType } from "react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { PageHeader } from "@/components/page-header";
import { type AuthPolicy, useAuthPolicy, useUpdateAuthPolicy } from "@/lib/auth-policy";

export const Route = createFileRoute("/_app/auth/login-methods/passwordless")({
  component: PasswordlessPage,
});

function PasswordlessPage() {
  const { t } = useTranslation("auth");
  const policyQ = useAuthPolicy();
  return (
    <div className="flex min-w-0 flex-col gap-6">
      <PageHeader description={t("loginMethods.passwordless.description")} />
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

type MethodDef = {
  key: MethodKey;
  translationKey: "passkeys" | "magicLinks" | "emailOtp" | "smsOtp";
  icon: ComponentType<{ className?: string }>;
};

const METHOD_DEFS: MethodDef[] = [
  { key: "passkey_enabled", translationKey: "passkeys", icon: FingerprintIcon },
  {
    key: "magic_link_enabled",
    translationKey: "magicLinks",
    icon: WandSparklesIcon,
  },
  { key: "otp_email_enabled", translationKey: "emailOtp", icon: MailIcon },
  { key: "otp_sms_enabled", translationKey: "smsOtp", icon: MessageSquareIcon },
];

function PasswordlessForm({ initial }: { initial: AuthPolicy }) {
  const { t } = useTranslation("auth");
  const updateM = useUpdateAuthPolicy();
  const [draft, setDraft] = useState<AuthPolicy>(initial);

  return (
    <>
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        {METHOD_DEFS.map((m) => {
          const Icon = m.icon;
          const on = draft[m.key];
          const methodTitle = t(`loginMethods.passwordless.methods.${m.translationKey}.title`);
          return (
            <Card key={m.key}>
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-base">
                  <Icon className="size-4" />
                  {methodTitle}
                </CardTitle>
                <CardDescription>
                  {t(`loginMethods.passwordless.methods.${m.translationKey}.description`)}
                </CardDescription>
              </CardHeader>
              <CardContent className="flex items-center justify-between">
                <span className="text-sm text-muted-foreground">
                  {on ? t("loginMethods.passwordless.enabled") : t("loginMethods.passwordless.off")}
                </span>
                <Switch
                  checked={on}
                  aria-label={methodTitle}
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
            <ShieldCheckIcon className="size-4" />{" "}
            {t("loginMethods.passwordless.trustedDevices.title")}
          </CardTitle>
          <CardDescription>
            {t("loginMethods.passwordless.trustedDevices.description")}
          </CardDescription>
        </CardHeader>
        <CardContent className="flex items-center justify-between">
          <span className="text-sm text-muted-foreground">
            {draft.remember_device_enabled
              ? t("loginMethods.passwordless.enabled")
              : t("loginMethods.passwordless.off")}
          </span>
          <Switch
            checked={draft.remember_device_enabled}
            aria-label={t("loginMethods.passwordless.trustedDevices.ariaLabel")}
            onCheckedChange={(v) => setDraft((d) => ({ ...d, remember_device_enabled: v }))}
          />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <KeyRoundIcon className="size-4" /> {t("loginMethods.passwordless.passkeysMgmt.title")}
          </CardTitle>
          <CardDescription>
            {t("loginMethods.passwordless.passkeysMgmt.description")}
          </CardDescription>
        </CardHeader>
      </Card>

      <div className="flex justify-end gap-2">
        <Button variant="outline" onClick={() => setDraft(initial)} disabled={updateM.isPending}>
          {t("loginMethods.passwordless.resetBtn")}
        </Button>
        <Button onClick={() => updateM.mutate(draft)} disabled={updateM.isPending}>
          {updateM.isPending
            ? t("loginMethods.passwordless.savingBtn")
            : t("loginMethods.passwordless.saveBtn")}
        </Button>
      </div>
    </>
  );
}
