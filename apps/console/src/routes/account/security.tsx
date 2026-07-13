import {
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  StatusPill,
  buttonVariants,
} from "@qeetrix/ui";
import { Link, createFileRoute } from "@tanstack/react-router";
import {
  FingerprintIcon,
  KeyRoundIcon,
  LinkIcon,
  RefreshCwIcon,
  ShieldCheckIcon,
  Trash2Icon,
} from "lucide-react";
import { useTranslation } from "react-i18next";

import { usePasskeys } from "@/lib/passkeys";
import { useSocialIdentities, useUnlinkIdentity } from "@/lib/social-identities";

export const Route = createFileRoute("/account/security")({ component: SecurityPage });

function titleCase(s: string) {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

function SecurityPage() {
  const { t } = useTranslation("account");
  const passkeysQ = usePasskeys();
  const passkeyCount = passkeysQ.data?.items?.length ?? 0;
  const identitiesQ = useSocialIdentities();
  const identities = identitiesQ.data?.items ?? [];
  const unlink = useUnlinkIdentity();

  return (
    <div className="grid gap-4 md:grid-cols-2">
      {/* Password */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <KeyRoundIcon className="size-5 text-muted-foreground" />
              <CardTitle className="text-base">{t("security.password.title")}</CardTitle>
            </div>
            <StatusPill status="active" />
          </div>
          <CardDescription>{t("security.password.description")}</CardDescription>
        </CardHeader>
        <CardContent>
          <Link
            to="/forgot-password"
            className={buttonVariants({ variant: "outline", size: "sm" })}
          >
            <RefreshCwIcon /> {t("security.password.reset")}
          </Link>
        </CardContent>
      </Card>

      {/* Passkeys */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <FingerprintIcon className="size-5 text-muted-foreground" />
              <CardTitle className="text-base">{t("security.passkeys.title")}</CardTitle>
            </div>
            <StatusPill status={passkeyCount > 0 ? "active" : "pending"} dot={false}>
              {passkeyCount > 0
                ? t("security.passkeys.enrolled", { count: passkeyCount })
                : t("security.passkeys.notEnrolled")}
            </StatusPill>
          </div>
          <CardDescription>{t("security.passkeys.description")}</CardDescription>
        </CardHeader>
        <CardContent>
          <Link
            to="/auth/login-methods/passkeys"
            className={buttonVariants({ variant: "outline", size: "sm" })}
          >
            <FingerprintIcon /> {t("security.passkeys.manage")}
          </Link>
        </CardContent>
      </Card>

      {/* Two-factor */}
      <Card className="md:col-span-2">
        <CardHeader>
          <div className="flex items-center gap-2">
            <ShieldCheckIcon className="size-5 text-muted-foreground" />
            <CardTitle className="text-base">{t("security.mfa.title")}</CardTitle>
          </div>
          <CardDescription>{t("security.mfa.description")}</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-2">
          <Link to="/auth/mfa/totp" className={buttonVariants({ variant: "outline", size: "sm" })}>
            {t("security.mfa.totp")}
          </Link>
          <Link
            to="/auth/mfa/sms-email"
            className={buttonVariants({ variant: "outline", size: "sm" })}
          >
            {t("security.mfa.smsEmail")}
          </Link>
          <Link
            to="/auth/mfa/recovery-codes"
            className={buttonVariants({ variant: "ghost", size: "sm" })}
          >
            {t("security.mfa.recoveryCodes")}
          </Link>
        </CardContent>
      </Card>

      {/* Connected accounts */}
      <Card className="md:col-span-2">
        <CardHeader>
          <div className="flex items-center gap-2">
            <LinkIcon className="size-5 text-muted-foreground" />
            <CardTitle className="text-base">{t("security.connected.title")}</CardTitle>
          </div>
          <CardDescription>{t("security.connected.description")}</CardDescription>
        </CardHeader>
        <CardContent>
          {identities.length === 0 ? (
            <p className="text-sm text-muted-foreground">{t("security.connected.empty")}</p>
          ) : (
            <ul className="divide-y">
              {identities.map((idn) => (
                <li
                  key={idn.id}
                  className="flex items-center justify-between gap-4 py-3 first:pt-0 last:pb-0"
                >
                  <div className="min-w-0">
                    <p className="text-sm font-medium">{titleCase(idn.provider)}</p>
                    <p className="truncate text-xs text-muted-foreground">
                      {idn.email ?? "—"}{" "}
                      {t("security.connected.linkedAt", {
                        date: new Date(idn.linked_at).toLocaleDateString(),
                      })}
                    </p>
                  </div>
                  <Button
                    variant="ghost"
                    size="sm"
                    disabled={unlink.isPending}
                    onClick={() => unlink.mutate(idn.id)}
                  >
                    <Trash2Icon /> {t("security.connected.unlink")}
                  </Button>
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
