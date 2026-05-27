import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  StatusPill,
  buttonVariants,
} from "@qeetid/ui";
import { Link, createFileRoute } from "@tanstack/react-router";
import {
  FingerprintIcon,
  KeyRoundIcon,
  RefreshCwIcon,
  ShieldCheckIcon,
} from "lucide-react";

import { usePasskeys } from "@/lib/passkeys";

export const Route = createFileRoute("/account/security")({ component: SecurityPage });

function SecurityPage() {
  const passkeysQ = usePasskeys();
  const passkeyCount = passkeysQ.data?.items?.length ?? 0;

  return (
    <div className="grid gap-4 md:grid-cols-2">
      {/* Password */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <KeyRoundIcon className="size-5 text-muted-foreground" />
              <CardTitle className="text-base">Password</CardTitle>
            </div>
            <StatusPill status="active" />
          </div>
          <CardDescription>
            Use a strong, unique password. We recommend a password manager.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Link
            to="/forgot-password"
            className={buttonVariants({ variant: "outline", size: "sm" })}
          >
            <RefreshCwIcon /> Reset password
          </Link>
        </CardContent>
      </Card>

      {/* Passkeys */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <FingerprintIcon className="size-5 text-muted-foreground" />
              <CardTitle className="text-base">Passkeys</CardTitle>
            </div>
            <StatusPill
              status={passkeyCount > 0 ? "active" : "pending"}
              dot={false}
            >
              {passkeyCount > 0
                ? `${passkeyCount} enrolled`
                : "Not enrolled"}
            </StatusPill>
          </div>
          <CardDescription>
            Faster, phishing-resistant sign-in using Touch ID, Face ID, Windows Hello, or a
            security key.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Link
            to="/auth/login-methods/passkeys"
            className={buttonVariants({ variant: "outline", size: "sm" })}
          >
            <FingerprintIcon /> Manage passkeys
          </Link>
        </CardContent>
      </Card>

      {/* Two-factor */}
      <Card className="md:col-span-2">
        <CardHeader>
          <div className="flex items-center gap-2">
            <ShieldCheckIcon className="size-5 text-muted-foreground" />
            <CardTitle className="text-base">Two-factor authentication</CardTitle>
          </div>
          <CardDescription>
            Add a second factor (authenticator app, SMS, or email code) to require a second
            step on every sign-in.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-2">
          <Link
            to="/auth/mfa/totp"
            className={buttonVariants({ variant: "outline", size: "sm" })}
          >
            Authenticator app (TOTP)
          </Link>
          <Link
            to="/auth/mfa/sms-email"
            className={buttonVariants({ variant: "outline", size: "sm" })}
          >
            SMS or email codes
          </Link>
          <Link
            to="/auth/mfa/recovery-codes"
            className={buttonVariants({ variant: "ghost", size: "sm" })}
          >
            Recovery codes
          </Link>
        </CardContent>
      </Card>
    </div>
  );
}
