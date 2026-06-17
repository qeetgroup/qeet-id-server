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

import { usePasskeys } from "@/lib/passkeys";
import { useSocialIdentities, useUnlinkIdentity } from "@/lib/social-identities";

export const Route = createFileRoute("/account/security")({ component: SecurityPage });

function titleCase(s: string) {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

function SecurityPage() {
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
            <StatusPill status={passkeyCount > 0 ? "active" : "pending"} dot={false}>
              {passkeyCount > 0 ? `${passkeyCount} enrolled` : "Not enrolled"}
            </StatusPill>
          </div>
          <CardDescription>
            Faster, phishing-resistant sign-in using Touch ID, Face ID, Windows Hello, or a security
            key.
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
            Add a second factor (authenticator app, SMS, or email code) to require a second step on
            every sign-in.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-2">
          <Link to="/auth/mfa/totp" className={buttonVariants({ variant: "outline", size: "sm" })}>
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

      {/* Connected accounts */}
      <Card className="md:col-span-2">
        <CardHeader>
          <div className="flex items-center gap-2">
            <LinkIcon className="size-5 text-muted-foreground" />
            <CardTitle className="text-base">Connected accounts</CardTitle>
          </div>
          <CardDescription>
            Social and identity providers linked to your account. You can sign in with any of them;
            unlink the ones you no longer use.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {identities.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No connected accounts. Link one by signing in with a provider from the sign-in screen.
            </p>
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
                      {idn.email ?? "—"} · linked {new Date(idn.linked_at).toLocaleDateString()}
                    </p>
                  </div>
                  <Button
                    variant="ghost"
                    size="sm"
                    disabled={unlink.isPending}
                    onClick={() => unlink.mutate(idn.id)}
                  >
                    <Trash2Icon /> Unlink
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
