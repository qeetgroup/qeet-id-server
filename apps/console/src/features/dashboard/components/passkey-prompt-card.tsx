import {
  Button,
  buttonVariants,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@qeetrix/ui";
import { Link } from "@tanstack/react-router";
import { FingerprintIcon, XIcon, ZapIcon } from "lucide-react";
import { useState } from "react";

import { usePasskeys } from "@/lib/passkeys";

const DISMISS_KEY = "qeetid-admin-passkey-prompt-dismissed";

/**
 * Soft nudge shown on the dashboard when the signed-in user has no
 * passkey on file. Built as a dismissible card (state persisted in
 * localStorage so it doesn't reappear on every refresh).
 *
 * Hidden in three cases:
 *   1. The user already has at least one passkey.
 *   2. The list query is still loading (avoid flicker).
 *   3. The user has explicitly dismissed it.
 *
 * The card renders the nudge and its CTA routes to the passkey settings
 * page, where the register ceremony (backed by the WebAuthn register
 * begin/finish endpoints) runs.
 */
export function PasskeyPromptCard() {
  const [dismissed, setDismissed] = useState(
    () => typeof window !== "undefined" && localStorage.getItem(DISMISS_KEY) === "1",
  );
  const q = usePasskeys();

  if (dismissed) return null;
  if (q.isLoading) return null;
  if ((q.data?.items?.length ?? 0) > 0) return null;

  function handleDismiss() {
    setDismissed(true);
    try {
      localStorage.setItem(DISMISS_KEY, "1");
    } catch {
      // Private-mode tolerant: dismissed in-memory for the session.
    }
  }

  return (
    <Card className="border-info/25 bg-info/5 shadow-none hover:shadow-none">
      <CardHeader className="flex flex-row items-start justify-between gap-3">
        <div className="flex items-start gap-3">
          <span className="grid size-9 shrink-0 place-items-center rounded-lg bg-info/10 text-info ring-1 ring-info/15">
            <FingerprintIcon className="size-4" />
          </span>
          <div>
            <CardTitle className="text-sm font-semibold">
              Protect this operator account with a passkey
            </CardTitle>
            <CardDescription>
              Use Touch ID, Face ID, Windows Hello, or a security key for phishing-resistant access.
            </CardDescription>
          </div>
        </div>
        <Button variant="ghost" size="icon" aria-label="Dismiss" onClick={handleDismiss}>
          <XIcon />
        </Button>
      </CardHeader>
      <CardContent className="flex flex-wrap items-center gap-2 border-t border-info/15 pt-3">
        <Link to="/auth/login-methods/passkeys" className={buttonVariants({ size: "sm" })}>
          <ZapIcon /> Add a passkey
        </Link>
        <Button variant="ghost" size="sm" onClick={handleDismiss}>
          Not now
        </Button>
        <span className="ms-auto text-[11px] text-muted-foreground">
          Recommended for privileged operators
        </span>
      </CardContent>
    </Card>
  );
}
