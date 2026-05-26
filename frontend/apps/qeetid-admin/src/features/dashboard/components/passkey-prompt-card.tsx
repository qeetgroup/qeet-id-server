import {
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  buttonVariants,
} from "@qeetid/ui";
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
 * Today the register endpoints return 501 (GAP-ANALYSIS P0-3); the
 * card still renders so users see the nudge — clicking the CTA routes
 * to the passkey settings page, which has its own "ceremony not
 * implemented yet" copy. Once the backend ceremony ships, this is
 * already wired.
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
    <Card className="border-sky-500/40 bg-sky-50/40 dark:bg-sky-950/15">
      <CardHeader className="flex flex-row items-start justify-between gap-3">
        <div className="flex items-start gap-3">
          <FingerprintIcon className="mt-0.5 size-6 shrink-0 text-sky-600 dark:text-sky-400" />
          <div>
            <CardTitle className="text-base">Speed up sign-in with a passkey</CardTitle>
            <CardDescription>
              Passkeys are faster than passwords and resist phishing. Your device handles the
              prompt — Touch ID, Face ID, Windows Hello, or a security key.
            </CardDescription>
          </div>
        </div>
        <Button
          variant="ghost"
          size="icon"
          aria-label="Dismiss"
          onClick={handleDismiss}
        >
          <XIcon />
        </Button>
      </CardHeader>
      <CardContent className="flex flex-wrap items-center gap-2 border-t pt-3">
        <Link
          to="/auth/login-methods/passkeys"
          className={buttonVariants({ size: "sm" })}
        >
          <ZapIcon /> Add a passkey
        </Link>
        <Button variant="ghost" size="sm" onClick={handleDismiss}>
          Not now
        </Button>
        <span className="ms-auto text-xs text-muted-foreground">
          Recommended for admins and anyone with sensitive access.
        </span>
      </CardContent>
    </Card>
  );
}
