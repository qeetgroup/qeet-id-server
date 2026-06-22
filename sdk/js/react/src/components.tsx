"use client";

import { useState, type CSSProperties, type ReactNode } from "react";

import { usePaths, useQeetidState, useUser } from "./context.js";
import type { QeetidUser } from "./types.js";

/** Renders children only when the user is signed in. */
export function SignedIn({ children }: { children: ReactNode }) {
  return useQeetidState().isAuthenticated ? <>{children}</> : null;
}

/** Renders children only when the user is signed out. */
export function SignedOut({ children }: { children: ReactNode }) {
  return useQeetidState().isAuthenticated ? null : <>{children}</>;
}

function navigate(url: string, returnTo?: string): void {
  const u = new URL(url, window.location.origin);
  if (returnTo !== undefined) u.searchParams.set("return_to", returnTo);
  window.location.href = u.toString();
}

export interface AuthButtonProps {
  children?: ReactNode;
  className?: string;
  /** Path to return to after sign-in (defaults to the current location). */
  returnTo?: string;
}

/** A button that sends the browser to the hosted login. */
export function SignInButton({ children, className, returnTo }: AuthButtonProps) {
  const { loginUrl } = usePaths();
  return (
    <button
      type="button"
      className={className}
      onClick={() =>
        navigate(loginUrl, returnTo ?? window.location.pathname + window.location.search)
      }
    >
      {children ?? "Sign in"}
    </button>
  );
}

/** A button that signs the user out (clears the session + RP-initiated logout). */
export function SignOutButton({ children, className }: AuthButtonProps) {
  const { logoutUrl } = usePaths();
  return (
    <button type="button" className={className} onClick={() => navigate(logoutUrl)}>
      {children ?? "Sign out"}
    </button>
  );
}

function imageURL(user: QeetidUser | null | undefined): string | undefined {
  // picture (OIDC standard) / imageUrl live under QeetidUser's index signature.
  if (typeof user?.["picture"] === "string") return user["picture"];
  if (typeof user?.["imageUrl"] === "string") return user["imageUrl"];
  return undefined;
}

export interface UserButtonProps {
  className?: string;
  /** Extra menu items rendered above "Sign out" (e.g. a link to account settings). */
  menuItems?: ReactNode;
}

/**
 * A drop-in account control: an avatar/initials trigger that opens a menu with
 * the signed-in user's name + email and a "Sign out" action. Renders nothing
 * when signed out. Headless-friendly (style via `className` on the wrapper);
 * ships with minimal neutral styles so it works out of the box.
 */
export function UserButton({ className, menuItems }: UserButtonProps) {
  const { user, isAuthenticated } = useUser();
  const { logoutUrl } = usePaths();
  const [open, setOpen] = useState(false);

  if (!isAuthenticated) return null;

  const label = user?.displayName || user?.email || "Account";
  const initial = (label.trim()[0] || "?").toUpperCase();
  const img = imageURL(user);

  const trigger: CSSProperties = {
    width: 32,
    height: 32,
    borderRadius: "9999px",
    border: "1px solid rgba(0,0,0,0.1)",
    background: img ? `center/cover no-repeat url(${img})` : "#e5e7eb",
    color: "#374151",
    fontSize: 13,
    fontWeight: 600,
    cursor: "pointer",
    display: "inline-flex",
    alignItems: "center",
    justifyContent: "center",
  };
  const menu: CSSProperties = {
    position: "absolute",
    top: "calc(100% + 6px)",
    right: 0,
    minWidth: 200,
    background: "#fff",
    color: "#111827",
    border: "1px solid rgba(0,0,0,0.1)",
    borderRadius: 8,
    boxShadow: "0 8px 24px rgba(0,0,0,0.12)",
    padding: 6,
    zIndex: 50,
    fontSize: 14,
  };
  const item: CSSProperties = {
    display: "block",
    width: "100%",
    textAlign: "left",
    padding: "8px 10px",
    border: "none",
    background: "transparent",
    borderRadius: 6,
    cursor: "pointer",
    color: "inherit",
    font: "inherit",
  };

  return (
    <div className={className} style={{ position: "relative", display: "inline-block" }}>
      <button
        type="button"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label="Account menu"
        style={trigger}
        onClick={() => setOpen((o) => !o)}
      >
        {img ? "" : initial}
      </button>
      {open && (
        <>
          {/* click-away backdrop */}
          <div
            aria-hidden
            onClick={() => setOpen(false)}
            style={{ position: "fixed", inset: 0, zIndex: 40 }}
          />
          <div role="menu" style={menu}>
            <div
              style={{
                padding: "8px 10px",
                borderBottom: "1px solid rgba(0,0,0,0.08)",
                marginBottom: 4,
              }}
            >
              {user?.displayName && <div style={{ fontWeight: 600 }}>{user.displayName}</div>}
              {user?.email && (
                <div
                  style={{
                    color: "#6b7280",
                    fontSize: 12,
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                  }}
                >
                  {user.email}
                </div>
              )}
            </div>
            {menuItems}
            <button type="button" role="menuitem" style={item} onClick={() => navigate(logoutUrl)}>
              Sign out
            </button>
          </div>
        </>
      )}
    </div>
  );
}
