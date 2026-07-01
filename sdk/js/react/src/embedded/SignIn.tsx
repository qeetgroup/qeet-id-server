"use client";

import { useState, type FormEvent } from "react";

import { useQeetIDClient, useAppearance } from "../context.js";
import { useSignIn } from "../hooks/useSignIn.js";
import { applyAppearance } from "./utils.js";
import type { Appearance } from "./types.js";

export interface SignInProps {
  /** Called after a successful sign-in. */
  onSuccess?: () => void;
  /** Called when the user clicks "Sign up instead". */
  onSignUp?: () => void;
  /** Called when the user clicks "Forgot password". */
  onForgotPassword?: () => void;
  /** Per-instance appearance override (merged with provider-level). */
  appearance?: Appearance;
  /** Tenant scope passed to signUp (required only when self-registration is enabled). */
  tenantId?: string;
}

/**
 * <SignIn/> is a prebuilt embedded sign-in form. Place it anywhere in your
 * app; it drives authentication directly via @qeet-id/client (no redirect).
 * Requires `apiUrl` on <QeetIDProvider>.
 *
 *   <SignIn onSuccess={() => router.push("/dashboard")} />
 */
export function SignIn({ onSuccess, onSignUp, onForgotPassword, appearance: localAppearance }: SignInProps) {
  const providerAppearance = useAppearance();
  const appearance = { ...providerAppearance, ...localAppearance };
  const vars = applyAppearance(appearance);

  const { status, signIn, verifyMfa, reset } = useSignIn();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");

  const el = appearance.elements ?? {};

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    await signIn({ email, password });
  }

  async function handleMfa(e: FormEvent) {
    e.preventDefault();
    await verifyMfa({ code });
    if (status.step === "complete" || (status.step !== "error" && status.step !== "loading")) {
      onSuccess?.();
    }
  }

  if (status.step === "complete") {
    onSuccess?.();
    return null;
  }

  const isLoading = status.step === "loading";
  const error = status.step === "error" ? status.error : null;

  if (status.step === "needs_mfa") {
    return (
      <div className={el.card} style={{ ...vars, maxWidth: 400, margin: "0 auto" }}>
        <h2 className={el.headerTitle} style={{ marginBottom: 4 }}>Two-factor authentication</h2>
        <p className={el.headerSubtitle} style={{ marginBottom: 20, color: "var(--qeetid-color-text-muted, #6b7280)", fontSize: 14 }}>
          Enter the code from your authenticator app.
        </p>
        {error && (
          <p className={el.errorMessage} style={{ color: "var(--qeetid-color-danger, #ef4444)", fontSize: 13, marginBottom: 12 }}>
            {error}
          </p>
        )}
        <form onSubmit={handleMfa}>
          <div className={el.formField} style={{ marginBottom: 16 }}>
            <label className={el.formLabel} style={{ display: "block", fontSize: 13, fontWeight: 500, marginBottom: 4 }}>
              Code
            </label>
            <input
              className={el.formInput}
              type="text"
              inputMode="numeric"
              autoComplete="one-time-code"
              value={code}
              onChange={(e) => setCode(e.target.value)}
              required
              style={inputStyle}
            />
          </div>
          <button
            type="submit"
            disabled={isLoading}
            className={el.buttonPrimary ?? el.button}
            style={primaryButtonStyle}
          >
            {isLoading ? "Verifying…" : "Verify"}
          </button>
        </form>
      </div>
    );
  }

  return (
    <div className={el.card} style={{ ...vars, maxWidth: 400, margin: "0 auto" }}>
      <h2 className={el.headerTitle} style={{ marginBottom: 4 }}>Sign in</h2>
      {error && (
        <p className={el.errorMessage} style={{ color: "var(--qeetid-color-danger, #ef4444)", fontSize: 13, marginBottom: 12 }}>
          {error}
        </p>
      )}
      <form onSubmit={handleSubmit}>
        <div className={el.formField} style={{ marginBottom: 16 }}>
          <label className={el.formLabel} style={labelStyle} htmlFor="qeetid-email">Email</label>
          <input
            id="qeetid-email"
            className={el.formInput}
            type="email"
            autoComplete="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            style={inputStyle}
          />
        </div>
        <div className={el.formField} style={{ marginBottom: 20 }}>
          <label className={el.formLabel} style={labelStyle} htmlFor="qeetid-password">Password</label>
          <input
            id="qeetid-password"
            className={el.formInput}
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            style={inputStyle}
          />
          {onForgotPassword && (
            <button type="button" onClick={onForgotPassword} className={el.footerLink} style={linkStyle}>
              Forgot password?
            </button>
          )}
        </div>
        <button
          type="submit"
          disabled={isLoading}
          className={el.buttonPrimary ?? el.button}
          style={primaryButtonStyle}
        >
          {isLoading ? "Signing in…" : "Sign in"}
        </button>
      </form>
      {onSignUp && (
        <p style={{ textAlign: "center", marginTop: 16, fontSize: 13, color: "var(--qeetid-color-text-muted, #6b7280)" }}>
          No account?{" "}
          <button type="button" onClick={onSignUp} className={el.footerLink} style={linkStyle}>
            Sign up
          </button>
        </p>
      )}
    </div>
  );
}

const inputStyle: React.CSSProperties = {
  display: "block",
  width: "100%",
  padding: "8px 12px",
  border: "1px solid var(--qeetid-color-border, #d1d5db)",
  borderRadius: "var(--qeetid-border-radius, 8px)",
  fontSize: 14,
  boxSizing: "border-box",
  outline: "none",
  background: "transparent",
  color: "inherit",
};

const labelStyle: React.CSSProperties = {
  display: "block",
  fontSize: 13,
  fontWeight: 500,
  marginBottom: 4,
};

const primaryButtonStyle: React.CSSProperties = {
  display: "block",
  width: "100%",
  padding: "10px 16px",
  background: "var(--qeetid-color-primary, #F26D0E)",
  color: "#fff",
  border: "none",
  borderRadius: "var(--qeetid-border-radius, 8px)",
  fontSize: 14,
  fontWeight: 500,
  cursor: "pointer",
};

const linkStyle: React.CSSProperties = {
  background: "none",
  border: "none",
  color: "var(--qeetid-color-primary, #F26D0E)",
  cursor: "pointer",
  fontSize: "inherit",
  padding: 0,
  textDecoration: "underline",
};
