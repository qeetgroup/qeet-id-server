"use client";

import { useState, type FormEvent } from "react";

import { useAppearance } from "../context.js";
import { useSignUp } from "../hooks/useSignUp.js";
import { applyAppearance } from "./utils.js";
import type { Appearance } from "./types.js";

export interface SignUpProps {
  /** Tenant (organization) to register under. */
  tenantId: string;
  /** Called after successful registration. */
  onSuccess?: () => void;
  /** Called when the user clicks "Sign in instead". */
  onSignIn?: () => void;
  appearance?: Appearance;
}

/**
 * <SignUp/> is a prebuilt embedded registration form.
 * Requires `apiUrl` on <QeetIDProvider>.
 *
 *   <SignUp tenantId="t_abc" onSuccess={() => router.push("/dashboard")} />
 */
export function SignUp({ tenantId, onSuccess, onSignIn, appearance: localAppearance }: SignUpProps) {
  const providerAppearance = useAppearance();
  const appearance = { ...providerAppearance, ...localAppearance };
  const vars = applyAppearance(appearance);

  const { status, signUp } = useSignUp();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [displayName, setDisplayName] = useState("");

  const el = appearance.elements ?? {};
  const isLoading = status.step === "loading";
  const error = status.step === "error" ? status.error : null;

  if (status.step === "complete") {
    onSuccess?.();
    return null;
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    await signUp({ email, password, displayName: displayName || undefined, tenantId });
  }

  return (
    <div className={el.card} style={{ ...vars, maxWidth: 400, margin: "0 auto" }}>
      <h2 className={el.headerTitle} style={{ marginBottom: 4 }}>Create an account</h2>
      {error && (
        <p className={el.errorMessage} style={{ color: "var(--qeetid-color-danger, #ef4444)", fontSize: 13, marginBottom: 12 }}>
          {error}
        </p>
      )}
      <form onSubmit={handleSubmit}>
        <div style={{ marginBottom: 16 }}>
          <label className={el.formLabel} style={labelStyle} htmlFor="qeetid-name">Full name</label>
          <input
            id="qeetid-name"
            className={el.formInput}
            type="text"
            autoComplete="name"
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
            style={inputStyle}
          />
        </div>
        <div style={{ marginBottom: 16 }}>
          <label className={el.formLabel} style={labelStyle} htmlFor="qeetid-su-email">Email</label>
          <input
            id="qeetid-su-email"
            className={el.formInput}
            type="email"
            autoComplete="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            style={inputStyle}
          />
        </div>
        <div style={{ marginBottom: 20 }}>
          <label className={el.formLabel} style={labelStyle} htmlFor="qeetid-su-password">Password</label>
          <input
            id="qeetid-su-password"
            className={el.formInput}
            type="password"
            autoComplete="new-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
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
          {isLoading ? "Creating account…" : "Create account"}
        </button>
      </form>
      {onSignIn && (
        <p style={{ textAlign: "center", marginTop: 16, fontSize: 13, color: "var(--qeetid-color-text-muted, #6b7280)" }}>
          Already have an account?{" "}
          <button type="button" onClick={onSignIn} style={linkStyle}>Sign in</button>
        </p>
      )}
    </div>
  );
}

const inputStyle: React.CSSProperties = {
  display: "block", width: "100%", padding: "8px 12px",
  border: "1px solid var(--qeetid-color-border, #d1d5db)",
  borderRadius: "var(--qeetid-border-radius, 8px)",
  fontSize: 14, boxSizing: "border-box", outline: "none",
  background: "transparent", color: "inherit",
};
const labelStyle: React.CSSProperties = { display: "block", fontSize: 13, fontWeight: 500, marginBottom: 4 };
const primaryButtonStyle: React.CSSProperties = {
  display: "block", width: "100%", padding: "10px 16px",
  background: "var(--qeetid-color-primary, #F26D0E)", color: "#fff",
  border: "none", borderRadius: "var(--qeetid-border-radius, 8px)",
  fontSize: 14, fontWeight: 500, cursor: "pointer",
};
const linkStyle: React.CSSProperties = {
  background: "none", border: "none", color: "var(--qeetid-color-primary, #F26D0E)",
  cursor: "pointer", fontSize: "inherit", padding: 0, textDecoration: "underline",
};
