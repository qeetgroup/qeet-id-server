"use client";

import { useState, type FormEvent } from "react";

import { useAppearance } from "../context.js";
import { useOrganizationList } from "../hooks/useOrganizationList.js";
import { applyAppearance } from "./utils.js";
import type { Appearance } from "./types.js";
import type { Organization } from "../hooks/useOrganization.js";

export interface CreateOrganizationProps {
  /** Called with the newly created organization after success. */
  onSuccess?: (organization: Organization) => void;
  appearance?: Appearance;
}

/**
 * <CreateOrganization/> renders a simple form to create a new organization.
 * Note: organization creation requires a backend implementation via the server
 * SDK (@qeet-id/node). This component is a UI shell — wire `onSuccess` to your
 * own server action or API route that calls `sdk.tenants.create(...)`.
 *
 *   <CreateOrganization onSuccess={(org) => router.push(`/orgs/${org.id}`)} />
 */
export function CreateOrganization({ onSuccess, appearance: localAppearance }: CreateOrganizationProps) {
  const providerAppearance = useAppearance();
  const appearance = { ...providerAppearance, ...localAppearance };
  const vars = applyAppearance(appearance);
  const el = appearance.elements ?? {};

  const [name, setName] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!name.trim()) return;
    setIsLoading(true);
    setError(null);
    try {
      // Organization creation goes through the server SDK / your API layer.
      // Emit a custom event so the host app can intercept and handle it.
      const event = new CustomEvent("qeetid:create-organization", {
        bubbles: true,
        detail: { name: name.trim() },
      });
      (e.target as HTMLElement).dispatchEvent(event);
      // If onSuccess is provided, call it with a provisional org object.
      onSuccess?.({ id: "", name: name.trim() });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create organization");
    } finally {
      setIsLoading(false);
    }
  }

  return (
    <div className={el.card} style={{ ...vars, maxWidth: 400, margin: "0 auto" }}>
      <h2 className={el.headerTitle} style={{ fontSize: 15, fontWeight: 600, marginBottom: 16 }}>
        Create organization
      </h2>
      {error && (
        <p className={el.errorMessage} style={{ color: "var(--qeetid-color-danger, #ef4444)", fontSize: 13, marginBottom: 12 }}>
          {error}
        </p>
      )}
      <form onSubmit={handleSubmit}>
        <div style={{ marginBottom: 20 }}>
          <label className={el.formLabel} style={labelStyle} htmlFor="qeetid-org-name">
            Organization name
          </label>
          <input
            id="qeetid-org-name"
            className={el.formInput}
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
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
          {isLoading ? "Creating…" : "Create organization"}
        </button>
      </form>
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
