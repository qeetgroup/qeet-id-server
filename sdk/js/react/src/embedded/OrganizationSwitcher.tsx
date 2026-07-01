"use client";

import { useState } from "react";

import { useAppearance } from "../context.js";
import { useOrganization } from "../hooks/useOrganization.js";
import { useOrganizationList } from "../hooks/useOrganizationList.js";
import { applyAppearance } from "./utils.js";
import type { Appearance } from "./types.js";

export interface OrganizationSwitcherProps {
  /** Called after the active organization changes. */
  onOrganizationChange?: (organizationId: string) => void;
  appearance?: Appearance;
}

/**
 * <OrganizationSwitcher/> renders a dropdown that lets the user switch between
 * organizations (tenants) they belong to. Requires `apiUrl` on <QeetIDProvider>.
 *
 *   <OrganizationSwitcher onOrganizationChange={(id) => router.refresh()} />
 */
export function OrganizationSwitcher({ onOrganizationChange, appearance: localAppearance }: OrganizationSwitcherProps) {
  const providerAppearance = useAppearance();
  const appearance = { ...providerAppearance, ...localAppearance };
  const vars = applyAppearance(appearance);

  const { organization, setActive } = useOrganization();
  const { organizationList, isLoaded } = useOrganizationList();
  const [open, setOpen] = useState(false);

  if (!isLoaded) return null;
  if (organizationList.length <= 1) {
    return (
      <span style={{ ...vars, fontSize: 14, fontWeight: 500 }}>
        {organization?.name ?? organization?.id ?? "—"}
      </span>
    );
  }

  async function handleSelect(id: string) {
    setOpen(false);
    await setActive(id);
    onOrganizationChange?.(id);
  }

  return (
    <div style={{ ...vars, position: "relative", display: "inline-block" }}>
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-haspopup="listbox"
        aria-expanded={open}
        style={triggerStyle}
      >
        {organization?.name ?? organization?.id ?? "Select organization"}
        <span aria-hidden style={{ marginLeft: 6 }}>▾</span>
      </button>
      {open && (
        <>
          <div aria-hidden onClick={() => setOpen(false)} style={{ position: "fixed", inset: 0, zIndex: 40 }} />
          <ul
            role="listbox"
            style={menuStyle}
          >
            {organizationList.map((org) => (
              <li key={org.id} role="option" aria-selected={org.id === organization?.id}>
                <button
                  type="button"
                  onClick={() => handleSelect(org.id)}
                  style={{ ...menuItemStyle, fontWeight: org.id === organization?.id ? 600 : 400 }}
                >
                  {org.name ?? org.id}
                </button>
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  );
}

const triggerStyle: React.CSSProperties = {
  display: "inline-flex", alignItems: "center", padding: "6px 12px",
  border: "1px solid var(--qeetid-color-border, #d1d5db)",
  borderRadius: "var(--qeetid-border-radius, 8px)",
  background: "transparent", cursor: "pointer", fontSize: 14, color: "inherit",
};
const menuStyle: React.CSSProperties = {
  position: "absolute", top: "calc(100% + 4px)", left: 0, zIndex: 50,
  minWidth: 180, background: "var(--qeetid-color-background, #fff)", color: "inherit",
  border: "1px solid var(--qeetid-color-border, #d1d5db)",
  borderRadius: "var(--qeetid-border-radius, 8px)",
  boxShadow: "0 8px 24px rgba(0,0,0,0.1)", padding: 4, listStyle: "none", margin: 0,
};
const menuItemStyle: React.CSSProperties = {
  display: "block", width: "100%", textAlign: "left",
  padding: "8px 12px", border: "none", background: "transparent",
  borderRadius: 6, cursor: "pointer", fontSize: 14, color: "inherit",
};
