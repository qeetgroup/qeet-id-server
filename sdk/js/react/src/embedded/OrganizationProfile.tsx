"use client";

import { useAppearance } from "../context.js";
import { useOrganization } from "../hooks/useOrganization.js";
import { applyAppearance } from "./utils.js";
import type { Appearance } from "./types.js";

export interface OrganizationProfileProps {
  appearance?: Appearance;
}

/**
 * <OrganizationProfile/> displays the active organization's details.
 * Requires `apiUrl` on <QeetIDProvider>.
 *
 *   <OrganizationProfile />
 */
export function OrganizationProfile({ appearance: localAppearance }: OrganizationProfileProps) {
  const providerAppearance = useAppearance();
  const appearance = { ...providerAppearance, ...localAppearance };
  const vars = applyAppearance(appearance);
  const el = appearance.elements ?? {};

  const { organization, isLoaded } = useOrganization();

  if (!isLoaded) return null;
  if (!organization) {
    return (
      <p style={{ fontSize: 13, color: "var(--qeetid-color-text-muted, #6b7280)" }}>
        No active organization.
      </p>
    );
  }

  return (
    <div className={el.card} style={{ ...vars, maxWidth: 480, margin: "0 auto" }}>
      <h2 className={el.headerTitle} style={{ fontSize: 15, fontWeight: 600, marginBottom: 16 }}>Organization</h2>
      <dl style={{ display: "grid", gridTemplateColumns: "100px 1fr", gap: "6px 16px", fontSize: 14 }}>
        <dt style={{ color: "var(--qeetid-color-text-muted, #6b7280)", fontWeight: 500 }}>ID</dt>
        <dd style={{ margin: 0, fontFamily: "monospace", fontSize: 12 }}>{organization.id}</dd>
        {organization.name && (
          <>
            <dt style={{ color: "var(--qeetid-color-text-muted, #6b7280)", fontWeight: 500 }}>Name</dt>
            <dd style={{ margin: 0 }}>{organization.name}</dd>
          </>
        )}
      </dl>
    </div>
  );
}
