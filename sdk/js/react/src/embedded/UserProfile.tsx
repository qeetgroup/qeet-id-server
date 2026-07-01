"use client";

import { useAppearance, useQeetIDClient } from "../context.js";
import { usePasskeys } from "../hooks/usePasskeys.js";
import { useSession } from "../hooks/useSession.js";
import { useUser } from "../context.js";
import { applyAppearance } from "./utils.js";
import type { Appearance } from "./types.js";

export interface UserProfileProps {
  appearance?: Appearance;
}

/**
 * <UserProfile/> displays the signed-in user's profile, active sessions, and
 * registered passkeys with management actions. Requires `apiUrl` on
 * <QeetIDProvider>.
 *
 *   <UserProfile />
 */
export function UserProfile({ appearance: localAppearance }: UserProfileProps) {
  const providerAppearance = useAppearance();
  const appearance = { ...providerAppearance, ...localAppearance };
  const vars = applyAppearance(appearance);
  const el = appearance.elements ?? {};

  const { user, isAuthenticated } = useUser();
  const { passkeys, remove: removePasskey, register } = usePasskeys();
  const { sessions, revoke } = useSession();

  if (!isAuthenticated) return null;

  return (
    <div className={el.card} style={{ ...vars, maxWidth: 560, margin: "0 auto" }}>
      <section style={{ marginBottom: 28 }}>
        <h2 className={el.headerTitle} style={sectionHeadStyle}>Profile</h2>
        <dl style={{ display: "grid", gridTemplateColumns: "120px 1fr", gap: "6px 16px", fontSize: 14 }}>
          {user?.displayName && (
            <>
              <dt style={{ color: "var(--qeetid-color-text-muted, #6b7280)", fontWeight: 500 }}>Name</dt>
              <dd style={{ margin: 0 }}>{user.displayName}</dd>
            </>
          )}
          {user?.email && (
            <>
              <dt style={{ color: "var(--qeetid-color-text-muted, #6b7280)", fontWeight: 500 }}>Email</dt>
              <dd style={{ margin: 0 }}>{user.email}</dd>
            </>
          )}
        </dl>
      </section>

      <section style={{ marginBottom: 28 }}>
        <h2 className={el.headerTitle} style={sectionHeadStyle}>Passkeys</h2>
        {passkeys.length === 0 ? (
          <p style={{ fontSize: 13, color: "var(--qeetid-color-text-muted, #6b7280)" }}>No passkeys registered.</p>
        ) : (
          <ul style={{ listStyle: "none", margin: 0, padding: 0 }}>
            {passkeys.map((pk) => (
              <li key={pk.id} style={listItemStyle}>
                <span>{pk.name ?? pk.id}</span>
                <button type="button" onClick={() => removePasskey(pk.id)} style={dangerLinkStyle}>Remove</button>
              </li>
            ))}
          </ul>
        )}
        <button type="button" onClick={register} style={secondaryButtonStyle}>Add a passkey</button>
      </section>

      <section>
        <h2 className={el.headerTitle} style={sectionHeadStyle}>Active sessions</h2>
        {sessions.length === 0 ? (
          <p style={{ fontSize: 13, color: "var(--qeetid-color-text-muted, #6b7280)" }}>No active sessions.</p>
        ) : (
          <ul style={{ listStyle: "none", margin: 0, padding: 0 }}>
            {sessions.map((s) => (
              <li key={s.id} style={listItemStyle}>
                <span style={{ fontSize: 13 }}>
                  {s.id}{s.current ? <strong> (current)</strong> : null}
                </span>
                {!s.current && (
                  <button type="button" onClick={() => revoke(s.id)} style={dangerLinkStyle}>Revoke</button>
                )}
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}

const sectionHeadStyle: React.CSSProperties = { fontSize: 15, fontWeight: 600, marginBottom: 12 };
const listItemStyle: React.CSSProperties = {
  display: "flex", justifyContent: "space-between", alignItems: "center",
  padding: "8px 0", borderBottom: "1px solid var(--qeetid-color-border, #e5e7eb)", fontSize: 14,
};
const secondaryButtonStyle: React.CSSProperties = {
  marginTop: 12, padding: "6px 14px", border: "1px solid var(--qeetid-color-border, #d1d5db)",
  borderRadius: "var(--qeetid-border-radius, 8px)", background: "transparent",
  cursor: "pointer", fontSize: 13, color: "inherit",
};
const dangerLinkStyle: React.CSSProperties = {
  background: "none", border: "none", color: "var(--qeetid-color-danger, #ef4444)",
  cursor: "pointer", fontSize: 13, padding: 0,
};
