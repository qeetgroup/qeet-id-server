import { describe, expect, it } from "vitest";

import {
  authMethodColor,
  formatAuditAction,
  formatDelta,
  mfaMethodColor,
  takeLatest,
} from "./dashboard-model";

describe("dashboard model", () => {
  it("formats positive, negative, and point deltas", () => {
    expect(formatDelta(4.25)).toBe("+4.3%");
    expect(formatDelta(-2.04)).toBe("-2.0%");
    expect(formatDelta(1.5, "pp")).toBe("+1.5pp");
  });

  it("takes the latest window without mutating its source", () => {
    const source = [1, 2, 3, 4];
    expect(takeLatest(source, 2)).toEqual([3, 4]);
    expect(source).toEqual([1, 2, 3, 4]);
  });

  it("maps authentication and MFA methods onto stable chart tokens", () => {
    expect(authMethodColor("passkey")).toBe("var(--chart-2)");
    expect(authMethodColor("unknown")).toBe("var(--chart-1)");
    expect(mfaMethodColor("Recovery Codes")).toBe("var(--chart-5)");
  });

  it("turns audit action identifiers into operator-readable labels", () => {
    expect(formatAuditAction("user.login_failed")).toBe("User Login Failed");
  });
});
