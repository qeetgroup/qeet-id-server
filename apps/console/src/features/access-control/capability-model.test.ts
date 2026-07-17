import { describe, expect, it } from "vitest";

import {
  CONSOLE_CAPABILITIES,
  classifyAccessMode,
  createCapabilitySet,
  hasAllCapabilities,
  hasAnyCapability,
  hasCapability,
} from "./capability-model";

describe("console capability model", () => {
  it("matches effective permissions exactly without inferring read from write", () => {
    const permissions = createCapabilitySet(["user.write"]);

    expect(hasCapability(permissions, "user.write")).toBe(true);
    expect(hasCapability(permissions, "user.read")).toBe(false);
    expect(hasCapability(permissions, undefined)).toBe(true);
  });

  it("supports composite workflow requirements", () => {
    const permissions = createCapabilitySet(["user.write", "role.read", "role.write"]);

    expect(hasAllCapabilities(permissions, ["user.write", "role.read", "role.write"])).toBe(true);
    expect(hasAllCapabilities(permissions, ["user.read", "user.write"])).toBe(false);
    expect(hasAnyCapability(permissions, ["audit.read", "role.read"])).toBe(true);
  });

  it("classifies setup, empty, read-only, restricted, and full access", () => {
    expect(classifyAccessMode(createCapabilitySet([]), false)).toBe("setup");
    expect(classifyAccessMode(createCapabilitySet([]), true)).toBe("none");
    expect(classifyAccessMode(createCapabilitySet(["user.read", "group.read"]), true)).toBe(
      "read-only",
    );
    expect(classifyAccessMode(createCapabilitySet(["user.read", "group.write"]), true)).toBe(
      "restricted",
    );
    expect(classifyAccessMode(createCapabilitySet(CONSOLE_CAPABILITIES), true)).toBe("full");
  });
});
