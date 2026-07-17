import { describe, expect, it } from "vitest";

import {
  filterNavigation,
  getRequiredCapabilityForPath,
  navGroups,
  safeNavigation,
} from "./navigation";
import { isNavBranchActive, isNavPathActive, type NavTreeItem } from "./navigation-state";

const users: NavTreeItem = {
  url: "/users",
  items: [{ url: "/users" }, { url: "/users/sessions" }],
};

describe("console navigation state", () => {
  it("marks leaf routes only on exact matches", () => {
    expect(isNavPathActive("/security", "/security")).toBe(true);
    expect(isNavPathActive("/security/audit-logs", "/security")).toBe(false);
    expect(isNavPathActive("/", "/")).toBe(true);
  });

  it("keeps a navigation branch active on child and detail routes", () => {
    expect(isNavBranchActive("/users", users)).toBe(true);
    expect(isNavBranchActive("/users/sessions", users)).toBe(true);
    expect(isNavBranchActive("/users/4c1f", users)).toBe(true);
    expect(isNavBranchActive("/groups", users)).toBe(false);
  });

  it("resolves exact routes before detail-route inheritance", () => {
    expect(getRequiredCapabilityForPath("/users/import")).toBe("user.write");
    expect(getRequiredCapabilityForPath("/users/4c1f")).toBe("user.read");
    expect(getRequiredCapabilityForPath("/auth/connections/oidc/client-1")).toBe("connection.read");
  });

  it("normalizes trailing slashes without matching lookalike prefixes", () => {
    expect(getRequiredCapabilityForPath("/users/")).toBe("user.read");
    expect(getRequiredCapabilityForPath("/users?status=active")).toBe("user.read");
    expect(getRequiredCapabilityForPath("/users-archive")).toBeUndefined();
    expect(getRequiredCapabilityForPath("/unknown")).toBeUndefined();
  });

  it("removes denied destinations while retaining a branch with an allowed child", () => {
    const visible = filterNavigation(
      navGroups,
      (permission) => permission === undefined || permission === "policy.read",
    );
    const authorization = visible.find((group) => group.label === "Authorization");
    const accessModel = authorization?.items.find((item) => item.title === "Access model");

    expect(accessModel?.items?.map((item) => item.title)).toEqual(["ABAC"]);
    expect(
      visible.find((group) => group.label === "Workspace")?.items.map((item) => item.title),
    ).toEqual(["Overview"]);
  });

  it("limits unresolved access navigation to overview and workspace selection", () => {
    const visiblePaths = safeNavigation(navGroups).flatMap((group) =>
      group.items.flatMap((item) => [item.url, ...(item.items?.map((child) => child.url) ?? [])]),
    );

    expect(new Set(visiblePaths)).toEqual(new Set(["/", "/organizations/tenants"]));
  });
});
