import { describe, expect, it } from "vitest";

import { parseActivityFrame } from "./activity-stream";

// ---------------------------------------------------------------------------
// parseActivityFrame — unit tests for the SSE frame parser
// ---------------------------------------------------------------------------

describe("parseActivityFrame", () => {
  it("returns null for keep-alive comment frames", () => {
    expect(parseActivityFrame(": keep-alive")).toBeNull();
    expect(parseActivityFrame(": ping")).toBeNull();
  });

  it("returns null for unknown event types", () => {
    const frame = "event: heartbeat\ndata: {}";
    expect(parseActivityFrame(frame)).toBeNull();
  });

  it("returns null when there is no data line", () => {
    expect(parseActivityFrame("event: activity")).toBeNull();
  });

  it("returns null for malformed JSON", () => {
    const frame = "event: activity\ndata: {not valid json}";
    expect(parseActivityFrame(frame)).toBeNull();
  });

  it("returns null when id field is missing or empty", () => {
    const frame = `event: activity\ndata: ${JSON.stringify({ type: "user.login", category: "auth", severity: "info", title: "Login" })}`;
    expect(parseActivityFrame(frame)).toBeNull();
  });

  it("returns null when type field is missing", () => {
    const frame = `event: activity\ndata: ${JSON.stringify({ id: "evt-1", category: "auth", severity: "info", title: "Login" })}`;
    expect(parseActivityFrame(frame)).toBeNull();
  });

  it("parses a well-formed activity frame", () => {
    const payload = {
      id: "evt-abc",
      type: "user.login.success",
      category: "authentication",
      severity: "success",
      title: "User logged in",
      at: "2024-06-15T12:00:00Z",
      actor: { name: "alice", type: "user" },
    };
    const frame = `event: activity\ndata: ${JSON.stringify(payload)}`;
    const result = parseActivityFrame(frame);
    expect(result).not.toBeNull();
    expect(result?.id).toBe("evt-abc");
    expect(result?.type).toBe("user.login.success");
    expect(result?.severity).toBe("success");
    expect(result?.actor?.name).toBe("alice");
  });

  it("defaults event type to 'activity' when no event: line is present", () => {
    const payload = {
      id: "evt-xyz",
      type: "webhook.delivery.failed",
      category: "developer",
      severity: "error",
      title: "Webhook failed",
      at: "2024-06-15T12:00:00Z",
    };
    // No "event:" line — should still parse as activity event (default type)
    const frame = `data: ${JSON.stringify(payload)}`;
    const result = parseActivityFrame(frame);
    expect(result?.id).toBe("evt-xyz");
  });

  it("skips comment lines (lines starting with ':')", () => {
    const payload = {
      id: "evt-1",
      type: "session.created",
      category: "authentication",
      severity: "info",
      title: "Session created",
      at: "2024-06-15T12:00:00Z",
    };
    // Comment injected between event and data
    const frame = `: retry hint\nevent: activity\n: another comment\ndata: ${JSON.stringify(payload)}`;
    const result = parseActivityFrame(frame);
    expect(result?.id).toBe("evt-1");
  });

  it("joins multi-line data fields", () => {
    // SSE allows multiple data: lines — they're concatenated with "\n".
    // A JSON object split across two data: lines still parses correctly
    // because JSON tolerates whitespace (including newlines) between tokens.
    const part1 = '{"id":"evt-multi","type":"user.created",';
    const part2 =
      '"category":"identity","severity":"success","title":"User created","at":"2024-01-01T00:00:00Z"}';
    const frame = `event: activity\ndata: ${part1}\ndata: ${part2}`;
    const result = parseActivityFrame(frame);
    // The newline-joined string is valid JSON — expect a parsed event
    expect(result).not.toBeNull();
    expect(result?.id).toBe("evt-multi");
    expect(result?.type).toBe("user.created");
  });
});
