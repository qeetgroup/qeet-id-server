"use client";

import { useState } from "react";

interface McpDemoProps {
  initialToken: string;
}

export function McpDemo({ initialToken }: McpDemoProps) {
  const [token, setToken] = useState(initialToken);
  const [scope, setScope] = useState("");
  const [result, setResult] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function verify() {
    setLoading(true);
    setResult(null);
    try {
      const res = await fetch("/api/verify", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ scope: scope || undefined }),
      });
      const data = await res.json() as Record<string, unknown>;
      setResult(JSON.stringify(data, null, 2));
    } catch (e) {
      setResult(String(e));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div>
      <label style={{ display: "block", marginBottom: "0.25rem" }}>
        <span className="muted">Bearer token (pre-filled from your session):</span>
        <textarea
          value={token}
          onChange={(e) => setToken(e.target.value)}
          rows={3}
          style={{ display: "block", width: "100%", fontFamily: "monospace", fontSize: "0.75rem", marginTop: "0.25rem" }}
        />
      </label>
      <label style={{ display: "block", marginBottom: "0.5rem" }}>
        <span className="muted">Required scope (optional — leave blank to skip scope check):</span>
        <input
          type="text"
          value={scope}
          onChange={(e) => setScope(e.target.value)}
          placeholder="e.g. billing:read"
          style={{ display: "block", width: "100%", fontFamily: "monospace", marginTop: "0.25rem" }}
        />
      </label>
      <button onClick={() => void verify()} disabled={loading || !token} className="link-btn">
        {loading ? "Verifying…" : "Test MCP guard →"}
      </button>
      {result && <pre className="code" style={{ marginTop: "0.75rem" }}>{result}</pre>}
    </div>
  );
}
