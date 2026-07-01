// Server-side QeetID management client — never import this in a Client Component.
// Requires QEETID_API_KEY env var (qk_… secret key). The QeetID instance is a
// singleton so the SDK's built-in connection pool is shared across requests.

import { QeetID } from "@qeet-id/node";

function createClient() {
  const apiKey = process.env.QEETID_API_KEY;
  if (!apiKey) throw new Error("QEETID_API_KEY env var is not set");
  return new QeetID({ apiKey });
}

// In a real app, cache the client at module scope (it's safe for concurrent use).
export const qeetid = createClient();
