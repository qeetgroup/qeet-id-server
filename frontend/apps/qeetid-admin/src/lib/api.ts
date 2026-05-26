// Thin HTTP client around the qeet-identity Go backend.
// - Base URL comes from VITE_API_URL (defaults to http://localhost:4001).
// - The access token from a successful signup/login is persisted under
//   localStorage["qeetid.access_token"] and attached as Bearer on every call.
// - On 401, we try `/v1/auth/refresh` once (single-flight, so a wave of
//   concurrent queries shares one refresh) and replay the original request.
//   If refresh itself fails, we clear local state and hard-redirect to
//   /sign-in — that side-steps stale React Query caches mid-render.
// - Errors are normalised into a typed `ApiError` so React Query / form
//   handlers can switch on `err.status` and surface `err.message`.

const TOKEN_KEY = "qeetid.access_token";
const REFRESH_KEY = "qeetid.refresh_token";
const TENANT_KEY = "qeetid.tenant_id";
const USER_KEY = "qeetid.user_id";

export const API_BASE_URL =
  (import.meta.env?.VITE_API_URL as string | undefined) ?? "http://localhost:4001";

export class ApiError extends Error {
  status: number;
  code: string;
  details?: unknown;

  constructor(status: number, code: string, message: string, details?: unknown) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

export const tokenStore = {
  get: () => (typeof window !== "undefined" ? window.localStorage.getItem(TOKEN_KEY) : null),
  set: (t: string) => window.localStorage.setItem(TOKEN_KEY, t),
  clear: () => {
    window.localStorage.removeItem(TOKEN_KEY);
    window.localStorage.removeItem(REFRESH_KEY);
    window.localStorage.removeItem(TENANT_KEY);
    window.localStorage.removeItem(USER_KEY);
  },
  getRefresh: () =>
    typeof window !== "undefined" ? window.localStorage.getItem(REFRESH_KEY) : null,
  setRefresh: (t: string) => window.localStorage.setItem(REFRESH_KEY, t),
  getTenantId: () =>
    typeof window !== "undefined" ? window.localStorage.getItem(TENANT_KEY) : null,
  setTenantId: (id: string) => window.localStorage.setItem(TENANT_KEY, id),
  getUserId: () => (typeof window !== "undefined" ? window.localStorage.getItem(USER_KEY) : null),
  setUserId: (id: string) => window.localStorage.setItem(USER_KEY, id),
};

type RequestOpts = {
  method?: "GET" | "POST" | "PATCH" | "PUT" | "DELETE";
  body?: unknown;
  query?: Record<string, string | number | undefined>;
  signal?: AbortSignal;
  /** Skip the auth header (used for public endpoints like signup/login). */
  anonymous?: boolean;
};

// Single-flight refresh: if many queries hit a 401 at once they all await the
// same in-flight `/v1/auth/refresh` instead of stampeding the endpoint (which
// would revoke the session on the second request, since refresh tokens are
// rotated single-use server-side — see auth/service.go Refresh()).
let refreshInFlight: Promise<string | null> | null = null;

type RefreshResponse = {
  access_token: string;
  refresh_token: string;
};

async function refreshAccessToken(): Promise<string | null> {
  if (refreshInFlight) return refreshInFlight;
  const rt = tokenStore.getRefresh();
  if (!rt) return null;

  refreshInFlight = (async () => {
    try {
      const url = new URL("v1/auth/refresh", `${API_BASE_URL}/`);
      const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify({ refresh_token: rt }),
      });
      if (!res.ok) return null;
      const data = (await res.json()) as RefreshResponse;
      tokenStore.set(data.access_token);
      tokenStore.setRefresh(data.refresh_token);
      return data.access_token;
    } catch {
      return null;
    } finally {
      refreshInFlight = null;
    }
  })();

  return refreshInFlight;
}

function onAuthLost() {
  tokenStore.clear();
  if (typeof window !== "undefined" && window.location.pathname !== "/sign-in") {
    window.location.assign("/sign-in");
  }
}

async function doFetch(
  url: URL,
  method: string,
  body: unknown,
  signal: AbortSignal | undefined,
  anonymous: boolean
): Promise<Response> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (!anonymous) {
    const tok = tokenStore.get();
    if (tok) headers.Authorization = `Bearer ${tok}`;
  }
  return fetch(url, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
    signal,
  });
}

export async function api<T = unknown>(path: string, opts: RequestOpts = {}): Promise<T> {
  const { method = "GET", body, query, signal, anonymous = false } = opts;

  const url = new URL(path.startsWith("/") ? path.slice(1) : path, `${API_BASE_URL}/`);
  if (query) {
    for (const [k, v] of Object.entries(query)) {
      if (v !== undefined && v !== null && v !== "") url.searchParams.set(k, String(v));
    }
  }

  let res = await doFetch(url, method, body, signal, anonymous);

  // Authenticated 401 → try to refresh once, then replay. Skip the retry for
  // the refresh endpoint itself (avoids infinite loop) and for explicitly
  // anonymous calls (login/signup form errors should surface immediately).
  if (res.status === 401 && !anonymous && !path.includes("/auth/refresh")) {
    const fresh = await refreshAccessToken();
    if (fresh) {
      res = await doFetch(url, method, body, signal, anonymous);
    } else {
      onAuthLost();
    }
  }

  if (res.status === 204) return undefined as T;

  const text = await res.text();
  const data = text ? safeParse(text) : null;

  if (!res.ok) {
    const err = (data as { error?: { code?: string; message?: string; details?: unknown } } | null)
      ?.error;
    throw new ApiError(
      res.status,
      err?.code ?? `http_${res.status}`,
      err?.message ?? res.statusText ?? "Request failed",
      err?.details
    );
  }

  return data as T;
}

function safeParse(s: string): unknown {
  try {
    return JSON.parse(s);
  } catch {
    return s;
  }
}
