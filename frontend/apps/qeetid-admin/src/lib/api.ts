// Thin HTTP client around the qeet-identity Go backend.
// - Base URL comes from VITE_API_URL (defaults to http://localhost:4001).
// - The access token from a successful signup/login is persisted under
//   localStorage["qeetid.access_token"] and attached as Bearer on every call.
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

export async function api<T = unknown>(path: string, opts: RequestOpts = {}): Promise<T> {
  const { method = "GET", body, query, signal, anonymous = false } = opts;

  const url = new URL(path.startsWith("/") ? path.slice(1) : path, `${API_BASE_URL}/`);
  if (query) {
    for (const [k, v] of Object.entries(query)) {
      if (v !== undefined && v !== null && v !== "") url.searchParams.set(k, String(v));
    }
  }

  const headers: Record<string, string> = {
    Accept: "application/json",
  };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (!anonymous) {
    const tok = tokenStore.get();
    if (tok) headers.Authorization = `Bearer ${tok}`;
  }

  const res = await fetch(url, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
    signal,
  });

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
