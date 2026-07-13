// Browser HTTP client for the hosted login/consent flow. Unlike the admin
// client (bearer tokens in localStorage), this app is cookie-based: the backend
// sets the HttpOnly SSO cookie (qe_ls), so every request uses
// `credentials: "include"`. Mutations echo the CSRF double-submit token.

export const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:4001";

export class ApiError extends Error {
  status: number;
  code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

function apiURL(path: string): string {
  return new URL(path.replace(/^\//, ""), `${API_BASE_URL}/`).toString();
}

function readCookie(name: string): string | null {
  if (typeof document === "undefined") return null;
  const m = document.cookie.match(new RegExp("(?:^|; )" + name + "=([^;]*)"));
  return m ? decodeURIComponent(m[1]) : null;
}

// ensureCsrf seeds the double-submit cookie. The backend issues `qe_csrf` on any
// GET; we read it back and echo it on mutations. (In dev CSRF is disabled; in
// prod the cookie must be readable here — set a shared CookieDomain across the
// login and API subdomains.)
async function csrfHeader(): Promise<Record<string, string>> {
  let tok = readCookie("qe_csrf");
  if (!tok) {
    try {
      await fetch(apiURL("/healthz"), { credentials: "include" });
    } catch {
      /* best-effort seed */
    }
    tok = readCookie("qe_csrf");
  }
  return tok ? { "X-CSRF-Token": tok } : {};
}

async function parse<T>(res: Response): Promise<T> {
  if (res.status === 204) return undefined as T;
  const text = await res.text();
  const data = text ? safeParse(text) : null;
  if (!res.ok) {
    const err = (data as { error?: { code?: string; message?: string } } | null)?.error;
    throw new ApiError(
      res.status,
      err?.code ?? `http_${res.status}`,
      err?.message ?? "Request failed",
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

export async function apiGet<T = unknown>(path: string): Promise<T> {
  const res = await fetch(apiURL(path), {
    method: "GET",
    headers: { Accept: "application/json" },
    credentials: "include",
  });
  return parse<T>(res);
}

export async function apiPost<T = unknown>(path: string, body?: unknown): Promise<T> {
  const res = await fetch(apiURL(path), {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
      ...(await csrfHeader()),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: "include",
  });
  return parse<T>(res);
}

export async function apiPatch<T = unknown>(path: string, body: unknown): Promise<T> {
  const res = await fetch(apiURL(path), {
    method: "PATCH",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
      ...(await csrfHeader()),
    },
    body: JSON.stringify(body),
    credentials: "include",
  });
  return parse<T>(res);
}

export async function apiDelete<T = unknown>(path: string): Promise<T> {
  const res = await fetch(apiURL(path), {
    method: "DELETE",
    headers: { Accept: "application/json", ...(await csrfHeader()) },
    credentials: "include",
  });
  return parse<T>(res);
}
