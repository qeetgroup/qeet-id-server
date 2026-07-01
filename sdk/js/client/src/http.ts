// Browser HTTP transport for the hosted-login / embedded auth flows. Unlike the
// server SDK (bearer API keys), this client is cookie-based: the backend sets
// the HttpOnly SSO cookie (qe_ls), so every request uses `credentials:
// "include"`. Mutations echo the CSRF double-submit token (qe_csrf), which the
// backend issues on any GET. Generalized from apps/login/src/lib/api.ts so the
// hosted login and the @qeet-id/react embedded components share one impl.

import { QeetIDApiError } from "./errors.js";

export class Http {
  private readonly baseUrl: string;

  constructor(baseUrl: string) {
    // Normalize to no trailing slash so `url()` joins predictably.
    this.baseUrl = baseUrl.replace(/\/+$/, "");
  }

  /** Absolute URL for an API path (e.g. "/v1/auth/session"). Exposed so callers
   * can build redirect URLs (social start, hosted authorize) themselves. */
  url(path: string): string {
    return `${this.baseUrl}/${path.replace(/^\/+/, "")}`;
  }

  async get<T = unknown>(path: string): Promise<T> {
    const res = await fetch(this.url(path), {
      method: "GET",
      headers: { Accept: "application/json" },
      credentials: "include",
    });
    return this.parse<T>(res);
  }

  async post<T = unknown>(path: string, body?: unknown): Promise<T> {
    const res = await fetch(this.url(path), {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        ...(await this.csrfHeader()),
      },
      body: JSON.stringify(body ?? {}),
      credentials: "include",
    });
    return this.parse<T>(res);
  }

  async del<T = unknown>(path: string): Promise<T> {
    const res = await fetch(this.url(path), {
      method: "DELETE",
      headers: { Accept: "application/json", ...(await this.csrfHeader()) },
      credentials: "include",
    });
    return this.parse<T>(res);
  }

  // csrfHeader seeds and echoes the double-submit token. The backend issues
  // `qe_csrf` on any GET; we read it back and send it on mutations. (In dev CSRF
  // is disabled; in prod the cookie must be readable here — set a shared
  // CookieDomain across the login and API subdomains.)
  private async csrfHeader(): Promise<Record<string, string>> {
    let tok = readCookie("qe_csrf");
    if (!tok) {
      try {
        await fetch(this.url("/healthz"), { credentials: "include" });
      } catch {
        /* best-effort seed */
      }
      tok = readCookie("qe_csrf");
    }
    return tok ? { "X-CSRF-Token": tok } : {};
  }

  private async parse<T>(res: Response): Promise<T> {
    if (res.status === 204) return undefined as T;
    const text = await res.text();
    const data = text ? safeParse(text) : null;
    if (!res.ok) {
      const err = (data as { error?: { code?: string; message?: string } } | null)?.error;
      throw new QeetIDApiError(
        res.status,
        err?.code ?? `http_${res.status}`,
        err?.message ?? "Request failed",
        res.headers.get("x-request-id") ?? undefined,
      );
    }
    return data as T;
  }
}

function readCookie(name: string): string | null {
  if (typeof document === "undefined") return null;
  const m = document.cookie.match(new RegExp("(?:^|; )" + name + "=([^;]*)"));
  return m ? decodeURIComponent(m[1]) : null;
}

function safeParse(s: string): unknown {
  try {
    return JSON.parse(s);
  } catch {
    return s;
  }
}
