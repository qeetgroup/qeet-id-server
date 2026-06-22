import { errorFromResponse, QeetidError } from "./errors.js";

/** A fetch implementation (defaults to the global `fetch`, Node ≥18). */
export type FetchLike = typeof globalThis.fetch;

export interface QeetidOptions {
  /** Server-side API key (`qk_…`). Never expose this in a browser. */
  apiKey: string;
  /** API base URL. Defaults to https://api.qeetid.com. */
  baseUrl?: string;
  /** Per-request timeout in ms (default 10000). */
  timeoutMs?: number;
  /** Max retries on 429 / 5xx for safe requests (default 2). */
  maxRetries?: number;
  /** Override fetch (for tests or custom agents). */
  fetch?: FetchLike;
}

interface RequestOptions {
  query?: Record<string, string | number | boolean | undefined>;
  body?: unknown;
  /** Safe to retry on a 5xx (GET/idempotent). 429 is always retried. */
  idempotent?: boolean;
}

const DEFAULT_BASE_URL = "https://api.qeetid.com";

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// HttpClient is the transport shared by every resource: auth header, JSON
// (de)serialisation, typed errors, timeouts, and backoff on 429/5xx.
export class HttpClient {
  private readonly apiKey: string;
  private readonly baseUrl: string;
  private readonly timeoutMs: number;
  private readonly maxRetries: number;
  private readonly fetchImpl: FetchLike;

  constructor(opts: QeetidOptions) {
    if (!opts.apiKey) {
      throw new QeetidError(0, "config_error", "Qeetid: apiKey is required");
    }
    this.apiKey = opts.apiKey;
    this.baseUrl = (opts.baseUrl ?? DEFAULT_BASE_URL).replace(/\/+$/, "");
    this.timeoutMs = opts.timeoutMs ?? 10_000;
    this.maxRetries = opts.maxRetries ?? 2;
    const f = opts.fetch ?? globalThis.fetch;
    if (!f) {
      throw new QeetidError(0, "config_error", "Qeetid: no fetch available — pass options.fetch on Node <18");
    }
    this.fetchImpl = f;
  }

  get<T>(path: string, opts: Omit<RequestOptions, "body"> = {}): Promise<T> {
    return this.request<T>("GET", path, { ...opts, idempotent: true });
  }
  post<T>(path: string, body?: unknown): Promise<T> {
    return this.request<T>("POST", path, { body });
  }
  patch<T>(path: string, body?: unknown): Promise<T> {
    return this.request<T>("PATCH", path, { body });
  }
  delete<T>(path: string): Promise<T> {
    return this.request<T>("DELETE", path, { idempotent: true });
  }

  async request<T>(method: string, path: string, opts: RequestOptions = {}): Promise<T> {
    const url = new URL(this.baseUrl + path);
    for (const [k, v] of Object.entries(opts.query ?? {})) {
      if (v !== undefined) url.searchParams.set(k, String(v));
    }

    const headers: Record<string, string> = {
      // Qeet ID API keys use the `ApiKey` auth scheme (not Bearer).
      Authorization: `ApiKey ${this.apiKey}`,
      Accept: "application/json",
    };
    let payload: string | undefined;
    if (opts.body !== undefined) {
      headers["Content-Type"] = "application/json";
      payload = JSON.stringify(opts.body);
    }

    let attempt = 0;
    for (;;) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeoutMs);
      let res: Response;
      try {
        res = await this.fetchImpl(url, { method, headers, body: payload, signal: controller.signal });
      } catch (cause) {
        clearTimeout(timer);
        // Network/timeout: retry idempotent calls, otherwise surface it.
        if (opts.idempotent && attempt < this.maxRetries) {
          await sleep(backoffMs(attempt));
          attempt++;
          continue;
        }
        throw new QeetidError(0, "network_error", `request failed: ${(cause as Error).message}`);
      }
      clearTimeout(timer);

      const retryable = res.status === 429 || (res.status >= 500 && opts.idempotent);
      if (retryable && attempt < this.maxRetries) {
        await sleep(retryAfterMs(res) ?? backoffMs(attempt));
        attempt++;
        continue;
      }

      const requestId = res.headers.get("X-Request-Id") ?? undefined;
      if (res.status === 204) return undefined as T;

      const text = await res.text();
      const data = text ? safeJSON(text) : null;
      if (!res.ok) {
        throw errorFromResponse(res.status, data, requestId, retryAfterSeconds(res));
      }
      return data as T;
    }
  }
}

function backoffMs(attempt: number): number {
  // Exponential with jitter: ~250ms, 500ms, 1s …
  const base = 250 * 2 ** attempt;
  return base + Math.floor(Math.random() * 100);
}

function retryAfterSeconds(res: Response): number | undefined {
  const h = res.headers.get("Retry-After");
  if (!h) return undefined;
  const n = Number(h);
  return Number.isFinite(n) ? n : undefined;
}

function retryAfterMs(res: Response): number | undefined {
  const s = retryAfterSeconds(res);
  return s === undefined ? undefined : s * 1000;
}

function safeJSON(s: string): unknown {
  try {
    return JSON.parse(s);
  } catch {
    return s;
  }
}
