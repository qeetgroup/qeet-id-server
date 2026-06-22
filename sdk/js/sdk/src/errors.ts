// Typed error hierarchy. Every failed API call throws a QeetidError (or a
// subclass), so callers can switch on `err.status` / `instanceof`.

export class QeetidError extends Error {
  readonly status: number;
  readonly code: string;
  readonly requestId?: string;

  constructor(status: number, code: string, message: string, requestId?: string) {
    super(message);
    this.name = "QeetidError";
    this.status = status;
    this.code = code;
    this.requestId = requestId;
  }
}

/** 401 — bad/expired API key or credentials. */
export class InvalidCredentialsError extends QeetidError {
  constructor(message: string, requestId?: string) {
    super(401, "unauthorized", message, requestId);
    this.name = "InvalidCredentialsError";
  }
}

/** 403 — authenticated but not permitted. */
export class ForbiddenError extends QeetidError {
  constructor(message: string, requestId?: string) {
    super(403, "forbidden", message, requestId);
    this.name = "ForbiddenError";
  }
}

/** 404 — resource not found. */
export class NotFoundError extends QeetidError {
  constructor(message: string, requestId?: string) {
    super(404, "not_found", message, requestId);
    this.name = "NotFoundError";
  }
}

/** 429 — rate limited. `retryAfterSeconds` is set when the server sent it. */
export class RateLimitError extends QeetidError {
  readonly retryAfterSeconds?: number;
  constructor(message: string, retryAfterSeconds?: number, requestId?: string) {
    super(429, "too_many_requests", message, requestId);
    this.name = "RateLimitError";
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

/** SessionVerificationError — a token failed local JWKS verification. */
export class SessionVerificationError extends QeetidError {
  constructor(message: string) {
    super(401, "invalid_token", message);
    this.name = "SessionVerificationError";
  }
}

interface ErrorBody {
  error?: { code?: string; message?: string };
}

// errorFromResponse maps an HTTP status + body to the right error subclass.
export function errorFromResponse(
  status: number,
  body: unknown,
  requestId: string | undefined,
  retryAfterSeconds: number | undefined,
): QeetidError {
  const err = (body as ErrorBody | null)?.error;
  const code = err?.code ?? `http_${status}`;
  const message = err?.message ?? `request failed with status ${status}`;
  switch (status) {
    case 401:
      return new InvalidCredentialsError(message, requestId);
    case 403:
      return new ForbiddenError(message, requestId);
    case 404:
      return new NotFoundError(message, requestId);
    case 429:
      return new RateLimitError(message, retryAfterSeconds, requestId);
    default:
      return new QeetidError(status, code, message, requestId);
  }
}
