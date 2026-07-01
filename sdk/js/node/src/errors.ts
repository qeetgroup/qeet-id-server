// Typed error hierarchy. Every failed API call throws a QeetIDError (or a
// subclass), so callers can switch on `err.status` / `instanceof`.

export class QeetIDError extends Error {
  readonly status: number;
  readonly code: string;
  readonly requestId?: string;

  constructor(status: number, code: string, message: string, requestId?: string) {
    super(message);
    this.name = "QeetIDError";
    this.status = status;
    this.code = code;
    this.requestId = requestId;
  }
}

/** 401 — bad/expired API key or credentials. */
export class InvalidCredentialsError extends QeetIDError {
  constructor(message: string, requestId?: string) {
    super(401, "unauthorized", message, requestId);
    this.name = "InvalidCredentialsError";
  }
}

/** 403 — authenticated but not permitted. */
export class ForbiddenError extends QeetIDError {
  constructor(message: string, requestId?: string) {
    super(403, "forbidden", message, requestId);
    this.name = "ForbiddenError";
  }
}

/** 404 — resource not found. */
export class NotFoundError extends QeetIDError {
  constructor(message: string, requestId?: string) {
    super(404, "not_found", message, requestId);
    this.name = "NotFoundError";
  }
}

/** 429 — rate limited. `retryAfterSeconds` is set when the server sent it. */
export class RateLimitError extends QeetIDError {
  readonly retryAfterSeconds?: number;
  constructor(message: string, retryAfterSeconds?: number, requestId?: string) {
    super(429, "too_many_requests", message, requestId);
    this.name = "RateLimitError";
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

/** SessionVerificationError — a token failed local JWKS verification. */
export class SessionVerificationError extends QeetIDError {
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
): QeetIDError {
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
      return new QeetIDError(status, code, message, requestId);
  }
}
