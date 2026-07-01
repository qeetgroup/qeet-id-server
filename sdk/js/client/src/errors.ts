// QeetIDApiError is thrown for any non-2xx response from the Qeet ID API. It
// carries the HTTP status plus the machine-readable `code` and `message` from
// the backend's error envelope ({ error: { code, message } }), so callers can
// branch on `code` for precise UX (e.g. "invalid_credentials" vs "mfa_required").

export class QeetIDApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly requestId?: string;

  constructor(status: number, code: string, message: string, requestId?: string) {
    super(message);
    this.name = "QeetIDApiError";
    this.status = status;
    this.code = code;
    this.requestId = requestId;
  }

  get isUnauthorized(): boolean {
    return this.status === 401;
  }
  get isForbidden(): boolean {
    return this.status === 403;
  }
  get isNotFound(): boolean {
    return this.status === 404;
  }
  get isRateLimited(): boolean {
    return this.status === 429;
  }
}

// WebAuthnError wraps failures in the browser passkey ceremony (unsupported
// platform, user cancelled, no credential) so callers can distinguish them from
// transport errors.
export class WebAuthnError extends Error {
  readonly reason: "unsupported" | "cancelled" | "failed";
  constructor(reason: "unsupported" | "cancelled" | "failed", message: string) {
    super(message);
    this.name = "WebAuthnError";
    this.reason = reason;
  }
}
