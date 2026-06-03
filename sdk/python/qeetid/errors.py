"""Typed error hierarchy for the Qeet ID SDK.

Every failed API call raises a :class:`QeetidError` (or a subclass), so callers
can branch on ``err.status`` or use ``isinstance``. This mirrors the Go SDK's
``*qeetid.Error`` (with its ``Is*`` helpers) and the TypeScript SDK's
``QeetidError`` class hierarchy.
"""

from __future__ import annotations

from typing import Any, Optional

__all__ = [
    "QeetidError",
    "InvalidCredentialsError",
    "ForbiddenError",
    "NotFoundError",
    "RateLimitError",
    "SessionVerificationError",
    "error_from_response",
]


class QeetidError(Exception):
    """Base error for every failed Qeet ID call.

    Attributes
    ----------
    status:
        HTTP status code (``0`` for client-side/transport errors).
    code:
        Machine-readable error code, e.g. ``"unauthorized"`` or
        ``"network_error"``.
    message:
        Human-readable message.
    request_id:
        The server's ``X-Request-Id`` when present.
    retry_after_seconds:
        Set on 429 when the server provided a ``Retry-After`` header.
    """

    def __init__(
        self,
        status: int,
        code: str,
        message: str,
        request_id: Optional[str] = None,
        retry_after_seconds: Optional[int] = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.request_id = request_id
        self.retry_after_seconds = retry_after_seconds

    def __str__(self) -> str:
        if self.request_id:
            return (
                f"qeetid: {self.message} "
                f"(status {self.status}, code {self.code!r}, request {self.request_id})"
            )
        return f"qeetid: {self.message} (status {self.status}, code {self.code!r})"

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"{type(self).__name__}(status={self.status!r}, code={self.code!r}, "
            f"message={self.message!r}, request_id={self.request_id!r})"
        )

    # Convenience predicates mirroring the Go SDK's Is* helpers.
    def is_unauthorized(self) -> bool:
        return self.status == 401

    def is_forbidden(self) -> bool:
        return self.status == 403

    def is_not_found(self) -> bool:
        return self.status == 404

    def is_rate_limited(self) -> bool:
        return self.status == 429


class InvalidCredentialsError(QeetidError):
    """401 - bad/expired API key or credentials."""

    def __init__(self, message: str, request_id: Optional[str] = None) -> None:
        super().__init__(401, "unauthorized", message, request_id)


class ForbiddenError(QeetidError):
    """403 - authenticated but not permitted."""

    def __init__(self, message: str, request_id: Optional[str] = None) -> None:
        super().__init__(403, "forbidden", message, request_id)


class NotFoundError(QeetidError):
    """404 - resource not found."""

    def __init__(self, message: str, request_id: Optional[str] = None) -> None:
        super().__init__(404, "not_found", message, request_id)


class RateLimitError(QeetidError):
    """429 - rate limited.

    ``retry_after_seconds`` is set when the server sent a ``Retry-After`` header.
    """

    def __init__(
        self,
        message: str,
        retry_after_seconds: Optional[int] = None,
        request_id: Optional[str] = None,
    ) -> None:
        super().__init__(
            429,
            "too_many_requests",
            message,
            request_id,
            retry_after_seconds=retry_after_seconds,
        )


class SessionVerificationError(QeetidError):
    """A token failed local JWKS verification (status 401, ``invalid_token``)."""

    def __init__(self, message: str) -> None:
        super().__init__(401, "invalid_token", message)


def error_from_response(
    status: int,
    body: Any,
    request_id: Optional[str],
    retry_after_seconds: Optional[int],
) -> QeetidError:
    """Map an HTTP status + parsed body to the right error subclass.

    Mirrors ``errorFromResponse`` (TS) / ``parseError`` (Go): pulls
    ``error.code`` / ``error.message`` out of the envelope when present and
    falls back to ``http_<status>`` otherwise.
    """
    err = body.get("error") if isinstance(body, dict) else None
    code = (err or {}).get("code") if isinstance(err, dict) else None
    message = (err or {}).get("message") if isinstance(err, dict) else None
    code = code or f"http_{status}"
    message = message or f"request failed with status {status}"

    if status == 401:
        return InvalidCredentialsError(message, request_id)
    if status == 403:
        return ForbiddenError(message, request_id)
    if status == 404:
        return NotFoundError(message, request_id)
    if status == 429:
        return RateLimitError(message, retry_after_seconds, request_id)
    return QeetidError(status, code, message, request_id, retry_after_seconds)
