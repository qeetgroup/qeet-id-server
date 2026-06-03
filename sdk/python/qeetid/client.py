"""HTTP transport shared by every resource.

Handles auth header, JSON (de)serialisation, typed errors, timeouts, and
backoff on 429/5xx. Mirrors ``sdk/go/client.go`` and the TS ``HttpClient``.
"""

from __future__ import annotations

import random
import time
from typing import Any, Mapping, Optional

import httpx

from .errors import QeetidError, error_from_response

__all__ = ["HttpClient", "DEFAULT_BASE_URL"]

DEFAULT_BASE_URL = "https://api.qeetid.com"

_MAX_RESPONSE_BYTES = 1 << 20  # 1 MiB, matching the Go client's LimitReader.


class HttpClient:
    """Shared transport: auth, JSON, typed errors, timeouts, and retries.

    Construct once and reuse; safe to share across calls. Pass a custom
    ``httpx.Client`` via ``http_client`` for tests or proxy agents.
    """

    def __init__(
        self,
        api_key: str,
        base_url: Optional[str] = None,
        timeout: float = 10.0,
        max_retries: int = 2,
        http_client: Optional[httpx.Client] = None,
    ) -> None:
        if not api_key:
            raise QeetidError(0, "config_error", "Qeetid: api_key is required")
        self._api_key = api_key
        self.base_url = (base_url or DEFAULT_BASE_URL).rstrip("/")
        self._timeout = timeout
        self._max_retries = max_retries if max_retries > 0 else 2
        self._http = http_client or httpx.Client(timeout=timeout)
        self._owns_http = http_client is None

    # ---- convenience verbs -------------------------------------------------
    def get(self, path: str, query: Optional[Mapping[str, Any]] = None) -> Any:
        return self.request("GET", path, query=query, idempotent=True)

    def post(self, path: str, body: Any = None) -> Any:
        return self.request("POST", path, body=body, idempotent=False)

    def patch(self, path: str, body: Any = None) -> Any:
        return self.request("PATCH", path, body=body, idempotent=False)

    def delete(self, path: str) -> Any:
        return self.request("DELETE", path, idempotent=True)

    # ---- core --------------------------------------------------------------
    def request(
        self,
        method: str,
        path: str,
        query: Optional[Mapping[str, Any]] = None,
        body: Any = None,
        idempotent: bool = False,
    ) -> Any:
        url = self.base_url + path
        params = None
        if query:
            params = {k: _str_param(v) for k, v in query.items() if v is not None}

        headers = {
            # Qeet ID API keys use the `ApiKey` auth scheme (not Bearer).
            "Authorization": f"ApiKey {self._api_key}",
            "Accept": "application/json",
        }
        content: Optional[bytes] = None
        if body is not None:
            import json

            headers["Content-Type"] = "application/json"
            content = json.dumps(body).encode("utf-8")

        attempt = 0
        while True:
            try:
                res = self._http.request(
                    method,
                    url,
                    params=params,
                    headers=headers,
                    content=content,
                    timeout=self._timeout,
                )
            except httpx.HTTPError as exc:
                # Network/timeout: retry idempotent calls, otherwise surface it.
                if idempotent and attempt < self._max_retries:
                    _sleep(_backoff(attempt))
                    attempt += 1
                    continue
                raise QeetidError(
                    0, "network_error", f"request failed: {exc}"
                ) from exc

            retryable = res.status_code == 429 or (
                res.status_code >= 500 and idempotent
            )
            if retryable and attempt < self._max_retries:
                wait = _retry_after_seconds(res)
                wait = wait if wait is not None else _backoff(attempt)
                _sleep(wait)
                attempt += 1
                continue

            request_id = res.headers.get("X-Request-Id")
            if res.status_code == 204:
                return None

            data = _safe_json(res)
            if res.status_code >= 300:
                raise error_from_response(
                    res.status_code, data, request_id, _retry_after_seconds(res)
                )
            return data

    def close(self) -> None:
        if self._owns_http:
            self._http.close()

    def __enter__(self) -> "HttpClient":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


def _str_param(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)


def _backoff(attempt: int) -> float:
    # Exponential with jitter: ~250ms, 500ms, 1s ...
    base = 0.25 * (2 ** attempt)
    return base + random.randint(0, 99) / 1000.0


def _retry_after_seconds(res: httpx.Response) -> Optional[int]:
    h = res.headers.get("Retry-After")
    if not h:
        return None
    try:
        return int(h)
    except ValueError:
        return None


def _sleep(seconds: float) -> None:
    if seconds > 0:
        time.sleep(seconds)


def _safe_json(res: httpx.Response) -> Any:
    body = res.content[:_MAX_RESPONSE_BYTES]
    if not body:
        return None
    try:
        import json

        return json.loads(body)
    except ValueError:
        return body.decode("utf-8", "replace")
