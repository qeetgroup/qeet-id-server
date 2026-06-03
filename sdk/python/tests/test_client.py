"""HTTP client tests: auth scheme, error mapping, retries, and resources."""

from __future__ import annotations

import httpx
import pytest

from qeetid import (
    CreateTenantInput,
    CreateUserInput,
    ForbiddenError,
    InvalidCredentialsError,
    NotFoundError,
    Qeetid,
    QeetidError,
    RateLimitError,
    UpdateUserInput,
)


def _client(handler, max_retries: int = 2) -> Qeetid:
    transport = httpx.MockTransport(handler)
    http_client = httpx.Client(transport=transport)
    return Qeetid(
        api_key="qk_test",
        base_url="https://api.test",
        max_retries=max_retries,
        http_client=http_client,
    )


def test_auth_header_uses_apikey_scheme():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers.get("Authorization")
        return httpx.Response(200, json={"allowed": True})

    q = _client(handler)
    q.can(user="u", tenant="t", permission="p")
    assert seen["auth"] == "ApiKey qk_test"


def test_api_key_required():
    with pytest.raises(QeetidError):
        Qeetid(api_key="")


def test_can_true_and_false():
    def handler(request: httpx.Request) -> httpx.Response:
        allowed = request.url.params.get("permission") == "billing:write"
        return httpx.Response(200, json={"allowed": allowed})

    q = _client(handler)
    assert q.can(user="u", tenant="t", permission="billing:write") is True
    assert q.can(user="u", tenant="t", permission="other") is False


def test_check_query_params():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.update(dict(request.url.params))
        return httpx.Response(200, json={"allowed": True})

    q = _client(handler)
    q.can(user="usr_1", tenant="tnt_1", permission="billing:write")
    assert seen == {
        "user_id": "usr_1",
        "tenant_id": "tnt_1",
        "permission": "billing:write",
    }


def test_can_all():
    def handler(request: httpx.Request) -> httpx.Response:
        perm = request.url.params.get("permission")
        return httpx.Response(200, json={"allowed": perm in ("a", "b")})

    q = _client(handler)
    assert q.can_all("u", "t", ["a", "b"]) is True
    assert q.can_all("u", "t", ["a", "c"]) is False


def test_error_mapping_401_403_404_429():
    cases = {
        "/v1/users/a": (401, InvalidCredentialsError),
        "/v1/users/b": (403, ForbiddenError),
        "/v1/users/c": (404, NotFoundError),
        "/v1/users/d": (429, RateLimitError),
    }

    def handler(request: httpx.Request) -> httpx.Response:
        status, _ = cases[request.url.path]
        headers = {"X-Request-Id": "req_123"}
        if status == 429:
            # Retry-After 0 keeps the retry loop instant; we still assert it's
            # parsed onto the error below.
            headers["Retry-After"] = "0"
        return httpx.Response(
            status,
            json={"error": {"code": "x", "message": "boom"}},
            headers=headers,
        )

    q = _client(handler)
    for path, (_, exc_type) in {
        "/v1/users/a": (401, InvalidCredentialsError),
        "/v1/users/b": (403, ForbiddenError),
        "/v1/users/c": (404, NotFoundError),
    }.items():
        with pytest.raises(exc_type) as exc:
            q.users.get(path.rsplit("/", 1)[-1])
        assert exc.value.request_id == "req_123"
    # Rate limit (429 is always retried, then surfaced) carries retry_after.
    with pytest.raises(RateLimitError) as exc:
        q.users.get("d")
    assert exc.value.retry_after_seconds == 0
    assert exc.value.request_id == "req_123"


def test_retry_on_5xx_for_idempotent_then_success():
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] < 3:
            return httpx.Response(503, json={"error": {"message": "down"}})
        return httpx.Response(
            200,
            json={"id": "usr_1", "email": "a@b.com", "status": "active", "created_at": "now"},
        )

    q = _client(handler)
    user = q.users.get("usr_1")
    assert user.id == "usr_1"
    assert calls["n"] == 3


def test_no_retry_on_5xx_for_non_idempotent():
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(503, json={"error": {"message": "down"}})

    q = _client(handler)
    with pytest.raises(QeetidError):
        q.users.create(CreateUserInput(email="a@b.com"))
    assert calls["n"] == 1  # POST is not retried on 5xx.


def test_users_crud_shapes():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST" and request.url.path == "/v1/users":
            import json

            body = json.loads(request.content)
            assert body["email"] == "new@acme.com"
            assert "phone" not in body  # None fields omitted.
            return httpx.Response(
                200,
                json={
                    "id": "usr_9",
                    "email": "new@acme.com",
                    "status": "active",
                    "created_at": "2026-01-01",
                    "tenant_id": "tnt_1",
                },
            )
        if request.method == "GET" and request.url.path == "/v1/users":
            return httpx.Response(
                200,
                json={
                    "items": [
                        {"id": "u1", "email": "a@x", "status": "active", "created_at": "t"},
                        {"id": "u2", "email": "b@x", "status": "active", "created_at": "t"},
                    ],
                    "next_cursor": None,
                },
            )
        if request.method == "PATCH":
            return httpx.Response(
                200,
                json={"id": "usr_9", "email": "new@acme.com", "status": "suspended", "created_at": "t"},
            )
        if request.method == "DELETE":
            return httpx.Response(204)
        return httpx.Response(404, json={})

    q = _client(handler)

    created = q.users.create(CreateUserInput(email="new@acme.com", display_name="New"))
    assert created.id == "usr_9"
    assert created.tenant_id == "tnt_1"

    page = q.users.list()
    assert [u.id for u in page.data] == ["u1", "u2"]
    assert page.next_cursor is None

    updated = q.users.update("usr_9", UpdateUserInput(status="suspended"))
    assert updated.status == "suspended"

    assert q.users.delete("usr_9") is None


def test_users_list_all_paginates():
    pages = {
        None: {"items": [{"id": "u1", "email": "a", "status": "s", "created_at": "t"}], "next_cursor": "c1"},
        "c1": {"items": [{"id": "u2", "email": "b", "status": "s", "created_at": "t"}], "next_cursor": None},
    }

    def handler(request: httpx.Request) -> httpx.Response:
        cursor = request.url.params.get("cursor")
        return httpx.Response(200, json=pages[cursor])

    q = _client(handler)
    ids = [u.id for u in q.users.list_all()]
    assert ids == ["u1", "u2"]


def test_tenants_list_data_fallback():
    def handler(request: httpx.Request) -> httpx.Response:
        # Uses `data` key instead of `items` — must still work.
        return httpx.Response(
            200,
            json={"data": [{"id": "t1", "name": "Acme", "slug": "acme", "created_at": "t"}], "next_cursor": "x"},
        )

    q = _client(handler)
    page = q.tenants.list(limit=10)
    assert page.data[0].name == "Acme"
    assert page.next_cursor == "x"


def test_tenant_create():
    def handler(request: httpx.Request) -> httpx.Response:
        import json

        body = json.loads(request.content)
        assert body == {"name": "Acme", "slug": "acme"}
        return httpx.Response(
            200, json={"id": "tnt_1", "name": "Acme", "slug": "acme", "created_at": "t"}
        )

    q = _client(handler)
    t = q.tenants.create(CreateTenantInput(name="Acme", slug="acme"))
    assert t.id == "tnt_1"
