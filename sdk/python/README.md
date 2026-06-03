# qeetid (Python)

Server-side Python SDK for [Qeet ID](https://qeetid.com). Manage users and
tenants, run authorization checks, and verify sessions — from your backend.

> **Server-side only.** Authenticate with a secret API key (`qk_…`). Never ship
> it to a browser.

Minimal dependencies: [`httpx`](https://www.python-httpx.org/) for HTTP and
[`cryptography`](https://cryptography.io/) for local ES256 JWT verification.
Python 3.10+.

## Install

```bash
pip install qeetid
```

## Quick start

```python
import os
from qeetid import Qeetid, CreateUserInput

qeetid = Qeetid(api_key=os.environ["QEETID_API_KEY"])

# Verify the caller's access token (local — checks the ES256 signature against
# the published JWKS, then expiry/issuer/audience). No network call after the
# keys are cached.
claims = qeetid.sessions.verify(access_token)

# Authorization
if qeetid.can(user=claims.user_id, tenant=claims.tenant_id, permission="billing:write"):
    ...

# Manage users / tenants
user = qeetid.users.create(CreateUserInput(email="new@acme.com", display_name="New User"))
for u in qeetid.users.list_all():
    print(u.email)
```

## API

| Call | Description |
| --- | --- |
| `qeetid.sessions.verify(token, options=None)` | Verify an ES256 token against JWKS; returns `SessionClaims`. |
| `qeetid.can(user=, tenant=, permission=)` | Single RBAC permission check → `bool`. |
| `qeetid.can_all(user, tenant, permissions)` | True only if all pass. |
| `qeetid.users.{create,get,update,delete,set_password,list,list_all}` | User management. |
| `qeetid.tenants.{create,get,update,delete,list}` | Tenant management. |

## Errors

Every failed call raises a `QeetidError` (or subclass) carrying `status`,
`code`, and `request_id`:

```python
from qeetid import RateLimitError, InvalidCredentialsError

try:
    qeetid.users.get("usr_missing")
except RateLimitError as err:
    wait(err.retry_after_seconds)
except InvalidCredentialsError:
    rotate_api_key()
```

429 and 5xx (for idempotent calls) are retried automatically with backoff,
honoring `Retry-After`.

## Configuration

```python
Qeetid(
    api_key="qk_…",                  # required
    base_url="https://api.qeetid.com",  # default
    timeout=10.0,                    # seconds
    max_retries=2,
    http_client=custom_httpx_client, # optional
)
```

The auth scheme is the HTTP header `Authorization: ApiKey <api_key>` (not
`Bearer`).
