# Pagination

All list endpoints in Qeet ID use **keyset (cursor-based) pagination** via [`platform/api/rest/paging`](../../platform/api/rest/paging/). This provides stable, consistent results even when items are added or removed between pages.

## Request parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `limit` | integer | 20 | Maximum items per page. Maximum value: 100. |
| `after` | string | — | Opaque cursor pointing to the last item of the previous page |

Example:
```
GET /v1/users?limit=50&after=eyJ0eXBlIjoiY3Vyc29yIn0
```

## Response format

```json
{
  "items": [
    { "id": "01J...", "email": "alice@acme.test", ... },
    { "id": "01J...", "email": "bob@acme.test", ... }
  ],
  "next_cursor": "eyJ0eXBlIjoiY3Vyc29yIiwidmFsdWUiOiIwMUo...In0"
}
```

| Field | Type | Description |
|---|---|---|
| `items` | array | The requested page of items |
| `next_cursor` | string? | Cursor to pass as `after` to get the next page. Absent when the last page has been reached. |

## How to paginate

```
# Page 1 — no cursor
GET /v1/users?limit=20

# Page 2 — use next_cursor from page 1
GET /v1/users?limit=20&after=<next_cursor from page 1>

# Page 3 — use next_cursor from page 2
GET /v1/users?limit=20&after=<next_cursor from page 2>

# Done — no next_cursor in response means you've reached the last page
```

## Cursor properties

- **Opaque:** Cursors are base64-encoded internal state. Do not parse, construct, or modify them. The format may change between API versions.
- **Stable:** A cursor obtained from one request can be used in a subsequent request even if items have been added or removed after the cursor position.
- **Scoped:** A cursor from one endpoint cannot be used with a different endpoint.
- **Expiry:** Cursors do not expire, but they may become invalid if the underlying data changes significantly (e.g., the item they reference is deleted). In this case, the API returns a `400 Bad Request` with `code: "invalid_cursor"` — restart pagination from the beginning.

## Sorting

List endpoints have a defined, stable sort order documented in the OpenAPI spec for each endpoint. Common orderings:

| Endpoint | Sort order |
|---|---|
| `GET /v1/users` | `created_at DESC, id DESC` |
| `GET /v1/audit-events` | `created_at DESC, id DESC` |
| `GET /v1/api-keys` | `created_at DESC, id DESC` |

The sort order is not configurable via API parameters in the current version.

## Full collection iteration

To iterate over all items in a collection (e.g., for a data export):

```python
cursor = None
all_items = []

while True:
    params = {"limit": 100}
    if cursor:
        params["after"] = cursor

    response = api.get("/v1/users", params=params)
    all_items.extend(response["items"])

    cursor = response.get("next_cursor")
    if not cursor:
        break
```

## Limits

- **Maximum `limit`:** 100 items per page. Requests with `limit > 100` return a `400 Bad Request`.
- **Minimum `limit`:** 1. Requests with `limit < 1` return a `400 Bad Request`.
- **Default `limit`:** 20 items when the parameter is omitted.
