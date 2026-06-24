# API Errors

## Standard error envelope

All API errors return a consistent JSON shape:

```json
{
  "error": {
    "code":       "not_found",
    "message":    "User not found",
    "detail":     "No user exists with id 01J...",
    "request_id": "req_01J..."
  }
}
```

| Field | Type | Description |
|---|---|---|
| `code` | string | Machine-readable error code (snake_case, stable across versions) |
| `message` | string | Human-readable summary suitable for display |
| `detail` | string | Additional debugging context (optional; may be empty) |
| `request_id` | string | Correlates to the server access log; include in support requests |

## HTTP status → error code mapping

| HTTP Status | `code` | When |
|---|---|---|
| `400 Bad Request` | `bad_request` | Malformed request body, invalid JSON, missing required field |
| `400 Bad Request` | `validation_error` | Field-level validation failure (invalid format, out-of-range) |
| `401 Unauthorized` | `unauthorized` | Missing or invalid authentication credential |
| `401 Unauthorized` | `token_expired` | Bearer token has expired |
| `403 Forbidden` | `forbidden` | Authenticated but insufficient permissions |
| `403 Forbidden` | `locked` | Account is temporarily locked (brute-force protection) |
| `403 Forbidden` | `hook_denied` | Auth hook explicitly denied the login |
| `404 Not Found` | `not_found` | Resource does not exist (or is not visible to the caller) |
| `409 Conflict` | `conflict` | Duplicate resource (e.g., email already registered) |
| `422 Unprocessable` | `unprocessable` | Request is valid but cannot be processed in current state |
| `429 Too Many Requests` | `too_many_requests` | Rate limit exceeded; see `Retry-After` header |
| `500 Internal Server Error` | `internal` | Unexpected server error; report with `request_id` |
| `501 Not Implemented` | `not_implemented` | Feature exists in spec but not yet implemented |
| `503 Service Unavailable` | `service_unavailable` | Hook failure with FailOpen=false configuration |

## Using request_id for debugging

Every response includes a `request_id` that maps to a line in the server access log:

```
{"level":"INFO","msg":"request","request_id":"req_01J...","method":"POST","path":"/v1/auth/login","status":401,"latency_ms":12}
```

When reporting a bug or contacting support, include the `request_id` from the error response. On a self-hosted installation, search server logs for that ID to find the full request context, including any upstream errors.

## Documented deviations

### SCIM (`/scim/v2/*`)

SCIM endpoints use the RFC 7644 error envelope instead of the standard Qeet envelope. This is required for compatibility with enterprise IdP provisioning agents (Okta, Azure AD, etc.):

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
  "status": "404",
  "detail": "Resource 01J... not found."
}
```

### SAML

SAML success paths return:
- **SP metadata:** XML document (`Content-Type: application/xml`)
- **SSO redirect:** HTTP 302 with `Location` header pointing to the IdP
- **ACS response:** HTTP 200 with an auto-submit HTML form (POST binding)

SAML _error_ paths (e.g., invalid SAML response) return the standard JSON envelope with HTTP 400 or 401.

## Common error patterns

### Missing authentication
```json
{ "error": { "code": "unauthorized", "message": "authentication required", "request_id": "..." } }
```
→ Include `Authorization: Bearer <token>` or `X-API-Key: qk_...`

### Expired token
```json
{ "error": { "code": "token_expired", "message": "access token has expired", "request_id": "..." } }
```
→ Refresh using `POST /v1/auth/refresh` with the refresh token

### Rate limit
```json
{ "error": { "code": "too_many_requests", "message": "rate limit exceeded", "request_id": "..." } }
```
→ Check the `Retry-After` response header for the backoff duration

### Conflict (duplicate)
```json
{ "error": { "code": "conflict", "message": "email address is already registered", "request_id": "..." } }
```
→ Use a different value or fetch the existing resource first
