# Postman

Every Qeet ID API call as one Postman collection, built from the five API documents in
[`api/openapi`](../openapi). Don't edit these files: edit the API sources in `api/openapi/src` and
run `make openapi`, which rebuilds the documents and this collection. `make openapi-check` (part of
`make ci`) fails when the collection is out of date.

| File                                     | What it is                                                  |
| ---------------------------------------- | ----------------------------------------------------------- |
| `qeet-id.postman_collection.json`        | The collection: a folder per API document, then one per tag |
| `qeet-id-local.postman_environment.json` | The local environment: `baseUrl` is `http://localhost:4001` |

## Use it

1. Start the server: `make db-up`, then `make dev`.
2. In Postman, **Import** both files, then pick **Qeet ID (local)** in the environment menu.
3. Run **Access › Auth › Sign up**, or **Sign in** if the account exists. The
   answer fills `bearerToken`, `refreshToken` and `userID`.
4. Verify the address, which creating an organization needs: run **Identity › Verification ›
   Start email verification**, find the code in Mailpit (http://localhost:8025),
   and send it in the body of **Confirm email verification**.
5. Run **Identity › Organizations › Create organization**. The answer fills
   `organizationID` and replaces `bearerToken` with a token for that organization, which its
   routes need. To work in another organization later, run **Access › Auth › Switch
   organization**, which sends `{{organizationID}}`.

Every create call fills its new id in the same way, such as `roleID`, `groupID` or `webhookID`, and
the routes and request fields for that resource read it. Request bodies are the documents'
examples: change them as you need. Optional query parameters are listed but switched off.

## Credentials

Each request uses the credential its operation names in the API document:

| Variable                             | Used by                                                       |
| ------------------------------------ | ------------------------------------------------------------- |
| `bearerToken`, `refreshToken`        | Signed-in calls, and Refresh (filled by sign-up and sign-in)  |
| `scimToken`                          | SCIM 2.0 calls, with an organization's SCIM token             |
| `oauthClientId`, `oauthClientSecret` | Client-credentials calls (Postman's **Get New Access Token**) |
| `adminPortalLink`                    | The admin-portal link exchange                                |
| `apiKey`                             | Calls you switch to an API key (`Authorization: ApiKey …`)    |

Calls made with the hosted-login or admin-portal session cookie need no variable: Postman's cookie
jar sends the cookie that signing in set. Cookie-session changes also need the CSRF header the API
documents describe.
