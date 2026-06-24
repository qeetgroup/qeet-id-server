# Key Rotation Runbook

## JWT signing key rotation

The JWT signing key is used to sign all access and refresh tokens. Rotating it invalidates no current tokens immediately — both old and new keys serve in JWKS during a grace window.

### Procedure

**Step 1: Generate a new EC P-256 keypair**

```bash
# Generate private key
openssl ecparam -name prime256v1 -genkey -noout -out jwt-signing-key-new.pem

# Extract public key (for verification)
openssl ec -in jwt-signing-key-new.pem -pubout -out jwt-signing-key-new-pub.pem

# Base64-encode for environment variable
base64 -i jwt-signing-key-new.pem | tr -d '\n' > jwt-signing-key-new.b64
```

**Step 2: Deploy new key alongside old key**

In `platform/security/jwt`, the key rotation design allows multiple active keys. Add the new key to the configuration:

```bash
# Kubernetes: update the secret
kubectl create secret generic qeet-id-jwt-signing-key \
  --from-file=new-key=jwt-signing-key-new.pem \
  --dry-run=client -o yaml | kubectl apply -f -
```

Set `JWT_SIGNING_KEY_2` (or the equivalent multi-key environment variable) to the new key.

Deploy. After deployment:
- Both old and new keys appear in `/jwks.json`
- New tokens are signed with the new key
- Old tokens (with old `kid`) still verify against the old key in JWKS

**Step 3: Wait for the grace window**

Minimum grace window = longest access token TTL = 15 minutes (default).

During this time, no valid tokens are invalidated.

**Step 4: Remove old key**

After the grace window:
```bash
# Remove old key from configuration
kubectl create secret generic qeet-id-jwt-signing-key \
  --from-file=key=jwt-signing-key-new.pem \
  --dry-run=client -o yaml | kubectl apply -f -
```

Deploy. Old tokens are now invalid (they were issued with the old `kid` which is no longer in JWKS). Users who held access tokens signed with the old key will need to refresh.

**Verification:**
```bash
curl https://api.id.qeet.in/jwks.json | jq '.keys[].kid'
# Should show only the new key's thumbprint
```

---

## CSRF HMAC key rotation

The `CSRF_KEY` signs `qe_csrf` cookies. Rotating it immediately invalidates all existing CSRF tokens — users will see a failed mutation on their next POST (after which they receive a new cookie).

### Procedure

**Step 1: Generate a new 32-byte key**

```bash
openssl rand -base64 32
```

**Step 2: Deploy with new key**

Update `CSRF_KEY` environment variable and redeploy.

**Impact:** Existing `qe_csrf` cookies are immediately invalid. On the first POST request after the deploy, users will receive a 403 CSRF failure. Their browser will receive a new `qe_csrf` cookie on the next GET, and subsequent mutations will succeed.

To minimize user disruption: deploy during low-traffic hours, or implement a rolling key (primary + previous key both accepted) — this requires a minor code change to `platform/api/rest/middleware/csrf.go`.

---

## Secrets vault AES key rotation

The secrets vault encrypts per-tenant secrets with AES-256-GCM. Rotating the key requires re-encrypting all stored secrets.

**Warning:** This is a data migration. Test in staging first.

### Procedure

**Step 1: Deploy with new key but old key still accessible**

The `secret.KeyProvider` interface supports a `Rotate(old, new)` operation (or implement a migration script using both providers).

**Step 2: Re-encrypt all secrets**

```bash
# Migration script (run manually against production DB):
# 1. Read each secret (decrypts with old key)
# 2. Re-encrypt with new key
# 3. Update the row
# This must be done atomically per row (use pgx transaction)
```

**Step 3: Remove old key**

Update `VAULT_ENCRYPTION_KEY` (or AWS KMS key ARN) and redeploy.

---

## SAML signing certificate rotation

SAML IdP signing certificates have a natural expiry. Rotate before expiry to avoid SAML failures.

### Procedure

**Step 1: Generate a new SAML signing keypair**

```bash
openssl req -x509 -newkey rsa:2048 -keyout saml-key-new.pem \
  -out saml-cert-new.pem -days 730 -nodes \
  -subj "/CN=Qeet ID SAML IdP"
```

**Step 2: Notify connected SP admins**

SAML Service Providers (the apps that use Qeet ID as an IdP) need to update their metadata to trust the new certificate. Send them the new certificate/metadata URL.

```bash
# New SP metadata URL (contains new cert):
GET https://api.id.qeet.in/saml/:conn/metadata.xml
```

**Step 3: Deploy new cert + key**

Update `SAML_SIGNING_KEY` and `SAML_SIGNING_CERT` environment variables.

Deploy. New SAML assertions are signed with the new cert.

**Step 4: SP migration window**

Allow SPs a reasonable migration window (1–2 weeks) to update their metadata. During this window, both old and new certificates may need to be trusted by SPs. Contact each SP admin to confirm they've updated.

---

## API key secret rotation

Individual API keys cannot be rotated — they must be revoked and replaced:

```bash
# Revoke old key
DELETE /v1/api-keys/:old_id
Authorization: Bearer <admin token>

# Create new key
POST /v1/api-keys
{ "name": "My Service (rotated)", "scopes": [...] }
# Returns plaintext secret once — save it immediately
```

Distribute the new key to the service that uses it, then revoke the old key.
