# Secrets Generation and Rotation

Commands for generating every production secret Qeet ID needs.

## Generate all secrets (initial setup)

```bash
# JWT signing key (EC P-256)
openssl ecparam -name prime256v1 -genkey -noout -out jwt-signing.pem
# Store the PEM content as JWT_SIGNING_KEY

# JWT HMAC secret (≥32 bytes)
openssl rand -base64 48
# Store as JWT_SECRET

# CSRF HMAC key (32 bytes)
openssl rand -base64 32
# Store as CSRF_KEY

# Vault encryption key (32 bytes, base64)
openssl rand -base64 32
# Store as SECRETS_KEY (or use AWS KMS — set SECRETS_PROVIDER=aws-kms)

# SAML IdP signing keypair
openssl req -x509 -newkey rsa:2048 -keyout saml-idp.key -out saml-idp.crt \
  -days 730 -nodes -subj "/CN=Qeet ID SAML IdP/O=Qeet Group"
# Store key as SAML_IDP_KEY, cert as SAML_IDP_CERT
```

## Store in AWS Secrets Manager

```bash
ENV=prod
PREFIX="qeet-id/${ENV}"

aws secretsmanager put-secret-value \
  --secret-id "${PREFIX}/JWT_SIGNING_KEY" \
  --secret-string "$(cat jwt-signing.pem)"

aws secretsmanager put-secret-value \
  --secret-id "${PREFIX}/JWT_SECRET" \
  --secret-string "$(openssl rand -base64 48)"

aws secretsmanager put-secret-value \
  --secret-id "${PREFIX}/CSRF_KEY" \
  --secret-string "$(openssl rand -base64 32)"

# Delete local secret files after storing
shred -u jwt-signing.pem saml-idp.key
```

## Verify boot gate

After updating secrets, verify the new deploy passes the production safety gate:

```bash
kubectl -n qeet-id logs job/qeet-id-migrate  # check migration succeeded
kubectl -n qeet-id rollout status deploy/qeet-id  # check new pods came up
curl https://api.id.qeet.in/healthz | jq .version  # confirm new version
```

If the API crashes immediately, it's almost always a `config.Validate()` failure. Check:
```bash
kubectl -n qeet-id logs deploy/qeet-id --previous | grep "config:"
```

## JWT signing key rotation (target: every 90 days)

Zero-downtime rotation:

```bash
# 1. Generate new key
openssl ecparam -name prime256v1 -genkey -noout -out jwt-signing-new.pem

# 2. Extract public key of OLD key (for JWT_RETIRED_KEYS grace window)
openssl ec -in jwt-signing-old.pem -pubout -out jwt-signing-old-pub.pem

# 3. Update secrets
aws secretsmanager put-secret-value \
  --secret-id "qeet-id/prod/JWT_SIGNING_KEY" \
  --secret-string "$(cat jwt-signing-new.pem)"

aws secretsmanager put-secret-value \
  --secret-id "qeet-id/prod/JWT_RETIRED_KEYS" \
  --secret-string "$(cat jwt-signing-old-pub.pem)"

# 4. Deploy (new tokens signed with new key; old tokens verify against retired key)

# 5. After 30d (refresh token TTL): remove JWT_RETIRED_KEYS, redeploy
```

## SAML cert rotation

```bash
# Generate new cert
openssl req -x509 -newkey rsa:2048 -keyout saml-idp-new.key -out saml-idp-new.crt \
  -days 730 -nodes -subj "/CN=Qeet ID SAML IdP/O=Qeet Group"

# Update secrets
aws secretsmanager put-secret-value \
  --secret-id "qeet-id/prod/SAML_IDP_KEY" \
  --secret-string "$(cat saml-idp-new.key)"
aws secretsmanager put-secret-value \
  --secret-id "qeet-id/prod/SAML_IDP_CERT" \
  --secret-string "$(cat saml-idp-new.crt)"

# Deploy — new SAML assertions use new cert
# Notify all connected SPs to re-import metadata from /saml/:conn/metadata.xml
```
