# platform/storage

Object / blob storage client.

Planned: unified `BlobStore` interface over S3-compatible stores for:
- User avatars
- Audit log exports
- SAML metadata caching

Provider: AWS S3 (`STORAGE_PROVIDER=s3`, `STORAGE_BUCKET`).
