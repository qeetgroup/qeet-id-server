-- 0243_jwt_signing_key_rs256 — the token signing key may be an RSA key, which
-- signs RS256, as well as an EC P-256 key, which signs ES256: OpenID Connect
-- requires a provider to support RS256.
ALTER TABLE platform.jwt_signing_keys DROP CONSTRAINT IF EXISTS jwt_signing_keys_algorithm_check;
ALTER TABLE platform.jwt_signing_keys
    ADD CONSTRAINT jwt_signing_keys_algorithm_check
        CHECK (algorithm IN ('ES256', 'RS256'));
