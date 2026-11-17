-- The earlier build can't load an RSA key, so it goes with the constraint.
DELETE FROM platform.jwt_signing_keys WHERE algorithm = 'RS256';
ALTER TABLE platform.jwt_signing_keys DROP CONSTRAINT IF EXISTS jwt_signing_keys_algorithm_check;
ALTER TABLE platform.jwt_signing_keys
    ADD CONSTRAINT jwt_signing_keys_algorithm_check
        CHECK (algorithm = 'ES256');
